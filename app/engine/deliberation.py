"""Multi-round deliberation between specialist agents.

The previous design had each agent propose once and critique once. That is a
panel, not a conversation: nobody can change their mind, nobody can answer an
objection, and no new option can appear once the round starts.

This module implements a bounded, typed deliberation:

    propose → support / oppose → challenge → reply → ruling → consensus

Properties that make it safe to run in production:

* **Bounded.** At most ``max_rounds``; if consensus is not reached the moderator
  records a forced decision and the dissent, and the arbiter still allocates the
  budget. Deliberation can never hang a hunt.
* **Deterministic.** No randomness; same view + same agents ⇒ same transcript.
* **Auditable.** Every utterance carries a round, an act, a score and the
  evidence behind it.
* **Grounded.** Agents argue about *instantiations* — a probe against a specific
  route — not abstractions, so a newly discovered route becomes a new option and
  the swarm can find a better avenue mid-conversation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.engine.agents import Critique, HuntingAgent, HuntView, Proposal
from app.engine.types import Cost, SafetyClass, ScopeGrant

MAX_ROUNDS = 5
CONSENSUS_MARGIN = 0.12
CONSENSUS_FLOOR = 0.52
WITHDRAW_THRESHOLD = 0.22


@dataclass(frozen=True, slots=True)
class Option:
    """A concrete thing the swarm could do: one probe against one route."""

    proposal: Proposal
    sponsor: str

    @property
    def id(self) -> str:
        return f"{self.proposal.probe_id}@{self.proposal.route}"

    @property
    def probe_id(self) -> str:
        return self.proposal.probe_id

    @property
    def route(self) -> str:
        return self.proposal.route

    @property
    def cost(self) -> Cost:
        return self.proposal.cost

    @property
    def safety(self) -> SafetyClass:
        return self.proposal.safety

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "probe_id": self.probe_id,
            "route": self.route,
            "sponsor": self.sponsor,
            "cost_requests": self.cost.requests,
            "safety": self.safety.name,
            "gain": round(self.proposal.expected_gain, 4),
        }


@dataclass(frozen=True, slots=True)
class Message:
    """One utterance in the transcript."""

    round: int
    agent: str
    act: str
    option_id: str
    text: str
    score: float | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "round": self.round,
            "agent": self.agent,
            "act": self.act,
            "option_id": self.option_id,
            "text": self.text,
            "score": round(self.score, 4) if self.score is not None else None,
            "evidence": self.evidence,
        }


@dataclass
class DeliberationResult:
    options: dict[str, Option]
    messages: list[Message]
    scores: dict[str, float]
    rounds: int
    converged: bool
    consensus_round: int | None
    leader: str | None
    agents: list[str]
    withdrawn: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "rounds": self.rounds,
            "converged": self.converged,
            "consensus_round": self.consensus_round,
            "leader": self.leader,
            "agents": self.agents,
            "withdrawn": self.withdrawn,
            "options": [option.to_dict() for option in self.options.values()],
            "scores": {key: round(value, 4) for key, value in self.scores.items()},
            "messages": [message.to_dict() for message in self.messages],
        }


class Deliberation:
    """Runs the conversation and returns a converged (or explicitly split) plan."""

    def __init__(
        self,
        agents: list[HuntingAgent],
        view: HuntView,
        grant: ScopeGrant,
        *,
        allowed: set[str] | None = None,
        max_rounds: int = MAX_ROUNDS,
        consensus_margin: float = CONSENSUS_MARGIN,
        consensus_floor: float = CONSENSUS_FLOOR,
    ) -> None:
        self.agents = list(agents)
        self.view = view
        self.grant = grant
        self.allowed = allowed
        self.max_rounds = max(2, max_rounds)
        self.consensus_margin = consensus_margin
        self.consensus_floor = consensus_floor
        self.messages: list[Message] = []
        self.options: dict[str, Option] = {}
        self.withdrawn: list[str] = []
        self._weights = {agent.name: agent.weight for agent in self.agents}

    # -- setup -----------------------------------------------------------
    def _add_option(self, option: Option, *, round_no: int, enforce_allowed: bool = True) -> bool:
        # Safety is absolute; the genome is only a default doctrine.
        if option.safety > self.view.max_safety:
            return False
        if enforce_allowed and self.allowed is not None and option.probe_id not in self.allowed:
            return False
        if option.id in self.options or option.id in self.withdrawn:
            return False
        self.options[option.id] = option
        self.messages.append(
            Message(
                round=round_no,
                agent=option.sponsor,
                act="propose",
                option_id=option.id,
                text=option.proposal.rationale,
                evidence={
                    "cost_requests": option.cost.requests,
                    "gain": round(option.proposal.expected_gain, 4),
                    "safety": option.safety.name,
                },
            )
        )
        return True

    def _spawn_specialists(self, round_no: int) -> None:
        """A generalist convenes a specialist when the surface justifies one."""

        for agent in list(self.agents):
            spawn = getattr(agent, "spawn", None)
            if spawn is None:
                continue
            for spawned, trigger in spawn(self.view):
                if any(existing.name == spawned.name for existing in self.agents):
                    continue
                self.agents.append(spawned)
                self._weights[spawned.name] = spawned.weight
                self.messages.append(
                    Message(
                        round=round_no,
                        agent=agent.name,
                        act="spawn",
                        option_id="",
                        text=f"Convening {spawned.name}: {trigger}",
                        evidence={"trigger": trigger},
                    )
                )
                for proposal in spawned.propose(self.view):
                    self._add_option(
                        Option(proposal=proposal, sponsor=spawned.name),
                        round_no=round_no,
                        enforce_allowed=False,
                    )

    # -- protocol --------------------------------------------------------
    def run(self) -> DeliberationResult:
        round_no = 1
        for agent in list(self.agents):
            for proposal in agent.propose(self.view):
                self._add_option(Option(proposal=proposal, sponsor=agent.name), round_no=round_no)
        self._spawn_specialists(round_no)

        scores: dict[str, float] = {}
        leader: str | None = None
        converged = False
        consensus_round: int | None = None
        previous_plan: tuple[str, ...] | None = None

        for round_no in range(2, self.max_rounds + 1):
            if not self.options:
                break
            scores = self._collect_votes(round_no)
            leader, margin = self._leader(scores)
            upheld, penalty = self._adjudicate(leader, round_no)
            if upheld:
                scores[leader] = max(0.0, scores.get(leader, 0.0) - penalty)
                leader_score = scores[leader]
            else:
                leader_score = scores.get(leader, 0.0)

            # Convergence is agreement on the plan, not worship of one option:
            # if two consecutive rounds select the same budgeted probe set, the
            # room has settled even when two options score closely.
            plan_ids = self._plan_set(scores)
            stable = previous_plan is not None and plan_ids == previous_plan and bool(plan_ids)

            if stable and leader_score >= self.consensus_floor:
                converged = True
                consensus_round = round_no
                self.messages.append(
                    Message(
                        round=round_no,
                        agent="moderator",
                        act="consensus",
                        option_id=leader,
                        text=(
                            f"Consensus on a plan of {len(plan_ids)} probes after {round_no} rounds "
                            f"(identical allocation two rounds running; leader {leader} at {leader_score:.2f})."
                        ),
                        score=leader_score,
                        evidence={
                            "margin": round(margin, 4),
                            "rounds": round_no,
                            "plan": list(plan_ids),
                        },
                    )
                )
                break

            if margin >= self.consensus_margin and leader_score >= self.consensus_floor and not upheld:
                converged = True
                consensus_round = round_no
                self.messages.append(
                    Message(
                        round=round_no,
                        agent="moderator",
                        act="consensus",
                        option_id=leader,
                        text=(
                            f"Consensus in round {round_no}: {leader} leads by {margin:.0%} "
                            f"with support {leader_score:.2f}."
                        ),
                        score=leader_score,
                        evidence={"margin": round(margin, 4), "rounds": round_no},
                    )
                )
                break

            previous_plan = plan_ids

            self.messages.append(
                Message(
                    round=round_no,
                    agent="moderator",
                    act="moderate",
                    option_id=leader,
                    text=(
                        f"No consensus in round {round_no} (margin {margin:.0%}, leader {leader_score:.2f}"
                        f"{', objection upheld' if upheld else ''}). Opening another round."
                    ),
                    evidence={"margin": round(margin, 4), "upheld": upheld},
                )
            )
            self._withdraw_weak(round_no, scores)

        if leader is None:
            scores = self._collect_votes(round_no + 1)
            leader, _ = self._leader(scores)

        if not converged:
            self.messages.append(
                Message(
                    round=round_no,
                    agent="moderator",
                    act="consensus",
                    option_id=leader or "",
                    text=(
                        f"Round limit reached without consensus. Proceeding with {leader} and recording "
                        "the dissent below for the auditor."
                    ),
                    evidence={"forced": True, "leader": leader},
                )
            )

        return DeliberationResult(
            options=dict(self.options),
            messages=self.messages,
            scores=scores,
            rounds=round_no,
            converged=converged,
            consensus_round=consensus_round,
            leader=leader,
            agents=[agent.name for agent in self.agents],
            withdrawn=list(self.withdrawn),
        )

    def _collect_votes(self, round_no: int) -> dict[str, float]:
        totals: dict[str, float] = dict.fromkeys(self.options, 0.0)
        active: list[str] = []

        for agent in self.agents:
            spoke = False
            for option in self.options.values():
                if option.id in self.withdrawn:
                    continue
                score, reason = self._evaluate(agent, option, round_no)
                totals[option.id] = totals.get(option.id, 0.0) + self._weights.get(agent.name, 1.0) * score
                spoke = True
                self.messages.append(
                    Message(
                        round=round_no,
                        agent=agent.name,
                        act="support" if score >= 0.5 else "oppose",
                        option_id=option.id,
                        text=reason,
                        score=score,
                    )
                )
            if spoke:
                active.append(agent.name)

        total_weight = sum(self._weights.get(agent, 1.0) for agent in active) or 1.0
        return {key: value / total_weight for key, value in totals.items()}

    def _evaluate(self, agent: HuntingAgent, option: Option, round_no: int) -> tuple[float, str]:
        critique: Critique = agent.critique(option.proposal, self.view)
        if critique.blocker:
            return 0.0, f"blocked: {critique.blocker}"

        # Sponsors advocate rather than self-score: a capped voice, not a veto.
        if agent.name == option.sponsor:
            advocate = min(0.7, 0.45 + 0.25 * option.proposal.priority)
            return advocate, f"sponsor advocacy (capped at {advocate:.2f})"

        score, reason = critique.score, critique.reason
        if round_no >= 3:
            history = self.view.bandit.arm(option.probe_id).mean
            score = 0.7 * score + 0.3 * history
            reason += f" round3_history={history:.2f}"
        return max(0.0, min(1.0, score)), reason

    def _plan_set(self, scores: dict[str, float]) -> tuple[str, ...]:
        """The budgeted set the current scores would select (one option per probe)."""

        allowance = max(1, int(self.view.budget_requests * 0.85))
        ordered = sorted(
            (option_id for option_id in self.options if option_id not in self.withdrawn),
            key=lambda option_id: scores.get(option_id, 0.0),
            reverse=True,
        )
        chosen: list[str] = []
        probes: set[str] = set()
        used = 0
        for option_id in ordered:
            option = self.options[option_id]
            if option.probe_id in probes:
                continue
            if used + option.cost.requests > allowance:
                continue
            used += option.cost.requests
            probes.add(option.probe_id)
            chosen.append(option_id)
        return tuple(sorted(chosen))

    def _leader(self, scores: dict[str, float]) -> tuple[str, float]:
        ranked = sorted(
            ((option_id, score) for option_id, score in scores.items() if option_id not in self.withdrawn),
            key=lambda item: item[1],
            reverse=True,
        )
        if not ranked:
            return "", 0.0
        top_id, top_score = ranked[0]
        second = ranked[1][1] if len(ranked) > 1 else 0.0
        return top_id, (top_score - second) / max(top_score, 1e-6)

    def _adjudicate(self, leader: str, round_no: int) -> tuple[bool, float]:
        """Challenge the leader, let the sponsor answer, let risk rule on it."""

        if not leader:
            return False, 0.0
        option = self.options[leader]
        challenger = next((agent for agent in self.agents if hasattr(agent, "challenge")), None)
        adjudicator = next((agent for agent in self.agents if hasattr(agent, "rule")), None)
        if challenger is None:
            return False, 0.0

        rivals = tuple(
            candidate
            for option_id, candidate in self.options.items()
            if option_id != leader and option_id not in self.withdrawn
        )
        objection = challenger.challenge(option, self.view, round_no, rivals)  # type: ignore[attr-defined]
        if objection is None:
            return False, 0.0
        self.messages.append(
            Message(
                round=round_no,
                agent=challenger.name,
                act="challenge",
                option_id=leader,
                text=objection.text,
                evidence={"code": objection.code, "blocking": objection.blocking, "penalty": objection.penalty},
            )
        )

        sponsor = next((agent for agent in self.agents if agent.name == option.sponsor), None)
        rebuttal = None
        if sponsor is not None:
            reply = getattr(sponsor, "reply", None)
            if reply is not None:
                rebuttal = reply(objection, option, self.view)
                if rebuttal is not None:
                    self.messages.append(
                        Message(
                            round=round_no,
                            agent=sponsor.name,
                            act="reply",
                            option_id=leader,
                            text=rebuttal.text,
                            evidence={"resolves": rebuttal.resolves},
                        )
                    )

        ruling = None
        if adjudicator is not None and hasattr(adjudicator, "rule"):
            ruling = adjudicator.rule(objection, rebuttal, option, self.view)  # type: ignore[attr-defined]
            if ruling is not None:
                self.messages.append(
                    Message(
                        round=round_no,
                        agent=adjudicator.name,
                        act="ruling",
                        option_id=leader,
                        text=ruling.text,
                        evidence={"upheld": ruling.upheld, "penalty": ruling.penalty},
                    )
                )

        if ruling is None:
            return objection.blocking, objection.penalty if objection.blocking else 0.0
        return ruling.upheld, ruling.penalty

    def _withdraw_weak(self, round_no: int, scores: dict[str, float]) -> None:
        """Let sponsors withdraw rather than defend an option nobody supports."""

        for option_id, score in list(scores.items()):
            if option_id in self.withdrawn or score >= WITHDRAW_THRESHOLD:
                continue
            option = self.options.get(option_id)
            if option is None:
                continue
            self.withdrawn.append(option_id)
            self.messages.append(
                Message(
                    round=round_no,
                    agent=option.sponsor,
                    act="withdraw",
                    option_id=option_id,
                    text=(
                        f"Withdrawing {option.probe_id} at {option.route}: support {score:.2f} does not "
                        "justify the budget."
                    ),
                    score=score,
                )
            )
