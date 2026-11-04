"""Render the deliberation transcript for humans.

The JSON form is for machines; this is for the person who has to justify the
hunt. It reads as a minute-by-minute account: who proposed what, who objected,
who answered, who ruled, and where the room landed.
"""

from __future__ import annotations

ACTS = {
    "propose": "proposes",
    "support": "supports",
    "oppose": "opposes",
    "challenge": "challenges",
    "reply": "replies",
    "ruling": "rules",
    "spawn": "convenes",
    "withdraw": "withdraws",
    "moderate": "moderates",
    "consensus": "closes",
}


def _plan_dict(plan: object) -> dict:
    if isinstance(plan, dict):
        return plan
    return plan.to_dict()  # type: ignore[union-attr]


def render_markdown(plan: object, *, include_votes: bool = True) -> str:
    data = _plan_dict(plan)
    debate = data.get("deliberation") or {}
    messages = debate.get("messages") or []
    decisions = data.get("decisions") or []
    rounds = debate.get("rounds", 0)
    converged = bool(debate.get("converged"))
    agents = debate.get("agents") or []

    lines = [
        f"# Deliberation - {data.get('target', '')}",
        "",
        f"- **Rounds:** {rounds}",
        f"- **Outcome:** {'consensus' if converged else 'no consensus (forced decision, dissent recorded)'}",
        f"- **Agents:** {', '.join(f'`{name}`' for name in agents) or 'none'}",
        f"- **Utterances:** {len(messages)}",
        f"- **Decision seed:** `{data.get('seed')}`",
        "",
        "## Conversation",
        "",
    ]

    by_round: dict[int, list[dict]] = {}
    for message in messages:
        by_round.setdefault(int(message.get("round", 0)), []).append(message)

    for round_no in sorted(by_round):
        lines.append(f"### Round {round_no}")
        lines.append("")
        for message in by_round[round_no]:
            act = str(message.get("act", ""))
            if act in {"support", "oppose"} and not include_votes:
                continue
            verb = ACTS.get(act, act)
            score = message.get("score")
            score_text = f" (`{score:.2f}`)" if isinstance(score, (int, float)) else ""
            target = message.get("option_id") or ""
            option_text = f" **{target}**" if target else ""
            lines.append(f"- **{message.get('agent')}** {verb}{option_text}{score_text} - {message.get('text', '')}")
        lines.append("")

    if not include_votes:
        votes = sum(1 for m in messages if m.get("act") in {"support", "oppose"})
        lines.append(f"_{votes} support/oppose votes recorded in the JSON transcript._")
        lines.append("")

    lines += ["## Final allocation", "", "| Probe | Score | Selected | Reason |", "|---|---|---|---|"]
    for decision in decisions:
        lines.append(
            f"| `{decision.get('probe_id')}` | {decision.get('score', 0):.2f} | "
            f"{'yes' if decision.get('selected') else 'no'} | {str(decision.get('reason', ''))[:120]} |"
        )
    lines.append("")

    dissent = [
        message
        for message in messages
        if message.get("act") in {"oppose", "challenge"}
        and message.get("round") == max((m.get("round", 0) for m in messages), default=0)
    ]
    if dissent and not converged:
        lines += ["## Dissent recorded at adjournment", ""]
        for message in dissent[:12]:
            lines.append(f"- **{message.get('agent')}**: {message.get('text', '')}")
        lines.append("")

    return "\n".join(lines)


def render_text(plan: object, *, include_votes: bool = False) -> str:
    data = _plan_dict(plan)
    debate = data.get("deliberation") or {}
    messages = debate.get("messages") or []
    out = [
        f"deliberation on {data.get('target')}: {debate.get('rounds', 0)} rounds, "
        f"{'consensus' if debate.get('converged') else 'no consensus'}, {len(messages)} utterances"
    ]
    for message in messages:
        if message.get("act") in {"support", "oppose"} and not include_votes:
            continue
        out.append(f"  r{message.get('round')} {message.get('agent')}: {message.get('act')} {message.get('option_id')}")
    return "\n".join(out)
