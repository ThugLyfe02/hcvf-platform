# Findings triage

A findings list is a report. Triage turns it into work: who owns the issue, what
decision was taken, when it is due, and what changed.

## The workflow

Every finding has a severity-derived SLA window:

| Severity | Decision window |
|---|---|
| critical | 24 hours |
| high | 72 hours |
| medium | 14 days |
| low | 30 days |
| info | 45 days |

`GET /api/v1/findings/summary` returns counts by severity and status, aging
buckets, and the overdue list with hours late. The console dashboard surfaces the
overdue count and the findings detail page shows the window and due date.

## Transitions

Transitions are validated, not free-form:

- `open` -> triaged, confirmed, false_positive, risk_accepted, fixed, verified
- `triaged` -> confirmed, false_positive, risk_accepted, fixed, verified, open
- `fixed` -> verified, open (a regression reopens it)
- `false_positive` -> open, triaged
- anything else is rejected with 409 and the allowed set in the message

An unknown status is a 400. Keeping validation and history separate means a client
cannot "jump" a finding into a state that hides it.

## Notes and history

Every decision writes a `finding_notes` row with the status before and after,
the author, the note, and a timestamp. Rows are append-only; the current status
column is a cache of the latest decision, never the record. `GET
/findings/{id}/notes` returns the timeline, and the console renders it.

`POST /findings/{id}/notes` adds a note without changing status (useful for
investigation logs).

## Audit and notifications

Each triage writes an audit-chain entry (`finding.triage`) with the transition
and note, and publishes `finding.triaged` to subscribed webhooks. A scheduled
sync would find triage in the audit export even if a webhook were lost.

## Assignment

`assignee` is free-form ownership (`platform`, `team-web`, an email). It appears
in the summary's overdue list so an operator can route work, and it is recorded
on every triage event.

## Known limit

Findings discovered by objectives are currently visible in the objective report
and evidence, not inserted into the findings table; campaign runs own that
pipeline. The triage workflow therefore applies to campaign-derived findings
today. Wiring objective findings into the same table (with a nullable run
reference or a synthetic run row) is the next step and is deliberately not
claimed as done here.
