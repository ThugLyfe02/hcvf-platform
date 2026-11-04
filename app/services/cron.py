"""Five-field cron expressions, evaluated without a dependency.

Supported: ``*``, exact numbers, ranges (``1-5``), steps (``*/15``, ``1-5/2``)
and comma lists (``1,15,30``). Day-of-month and day-of-week follow Vixie cron:
when both are restricted, a date matches if either matches.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

MAX_MINUTES = 366 * 24 * 60


class CronError(ValueError):
    pass


def _parse_field(field: str, low: int, high: int) -> set[int]:
    values: set[int] = set()
    for chunk in field.split(","):
        chunk = chunk.strip()
        if not chunk:
            raise CronError(f"empty cron field segment in {field!r}")
        step = 1
        if "/" in chunk:
            chunk, raw_step = chunk.split("/", 1)
            step = int(raw_step)
            if step < 1:
                raise CronError("cron step must be >= 1")
        if chunk == "*":
            start, end = low, high
        elif "-" in chunk:
            start_raw, end_raw = chunk.split("-", 1)
            start, end = int(start_raw), int(end_raw)
        else:
            start = end = int(chunk)
            if "/" in field and step:
                end = high
        if start < low or end > high or start > end:
            raise CronError(f"cron field {field!r} out of range {low}-{high}")
        values.update(range(start, end + 1, step))
    if not values:
        raise CronError(f"cron field {field!r} matched nothing")
    return values


class CronExpression:
    def __init__(self, expression: str) -> None:
        parts = expression.split()
        if len(parts) != 5:
            raise CronError("cron expression must have five fields")
        self.expression = " ".join(parts)
        self.minutes = _parse_field(parts[0], 0, 59)
        self.hours = _parse_field(parts[1], 0, 23)
        self.days_of_month = _parse_field(parts[2], 1, 31)
        self.months = _parse_field(parts[3], 1, 12)
        self.days_of_week = {value % 7 for value in _parse_field(parts[4], 0, 7)}
        self.dom_restricted = parts[2] != "*"
        self.dow_restricted = parts[4] != "*"

    def matches(self, moment: datetime) -> bool:
        if moment.minute not in self.minutes or moment.hour not in self.hours:
            return False
        if moment.month not in self.months:
            return False
        dom_ok = moment.day in self.days_of_month
        dow_ok = (moment.weekday() + 1) % 7 in self.days_of_week  # cron: Sunday=0
        if self.dom_restricted and self.dow_restricted:
            return dom_ok or dow_ok
        if self.dom_restricted:
            return dom_ok
        if self.dow_restricted:
            return dow_ok
        return True

    def next_after(self, moment: datetime) -> datetime:
        candidate = (moment + timedelta(minutes=1)).replace(second=0, microsecond=0)
        for _ in range(MAX_MINUTES):
            if self.matches(candidate):
                return candidate
            candidate += timedelta(minutes=1)
        raise CronError(f"no occurrence within a year for {self.expression!r}")


def next_run(expression: str, *, after: datetime | None = None) -> datetime:
    after = after or datetime.now(UTC)
    if after.tzinfo is None:
        after = after.replace(tzinfo=UTC)
    return CronExpression(expression).next_after(after)
