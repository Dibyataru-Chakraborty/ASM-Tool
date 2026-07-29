"""Small, dependency-free five-field cron evaluator with timezone support."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class CronValidationError(ValueError):
    """Raised when a cron expression or timezone is invalid."""


def validate_timezone(timezone_name: str) -> ZoneInfo:
    try:
        return ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise CronValidationError(f"Unknown timezone: {timezone_name}") from exc


def _parse_field(
    raw: str,
    minimum: int,
    maximum: int,
    *,
    weekday: bool = False,
) -> tuple[set[int], bool]:
    value = raw.strip()
    if not value:
        raise CronValidationError("Cron fields cannot be empty")

    wildcard = value == "*" or value.startswith("*/")
    result: set[int] = set()

    for part in value.split(","):
        part = part.strip()
        if not part:
            raise CronValidationError(f"Invalid empty cron item in '{raw}'")

        if "/" in part:
            base, step_text = part.split("/", 1)
            try:
                step = int(step_text)
            except ValueError as exc:
                raise CronValidationError(f"Invalid cron step '{step_text}'") from exc
            if step <= 0:
                raise CronValidationError("Cron step must be greater than zero")
        else:
            base, step = part, 1

        if base == "*":
            start, end = minimum, maximum
        elif "-" in base:
            start_text, end_text = base.split("-", 1)
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise CronValidationError(f"Invalid cron range '{base}'") from exc
            if start > end:
                raise CronValidationError(f"Cron range starts after it ends: '{base}'")
        else:
            try:
                start = end = int(base)
            except ValueError as exc:
                raise CronValidationError(f"Invalid cron value '{base}'") from exc

        allowed_maximum = 7 if weekday else maximum
        if start < minimum or end > allowed_maximum:
            raise CronValidationError(
                f"Cron value '{base}' must be between {minimum} and {allowed_maximum}"
            )

        for item in range(start, end + 1, step):
            result.add(0 if weekday and item == 7 else item)

    if not result:
        raise CronValidationError(f"Cron field '{raw}' selects no values")
    return result, wildcard


class CronExpression:
    """Parse and calculate the next occurrence of a standard five-field cron."""

    def __init__(self, expression: str):
        fields = expression.strip().split()
        if len(fields) != 5:
            raise CronValidationError(
                "Cron must contain five fields: minute hour day month weekday"
            )

        self.expression = " ".join(fields)
        self.minutes, _ = _parse_field(fields[0], 0, 59)
        self.hours, _ = _parse_field(fields[1], 0, 23)
        self.days, self.day_wildcard = _parse_field(fields[2], 1, 31)
        self.months, _ = _parse_field(fields[3], 1, 12)
        self.weekdays, self.weekday_wildcard = _parse_field(
            fields[4],
            0,
            6,
            weekday=True,
        )

    def matches(self, local_time: datetime) -> bool:
        cron_weekday = local_time.isoweekday() % 7
        day_match = local_time.day in self.days
        weekday_match = cron_weekday in self.weekdays

        if self.day_wildcard and self.weekday_wildcard:
            calendar_match = True
        elif self.day_wildcard:
            calendar_match = weekday_match
        elif self.weekday_wildcard:
            calendar_match = day_match
        else:
            # Standard cron treats restricted day-of-month and day-of-week as OR.
            calendar_match = day_match or weekday_match

        return (
            local_time.minute in self.minutes
            and local_time.hour in self.hours
            and local_time.month in self.months
            and calendar_match
        )

    def next_after(
        self,
        after: datetime,
        timezone_name: str,
        *,
        search_days: int = 370,
    ) -> datetime:
        zone = validate_timezone(timezone_name)
        if after.tzinfo is None:
            after = after.replace(tzinfo=timezone.utc)
        after_utc = after.astimezone(timezone.utc)
        candidate = after_utc.replace(second=0, microsecond=0) + timedelta(minutes=1)
        limit = candidate + timedelta(days=search_days)

        # Iterating UTC minutes makes daylight-saving transitions correct:
        # nonexistent wall times are skipped and repeated times remain unambiguous.
        while candidate <= limit:
            if self.matches(candidate.astimezone(zone)):
                return candidate
            candidate += timedelta(minutes=1)

        raise CronValidationError(
            f"No execution time found within {search_days} days for '{self.expression}'"
        )

