"""Time ranges and tolerant time parsing, normalized to UTC.

"Any time range" and "any time format" are explicit product requirements, so this
module is deliberately permissive on input and strict on internal representation:

    * Internally a :class:`TimeRange` is always a pair of timezone-aware UTC
      datetimes, closed on both ends (``start <= ts <= end``).
    * On input we accept relative windows ("last 24 hours", "past 7 days"),
      calendar words ("today", "yesterday"), ISO-8601 instants (with ``Z`` or
      numeric offset, ``T`` or space separator, date-only), epoch seconds, and
      explicit ``start..end`` / ``since``/``until`` combinations.

A naive instant (one with no timezone) is interpreted in an explicit reference
timezone supplied by the caller (normally the host's local zone) -- never
silently assumed to be UTC.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Optional


class TimeParseError(ValueError):
    """Raised when a time expression cannot be understood."""


@dataclass(frozen=True)
class TimeRange:
    """A closed UTC interval ``[start, end]``."""

    start: datetime
    end: datetime
    label: str = ""
    expr: str = ""

    def __post_init__(self) -> None:
        for name, dt in (("start", self.start), ("end", self.end)):
            if dt.tzinfo is None:
                raise ValueError(f"TimeRange.{name} must be timezone-aware")
        object.__setattr__(self, "start", self.start.astimezone(timezone.utc))
        object.__setattr__(self, "end", self.end.astimezone(timezone.utc))
        if self.end < self.start:
            raise TimeParseError(
                f"time range end ({self.end.isoformat()}) precedes start "
                f"({self.start.isoformat()})"
            )

    def contains(self, ts: datetime) -> bool:
        ts = ts.astimezone(timezone.utc)
        return self.start <= ts <= self.end

    def overlaps(self, a: datetime, b: Optional[datetime]) -> bool:
        """True if the interval ``[a, b]`` intersects this range.

        ``b`` may be ``None`` (an open-ended interval, e.g. a session that has not
        yet ended); it is then treated as extending to +infinity.
        """
        a = a.astimezone(timezone.utc)
        if b is None:
            return a <= self.end
        b = b.astimezone(timezone.utc)
        return a <= self.end and b >= self.start

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    def to_dict(self) -> dict:
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "label": self.label,
            "expr": self.expr,
        }

    def describe(self) -> str:
        if self.label:
            return f"{self.label} ({self.start.isoformat()} -> {self.end.isoformat()})"
        return f"{self.start.isoformat()} -> {self.end.isoformat()}"


# --------------------------------------------------------------------------- #
# Instant parsing
# --------------------------------------------------------------------------- #

_ISO_RE = re.compile(
    r"""^
    (?P<date>\d{4}-\d{2}-\d{2})
    (?:
        [ T]
        (?P<time>\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?)
        (?P<tz>Z|[+-]\d{2}:?\d{2})?
    )?
    $""",
    re.VERBOSE,
)


def parse_instant(text: str, default_tz: tzinfo) -> datetime:
    """Parse a single instant into a timezone-aware UTC datetime.

    Accepts ISO-8601 (with ``Z`` or numeric offset, ``T`` or space separator, or
    date-only), and integer/float epoch seconds. A value without an explicit
    timezone is localized using ``default_tz``.
    """
    s = text.strip()
    if not s:
        raise TimeParseError("empty time value")

    # Epoch seconds (all digits, optional fractional part).
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return datetime.fromtimestamp(float(s), tz=timezone.utc)

    m = _ISO_RE.match(s)
    if not m:
        raise TimeParseError(f"unrecognized timestamp: {text!r}")

    date_part = m.group("date")
    time_part = m.group("time") or "00:00:00"
    if time_part.count(":") == 1:
        time_part += ":00"
    tz_part = m.group("tz")

    # Normalize fractional seconds to microseconds.
    if "." in time_part:
        hms, frac = time_part.split(".", 1)
        frac = (frac + "000000")[:6]
        base = datetime.strptime(f"{date_part} {hms}", "%Y-%m-%d %H:%M:%S")
        base = base.replace(microsecond=int(frac))
    else:
        base = datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S")

    if tz_part is None:
        base = base.replace(tzinfo=default_tz)
    elif tz_part == "Z":
        base = base.replace(tzinfo=timezone.utc)
    else:
        tz_part = tz_part.replace(":", "")
        sign = 1 if tz_part[0] == "+" else -1
        hh = int(tz_part[1:3])
        mm = int(tz_part[3:5])
        base = base.replace(tzinfo=timezone(sign * timedelta(hours=hh, minutes=mm)))

    return base.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Range parsing
# --------------------------------------------------------------------------- #

_REL_RE = re.compile(
    r"^(?:last|past|previous)\s+(?P<num>\d+)?\s*(?P<unit>second|minute|hour|day|week|month)s?$"
)
_UNIT_SECONDS = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "week": 604800,
    "month": 2592000,  # 30 days; calendar months are ambiguous, documented below.
}


def parse_range(
    expr: str,
    *,
    now: datetime,
    default_tz: tzinfo,
) -> TimeRange:
    """Parse a natural time-range expression relative to ``now``.

    ``now`` must be timezone-aware. Supported forms (case-insensitive):

        * ``"last 24 hours"``, ``"past 7 days"``, ``"last hour"``, ``"last week"``
        * ``"today"``, ``"yesterday"``
        * ``"<instant>..<instant>"`` or ``"<instant>/<instant>"`` ISO ranges
        * a single instant (treated as that instant's whole day)

    A calendar ``"month"`` is treated as 30 days (documented, deterministic); use
    explicit start/end for exact calendar boundaries.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    raw = expr.strip()
    low = raw.lower()

    # Relative windows.
    m = _REL_RE.match(low)
    if m:
        num = int(m.group("num")) if m.group("num") else 1
        unit = m.group("unit")
        seconds = num * _UNIT_SECONDS[unit]
        start = now - timedelta(seconds=seconds)
        label = f"last {num} {unit}" + ("s" if num != 1 else "")
        return TimeRange(start=start, end=now, label=label, expr=raw)

    if low in ("today",):
        local_now = now.astimezone(default_tz)
        start_local = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
        return TimeRange(start=start_local, end=now, label="today", expr=raw)

    if low in ("yesterday",):
        local_now = now.astimezone(default_tz)
        start_today = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
        start_y = start_today - timedelta(days=1)
        end_y = start_today - timedelta(microseconds=1)
        return TimeRange(start=start_y, end=end_y, label="yesterday", expr=raw)

    # Explicit ranges: "A..B", "A / B", "A to B".
    sep_match = re.split(r"\s*(?:\.\.|/|\bto\b)\s*", raw, maxsplit=1)
    if len(sep_match) == 2 and sep_match[0] and sep_match[1]:
        start = parse_instant(sep_match[0], default_tz)
        end = parse_instant(sep_match[1], default_tz)
        return TimeRange(start=start, end=end, label="", expr=raw)

    # A single instant -> that calendar day in default_tz.
    inst = parse_instant(raw, default_tz)
    local = inst.astimezone(default_tz)
    day_start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end = day_start + timedelta(days=1) - timedelta(microseconds=1)
    return TimeRange(start=day_start, end=day_end, label=raw, expr=raw)


def build_range(
    *,
    expr: Optional[str],
    since: Optional[str],
    until: Optional[str],
    now: datetime,
    default_tz: tzinfo,
) -> TimeRange:
    """Resolve a time range from an optional expression and/or since/until.

    Precedence: explicit ``since``/``until`` override ``expr``. If neither is
    given, defaults to the last 24 hours.
    """
    if since or until:
        start = parse_instant(since, default_tz) if since else now - timedelta(days=1)
        end = parse_instant(until, default_tz) if until else now
        label = ""
        if since and not until:
            label = f"since {since}"
        return TimeRange(start=start, end=end, label=label, expr=(expr or ""))
    if expr:
        return parse_range(expr, now=now, default_tz=default_tz)
    return TimeRange(
        start=now - timedelta(days=1), end=now, label="last 24 hours", expr=""
    )
