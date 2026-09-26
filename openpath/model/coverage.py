"""The coverage ledger: OpenPath's honest account of what it could and could not see.

This is the machinery behind the "Gaps" question (family 13) and behind the whole
soundness contract. A facet that has no evidence has two very different possible
explanations:

    1. the user genuinely did nothing of that kind, or
    2. the host was not instrumented to record it (auditd rule missing, log not
       retained, source absent, or the requested window predates the oldest
       record).

Conflating those is the classic way a forensic tool lies by omission. Every
collector therefore reports a :class:`SourceCoverage` describing its status, the
time horizon it actually spans, and which instrumentation checks passed. Facets
translate missing prerequisites into explicit :class:`Gap` entries.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from openpath.model.timerange import TimeRange


class SourceStatus(enum.Enum):
    AVAILABLE = "available"            # present and readable, with records
    EMPTY = "empty"                    # present and readable, but zero records
    NOT_CONFIGURED = "not_configured"  # present but not instrumented for this data
    ABSENT = "absent"                  # the source does not exist on this host
    UNREADABLE = "unreadable"          # exists but permission/parse error
    OUT_OF_HORIZON = "out_of_horizon"  # exists, but retention predates the window


@dataclass
class InstrumentationCheck:
    """Whether a specific recording capability is switched on.

    e.g. ``name="execve syscall audit rule"``, ``present=False`` means process
    executions are not being recorded, so the Commands/Root-activity questions
    cannot be answered from this host and must disclose that.
    """

    name: str
    present: bool
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "present": self.present, "detail": self.detail}


@dataclass
class SourceCoverage:
    """What one collector observed about its own completeness."""

    source_id: str
    status: SourceStatus
    detail: str = ""
    horizon_start: Optional[datetime] = None  # earliest record actually available
    horizon_end: Optional[datetime] = None    # latest record actually available
    record_count: int = 0
    # Evidence conservation. ``records_scanned`` is how many raw units the parser
    # examined for event content; ``unparseable`` is how many of those it could not
    # decode and therefore dropped. ``unparseable`` MUST be zero on a healthy
    # source; any non-zero value is surfaced as a conservation gap so a record can
    # never vanish silently (the "225 in, 200 out, success reported" failure).
    records_scanned: int = 0
    unparseable: int = 0
    unparseable_detail: str = ""
    instrumentation: List[InstrumentationCheck] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)  # files/paths consulted
    # True when the collector saw evidence its history is retention-bounded (a
    # rotated .1/.2 file was present). Only then does "earliest record is after
    # the window start" indicate a real blind spot rather than merely a quiet log.
    retention_bounded: bool = False

    def covers_window(self, window: TimeRange, effective_start: Optional[datetime] = None) -> bool:
        """True if this source can speak to the whole (effective) window.

        A continuous (non-rotated) log is assumed to span back to its own creation,
        so a late first *record* does not, by itself, mean missing coverage -- the
        log was simply quiet. Only a retention-bounded source must prove its
        earliest record reaches the window start.

        ``effective_start`` lets callers pass a boot-adjusted start (the machine
        was down before it, so nothing could have happened).
        """
        if self.status not in (SourceStatus.AVAILABLE, SourceStatus.EMPTY):
            return False
        start = effective_start or window.start
        start = start.astimezone(timezone.utc)
        if not self.retention_bounded:
            return True
        if self.horizon_start is None:
            return False
        return self.horizon_start.astimezone(timezone.utc) <= start

    def instrument(self, name: str) -> Optional[InstrumentationCheck]:
        for c in self.instrumentation:
            if c.name == name:
                return c
        return None

    def has_instrument(self, name: str) -> bool:
        c = self.instrument(name)
        return bool(c and c.present)

    @property
    def usable(self) -> bool:
        """True if the source produced (or could produce) records for the window."""
        return self.status in (SourceStatus.AVAILABLE, SourceStatus.EMPTY)

    def freshness_seconds(self, now: datetime) -> Optional[float]:
        """Age of the NEWEST record vs the analysis anchor, in seconds.

        This is the evidence-freshness signal: how stale the most recent thing this
        source can attest to is. ``None`` when the source carries no timestamped
        record (nothing to measure), so a caller never mistakes "unknown" for
        "fresh". State-snapshot sources (persistence/authz/...) stamp at ``now``, so
        their freshness is ~0 by construction, which is correct: they describe the
        present.
        """
        if self.horizon_end is None:
            return None
        return (now.astimezone(timezone.utc)
                - self.horizon_end.astimezone(timezone.utc)).total_seconds()

    def is_stale(self, now: datetime, max_age_seconds: float) -> bool:
        """True when the newest record is older than ``max_age_seconds``.

        Only meaningful for a source that should be continuously fed; a source with
        no timestamped record (freshness None) is not called stale here -- absence is
        a coverage question, staleness a freshness one, and the two are kept
        distinct so neither masks the other.
        """
        age = self.freshness_seconds(now)
        return age is not None and age > max_age_seconds

    def to_dict(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        d = {
            "source_id": self.source_id,
            "status": self.status.value,
            "detail": self.detail,
            "horizon_start": self.horizon_start.isoformat() if self.horizon_start else None,
            "horizon_end": self.horizon_end.isoformat() if self.horizon_end else None,
            "record_count": self.record_count,
            "records_scanned": self.records_scanned,
            "unparseable": self.unparseable,
            "unparseable_detail": self.unparseable_detail,
            "retention_bounded": self.retention_bounded,
            "instrumentation": [c.to_dict() for c in self.instrumentation],
            "locations": list(self.locations),
        }
        if now is not None:
            d["freshness_seconds"] = self.freshness_seconds(now)
        return d


def ledger_source_met(ledger: "CoverageLedger", source_id: str,
                      instrument: Optional[str] = None) -> bool:
    """True if a source is usable for answering (present, in-horizon, instrumented).

    The single availability predicate shared by the facet prereq checks and the
    confidence layer, so "answerable" and "not UNANSWERABLE" can never disagree.
    """
    cov = ledger.get(source_id)
    if cov is None or cov.status in (
        SourceStatus.ABSENT, SourceStatus.UNREADABLE, SourceStatus.OUT_OF_HORIZON,
    ):
        return False
    if instrument is not None and not cov.has_instrument(instrument):
        return False
    return True


@dataclass
class Gap:
    """Something OpenPath could not determine, stated plainly with a reason.

    Attributes:
        question: The question family / facet this gap belongs to.
        reason: Why it could not be determined (missing source, missing rule,
            retention horizon, permission).
        source_id: The source that would have answered it, if identifiable.
        remedy: Optional actionable hint to close the gap (e.g. the audit rule to
            add), so the ledger is not just a complaint but a checklist.
    """

    question: str
    reason: str
    source_id: Optional[str] = None
    remedy: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {"question": self.question, "reason": self.reason}
        if self.source_id:
            d["source_id"] = self.source_id
        if self.remedy:
            d["remedy"] = self.remedy
        return d


@dataclass
class CoverageLedger:
    """Aggregate of per-source coverage plus derived gaps and horizon findings."""

    window: TimeRange
    sources: List[SourceCoverage] = field(default_factory=list)
    gaps: List[Gap] = field(default_factory=list)
    # First system boot observed within the window, if any. Before it the machine
    # was down, so that sub-interval is not a blind spot -- nothing could happen.
    first_boot: Optional[datetime] = None

    def add_source(self, cov: SourceCoverage) -> None:
        self.sources.append(cov)

    def add_gap(self, gap: Gap) -> None:
        self.gaps.append(gap)

    def get(self, source_id: str) -> Optional[SourceCoverage]:
        for s in self.sources:
            if s.source_id == source_id:
                return s
        return None

    def effective_start(self) -> datetime:
        """Window start adjusted for a boot: the earliest instant activity was possible."""
        if self.first_boot is not None:
            fb = self.first_boot.astimezone(timezone.utc)
            if fb > self.window.start:
                return fb
        return self.window.start

    def horizon_shortfalls(self) -> List[Gap]:
        """Sources with a *real* retention shortfall for the effective window.

        Fires only when either (a) the source's data lies entirely outside the
        window (OUT_OF_HORIZON), or (b) the source is retention-bounded (a rotated
        file was present) and its earliest retained record is still after the
        effective window start. A merely-quiet continuous log is not a gap.
        """
        eff = self.effective_start()
        out: List[Gap] = []
        for s in self.sources:
            if s.status == SourceStatus.OUT_OF_HORIZON:
                out.append(Gap(
                    question="horizon",
                    reason=(
                        f"{s.source_id}: retained data begins "
                        f"{s.horizon_start.isoformat() if s.horizon_start else 'unknown'}, "
                        f"after the requested window; activity in the window cannot "
                        f"be confirmed or denied from this source."
                    ),
                    source_id=s.source_id,
                    remedy="increase retention / provide older rotated logs or an "
                           "archived evidence bundle covering the window.",
                ))
            elif (
                s.retention_bounded
                and s.status == SourceStatus.AVAILABLE
                and s.horizon_start is not None
                and s.horizon_start.astimezone(timezone.utc) > eff
            ):
                out.append(Gap(
                    question="horizon",
                    reason=(
                        f"{s.source_id}: history is retention-bounded and its "
                        f"earliest retained record is {s.horizon_start.isoformat()}, "
                        f"after the effective window start {eff.isoformat()}; the "
                        f"interval before that is a blind spot for this source."
                    ),
                    source_id=s.source_id,
                    remedy="provide older rotated logs to extend coverage back to "
                           "the window start.",
                ))
        return out

    def conservation_gaps(self) -> List[Gap]:
        """A gap for every source that dropped a record it could not decode.

        This is the evidence-conservation guarantee: a parser that reads N raw
        units and emits fewer must account for the difference. Any ``unparseable``
        count > 0 is disclosed here rather than being swallowed, so OpenPath can
        never report success while records have silently disappeared.
        """
        out: List[Gap] = []
        for s in self.sources:
            if s.unparseable > 0:
                out.append(Gap(
                    question="conservation",
                    reason=(
                        f"{s.source_id}: {s.unparseable} record(s) could not be "
                        f"decoded and are therefore unaccounted for"
                        + (f" ({s.unparseable_detail})" if s.unparseable_detail else "")
                        + "; the evidence from this source may be incomplete."
                    ),
                    source_id=s.source_id,
                    remedy="inspect the source for truncation or corruption and "
                           "provide an intact copy (or an evidence bundle captured "
                           "with integrity) covering the window.",
                ))
        return out

    def all_gaps(self) -> List[Gap]:
        """Facet gaps + derived horizon shortfalls + conservation gaps, de-duped."""
        seen = set()
        out: List[Gap] = []
        for g in (list(self.gaps) + self.horizon_shortfalls()
                  + self.conservation_gaps()):
            key = (g.question, g.reason, g.source_id)
            if key not in seen:
                seen.add(key)
                out.append(g)
        return out

    def to_dict(self) -> Dict[str, Any]:
        # The window end is the analysis anchor; freshness is measured against it.
        now = self.window.end
        return {
            "window": self.window.to_dict(),
            "sources": [s.to_dict(now=now) for s in self.sources],
            "gaps": [g.to_dict() for g in self.all_gaps()],
        }
