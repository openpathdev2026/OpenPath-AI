"""btmp collector: failed login attempts (the evidence behind `lastb`).

``/var/log/btmp`` records failed logins in the same binary ``struct utmp`` format
as wtmp, so we reuse the wtmp parser. Each record is one failed attempt: the
account name that was tried, where it came from, and when -- exactly what the
Login question (family 4, "where did they connect from") needs to also answer
"who tried and failed to log in as <user>, and from where".
"""

from __future__ import annotations

from typing import List, Tuple

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import (
    InstrumentationCheck,
    SourceCoverage,
    SourceStatus,
)
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector
from openpath.sources.wtmp import parse_utmp_bytes

_BTMP_PATHS = ["var/log/btmp.1", "var/log/btmp"]


class BtmpCollector(Collector):
    source_id = "btmp"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        records = []
        locations: List[str] = []
        for rel in _BTMP_PATHS:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p))
            try:
                data = p.read_bytes()
            except OSError:
                continue
            records.extend(parse_utmp_bytes(data, rel))

        if not locations:
            cov = SourceCoverage(
                source_id=self.source_id, status=SourceStatus.ABSENT,
                detail="no btmp file found under data root",
                instrumentation=[InstrumentationCheck(
                    "btmp accounting present", False,
                    "var/log/btmp not found; failed-login history unavailable")],
            )
            return CollectResult(events=[], coverage=cov)

        timed = [r for r in records if r.ts is not None]
        hstart, hend = self._span([r.ts for r in timed])

        events: List[Event] = []
        for r in timed:
            if not window.contains(r.ts):
                continue
            origin = r.host or "local"
            events.append(Event(
                ts=r.ts, type=EventType.LOGIN, source_id=self.source_id,
                summary=f"failed login as {r.user or '?'} from {origin} on {r.line}",
                actor_name=r.user or None,
                attrs={"result": "failed", "origin": origin, "host": r.host,
                       "line": r.line},
                citations=[Citation(self.source_id, r.locator, r.raw)],
            ))
        events.sort(key=lambda e: e.ts)

        status = SourceStatus.AVAILABLE if records else SourceStatus.EMPTY
        if hstart is not None and hstart > window.end:
            status = SourceStatus.OUT_OF_HORIZON

        cov = SourceCoverage(
            source_id=self.source_id, status=status,
            detail=f"{len(records)} btmp records parsed",
            horizon_start=hstart, horizon_end=hend, record_count=len(records),
            locations=locations,
            retention_bounded=any("btmp." in loc for loc in locations),
            instrumentation=[InstrumentationCheck("btmp accounting present", True)],
        )
        return CollectResult(events=events, coverage=cov)
