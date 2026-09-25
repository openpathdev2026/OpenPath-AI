"""The analysis engine: collect once, resolve identity once, answer any facet.

The engine enforces the pipeline that makes answers consistent and sound:

    1. Run every collector against the environment/window -> normalized events +
       one coverage report per source.
    2. Build the coverage ledger (the basis for gap disclosure).
    3. Resolve the requested username to a :class:`Subject` using the passwd
       snapshot and the account-change events just collected -- so a user created
       or deleted *inside* the window is resolved from evidence, not from the
       present-tense passwd file alone.
    4. Run the requested facet over that shared context.

Collecting once and sharing the context means the per-family answers, the
federated overview, the evidence list, and the gap ledger can never disagree.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from openpath.env import Env
from openpath.facets import get_facet
from openpath.facets.base import AnalysisContext
from openpath.model.coverage import CoverageLedger
from openpath.model.event import Event, EventType
from openpath.model.finding import Finding
from openpath.model.identity import Subject, resolve_identity
from openpath.model.timerange import TimeRange
from openpath.sources import Collector, default_collectors


@dataclass
class AnalysisResult:
    finding: Finding
    subject: Subject
    ledger: CoverageLedger
    context: AnalysisContext


class Engine:
    def __init__(self, collectors: Optional[List[Collector]] = None):
        self.collectors = collectors if collectors is not None else default_collectors()

    def build_context(
        self, env: Env, username: str, window: TimeRange
    ) -> AnalysisContext:
        all_events: List[Event] = []
        ledger = CoverageLedger(window=window)
        for collector in self.collectors:
            try:
                result = collector.collect(env, window)
            except Exception as exc:  # a broken source must not sink the analysis
                from openpath.model.coverage import SourceCoverage, SourceStatus
                ledger.add_source(SourceCoverage(
                    source_id=getattr(collector, "source_id", "unknown"),
                    status=SourceStatus.UNREADABLE,
                    detail=f"collector raised {type(exc).__name__}: {exc}",
                ))
                continue
            if result.coverage is not None:
                ledger.add_source(result.coverage)
            all_events.extend(result.events)

        # Boot-awareness: the earliest boot inside the window marks when the
        # machine came up; before it, nothing could have happened.
        boots = sorted(
            e.ts for e in all_events
            if e.type == EventType.BOOT and window.contains(e.ts)
        )
        if boots:
            ledger.first_boot = boots[0]

        account_events = [e for e in all_events if e.type == EventType.ACCOUNT_CHANGE]
        subject = resolve_identity(
            username, window,
            passwd_entries=env.read_passwd(),
            account_events=account_events,
        )
        return AnalysisContext(
            subject=subject, window=window, events=all_events, ledger=ledger
        )

    def analyze(
        self, env: Env, username: str, window: TimeRange, facet_name: str
    ) -> AnalysisResult:
        ctx = self.build_context(env, username, window)
        finding = get_facet(facet_name).analyze(ctx)
        return AnalysisResult(
            finding=finding, subject=ctx.subject, ledger=ctx.ledger, context=ctx
        )
