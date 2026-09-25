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
from openpath.facets import FAMILIES, get_facet
from openpath.facets.base import AnalysisContext, check_prereqs
from openpath.model.coverage import CoverageLedger, Gap, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.finding import Finding
from openpath.model.identity import Subject, resolve_identity, resolve_name_for_uid
from openpath.model.timerange import TimeRange
from openpath.sources import Collector, default_collectors


@dataclass
class AnalysisResult:
    finding: Finding
    subject: Subject
    ledger: CoverageLedger
    context: AnalysisContext


# The four families that aggregate the others rather than reading a source of
# their own; they always "run", so they must not inflate the readiness count.
_AGGREGATE_FAMILIES = {"core", "timeline", "evidence", "gaps"}


@dataclass
class FamilyReadiness:
    number: int
    name: str
    label: str
    answerable: bool
    gaps: List[Gap]
    kind: str = "data"  # "data" (reads a source) or "aggregate" (federates others)

    def to_dict(self) -> dict:
        return {
            "number": self.number, "name": self.name, "label": self.label,
            "answerable": self.answerable, "kind": self.kind,
            "gaps": [g.to_dict() for g in self.gaps],
        }


@dataclass
class ReadinessReport:
    window: TimeRange
    ledger: CoverageLedger
    families: List[FamilyReadiness]

    @property
    def data_families(self) -> List[FamilyReadiness]:
        return [fr for fr in self.families if fr.kind == "data"]

    @property
    def answerable(self) -> int:
        """Answerable count among the substantive data questions (not aggregates)."""
        return sum(1 for fr in self.data_families if fr.answerable)

    @property
    def data_total(self) -> int:
        return len(self.data_families)

    def to_dict(self) -> dict:
        return {
            "window": self.window.to_dict(),
            "answerable": self.answerable,
            "data_total": self.data_total,
            "aggregate_views": len(self.families) - self.data_total,
            "families": [fr.to_dict() for fr in self.families],
            "coverage": self.ledger.to_dict(),
        }


@dataclass
class Collected:
    """Result of running every collector once: events + coverage + passwd snapshot.

    Kept separate from identity resolution so a multi-user sweep collects the raw
    evidence a single time and resolves each subject against the shared set.
    """

    events: List[Event]
    ledger: CoverageLedger
    passwd: List
    window: TimeRange


class Engine:
    def __init__(self, collectors: Optional[List[Collector]] = None):
        self.collectors = collectors if collectors is not None else default_collectors()

    def collect(self, env: Env, window: TimeRange) -> Collected:
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

        return Collected(
            events=all_events, ledger=ledger,
            passwd=env.read_passwd(), window=window,
        )

    def context_for(self, collected: Collected, username: str) -> AnalysisContext:
        account_events = [
            e for e in collected.events if e.type == EventType.ACCOUNT_CHANGE
        ]
        subject = resolve_identity(
            username, collected.window,
            passwd_entries=collected.passwd, account_events=account_events,
        )
        return AnalysisContext(
            subject=subject, window=collected.window,
            events=collected.events, ledger=collected.ledger,
            passwd=collected.passwd,
        )

    def build_context(
        self, env: Env, username: str, window: TimeRange
    ) -> AnalysisContext:
        return self.context_for(self.collect(env, window), username)

    def analyze(
        self, env: Env, username: str, window: TimeRange, facet_name: str
    ) -> AnalysisResult:
        ctx = self.build_context(env, username, window)
        finding = get_facet(facet_name).analyze(ctx)
        return AnalysisResult(
            finding=finding, subject=ctx.subject, ledger=ctx.ledger, context=ctx
        )

    def discover_subjects(self, collected: Collected) -> List[str]:
        """Every user worth analyzing: local accounts plus anyone who appears in
        the evidence (by name, or resolved from a login uid seen in the window)."""
        names = set()
        for name, _uid in collected.passwd:
            names.add(name)
        account_events = [
            e for e in collected.events if e.type == EventType.ACCOUNT_CHANGE
        ]
        for e in collected.events:
            if e.actor_name:
                names.add(e.actor_name)
            if e.auid is not None:
                nm, _note = resolve_name_for_uid(
                    e.auid, e.ts, collected.window,
                    passwd_entries=collected.passwd, account_events=account_events,
                )
                names.add(nm if nm else f"uid:{e.auid}")
        return sorted(names)

    def analyze_all(
        self, env: Env, window: TimeRange, facet_name: str,
    ) -> List[AnalysisResult]:
        """Run a facet for every discovered subject, collecting evidence once."""
        collected = self.collect(env, window)
        results = []
        for username in self.discover_subjects(collected):
            ctx = self.context_for(collected, username)
            finding = get_facet(facet_name).analyze(ctx)
            results.append(AnalysisResult(
                finding=finding, subject=ctx.subject,
                ledger=ctx.ledger, context=ctx,
            ))
        return results

    def readiness(self, env: Env, window: TimeRange) -> ReadinessReport:
        """Assess, independent of any user, which catalog questions this host is
        instrumented to answer over the window -- the operator's "am I ready?".

        Each family's declared requirements are checked against the coverage
        ledger; a family with no unmet requirement is answerable, otherwise the
        prerequisite gaps (with remedies) explain what is missing.
        """
        collected = self.collect(env, window)
        # A subject is irrelevant to instrumentation coverage; use a placeholder.
        ctx = AnalysisContext(
            subject=Subject(username="(host)", exists_now=False, current_uid=None),
            window=window, events=collected.events, ledger=collected.ledger,
            passwd=collected.passwd,
        )
        families: List[FamilyReadiness] = []
        for spec in FAMILIES:
            facet = spec.cls()
            gaps = check_prereqs(ctx, getattr(facet, "requirements", ()))
            families.append(FamilyReadiness(
                number=spec.number, name=spec.name, label=spec.label,
                answerable=not gaps, gaps=gaps,
                kind="aggregate" if spec.name in _AGGREGATE_FAMILIES else "data",
            ))
        return ReadinessReport(window=window, ledger=collected.ledger,
                               families=families)
