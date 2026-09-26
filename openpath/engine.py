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

from openpath.catalog import spec_for_facet
from openpath.env import Env
from openpath.facets import FAMILIES, get_facet
from openpath.facets.base import AnalysisContext, check_prereqs
from openpath.model.coverage import CoverageLedger, Gap, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.evidence_matrix import Confidence, assess
from openpath.model.finding import Finding
from openpath.model.identity import Subject, resolve_identity, resolve_name_for_uid
from openpath.model.timerange import TimeRange
from openpath.sources import Collector, default_collectors


# Aggregate facets set their own (federated) confidence inside analyze(); this
# fills in the data facets, whose confidence is their catalog EvidenceSpec assessed
# against the ledger, finding-aware.
_AGGREGATE_FACETS = {"core", "timeline", "evidence", "gaps",
                     "host_changes", "attribution", "concurrent"}


def _query_summary(spec, events, who_label: str, family: str) -> str:
    from openpath.query import ACTOR_SUBJECT, ACTOR_ANY
    who = (who_label if spec.actor == ACTOR_SUBJECT
           else "any actor (host-wide)" if spec.actor == ACTOR_ANY
           else "unattributable actors (no login uid / no named actor)")
    scope = spec.describe()
    scope_txt = f" [{scope}]" if scope else ""
    fam = family.lower()
    if events:
        return f"{len(events)} {fam} event(s) for {who}{scope_txt}."
    return (f"No {fam} events for {who}{scope_txt} were recorded within the covered "
            f"evidence scope (an evidenced negative -- see CONFIDENCE and GAPS -- "
            f"not a claim that none occurred by an unobserved path).")


def _apply_confidence(finding: Finding, ctx: AnalysisContext) -> None:
    if finding.confidence is not None:
        return  # an aggregate facet already set it
    spec = spec_for_facet(finding.facet)
    if spec is None:
        return
    a = assess(spec, ctx.ledger, finding)
    finding.confidence, finding.confidence_note = a.confidence, a.note


@dataclass
class AnalysisResult:
    finding: Finding
    subject: Subject
    ledger: CoverageLedger
    context: AnalysisContext


# The four families that aggregate the others rather than reading a source of
# their own; they always "run", so they must not inflate the readiness count.
_AGGREGATE_FAMILIES = {"core", "timeline", "evidence", "gaps",
                       "host_changes", "attribution", "concurrent"}


@dataclass
class FamilyReadiness:
    number: int
    name: str
    label: str
    answerable: bool
    gaps: List[Gap]
    kind: str = "data"  # "data" (reads a source) or "aggregate" (federates others)
    confidence: Optional[Confidence] = None  # CERTIFIED / PARTIAL / UNANSWERABLE

    def to_dict(self) -> dict:
        return {
            "number": self.number, "name": self.name, "label": self.label,
            "answerable": self.answerable, "kind": self.kind,
            "confidence": self.confidence.value if self.confidence else None,
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

    def _count(self, conf: Confidence) -> int:
        return sum(1 for fr in self.data_families if fr.confidence is conf)

    @property
    def certified(self) -> int:
        return self._count(Confidence.CERTIFIED)

    @property
    def partial(self) -> int:
        return self._count(Confidence.PARTIAL)

    @property
    def unanswerable(self) -> int:
        return self._count(Confidence.UNANSWERABLE)

    def to_dict(self) -> dict:
        return {
            "window": self.window.to_dict(),
            "answerable": self.answerable,
            "certified": self.certified,
            "partial": self.partial,
            "unanswerable": self.unanswerable,
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
        _apply_confidence(finding, ctx)
        return AnalysisResult(
            finding=finding, subject=ctx.subject, ledger=ctx.ledger, context=ctx
        )

    def query(self, env: Env, window: TimeRange, base_facet: str, spec,
              username: Optional[str] = None) -> AnalysisResult:
        """Answer a filtered/pivoted projection deterministically over the evidence.

        The query is a filter over the federated event set (provenance preserved:
        the returned events still carry their citations). Gaps and confidence are
        INHERITED from the base facet -- we run it to get its honest instrumentation
        and scope gaps -- so a filtered negative is scoped to both the filter and the
        evidence actually covered, never a false "nothing happened".
        """
        from openpath.query import apply_query, ACTOR_SUBJECT
        if base_facet in _AGGREGATE_FACETS:
            # Aggregate facets have no single EvidenceSpec to assess; their
            # confidence is federated (derive_aggregate). Filtering them would
            # mislabel confidence, so a query must target a data facet.
            raise ValueError(
                f"query filters apply to a data facet, not the aggregate "
                f"'{base_facet}'; pick a concrete facet (commands, files, "
                f"accounts, network, ...) or use it unfiltered.")
        collected = self.collect(env, window)
        ctx = self.context_for(collected, username or "(host)")
        facet = get_facet(base_facet)
        base = facet.analyze(ctx)  # reuse its exact prereq + scope gap disclosure

        f = Finding(
            facet=base_facet, question_family=facet.question_family,
            subject_label=(username if spec.actor == ACTOR_SUBJECT else f"({spec.actor})"),
            window=window,
        )
        f.gaps.extend(base.gaps)
        # For a subject query, filter the facet's OWN output events -- these already
        # carry the facet's attribution/correlation (e.g. packages correlated to the
        # user's audited package-manager exec; root actions attributed to the human).
        # For host-wide (any) / unattributable pivots, filter the raw federated set.
        if spec.actor == ACTOR_SUBJECT:
            f.events = apply_query(base.events, spec, ctx.subject)
        else:
            f.events = apply_query(ctx.events, spec, None)
        f.summary = _query_summary(spec, f.events, f.subject_label, facet.question_family)
        _apply_confidence(f, ctx)
        return AnalysisResult(finding=f, subject=ctx.subject, ledger=ctx.ledger, context=ctx)

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
            _apply_confidence(finding, ctx)
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
        # First pass: data families (answerable + confidence from their spec).
        from openpath.model.evidence_matrix import derive_aggregate
        families: List[FamilyReadiness] = []
        data_confidences: List[Confidence] = []
        for spec in FAMILIES:
            facet = spec.cls()
            is_aggregate = spec.name in _AGGREGATE_FAMILIES
            gaps = check_prereqs(ctx, getattr(facet, "requirements", ()))
            conf = None
            if not is_aggregate:
                espec = spec_for_facet(spec.name)
                if espec is not None:
                    # Host readiness has no subject/finding; confidence is purely
                    # source availability (the finding-aware invariant is moot here).
                    conf = assess(espec, collected.ledger, None).confidence
                    data_confidences.append(conf)
            families.append(FamilyReadiness(
                number=spec.number, name=spec.name, label=spec.label,
                answerable=not gaps, gaps=gaps,
                kind="aggregate" if is_aggregate else "data",
                confidence=conf,
            ))
        # Second pass: aggregate families derive from the data confidences (gaps
        # is always CERTIFIED -- its content is the disclosure).
        for fr in families:
            if fr.kind == "aggregate":
                fr.confidence = (Confidence.CERTIFIED if fr.name == "gaps"
                                 else derive_aggregate(data_confidences))
        return ReadinessReport(window=window, ledger=collected.ledger,
                               families=families)
