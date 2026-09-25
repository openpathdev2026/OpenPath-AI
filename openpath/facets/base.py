"""Facet base class and shared helpers.

A facet answers one question family for one resolved subject over one window. It
operates on the *already-collected* set of normalized events plus the coverage
ledger, so all sources are federated and every facet attributes activity the same
way (via :meth:`Subject.matches`).

The single most important helper here is :func:`check_prereqs`. It encodes the
soundness rule: a facet may only return an *evidenced negative* ("the user did
not do X") when the sources that would have recorded X were actually present and
instrumented. Otherwise the absence of events is reported as a disclosed gap, not
as a false "nothing happened".
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence

from openpath.model.coverage import CoverageLedger, Gap, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.finding import Finding
from openpath.model.identity import Subject
from openpath.model.timerange import TimeRange


@dataclass
class AnalysisContext:
    """Everything a facet needs, computed once by the engine and shared."""

    subject: Subject
    window: TimeRange
    events: List[Event]           # all normalized events from all collectors
    ledger: CoverageLedger

    def subject_events(
        self, types: Optional[Iterable[EventType]] = None
    ) -> List[Event]:
        """Events attributable to the subject, optionally filtered by type.

        Attribution attaches the resolved username to matched events (so later
        rendering can show it) without mutating source data semantics.
        """
        typeset = set(types) if types is not None else None
        out: List[Event] = []
        for e in self.events:
            if typeset is not None and e.type not in typeset:
                continue
            if self.subject.matches(e):
                if e.actor_name is None:
                    e.actor_name = self.subject.username
                out.append(e)
        out.sort(key=lambda e: e.ts)
        return out


@dataclass(frozen=True)
class Requirement:
    """A source (and optionally a specific instrumentation) a facet depends on."""

    source_id: str
    question: str
    instrument: Optional[str] = None  # named InstrumentationCheck that must be present
    remedy: Optional[str] = None


def check_prereqs(ctx: AnalysisContext, requirements: Sequence[Requirement]) -> List[Gap]:
    """Return a gap for every unmet requirement.

    A requirement is unmet when the source is absent/unreadable/out-of-horizon,
    or when its named instrumentation check is not present. The instrumentation
    check's own ``detail`` (which carries the concrete remedy, e.g. the audit rule
    to add) is preferred as the gap remedy.
    """
    gaps: List[Gap] = []
    for req in requirements:
        cov = ctx.ledger.get(req.source_id)
        if cov is None or cov.status in (
            SourceStatus.ABSENT,
            SourceStatus.UNREADABLE,
            SourceStatus.OUT_OF_HORIZON,
        ):
            reason = (
                f"source '{req.source_id}' is "
                f"{cov.status.value if cov else 'not present'}; "
                f"this question cannot be answered from the available evidence."
            )
            gaps.append(Gap(req.question, reason, req.source_id, req.remedy))
            continue
        if req.instrument is not None:
            check = cov.instrument(req.instrument)
            if check is None or not check.present:
                remedy = req.remedy or (check.detail if check else None)
                gaps.append(
                    Gap(
                        req.question,
                        f"'{req.source_id}' is present but '{req.instrument}' is not "
                        f"enabled; the relevant activity is not being recorded, so "
                        f"absence of results does not mean the user did nothing.",
                        req.source_id,
                        remedy,
                    )
                )
    return gaps


class Facet(ABC):
    #: Short machine name, e.g. "sessions".
    name: str = "base"
    #: The question-family label from the product's 13-question taxonomy.
    question_family: str = ""
    #: Sources/instrumentation this facet needs to give a sound answer.
    requirements: Sequence[Requirement] = ()

    @abstractmethod
    def analyze(self, ctx: AnalysisContext) -> Finding:
        raise NotImplementedError

    # -- helpers ------------------------------------------------------------ #

    def _new_finding(self, ctx: AnalysisContext, summary: str = "") -> Finding:
        return Finding(
            facet=self.name,
            question_family=self.question_family,
            subject_label=ctx.subject.username,
            window=ctx.window,
            summary=summary,
        )

    def _prereq_gaps(self, ctx: AnalysisContext) -> List[Gap]:
        return check_prereqs(ctx, self.requirements)
