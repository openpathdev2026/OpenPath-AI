"""Timeline (family 2): everything the user did, in chronological order.

This is the federated view -- it merges every attributable event across all
sources onto one UTC axis. Because completeness of a timeline is exactly bounded
by coverage, the timeline surfaces the full gap ledger: a chronology is only
honest if it says where it might be missing entries.
"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet
from openpath.facets.packages import attribute_packages
from openpath.model.event import EventType
from openpath.model.finding import Finding

_TIMELINE_TYPES = [
    EventType.SESSION,
    EventType.SSH_AUTH,
    EventType.PRIVILEGE_ESCALATION,
    EventType.EXEC,
    EventType.FILE_CHANGE,
    EventType.NETWORK,
    EventType.ACCOUNT_CHANGE,
    EventType.GROUP_CHANGE,
]


class TimelineFacet(Facet):
    name = "timeline"
    question_family = "Timeline"

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)

        events = ctx.subject_events(_TIMELINE_TYPES)
        attributed_pkgs, _host, _can = attribute_packages(ctx)
        events = sorted(events + attributed_pkgs, key=lambda e: e.ts)
        f.events = events

        # Completeness of a chronology is bounded by coverage: surface every gap.
        f.gaps.extend(ctx.ledger.all_gaps())

        # Confidence is federated over the data questions (best-of; blind slices
        # named). Imported lazily to avoid a facet-module import cycle.
        from openpath.facets.meta import federated_confidence
        f.confidence, f.confidence_note = federated_confidence(ctx)

        if not events:
            f.summary = (
                f"No attributable activity for {ctx.subject.username} in "
                f"{ctx.window.label or 'the window'}."
                + (" Coverage is incomplete (see gaps)." if f.gaps else
                   " Sources were present; this is an evidenced negative.")
            )
            return f

        span = f"{events[0].ts.isoformat()} .. {events[-1].ts.isoformat()}"
        f.summary = (
            f"{len(events)} chronological event(s) for {ctx.subject.username} "
            f"spanning {span}."
        )
        for e in events:
            root = " (root)" if (e.uid == 0 or e.attrs.get("euid") == 0
                                 or e.attrs.get("as_root")) else ""
            f.notes.append(f"{e.ts.isoformat()} [{e.type.value}]{root} {e.summary}")
        return f
