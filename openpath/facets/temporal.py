"""Temporal / cross-user meta facets (TM-03, TM-06, TM-13).

These are aggregate views (like Core/Timeline): they set their own confidence and
are not per-family data sources.

  * HostChanges (TM-03): everything that CHANGED on the host in the window, across
    all users -- the host-wide mutation set (files, accounts, groups, packages,
    persistence, authorization, firewall), each cited.
  * Attribution (TM-06): the subject's recorded actions each labelled with how
    confidently it is attributed to them (high = own login uid / named actor;
    medium = a correlation; low = uid-only, no login uid).
  * Concurrent (TM-13): what OTHER users were doing around the time of the subject's
    activity -- concurrent / possibly-lateral movement, from a pivot window.
"""

from __future__ import annotations

from datetime import timedelta
from typing import List

from openpath.facets.base import AnalysisContext, Facet
from openpath.model.event import Event, EventType
from openpath.model.evidence_matrix import Confidence
from openpath.model.finding import Finding

_CHANGE_TYPES = (
    EventType.FILE_CHANGE, EventType.ACCOUNT_CHANGE, EventType.GROUP_CHANGE,
    EventType.PACKAGE_CHANGE, EventType.PERSISTENCE, EventType.AUTHZ,
    EventType.FIREWALL, EventType.PKG_POLICY,
)
_ACTIVITY_TYPES = (
    EventType.EXEC, EventType.FILE_CHANGE, EventType.NETWORK,
    EventType.PRIVILEGE_ESCALATION, EventType.SESSION,
)


def _attribution_confidence(e: Event) -> str:
    if e.actor_name:
        return "high"
    if e.auid is not None:
        return "high"
    if e.attrs.get("attributed_via") or e.attrs.get("via"):
        return "medium"
    if e.uid is not None:
        return "low"
    return "unattributable"


class HostChangesFacet(Facet):
    """TM-03: what changed on the host between T1 and T2, across all users."""

    name = "host_changes"
    question_family = "Host changes"

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        changes = sorted((e for e in ctx.events if e.type in _CHANGE_TYPES),
                         key=lambda e: e.ts)
        f.events = changes
        by_type: dict = {}
        for e in changes:
            by_type[e.type.value] = by_type.get(e.type.value, 0) + 1
        if not changes:
            f.summary = (f"No host state changes recorded in "
                         f"{ctx.window.label or 'the window'} (evidenced negative "
                         f"within the covered change sources).")
        else:
            summ = ", ".join(f"{v} {k}" for k, v in sorted(by_type.items()))
            f.summary = (f"{len(changes)} host state change(s) across all users in "
                         f"{ctx.window.label or 'the window'}: {summ}.")
            for e in changes:
                who = e.actor_name or (f"auid {e.auid}" if e.auid is not None
                                       else "unattributed")
                f.notes.append(f"{e.ts.isoformat()} [{e.type.value}] "
                               f"{e.target()[1]} by {who}")
        f.confidence = Confidence.CERTIFIED
        f.confidence_note = ("host-wide change set across the modeled change sources "
                             "(files, accounts, groups, packages, persistence, "
                             "authorization, firewall)")
        return f


class AttributionFacet(Facet):
    """TM-06: which of the subject's actions are attributable, and how confidently."""

    name = "attribution"
    question_family = "Attribution"

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        acts = sorted(ctx.subject_events(list(_ACTIVITY_TYPES)), key=lambda e: e.ts)
        f.events = acts
        buckets: dict = {"high": 0, "medium": 0, "low": 0, "unattributable": 0}
        for e in acts:
            c = _attribution_confidence(e)
            buckets[c] = buckets.get(c, 0) + 1
            f.notes.append(f"{e.ts.isoformat()} [{e.type.value}] {e.target()[1]} "
                           f"-> attribution: {c}"
                           + (f" (login uid {e.auid})" if e.auid is not None else "")
                           + (f" (via {e.attrs.get('via') or e.attrs.get('attributed_via')})"
                              if _attribution_confidence(e) == "medium" else ""))
        if not acts:
            f.summary = (f"No attributable actions recorded for "
                         f"{ctx.subject.username} in {ctx.window.label or 'the window'}.")
        else:
            f.summary = (
                f"{len(acts)} recorded action(s) for {ctx.subject.username}: "
                f"{buckets['high']} high-confidence (own login uid / named actor), "
                f"{buckets['medium']} medium (correlation), {buckets['low']} low "
                f"(uid only, no login uid).")
        f.confidence = Confidence.CERTIFIED
        f.confidence_note = ("attribution strength is derived from the auid-centric "
                             "identity model (login uid survives sudo/su)")
        return f


class ConcurrentFacet(Facet):
    """TM-13: what OTHER users were doing around the time of the subject's activity."""

    name = "concurrent"
    question_family = "Concurrent activity"
    _PIVOT = timedelta(hours=1)

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        mine = sorted(ctx.subject_events(list(_ACTIVITY_TYPES)), key=lambda e: e.ts)
        # windows around each of the subject's actions (bounded by the analysis window)
        spans = [(e.ts - self._PIVOT, e.ts + self._PIVOT) for e in mine] or \
                [(ctx.window.start, ctx.window.end)]

        def near(e):
            return any(lo <= e.ts <= hi for lo, hi in spans)

        others = sorted(
            (e for e in ctx.events
             if e.type in _ACTIVITY_TYPES and not ctx.subject.matches(e) and near(e)),
            key=lambda e: e.ts)
        f.events = others
        by_actor: dict = {}
        for e in others:
            who = e.actor_name or (f"auid {e.auid}" if e.auid is not None
                                   else "unattributed")
            by_actor.setdefault(who, []).append(e)
            f.notes.append(f"{e.ts.isoformat()} [{e.type.value}] {e.target()[1]} "
                           f"by {who}")
        if not others:
            f.summary = (f"No other users were active around {ctx.subject.username}'s "
                         f"activity in {ctx.window.label or 'the window'} (evidenced "
                         f"negative within the covered evidence).")
        else:
            who = ", ".join(f"{a} ({len(evs)})" for a, evs in sorted(by_actor.items()))
            f.summary = (f"{len(others)} concurrent action(s) by other principals "
                         f"around {ctx.subject.username}'s activity: {who}.")
        f.confidence = Confidence.CERTIFIED
        f.confidence_note = ("concurrent activity by other principals within +/-1h of "
                             "the subject's actions (lateral-movement context)")
        return f
