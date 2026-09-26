"""Meta facets that aggregate the base facets.

    * Core (family 1)     -- a federated overview: every family's headline answer.
    * Evidence (family 12) -- every raw record behind every claim, grouped by source.
    * Gaps (family 13)    -- the honest ledger of what could not be determined.

These run the base facets themselves so the overview, the evidence list, and the
gap ledger are always consistent with the per-family answers.
"""

from __future__ import annotations

from typing import List

from openpath.facets.accounts import AccountsFacet, GroupsFacet
from openpath.facets.authorization import AuthorizationFacet
from openpath.facets.attribution import (
    attribute_root_actions,
    summarize_responsibility,
)
from openpath.facets.base import AnalysisContext, Facet
from openpath.facets.files import FilesFacet
from openpath.facets.network import NetworkFacet
from openpath.facets.packages import PackagesFacet
from openpath.facets.persistence import PersistenceFacet
from openpath.facets.privilege import (
    CommandsFacet,
    PrivilegeFacet,
    RootActivityFacet,
)
from openpath.facets.sessions import LoginFacet, SessionsFacet
from openpath.catalog import spec_for_facet
from openpath.model.coverage import Gap
from openpath.model.evidence_matrix import Confidence, assess, derive_aggregate
from openpath.model.finding import Finding

# Evidence classes OpenPath models no collector for yet. Disclosed as standing,
# always-open gaps so the "Gaps" answer names its own unknown-unknowns instead of
# implying the modeled six sources are the whole picture.
_UNMODELED_SOURCE_GAPS = (
    "scheduled-task / service STATE (cron, systemd units/timers, linger, legacy "
    "startup) is inventoried by the persistence collector, but runtime activity "
    "LAUNCHED by a scheduler has an unset login uid and is disclosed as "
    "unattributable (root_no_session/daemon), never tied to the job that spawned it.",
    "no collector for network origin/destination beyond audited connect/bind "
    "syscalls (firewall, VPN, cloud, web/proxy logs).",
    "no general journald collector (only the sshd slice); non-sshd service logs "
    "are not read.",
)


def _base_facets() -> List[Facet]:
    return [
        SessionsFacet(),
        LoginFacet(),
        PrivilegeFacet(),
        RootActivityFacet(),
        CommandsFacet(),
        FilesFacet(),
        AccountsFacet(),
        GroupsFacet(),
        PackagesFacet(),
        NetworkFacet(),
        PersistenceFacet(),
        AuthorizationFacet(),
    ]


def run_base_findings(ctx: AnalysisContext) -> List[Finding]:
    return [facet.analyze(ctx) for facet in _base_facets()]


def data_confidence(ledger, finding) -> Confidence:
    """Confidence of one data finding via its catalog EvidenceSpec (finding-aware)."""
    spec = spec_for_facet(finding.facet)
    if spec is None:
        return Confidence.CERTIFIED if finding.determined else Confidence.PARTIAL
    return assess(spec, ledger, finding).confidence


def federated_confidence(ctx: AnalysisContext, findings=None):
    """(Confidence, note) for an aggregate question, best-of over its data slices.

    Best-of never hides a blind slice: the note names every non-certified family
    explicitly, so a CERTIFIED overview still says exactly what is missing.
    """
    if findings is None:
        findings = run_base_findings(ctx)
    per = [(fd.question_family, data_confidence(ctx.ledger, fd)) for fd in findings]
    conf = derive_aggregate([c for _lbl, c in per])
    blind = [lbl for lbl, c in per if c is not Confidence.CERTIFIED]
    if not blind:
        note = f"federated; all {len(per)} question families certified"
    else:
        note = (f"federated ({len(per) - len(blind)}/{len(per)} families certified); "
                f"not fully certified: {', '.join(blind)} -- see gaps")
    return conf, note


class CoreFacet(Facet):
    """What did the user do during the window? (federated overview)"""

    name = "core"
    question_family = "Core"

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        findings = run_base_findings(ctx)

        # Union of all attributed events (dedup by identity).
        seen = set()
        union: List = []
        for fd in findings:
            for e in fd.events:
                key = (e.ts, e.type, e.summary, id(e))
                short = (e.ts, e.type, e.summary)
                if short not in seen:
                    seen.add(short)
                    union.append(e)
        union.sort(key=lambda e: e.ts)
        f.events = union

        active = [fd for fd in findings if fd.events]
        f.summary = (
            f"During {ctx.window.label or 'the window'}, {ctx.subject.username} "
            f"has recorded activity across {len(active)} of {len(findings)} "
            f"question families."
        )
        if not ctx.subject.exists_now:
            f.notes.append(
                f"NOTE: '{ctx.subject.username}' is not a current local account "
                f"(may be newly-created-then-removed, remote/directory-managed, or "
                f"never-existed). See identity notes under gaps."
            )
        for fd in findings:
            f.notes.append(f"[{fd.question_family}] {fd.summary}")

        # Host-wide root attribution: who became root and acted with it. Only
        # surfaced when the subject IS root -- a per-user Core answer must not leak
        # other principals' root activity into that user's report.
        subject_is_root = (
            ctx.subject.username == "root"
            or ctx.subject.current_uid == 0
            or any(iv.uid == 0 for iv in ctx.subject.intervals)
        )
        if subject_is_root:
            from openpath.model.event import EventType
            root_candidates = [
                e for e in ctx.events
                if e.type in (EventType.EXEC, EventType.FILE_CHANGE, EventType.NETWORK)
            ]
            pairs = attribute_root_actions(ctx, root_candidates)
            if pairs:
                f.notes.append("[Root attribution] root privilege on this host was "
                               "exercised by -> "
                               + "; ".join(summarize_responsibility(pairs)))

        # Aggregate gaps + identity resolution caveats.
        gap_keys = set()
        for fd in findings:
            for g in fd.gaps:
                k = (g.question, g.reason)
                if k not in gap_keys:
                    gap_keys.add(k)
                    f.gaps.append(g)
        for g in ctx.ledger.all_gaps():
            k = (g.question, g.reason)
            if k not in gap_keys:
                gap_keys.add(k)
                f.gaps.append(g)
        f.confidence, f.confidence_note = federated_confidence(ctx, findings)
        return f


class EvidenceFacet(Facet):
    """What evidence supports what the user did?"""

    name = "evidence"
    question_family = "Evidence"

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        findings = run_base_findings(ctx)

        # Every citation behind every claim, grouped by source, de-duplicated.
        by_source: dict = {}
        total = 0
        seen_events = set()
        for fd in findings:
            for c in fd.citations():
                by_source.setdefault(c.source_id, [])
                key = (c.locator, c.raw)
                if key not in {(x.locator, x.raw) for x in by_source[c.source_id]}:
                    by_source[c.source_id].append(c)
                    total += 1
            # keep the events so the evidence finding can be rendered/serialized,
            # de-duplicated (the same event is surfaced by several base facets).
            for e in fd.events:
                locs = tuple(c.locator for c in e.citations)
                key = (e.ts, e.type, e.target(), locs)
                if key not in seen_events:
                    seen_events.add(key)
                    f.events.append(e)

        if total == 0:
            f.summary = (
                f"No evidence records back any activity for {ctx.subject.username} "
                f"in {ctx.window.label or 'the window'}."
            )
        else:
            f.summary = (
                f"{total} raw evidence record(s) from {len(by_source)} source(s) "
                f"substantiate the findings for {ctx.subject.username}."
            )
        for source_id in sorted(by_source):
            cites = by_source[source_id]
            f.notes.append(f"--- {source_id} ({len(cites)} record(s)) ---")
            for c in cites:
                f.notes.append(f"  {c.locator}: {c.raw}")
        f.confidence, f.confidence_note = federated_confidence(ctx, findings)
        return f


class GapsFacet(Facet):
    """What could OpenPath not determine about the user?"""

    name = "gaps"
    question_family = "Gaps"

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        findings = run_base_findings(ctx)

        # 1. Facet-declared gaps (missing instrumentation, unanswerable families).
        gap_keys = set()
        for fd in findings:
            for g in fd.gaps:
                k = (g.question, g.reason)
                if k not in gap_keys:
                    gap_keys.add(k)
                    f.gaps.append(g)
        # 2. Coverage-derived gaps (retention horizons, out-of-window sources).
        for g in ctx.ledger.all_gaps():
            k = (g.question, g.reason)
            if k not in gap_keys:
                gap_keys.add(k)
                f.gaps.append(g)

        # 3. Source availability ledger (blind spots).
        f.notes.append("Coverage ledger:")
        for cov in ctx.ledger.sources:
            horizon = (
                f"{cov.horizon_start.isoformat()} .. {cov.horizon_end.isoformat()}"
                if cov.horizon_start and cov.horizon_end else "n/a"
            )
            covers = cov.covers_window(ctx.window, ctx.ledger.effective_start())
            conservation = (f"; UNPARSEABLE={cov.unparseable}"
                            if cov.unparseable else "")
            f.notes.append(
                f"  {cov.source_id}: {cov.status.value}; retained {horizon}; "
                f"covers requested window: {covers}{conservation}; {cov.detail}"
            )
            for ic in cov.instrumentation:
                if not ic.present:
                    f.notes.append(f"    - MISSING: {ic.name} -- {ic.detail}")

        # 4. Identity-resolution caveats (the "any user" honesty).
        if ctx.subject.resolution_notes:
            f.notes.append("Identity resolution caveats:")
            for n in ctx.subject.resolution_notes:
                f.notes.append(f"  - {n}")

        # 5. Standing blind spots: whole classes of evidence OpenPath models no
        # collector for. Naming them keeps "Gaps" from hiding unknown-unknowns --
        # its completeness is explicitly bounded to the modeled source set.
        for reason in _UNMODELED_SOURCE_GAPS:
            f.gaps.append(Gap("scope", reason, None,
                              "add a collector for this source class, or ingest an "
                              "equivalent evidence bundle"))

        if f.gaps:
            f.summary = (
                f"OpenPath could not fully determine {len(f.gaps)} aspect(s) of "
                f"{ctx.subject.username}'s activity; each is listed with a reason "
                f"and remedy."
            )
        else:
            f.summary = (
                f"No coverage gaps: every question family for {ctx.subject.username} "
                f"was answerable from present, instrumented, in-horizon sources."
            )
        # Gaps is always answerable: its content IS the disclosure of what the
        # other questions could not determine (an absent source produces MORE gap
        # content, not less). Its completeness is bounded to the modeled sources.
        f.confidence = Confidence.CERTIFIED
        f.confidence_note = ("the gap ledger is itself the disclosure; bounded to "
                             "the modeled source set (see standing scope gaps)")
        return f
