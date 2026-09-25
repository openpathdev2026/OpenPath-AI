"""Meta facets that aggregate the base facets.

    * Core (family 1)     -- a federated overview: every family's headline answer.
    * Evidence (family 12) -- every raw record behind every claim, grouped by source.
    * Gaps (family 13)    -- the honest ledger of what could not be determined.

These run the base facets themselves so the overview, the evidence list, and the
gap ledger are always consistent with the per-family answers.
"""

from __future__ import annotations

from typing import List

from openpath.facets.accounts import AccountsFacet
from openpath.facets.base import AnalysisContext, Facet
from openpath.facets.files import FilesFacet
from openpath.facets.network import NetworkFacet
from openpath.facets.packages import PackagesFacet
from openpath.facets.privilege import (
    CommandsFacet,
    PrivilegeFacet,
    RootActivityFacet,
)
from openpath.facets.sessions import LoginFacet, SessionsFacet
from openpath.model.finding import Finding


def _base_facets() -> List[Facet]:
    return [
        SessionsFacet(),
        LoginFacet(),
        PrivilegeFacet(),
        RootActivityFacet(),
        CommandsFacet(),
        FilesFacet(),
        AccountsFacet(),
        PackagesFacet(),
        NetworkFacet(),
    ]


def run_base_findings(ctx: AnalysisContext) -> List[Finding]:
    return [facet.analyze(ctx) for facet in _base_facets()]


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
        for fd in findings:
            for c in fd.citations():
                by_source.setdefault(c.source_id, [])
                key = (c.locator, c.raw)
                if key not in {(x.locator, x.raw) for x in by_source[c.source_id]}:
                    by_source[c.source_id].append(c)
                    total += 1
            # keep the events so the evidence finding can be rendered/serialized
            for e in fd.events:
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
            f.notes.append(
                f"  {cov.source_id}: {cov.status.value}; retained {horizon}; "
                f"covers requested window: {covers}; {cov.detail}"
            )
            for ic in cov.instrumentation:
                if not ic.present:
                    f.notes.append(f"    - MISSING: {ic.name} -- {ic.detail}")

        # 4. Identity-resolution caveats (the "any user" honesty).
        if ctx.subject.resolution_notes:
            f.notes.append("Identity resolution caveats:")
            for n in ctx.subject.resolution_notes:
                f.notes.append(f"  - {n}")

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
        return f
