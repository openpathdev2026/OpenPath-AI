"""Rendering of an :class:`AnalysisResult` to text or JSON.

The text renderer tells the story of what the user did in flowing sentences, then
backs it with evidence keyed by the object each action was performed against, then
discloses the gaps. Claim → proof (with the acted-upon object) → limits, every
time. Aggregator views (Core, Gaps) keep their structured overview instead of a
per-event narrative.
"""

from __future__ import annotations

import json
from typing import List

from openpath.engine import AnalysisResult, ReadinessReport
from openpath.narrate import narrate_finding

# Facets that are overviews/ledgers rather than a stream of activity.
_OVERVIEW_FACETS = {"core", "gaps"}


def _narration_for(f, *, full: bool = False):
    """(sentences, evidence, overflow) with the right cap for the facet.

    Overview facets (Core, Gaps) carry a structured overview, not a per-event
    narrative. The Evidence facet is always exhaustive. ``full=True`` (used by the
    JSON renderer) disables the cap for every facet, so the machine-readable output
    is complete -- which is what makes the text overflow note's "full detail in
    --format json" a true statement rather than a broken promise.
    """
    if f.facet in _OVERVIEW_FACETS:
        return [], [], None
    if full or f.facet == "evidence":
        return narrate_finding(f, limit=None)
    return narrate_finding(f)


def render_json(result: AnalysisResult) -> str:
    f = result.finding
    sentences, evidence, overflow = _narration_for(f, full=True)
    payload = {
        "question_family": f.question_family,
        "facet": f.facet,
        "subject": result.subject.to_dict(),
        "finding": f.to_dict(),
        "narrative": sentences,
        "narrative_overflow": overflow,
        "evidence": [e.to_dict() for e in evidence],
        "coverage": result.ledger.to_dict(),
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def render_readiness_json(report: ReadinessReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def render_readiness(report: ReadinessReport) -> str:
    """Operator-facing host readiness report."""
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("OpenPath | Host readiness")
    lines.append(f"Window  : {report.window.describe()}")
    lines.append(f"Certified: {report.certified}  Partial: {report.partial}  "
                 f"Unanswerable: {report.unanswerable}  of {report.data_total} data "
                 f"questions (+ {len(report.families) - report.data_total} "
                 f"aggregate views)")
    lines.append("=" * 72)
    lines.append("")
    lines.append("QUESTION FAMILIES")
    _CODE = {"certified": "CERT", "partial": "PART", "unanswerable": "----"}
    for fr in report.families:
        cval = fr.confidence.value if fr.confidence else ""
        if fr.kind == "aggregate":
            lines.append(f"  [agg ] {fr.number:2d} {fr.label}"
                         f" -> {cval.upper() or 'n/a'}")
        else:
            lines.append(f"  [{_CODE.get(cval, '?   ')}] {fr.number:2d} {fr.label}")
        for g in fr.gaps:
            lines.append(f"           needs: {g.reason}")
            if g.remedy:
                lines.append(f"           remedy: {g.remedy}")
    lines.append("")
    lines.append("SOURCES")
    for cov in report.ledger.sources:
        horizon = (f"{cov.horizon_start.isoformat()} .. {cov.horizon_end.isoformat()}"
                   if cov.horizon_start and cov.horizon_end else "n/a")
        lines.append(f"  {cov.source_id:14s} {cov.status.value:14s} "
                     f"records={cov.record_count}  retained {horizon}")
        if cov.unparseable:
            lines.append(f"       ! CONSERVATION: {cov.unparseable} record(s) "
                         f"could not be decoded and are unaccounted for"
                         + (f" ({cov.unparseable_detail})"
                            if cov.unparseable_detail else ""))
        for ic in cov.instrumentation:
            if not ic.present:
                lines.append(f"       - off: {ic.name}"
                             + (f" ({ic.detail})" if ic.detail else ""))

    # Evidence conservation summary: zero silent loss is the pass condition.
    cons = report.ledger.conservation_gaps()
    lines.append("")
    lines.append("EVIDENCE CONSERVATION")
    if cons:
        lines.append(f"  FAIL: {len(cons)} source(s) dropped records that could not "
                     f"be decoded (see '!' above). Evidence may be incomplete.")
    else:
        lines.append("  OK: every record examined was accounted for "
                     "(0 silent loss across all sources).")
    lines.append("")
    return "\n".join(lines)


def render_contract(rows) -> str:
    """The production-contract scoreboard: per-question certification status."""
    from collections import defaultdict
    from openpath.contract import CatalogStatus, status_counts
    counts = status_counts()
    certified = [q for q in rows if q.status is CatalogStatus.CERTIFIED]
    contracted = [q for q in rows if q.status is CatalogStatus.CONTRACTED]
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("OpenPath | Production question contract")
    lines.append(f"{len(rows)} questions  |  CERTIFIED "
                 f"{counts[CatalogStatus.CERTIFIED]}  CONTRACTED "
                 f"{counts[CatalogStatus.CONTRACTED]}")
    lines.append("=" * 72)
    lines.append("Certification is a per-question status, not a limit on which questions")
    lines.append("exist. CERTIFIED = wired and proven end-to-end today. CONTRACTED = in the")
    lines.append("contract but needs the named collector or subsystem first; it is never")
    lines.append("answered from thin air.")
    lines.append("")
    lines.append(f"CERTIFIED ({len(certified)}) -- answerable today:")
    for q in certified:
        lines.append(f"  [C] {q.id}  {q.question}")
    lines.append("")
    lines.append(f"CONTRACTED ({len(contracted)}) -- roadmap, grouped by what unblocks them:")
    groups = defaultdict(list)
    for q in contracted:
        groups[q.needs].append(q)
    for need in sorted(groups, key=lambda n: (-len(groups[n]), n)):
        ids = ", ".join(q.id for q in groups[need])
        lines.append(f"  {len(groups[need]):2d}x  {need}")
        lines.append(f"        {ids}")
    lines.append("")
    lines.append("Full per-question detail (sources, blind spots): "
                 "docs/PRODUCTION-CATALOG.md")
    lines.append("")
    return "\n".join(lines)


def render_contract_json(rows) -> str:
    from openpath.contract import status_counts
    payload = {
        "total": len(rows),
        "counts": {s.value: n for s, n in status_counts().items()},
        "questions": [
            {"id": q.id, "question": q.question, "facet": q.facet,
             "status": q.status.value, "needs": q.needs,
             "sources": list(q.sources), "blind_spots": q.blind_spots}
            for q in rows
        ],
    }
    return json.dumps(payload, indent=2)


def render_text(result: AnalysisResult, *, verbose: bool = False) -> str:
    f = result.finding
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append(f"OpenPath | {f.question_family}  (facet: {f.facet})")
    lines.append(f"Subject : {result.subject.username}"
                 + ("" if result.subject.exists_now
                    else "  [not a current local account]"))
    lines.append(f"Window  : {f.window.describe()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append("ANSWER")
    lines.append(f"  {f.summary}")

    # Confidence is separate from the answer: a CERTIFIED answer with a corroborating
    # source missing says so here rather than weakening the answer itself.
    if f.confidence is not None:
        lines.append("")
        lines.append("CONFIDENCE")
        lines.append(f"  {f.confidence.value.upper():12s} ({f.confidence_note})")

    if f.facet in _OVERVIEW_FACETS:
        if f.notes:
            lines.append("")
            lines.append("DETAIL")
            for n in f.notes:
                lines.append(f"  {n}")
    else:
        sentences, evidence, overflow = _narration_for(f)
        # The Evidence question is answered by the evidence listing itself, so it
        # does not repeat the chronological narrative.
        if sentences and f.facet != "evidence":
            lines.append("")
            lines.append("WHAT HAPPENED")
            for s in sentences:
                lines.append(f"  {s}")
            if overflow:
                lines.append(f"  {overflow}")
        if evidence:
            lines.append("")
            lines.append("EVIDENCE  (object acted against -> source record)")
            for ent in evidence:
                first = ent.records[0]
                more = (f"  (+{len(ent.records) - 1} more record(s))"
                        if len(ent.records) > 1 else "")
                lines.append(
                    f"  [{ent.ref}] {ent.target_kind}: {ent.target}"
                    f"  <-  {first[0]} {first[1]}{more}"
                )
                if verbose:
                    for (src, loc, raw) in ent.records:
                        lines.append(f"        {src} {loc}: {raw}")

    # Gaps (the honesty layer).
    from openpath.model.evidence_matrix import Confidence
    lines.append("")
    if f.gaps:
        lines.append(f"GAPS  ({len(f.gaps)} thing(s) not fully determinable)")
        for g in f.gaps:
            lines.append(f"  - [{g.question}] {g.reason}")
            if g.remedy:
                lines.append(f"      remedy: {g.remedy}")
    elif f.confidence in (None, Confidence.CERTIFIED):
        lines.append("GAPS  (none for this question -- the answer is fully "
                     "substantiated and complete)")
    else:
        # Not CERTIFIED but no question-local gap: the caveat lives in the
        # CONFIDENCE note and the coverage ledger. Never claim completeness here.
        lines.append("GAPS  (a scope/coverage caveat applies -- see the CONFIDENCE "
                     "note above and the Gaps question / --coverage for the ledger)")

    lines.append("")
    return "\n".join(lines)
