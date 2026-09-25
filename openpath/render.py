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

from openpath.engine import AnalysisResult
from openpath.narrate import narrate_finding

# Facets that are overviews/ledgers rather than a stream of activity.
_OVERVIEW_FACETS = {"core", "gaps"}


def _narration_for(f):
    """(sentences, evidence, overflow) with the right cap for the facet.

    Overview facets (Core, Gaps) carry a structured overview, not a per-event
    narrative. The Evidence facet is exhaustive (no cap).
    """
    if f.facet in _OVERVIEW_FACETS:
        return [], [], None
    if f.facet == "evidence":
        return narrate_finding(f, limit=None)
    return narrate_finding(f)


def render_json(result: AnalysisResult) -> str:
    f = result.finding
    sentences, evidence, overflow = _narration_for(f)
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
    lines.append("")
    if f.gaps:
        lines.append(f"GAPS  ({len(f.gaps)} thing(s) not fully determinable)")
        for g in f.gaps:
            lines.append(f"  - [{g.question}] {g.reason}")
            if g.remedy:
                lines.append(f"      remedy: {g.remedy}")
    else:
        lines.append("GAPS  (none for this question -- the answer is fully "
                     "substantiated and complete)")

    lines.append("")
    return "\n".join(lines)
