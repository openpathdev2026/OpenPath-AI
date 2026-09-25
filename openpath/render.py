"""Rendering of an :class:`AnalysisResult` to text or JSON.

The text renderer always shows three things in this order: the answer, the
evidence backing it, and the gaps around it. That ordering is the product thesis
made visible -- a claim, its proof, and its limits, every time.
"""

from __future__ import annotations

import json
from typing import Optional

from openpath.engine import AnalysisResult


def render_json(result: AnalysisResult) -> str:
    payload = {
        "question_family": result.finding.question_family,
        "facet": result.finding.facet,
        "subject": result.subject.to_dict(),
        "finding": result.finding.to_dict(),
        "coverage": result.ledger.to_dict(),
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def render_text(result: AnalysisResult, *, verbose: bool = False) -> str:
    f = result.finding
    lines = []
    lines.append("=" * 72)
    lines.append(f"OpenPath | {f.question_family}  (facet: {f.facet})")
    lines.append(f"Subject : {result.subject.username}"
                 + ("" if result.subject.exists_now else "  [not a current local account]"))
    lines.append(f"Window  : {f.window.describe()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append("ANSWER")
    lines.append(f"  {f.summary}")

    if f.notes:
        lines.append("")
        lines.append("DETAIL")
        for n in f.notes:
            lines.append(f"  {n}")

    # Evidence summary (family 12 is the full list; here we show the count and,
    # if verbose, the raw records behind this specific answer).
    cites = f.citations()
    lines.append("")
    lines.append(f"EVIDENCE  ({len(cites)} raw record(s) substantiate this answer)")
    if verbose and cites:
        for c in cites:
            lines.append(f"  {c.locator}: {c.raw}")
    elif cites and f.facet != "evidence":
        shown = cites[:3]
        for c in shown:
            lines.append(f"  {c.short()}")
        if len(cites) > 3:
            lines.append(f"  ... and {len(cites) - 3} more (use --verbose or the "
                         f"Evidence question for all)")

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
