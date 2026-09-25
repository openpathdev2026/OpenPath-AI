"""A Finding: a facet's answer for one subject over one time range.

A Finding is deliberately shaped around the soundness contract:

    * ``events`` are the evidenced facts -- each carries its own citations, so the
      set of citations behind an answer is always recoverable (family 12).
    * ``summary`` is a derived, human-readable headline that must not assert
      anything beyond what ``events`` substantiate.
    * ``gaps`` are the things this facet could not determine and why (family 13).

A facet that finds no events and has full coverage returns an *evidenced negative*
("no such activity, and the sources that would have shown it were present and
instrumented"). A facet that finds no events but lacks coverage returns gaps, not
a false negative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from openpath.model.citation import Citation
from openpath.model.coverage import Gap
from openpath.model.event import Event
from openpath.model.timerange import TimeRange


@dataclass
class Finding:
    facet: str
    question_family: str
    subject_label: str
    window: TimeRange
    summary: str = ""
    events: List[Event] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    gaps: List[Gap] = field(default_factory=list)

    def citations(self) -> List[Citation]:
        """Every citation behind this finding, order-preserving and de-duplicated."""
        seen = set()
        out: List[Citation] = []
        for ev in self.events:
            for c in ev.citations:
                key = (c.source_id, c.locator, c.raw)
                if key not in seen:
                    seen.add(key)
                    out.append(c)
        return out

    @property
    def determined(self) -> bool:
        """True if the answer is fully substantiated (no blocking gaps)."""
        return not self.gaps

    def to_dict(self) -> Dict[str, Any]:
        return {
            "facet": self.facet,
            "question_family": self.question_family,
            "subject": self.subject_label,
            "window": self.window.to_dict(),
            "summary": self.summary,
            "events": [e.to_dict() for e in self.events],
            "notes": list(self.notes),
            "gaps": [g.to_dict() for g in self.gaps],
            "citation_count": len(self.citations()),
        }
