"""Citations: the pointer from an asserted fact back to a raw source record.

Every :class:`~openpath.model.event.Event` and therefore every claim OpenPath
makes carries at least one Citation. This is what makes the "Evidence" question
(family 12) trivially answerable and what enforces soundness: if a fact cannot be
cited, it is not asserted -- it becomes a disclosed gap instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Citation:
    """A verifiable pointer to a single raw source record.

    Attributes:
        source_id: Stable identifier of the collector that produced this record,
            e.g. ``"wtmp"``, ``"auditd"``, ``"journal.sshd"``, ``"dnf.rpm"``.
        locator: Human-verifiable location of the record, e.g.
            ``"/var/log/audit/audit.log:1423"`` or ``"wtmp#12"``. Should be stable
            enough that an auditor can open the source and find the exact record.
        raw: The raw record text (or a faithful repr for binary formats). This is
            the primary substantiation shown to a human reviewer.
        record_id: Optional source-native identifier (e.g. an auditd event serial)
            used to correlate multiple lines belonging to one logical event.
        extra: Optional structured detail (offsets, byte ranges, field map).
    """

    source_id: str
    locator: str
    raw: str
    record_id: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "source_id": self.source_id,
            "locator": self.locator,
            "raw": self.raw,
        }
        if self.record_id is not None:
            d["record_id"] = self.record_id
        if self.extra:
            d["extra"] = dict(self.extra)
        return d

    def short(self) -> str:
        """A one-line reference suitable for inline display."""
        return f"[{self.source_id}] {self.locator}"
