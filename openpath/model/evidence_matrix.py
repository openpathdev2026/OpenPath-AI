"""The federated evidence model: per-question source tiers + answer confidence.

OpenPath's resilience property is: *we can still tell the story accurately when
one source is missing, incomplete, rotated, corrupted, or contradictory -- and we
say which source was gone.* That requires treating each question, not each source,
as the unit, and knowing for every question which sources are the **primary**
carriers of the answer versus merely **supporting** corroboration.

Each :class:`EvidenceSpec` declares, for one catalog question:
  * ``certified_any_of`` -- groups of (source, instrument) that, if a whole group
    is present+usable, make the answer fully substantiated (CERTIFIED). Multiple
    groups are alternatives (auditd, OR auth, OR ...).
  * ``partial_any_of`` -- sources that alone yield a substantive but explicitly
    degraded answer (PARTIAL) -- e.g. auth.log for commands (sudo-only).
  * ``supporting`` / ``optional`` -- corroboration whose absence never changes the
    answer but IS disclosed ("CERTIFIED; corroborating source wtmp absent").
  * ``fatal_if_all_missing`` -- if none present, the question is UNANSWERABLE.

:func:`assess` is deliberately **finding-aware**, not ledger-only. Several facets
answer from sources outside their declared spec (Privilege reads wtmp sessions;
the aggregators read cross-user/host events), so a purely source-availability
verdict could contradict the answer the facet actually produced. The hard
invariant is therefore: **a finding that carries determined, cited events is never
UNANSWERABLE.** Confidence is a label *of what the facet produced*, not a second,
independent judgement that can disagree with it.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from openpath.model.coverage import (
    CoverageLedger,
    SourceStatus,
    ledger_source_met,
)

SourceReq = Tuple[str, Optional[str]]  # (source_id, instrument-or-None)


class Confidence(enum.Enum):
    CERTIFIED = "certified"        # sources that record this class of activity were present+instrumented
    PARTIAL = "partial"            # substantive and cited, but a named scope/coverage gap is disclosed
    UNANSWERABLE = "unanswerable"  # no usable carrier; "cannot determine (see gaps)", never a false negative


def parse_member(s: str) -> SourceReq:
    """``"auditd(execve audit rule)"`` -> ``("auditd", "execve audit rule")``;
    ``"wtmp"`` -> ``("wtmp", None)``."""
    if s.endswith(")") and "(" in s:
        sid, instr = s[:-1].split("(", 1)
        return (sid.strip(), instr.strip())
    return (s.strip(), None)


def _group(members: Sequence[str]) -> Tuple[SourceReq, ...]:
    return tuple(parse_member(m) for m in members)


@dataclass(frozen=True)
class EvidenceSpec:
    """The evidence requirement + tier classification for one catalog question."""

    certified_any_of: Tuple[Tuple[SourceReq, ...], ...] = ()
    partial_any_of: Tuple[SourceReq, ...] = ()
    supporting: Tuple[str, ...] = ()
    optional: Tuple[str, ...] = ()
    fatal_if_all_missing: Tuple[str, ...] = ()
    # For aggregate questions only: the facet names whose confidence it federates.
    # When set, confidence is derived (best-of) from those, not from sources here.
    derived_from: Tuple[str, ...] = ()

    @staticmethod
    def make(certified=(), partial=(), supporting=(), optional=(),
             fatal=(), derived_from=()) -> "EvidenceSpec":
        return EvidenceSpec(
            certified_any_of=tuple(_group(g) for g in certified),
            partial_any_of=_group(partial),
            supporting=tuple(supporting),
            optional=tuple(optional),
            fatal_if_all_missing=tuple(fatal),
            derived_from=tuple(derived_from),
        )

    def answerability_sources(self) -> List[str]:
        """Sources that ALONE make this question answerable (at least PARTIAL).

        A source qualifies if it is the sole member of a certified group or a
        partial member. Multi-member certified groups (AND-conjuncts, e.g. packages
        + command telemetry for attribution) are *upgrades* to CERTIFIED, not
        answerability, so their extra members are excluded. This is exactly the set
        the facet's own prereq requirement covers; a golden test asserts the two
        agree so the spec and the facet requirements can never drift.
        """
        out: List[str] = []
        for grp in self.certified_any_of:
            if len(grp) == 1:
                out.append(grp[0][0])
        for (sid, _i) in self.partial_any_of:
            out.append(sid)
        return list(dict.fromkeys(out))


@dataclass
class Assessment:
    confidence: Confidence
    winning: Optional[Tuple[SourceReq, ...]]      # the certified group that was met, if any
    missing_non_fatal: List[str] = field(default_factory=list)
    note: str = ""


def _met(ledger: CoverageLedger, member: SourceReq) -> bool:
    return ledger_source_met(ledger, member[0], member[1])


def assess(spec: EvidenceSpec, ledger: CoverageLedger, finding) -> Assessment:
    """Confidence for a data question, finding-aware (see module docstring)."""
    label = getattr(finding, "question_family", "") or ""
    has_events = bool(getattr(finding, "events", None))

    winning = None
    for grp in spec.certified_any_of:
        if grp and all(_met(ledger, m) for m in grp):
            winning = grp
            break
    partial_met = any(_met(ledger, m) for m in spec.partial_any_of)

    # A same-question gap while a certified carrier IS present can only be a scope
    # caveat (the prereq AnyOf is satisfied), so it downgrades CERTIFIED -> PARTIAL.
    scope_gap = any(g.question == label for g in getattr(finding, "gaps", []))

    if winning is None and not partial_met and not has_events:
        conf = Confidence.UNANSWERABLE
    elif winning is not None and not scope_gap:
        conf = Confidence.CERTIFIED
    else:
        conf = Confidence.PARTIAL

    # Hard invariant: determined, cited events are never UNANSWERABLE.
    if conf is Confidence.UNANSWERABLE and has_events:
        conf = Confidence.PARTIAL

    # Coverage-derived degrade: a conservation or retention shortfall on ANY source
    # the answer actually rests on -- the winning group OR any source that supplied
    # the finding's shown events -- means "certified only for the covered
    # sub-interval". Checking the cited sources too closes the hole where a
    # supporting source (e.g. wtmp) feeds the events but dropped records unnoticed.
    degrade = None
    if conf is Confidence.CERTIFIED:
        rest_on = {sid for (sid, _i) in (winning or ())}
        rest_on |= {getattr(e, "source_id", None)
                    for e in getattr(finding, "events", []) or ()}
        rest_on.discard(None)
        for sid in sorted(rest_on):
            cov = ledger.get(sid)
            if cov and cov.unparseable:
                degrade = f"{sid} has undecodable records"
                break
        if degrade is None:
            shortfalls = {g.source_id for g in ledger.horizon_shortfalls()}
            hit = rest_on & shortfalls
            if hit:
                degrade = f"{sorted(hit)[0]} has a retention shortfall"
    if degrade:
        conf = Confidence.PARTIAL

    partial_hits = [sid for (sid, i) in spec.partial_any_of
                    if ledger_source_met(ledger, sid, i)]
    missing = _missing_non_fatal(spec, ledger, winning)
    note = _note(conf, winning, missing, degrade, partial_hits)
    return Assessment(conf, winning, missing, note)


def _missing_non_fatal(spec, ledger, winning) -> List[str]:
    win_ids = {sid for (sid, _i) in (winning or ())}
    out: List[str] = []
    for sid in list(spec.supporting) + list(spec.optional):
        if sid in win_ids:
            continue
        cov = ledger.get(sid)
        if cov is None or cov.status in (SourceStatus.ABSENT,
                                         SourceStatus.NOT_CONFIGURED,
                                         SourceStatus.OUT_OF_HORIZON):
            out.append(sid)
    return list(dict.fromkeys(out))


def _note(conf, winning, missing, degrade, partial_hits) -> str:
    if conf is Confidence.UNANSWERABLE:
        return "no source present that records this class of activity -- see gaps"
    if conf is Confidence.CERTIFIED:
        src = ", ".join(sorted({sid for (sid, _i) in (winning or ())})) or "present sources"
        note = src
        if missing:
            note += (f"; corroborating source(s) {', '.join(missing)} absent"
                     f" -- do not affect this answer")
        return note
    # PARTIAL
    if degrade:
        return f"certified for the covered sub-interval; {degrade} -- see gaps"
    if winning is None and partial_hits:
        srcs = ", ".join(sorted(set(partial_hits)))
        return f"{srcs} only (a fallback source); a scope/coverage gap is disclosed -- see gaps"
    if winning is None:
        return "a fallback source only; a scope/coverage gap is disclosed -- see gaps"
    return "a certified source is present but a scope gap is disclosed -- see gaps"


def derive_aggregate(confidences: Sequence[Confidence]) -> Confidence:
    """Best-of over the federated data questions' confidences.

    A federated overview is as strong as its strongest slice; every weaker slice is
    disclosed as a gap, so best-of never hides a blind slice (the renderer names
    them). If nothing federated is answerable, the aggregate is UNANSWERABLE.
    """
    if not confidences:
        return Confidence.UNANSWERABLE
    if any(c is Confidence.CERTIFIED for c in confidences):
        return Confidence.CERTIFIED
    if any(c is Confidence.PARTIAL for c in confidences):
        return Confidence.PARTIAL
    return Confidence.UNANSWERABLE
