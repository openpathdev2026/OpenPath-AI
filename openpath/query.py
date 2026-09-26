"""The deterministic investigation/query layer.

Most of the production contract's projection questions ("did {user} delete an
account?", "what files under /etc did {user} change?", "who installed package X?",
"what activity cannot be attributed to a human?") are not new evidence -- they are
**deterministic filters and pivots over the already-normalized, already-cited event
set** that the certified facets produce. This module is that layer.

Design invariants (they are the trust contract, not conveniences):
  * **Provenance is preserved.** A query never builds new facts; it selects existing
    :class:`Event` objects, each of which still carries its own citations. raw
    evidence -> normalized event -> filter -> result -> citation is unbroken.
  * **Attribution is reused, never reinvented.** Actor selection delegates to
    :meth:`Subject.matches` (auid-centric, survives sudo/su), so the query layer
    cannot introduce a wrong-human attribution the facets don't already make.
  * **Absence is not proof.** A query that matches nothing is scoped to BOTH the
    evidence actually covered AND the filter ("no account deletions by alice in the
    covered evidence scope") -- it inherits the base facet's confidence and gaps, so
    an un-instrumented host yields UNANSWERABLE/gap, never a false negative.
  * **Deterministic.** Same events + same spec -> same result, always. No LLM, no
    heuristics; the LLM stays downstream of this layer.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from openpath.model.event import Event, EventType
from openpath.model.identity import Subject

# Actor-selection modes.
ACTOR_SUBJECT = "subject"            # events attributable to a named subject
ACTOR_ANY = "any"                    # host-wide: every actor (the "who did X" pivot)
ACTOR_UNATTRIBUTABLE = "unattributable"  # no login uid and no named actor (daemon/cron/boot)

# Pivots (how results are organized, not what they contain).
PIVOT_CHRONOLOGICAL = "chronological"
PIVOT_BY_ACTOR = "by_actor"


@dataclass(frozen=True)
class QuerySpec:
    """A declarative, composable filter over normalized events.

    Every field is an independent, conjunctive constraint (all must hold). Empty /
    ``None`` means "no constraint on this dimension". Nothing here selects a time
    window -- the engine applies the requested window before the query runs.
    """

    types: Tuple[EventType, ...] = ()      # event-type filter (empty = any type)
    sources: Tuple[str, ...] = ()          # source_id membership (empty = any source)
    actor: str = ACTOR_SUBJECT
    object_contains: str = ""              # case-insensitive substring on the acted-on object
    object_paths: Tuple[str, ...] = ()     # any-prefix / glob match on a file path or object
    command_contains: str = ""             # case-insensitive substring on cmdline/exe/comm/argv
    actions: Tuple[str, ...] = ()          # membership on attrs action/op/tool
    direction: str = ""                    # network direction (outbound/inbound)
    as_root: Optional[bool] = None         # True: only root-privileged events; False: only non-root
    via_sudo: Optional[bool] = None        # True: only sudo-invoked; False: only non-sudo
    result: str = ""                       # "success" | "failed" -- outcome of the action
    target_user: str = ""                  # the identity switched TO (sudo -u / su target)
    tty: str = ""                          # controlling terminal (substring; "" = any)
    pivot: str = PIVOT_CHRONOLOGICAL

    def describe(self) -> str:
        """A human phrase for the constraints, for scoped summaries/negatives."""
        bits: List[str] = []
        if self.actions:
            bits.append(f"action in {{{', '.join(self.actions)}}}")
        if self.object_paths:
            bits.append(f"path matching {{{', '.join(self.object_paths)}}}")
        if self.object_contains:
            bits.append(f"object containing '{self.object_contains}'")
        if self.command_contains:
            bits.append(f"command containing '{self.command_contains}'")
        if self.direction:
            bits.append(f"{self.direction} direction")
        if self.as_root is True:
            bits.append("as root")
        elif self.as_root is False:
            bits.append("not as root")
        if self.via_sudo is True:
            bits.append("via sudo")
        elif self.via_sudo is False:
            bits.append("not via sudo")
        if self.result:
            bits.append(f"result={self.result}")
        if self.target_user:
            bits.append(f"switched to {self.target_user}")
        if self.tty:
            bits.append(f"tty~{self.tty}")
        if self.sources:
            bits.append(f"from source {{{', '.join(self.sources)}}}")
        return "; ".join(bits)

    @property
    def is_filtered(self) -> bool:
        return bool(self.actions or self.object_paths or self.object_contains
                    or self.command_contains or self.direction or self.sources
                    or self.as_root is not None or self.via_sudo is not None
                    or self.result or self.target_user or self.tty)


def _event_is_root(e: Event) -> bool:
    return bool(e.uid == 0 or e.attrs.get("euid") == 0 or e.attrs.get("as_root"))


def _event_result(e: Event) -> str:
    """Normalize an event's outcome to 'success' | 'failed' | '' (unknown)."""
    a = e.attrs
    res = str(a.get("res") or a.get("result") or "").lower()
    if res in ("failed", "denied", "fail"):
        return "failed"
    if res in ("success", "accepted", "ok"):
        return "success"
    succ = str(a.get("success") or "").lower()
    if succ == "no":
        return "failed"
    if succ == "yes":
        return "success"
    return ""


def _command_text(e: Event) -> str:
    a = e.attrs
    argv = a.get("argv") or []
    return " ".join([str(a.get("cmdline") or ""), str(a.get("exe") or ""),
                     str(a.get("comm") or ""), " ".join(str(x) for x in argv)]).lower()


def _object_value(e: Event) -> str:
    _kind, val = e.target()
    return str(val)


def _path_matches(e: Event, patterns: Tuple[str, ...]) -> bool:
    candidates = [e.attrs.get("path"), _object_value(e)]
    for cand in candidates:
        if not cand:
            continue
        for pat in patterns:
            if any(ch in pat for ch in "*?["):
                if fnmatch.fnmatch(cand, pat):
                    return True
            elif cand == pat:
                return True
            else:
                # A bare directory is a prefix, but only at a path boundary, so
                # "/etc" matches "/etc/passwd" -- NOT "/etcpasswd" or "/etc-backup".
                base = pat.rstrip("/")
                if cand.startswith(base + "/"):
                    return True
    return False


def _actor_selected(e: Event, spec: QuerySpec, subject: Optional[Subject]) -> bool:
    if spec.actor == ACTOR_ANY:
        return True
    if spec.actor == ACTOR_UNATTRIBUTABLE:
        # No login uid AND no named actor: a daemon/cron/boot action with no human
        # behind it. (uid alone, e.g. uid=0 with no auid/name, still counts here.)
        return e.auid is None and not e.actor_name
    # Default: attributable to the named subject, via the auid-centric matcher.
    return bool(subject and subject.matches(e))


def matches(e: Event, spec: QuerySpec, subject: Optional[Subject]) -> bool:
    """True if a single event satisfies every constraint in the spec."""
    if spec.types and e.type not in spec.types:
        return False
    if spec.sources and e.source_id not in spec.sources:
        return False
    if not _actor_selected(e, spec, subject):
        return False
    if spec.object_contains and spec.object_contains.lower() not in _object_value(e).lower():
        return False
    if spec.object_paths and not _path_matches(e, spec.object_paths):
        return False
    if spec.command_contains and spec.command_contains.lower() not in _command_text(e):
        return False
    if spec.actions:
        vals = {str(e.attrs.get(k)) for k in ("action", "op", "tool") if e.attrs.get(k)}
        if not (set(spec.actions) & vals):
            return False
    if spec.direction and e.attrs.get("direction") != spec.direction:
        return False
    if spec.as_root is not None and _event_is_root(e) != spec.as_root:
        return False
    if spec.via_sudo is not None and bool(e.attrs.get("via_sudo")) != spec.via_sudo:
        return False
    if spec.result and _event_result(e) != spec.result:
        return False
    if spec.target_user and e.attrs.get("target_user") != spec.target_user:
        return False
    if spec.tty and spec.tty not in str(e.attrs.get("tty") or ""):
        return False
    return True


def apply_query(events: List[Event], spec: QuerySpec,
                subject: Optional[Subject]) -> List[Event]:
    """Select the events satisfying the spec, in chronological order.

    Pure and deterministic: returns the same :class:`Event` objects (citations
    intact), never copies-with-new-facts, so provenance is preserved end to end.
    """
    out = [e for e in events if matches(e, spec, subject)]
    out.sort(key=lambda e: e.ts)
    return out
