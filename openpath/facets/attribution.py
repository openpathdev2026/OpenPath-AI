"""Root attribution: who was actually behind each action performed as root.

The rule the product must get right:

    * A non-root user who escalates (``sudo``/``su``) keeps their audit login uid
      (``auid``) while their effective ``uid`` becomes 0. Such a root action is
      attributed to that **base user** -- "who became root and did this".
    * **Unless a user logged in directly as root** (e.g. ``ssh root@host``): then
      the login uid is 0 and there is no base user to credit. The action is
      attributed to that **direct root login**, tagged with where it came from.
    * A root action with **no login uid** (a daemon, a boot script, an unattended
      cron job) has no human behind it and is disclosed as unattributable rather
      than blamed on anyone.

This module classifies each root (uid/euid 0) action into exactly one of those,
resolving the base user via the reverse uid->name resolver so time-bounded
identity intervals and UID reuse are honoured.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from openpath.facets.base import AnalysisContext
from openpath.model.event import Event, EventType
from openpath.model.identity import resolve_name_for_uid

# Attribution kinds.
ESCALATED = "escalated"                 # base user became root via sudo/su
DIRECT_ROOT_LOGIN = "direct_root_login"  # someone logged in directly as root
ROOT_NO_SESSION = "root_no_session"      # loginuid 0 but no login session (cron/boot as root)
DAEMON = "daemon"                        # no login uid: system/daemon, not a human


@dataclass
class Attribution:
    kind: str
    actor: Optional[str]         # responsible account name, or None if unattributable
    origin: Optional[str] = None  # source (IP / tty) for a direct root login
    detail: str = ""
    escalation: Optional[Event] = None  # the sudo/su event, if one was found
    named: bool = True            # False when the login uid resolved to no account

    @property
    def attributable(self) -> bool:
        # Attributable to a specific principal only when we actually have one:
        # an escalation whose login uid maps to no account name is NOT.
        if self.kind == DIRECT_ROOT_LOGIN:
            return True
        if self.kind == ESCALATED:
            return self.named
        return False

    def label(self) -> str:
        if self.kind == ESCALATED:
            if not self.named:
                return f"{self.actor} (escalated; login uid maps to no known account)"
            return f"{self.actor} (via sudo/su)"
        if self.kind == DIRECT_ROOT_LOGIN:
            return f"root (direct login{f' from {self.origin}' if self.origin else ''})"
        if self.kind == ROOT_NO_SESSION:
            return "root (loginuid 0, no login session -- cron/boot)"
        return "unattributable (no login uid: system/daemon)"

    def narration(self) -> "tuple[str, str]":
        """(`actor_display`, `via_phrase`) for a flowing narrative sentence."""
        if self.kind == ESCALATED and self.named:
            return (self.actor, "via sudo/su")
        if self.kind == ESCALATED:  # unresolved login uid
            return (self.actor, "after escalating (login uid maps to no known account)")
        if self.kind == DIRECT_ROOT_LOGIN:
            origin = f" from {self.origin}" if self.origin else ""
            return ("root", f"via a direct root login{origin}")
        if self.kind == ROOT_NO_SESSION:
            return ("root", "as root with no login session (cron/boot)")
        return ("the system", "as an unattributed daemon (no login uid)")

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "actor": self.actor, "origin": self.origin,
            "detail": self.detail, "label": self.label(),
        }


def _root_sessions(ctx: AnalysisContext) -> List[Event]:
    """All login sessions whose account is root (candidate direct root logins)."""
    return [
        e for e in ctx.events
        if e.type == EventType.SESSION and e.actor_name == "root"
    ]


def is_root_action(event: Event) -> bool:
    return event.uid == 0 or event.attrs.get("euid") == 0 or bool(event.attrs.get("as_root"))


def classify_root_action(event: Event, ctx: AnalysisContext,
                         root_sessions: Optional[List[Event]] = None) -> Attribution:
    if root_sessions is None:
        root_sessions = _root_sessions(ctx)
    auid = event.auid

    # No login uid (e.g. a syslog/auth.log record) -- but the line may still name
    # the human who acted (a sudo invoker, an su caller). Credit them.
    if auid is None:
        if event.actor_name and event.actor_name != "root":
            return Attribution(
                ESCALATED, event.actor_name,
                detail="attributed by account name from auth.log (sudo/su)",
                named=True)
        # Otherwise no human is identifiable -> daemon/system.
        return Attribution(DAEMON, None, detail="no login uid recorded")

    # Login uid 0 -> the login session itself was root.
    if auid == 0:
        covering = [
            s for s in root_sessions if s.ts <= event.ts and (
                s.ts_end is None or event.ts <= s.ts_end
            )
        ]
        if covering:
            origin = covering[0].attrs.get("origin") or covering[0].attrs.get("host")
            return Attribution(
                DIRECT_ROOT_LOGIN, "root", origin=origin,
                detail="logged in directly as root (no base user to attribute to)",
            )
        return Attribution(
            ROOT_NO_SESSION, "root",
            detail="loginuid 0 with no matching login session (cron/boot/system as root)",
        )

    # Escalation: a base user became root. Resolve the base user by login uid.
    name, note = resolve_name_for_uid(
        auid, event.ts, ctx.window,
        passwd_entries=ctx.passwd, account_events=ctx.account_events(),
    )
    esc = _find_escalation(event, auid, ctx)
    return Attribution(
        ESCALATED, name or f"uid:{auid}",
        detail=("escalated via sudo/su" + (f"; {note}" if note else "")),
        escalation=esc, named=name is not None,
    )


def _find_escalation(event: Event, auid: int, ctx: AnalysisContext) -> Optional[Event]:
    """The most recent successful sudo/su by this login uid at or before the action."""
    best = None
    for e in ctx.events:
        if e.type != EventType.PRIVILEGE_ESCALATION or e.auid != auid:
            continue
        if e.attrs.get("res") not in (None, "success"):
            continue
        if e.ts <= event.ts and (best is None or e.ts > best.ts):
            best = e
    return best


def attribute_root_actions(
    ctx: AnalysisContext, events: List[Event]
) -> List[Tuple[Event, Attribution]]:
    root_sessions = _root_sessions(ctx)
    return [
        (e, classify_root_action(e, ctx, root_sessions))
        for e in events if is_root_action(e)
    ]


def summarize_responsibility(pairs: List[Tuple[Event, Attribution]]) -> List[str]:
    """Group attributed root actions by responsible party -> human-readable lines."""
    buckets: dict = {}
    for _e, attr in pairs:
        buckets.setdefault(attr.label(), 0)
        buckets[attr.label()] += 1
    return [f"{label}: {n} action(s)" for label, n in
            sorted(buckets.items(), key=lambda kv: (-kv[1], kv[0]))]
