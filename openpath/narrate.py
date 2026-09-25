"""Turn a finding's cited events into flowing sentences a client can read.

Each sentence names the actor, the action, and -- crucially -- the object the
action was performed against (the file, command, endpoint, account, group, or
package), followed by an evidence marker ``[E#]``. The matching evidence entry
leads with that same object and lists the raw source record(s) behind it, so a
reader can trace every claim to its proof and to the thing that was acted upon.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from typing import Callable, List, Optional, Tuple

from openpath.model.event import Event, EventType
from openpath.model.finding import Finding

# How many events to narrate/enumerate before summarizing the remainder, so a
# huge result set stays readable. Full detail is always in the JSON output.
_MAX_NARRATED = 60

_FILE_OP_VERB = {
    "unlink": "deleted", "unlinkat": "deleted",
    "rename": "renamed", "renameat": "renamed", "renameat2": "renamed",
    "chmod": "changed permissions on", "fchmodat": "changed permissions on",
    "fchmod": "changed permissions on",
    "chown": "changed ownership of", "fchownat": "changed ownership of",
    "fchown": "changed ownership of", "lchown": "changed ownership of",
    "truncate": "truncated", "ftruncate": "truncated",
    "creat": "created", "openat": "modified", "open": "modified",
    "link": "hard-linked", "linkat": "hard-linked",
    "symlink": "symlinked", "symlinkat": "symlinked",
    "mknod": "created device node", "mknodat": "created device node",
}
_PKG_VERB = {
    "install": "installed", "reinstall": "reinstalled", "remove": "removed",
    "upgrade": "upgraded", "downgrade": "downgraded", "obsolete": "obsoleted",
}
_ACCT_VERB = {
    "add_user": "created the account", "del_user": "deleted the account",
    "passwd_change": "changed the password for the account",
    "user_mgmt": "modified the account", "acct_lock": "locked the account",
    "acct_unlock": "unlocked the account",
}
_GRP_VERB = {
    "add_group": "created the group", "del_group": "deleted the group",
    "grp_mgmt": "modified the group",
    "group_passwd_change": "changed the password for the group",
}


@dataclass
class EvidenceEntry:
    ref: str
    target_kind: str
    target: str
    records: List[Tuple[str, str, str]]  # (source_id, locator, raw)

    def to_dict(self) -> dict:
        return {
            "ref": self.ref,
            "object_kind": self.target_kind,
            "object": self.target,
            "records": [
                {"source_id": s, "locator": loc, "raw": raw}
                for (s, loc, raw) in self.records
            ],
        }


def _fmt_time(dt) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _verb_phrase(e: Event) -> str:
    a = e.attrs
    t = e.type
    _kind, obj = e.target()
    if t is EventType.EXEC:
        return f"ran the command `{obj}`"
    if t is EventType.FILE_CHANGE:
        return f"{_FILE_OP_VERB.get(a.get('op'), 'modified')} the file `{obj}`"
    if t is EventType.NETWORK:
        if a.get("direction") == "outbound":
            return f"connected outbound to {obj}"
        return f"{a.get('syscall', 'listened')} on {obj}"
    if t is EventType.ACCOUNT_CHANGE:
        verb = _ACCT_VERB.get(a.get("action"), "changed the account")
        idpart = f" (uid {a.get('id')})" if a.get("id") is not None else ""
        return f"{verb} `{a.get('acct') or obj}`{idpart}"
    if t is EventType.GROUP_CHANGE:
        verb = _GRP_VERB.get(a.get("action"), "changed the group")
        idpart = f" (gid {a.get('id')})" if a.get("id") is not None else ""
        return f"{verb} `{a.get('grp') or obj}`{idpart}"
    if t is EventType.PACKAGE_CHANGE:
        return f"{_PKG_VERB.get(a.get('action'), 'changed')} the package `{obj}`"
    if t is EventType.PRIVILEGE_ESCALATION:
        if a.get("cmd"):
            return f"used {a.get('tool', 'sudo')} to run `{a.get('cmd')}`"
        return f"started a {a.get('tool', 'privilege')} session"
    if t is EventType.SSH_AUTH:
        res = "authenticated" if a.get("result") == "accepted" \
            else "failed to authenticate"
        return (f"{res} over SSH from {a.get('ip')} using {a.get('method')}")
    if t is EventType.LOGIN and a.get("result") == "failed":
        return (f"failed a login attempt from {a.get('origin') or 'local'} "
                f"on {a.get('line') or 'a terminal'}")
    if t is EventType.BOOT:
        return "the system booted"
    return e.summary


def narrate_event(e: Event, actor: str) -> str:
    """One flowing sentence for a single event (no evidence marker)."""
    if e.type is EventType.SESSION:
        origin = e.attrs.get("origin") or "local"
        line = e.attrs.get("line") or "a terminal"
        if e.ts_end is not None:
            tail = f"and logged out at {_fmt_time(e.ts_end)}"
        else:
            tail = "and was still logged in at the end of the window"
        return (f"{actor} logged in from {origin} on {line} at "
                f"{_fmt_time(e.ts)} {tail}.")
    qualifier = ""
    via = e.attrs.get("via")
    if via:
        qualifier = f" {via}"
    elif e.uid == 0 or e.attrs.get("euid") == 0 or e.attrs.get("as_root"):
        qualifier = " as root"
    return f"At {_fmt_time(e.ts)}, {actor} {_verb_phrase(e)}{qualifier}."


def narrate_finding(
    finding: Finding,
    actor_of: Optional[Callable[[Event], str]] = None,
    limit: Optional[int] = _MAX_NARRATED,
) -> Tuple[List[str], List[EvidenceEntry], Optional[str]]:
    """Return (sentences, evidence_entries, overflow_note).

    ``actor_of`` maps an event to the actor to credit; by default the event's own
    ``actor_name`` or the finding's subject. Each sentence carries an ``[E#]``
    marker whose evidence entry leads with the acted-upon object. ``limit`` caps
    how many events are rendered (``None`` = all, used by the Evidence question,
    which must be exhaustive).
    """
    subject = finding.subject_label

    def default_actor(e: Event) -> str:
        return e.actor_name or subject

    pick = actor_of or default_actor
    sentences: List[str] = []
    evidence: List[EvidenceEntry] = []
    events = finding.events
    shown = events if limit is None else events[:limit]
    for i, e in enumerate(shown, start=1):
        ref = f"E{i}"
        sentence = narrate_event(e, pick(e))
        if e.citations:
            sentence = f"{sentence} [{ref}]"
            kind, obj = e.target()
            evidence.append(EvidenceEntry(
                ref=ref, target_kind=kind, target=obj,
                records=[(c.source_id, c.locator, c.raw) for c in e.citations],
            ))
        sentences.append(sentence)
    overflow = None
    if limit is not None and len(events) > limit:
        overflow = (f"... and {len(events) - limit} further event(s) not "
                    f"narrated here (full detail in --format json).")
    return sentences, evidence, overflow
