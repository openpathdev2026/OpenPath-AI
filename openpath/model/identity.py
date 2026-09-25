"""Identity resolution -- the part that makes "any user, not just existing ones" true.

The naive approach (look up ``username`` in the current ``/etc/passwd``, get a
UID, filter records where ``uid == that``) is wrong in at least four ways that
this module handles explicitly:

    1. **Privilege changes.** After ``sudo``/``su`` the effective ``uid`` becomes
       0 (or the target user's), but the *audit login uid* (``auid``) stays the
       original user. Attribution is therefore keyed on ``auid`` first, so a
       user's root actions are still attributed to them.

    2. **Users created or deleted inside the window.** The question family for
       accounts (family 9) is literally about users appearing and disappearing, so
       the current passwd file is not authoritative for the whole window. We build
       time-bounded identity intervals from account-change events.

    3. **UID reuse.** A UID freed by one deleted user and handed to a new one must
       not cross-attribute. Intervals are time-bounded and reuse is flagged.

    4. **Users that do not exist now / never existed.** These must still yield a
       correct, evidenced answer -- typically an evidenced negative plus a
       disclosed limitation that numeric-only records cannot be attributed to a
       name we cannot resolve.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange


@dataclass(frozen=True)
class IdentityInterval:
    """A period during which a numeric uid mapped to the subject's username.

    ``start``/``end`` of ``None`` mean unbounded (-inf / +inf). ``source`` records
    where the mapping came from ("passwd" snapshot or an "auditd" account event),
    which matters for how much we trust it.
    """

    uid: int
    start: Optional[datetime]
    end: Optional[datetime]
    source: str
    note: str = ""

    def covers(self, ts: datetime) -> bool:
        ts = ts.astimezone(timezone.utc)
        if self.start is not None and ts < self.start:
            return False
        if self.end is not None and ts > self.end:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uid": self.uid,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "source": self.source,
            "note": self.note,
        }


@dataclass
class Subject:
    """A resolved (or partially resolved) identity for a requested username."""

    username: str
    exists_now: bool
    current_uid: Optional[int]
    intervals: List[IdentityInterval] = field(default_factory=list)
    resolution_notes: List[str] = field(default_factory=list)

    @property
    def has_uid_mapping(self) -> bool:
        return bool(self.intervals)

    def uid_at(self, ts: datetime) -> Optional[int]:
        for iv in self.intervals:
            if iv.covers(ts):
                return iv.uid
        return None

    def matches(self, event: Event) -> bool:
        """Decide whether ``event`` is attributable to this subject.

        Order of evidence, strongest first:

            1. The record itself names the actor (``actor_name``) -- e.g. wtmp and
               many sudo records carry the account name directly.
            2. The record has an ``auid`` (login uid). We match only if one of our
               time-bounded uid intervals held that uid at the event's instant.
               If ``auid`` is present but is not ours, we do *not* fall back to
               ``uid`` (that ``uid`` may be root due to someone else's sudo).
            3. The record has only ``uid`` (no login uid, e.g. some non-syscall
               records). We match on ``uid`` within an interval as weaker evidence.
        """
        if event.actor_name is not None and event.actor_name == self.username:
            return True

        if event.auid is not None:
            for iv in self.intervals:
                if iv.uid == event.auid and iv.covers(event.ts):
                    return True
            return False

        if event.uid is not None:
            for iv in self.intervals:
                if iv.uid == event.uid and iv.covers(event.ts):
                    return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "exists_now": self.exists_now,
            "current_uid": self.current_uid,
            "intervals": [iv.to_dict() for iv in self.intervals],
            "resolution_notes": list(self.resolution_notes),
            "has_uid_mapping": self.has_uid_mapping,
        }


def resolve_identity(
    username: str,
    window: TimeRange,
    *,
    passwd_entries: List[Tuple[str, int]],
    account_events: List[Event],
) -> Subject:
    """Build a :class:`Subject` from a passwd snapshot and account-change events.

    Args:
        username: The requested account name (may not currently exist).
        window: The time range under investigation (used only for notes/scoping).
        passwd_entries: ``(name, uid)`` pairs from the current passwd snapshot.
        account_events: Normalized ACCOUNT_CHANGE events (add/del user) across the
            available history, each with ``attrs["action"]`` in
            ``{"add_user", "del_user"}``, ``attrs["acct"]`` and ``attrs["id"]``.
    """
    notes: List[str] = []

    # Current mapping.
    current_uid: Optional[int] = None
    exists_now = False
    for name, uid in passwd_entries:
        if name == username:
            exists_now = True
            current_uid = uid
            break

    # Account events that name this user, in chronological order.
    mine = sorted(
        (
            e
            for e in account_events
            if e.type == EventType.ACCOUNT_CHANGE
            and e.attrs.get("acct") == username
        ),
        key=lambda e: e.ts,
    )

    intervals: List[IdentityInterval] = []
    open_start: Optional[datetime] = None
    open_uid: Optional[int] = None
    for e in mine:
        action = e.attrs.get("action")
        uid = e.attrs.get("id")
        if action == "add_user":
            # Close any previously-open interval defensively (add without del).
            if open_start is not None and open_uid is not None:
                intervals.append(
                    IdentityInterval(open_uid, open_start, e.ts, "auditd",
                                     "implicit close: consecutive add_user")
                )
            open_start = e.ts
            open_uid = uid if uid is not None else current_uid
        elif action == "del_user":
            close_uid = uid if uid is not None else open_uid
            if close_uid is not None:
                intervals.append(
                    IdentityInterval(close_uid, open_start, e.ts, "auditd",
                                     "created and removed within observed history")
                )
            open_start = None
            open_uid = None

    # A still-open account (created in history, not deleted).
    if open_start is not None and open_uid is not None:
        intervals.append(
            IdentityInterval(open_uid, open_start, None, "auditd",
                             "created within observed history, still present")
        )
        if exists_now and current_uid is not None and current_uid != open_uid:
            notes.append(
                f"account-event uid {open_uid} differs from current passwd uid "
                f"{current_uid}; both retained as intervals."
            )

    # If the user exists now but no add/del event bounds it, assume the current
    # mapping held for the whole window -- but say so, because it is an assumption
    # backed only by a single present-tense snapshot.
    if exists_now and current_uid is not None and not any(
        iv.end is None for iv in intervals
    ):
        intervals.append(
            IdentityInterval(current_uid, None, None, "passwd",
                             "current mapping; no account-change record in history "
                             "-- assumed stable across the window")
        )

    # No mapping at all.
    if not intervals:
        if exists_now and current_uid is not None:
            intervals.append(
                IdentityInterval(current_uid, None, None, "passwd", "current mapping")
            )
        else:
            notes.append(
                f"'{username}' is not in the current passwd snapshot and no "
                f"account-change record references it; numeric-only records "
                f"(those with a login uid but no account name) cannot be "
                f"attributed to this name. Name-carrying records are still matched."
            )

    # UID reuse detection across the whole account-event history.
    uid_to_names: Dict[int, set] = {}
    for e in account_events:
        if e.type == EventType.ACCOUNT_CHANGE and e.attrs.get("id") is not None:
            uid_to_names.setdefault(e.attrs["id"], set()).add(e.attrs.get("acct"))
    for iv in intervals:
        others = uid_to_names.get(iv.uid, set()) - {username, None}
        if others:
            notes.append(
                f"uid {iv.uid} was also associated with account(s) "
                f"{sorted(others)} in the history; attribution relies on the "
                f"time interval to avoid cross-attribution (UID reuse)."
            )

    return Subject(
        username=username,
        exists_now=exists_now,
        current_uid=current_uid,
        intervals=intervals,
        resolution_notes=notes,
    )
