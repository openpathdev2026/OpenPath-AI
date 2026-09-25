"""The normalized cross-source event model.

Collectors read heterogeneous raw formats (binary wtmp, auditd text records,
journal JSON, dnf logs) and emit a single normalized :class:`Event` type with a
timezone-aware UTC timestamp and one or more :class:`Citation` objects. Facets
then reason over Events without caring which source they came from -- which is
what lets the "Core" (family 1) and "Timeline" (family 2) questions federate.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from openpath.model.citation import Citation


class EventType(enum.Enum):
    """Semantic category of a normalized event.

    The value is a stable string used in serialized output.
    """

    # Sessions / login (wtmp, journal)
    BOOT = "boot"
    SHUTDOWN = "shutdown"
    LOGIN = "login"
    LOGOUT = "logout"
    SESSION = "session"          # a login..logout interval (derived)
    SSH_AUTH = "ssh_auth"        # sshd authentication event (journal)

    # Privilege
    PRIVILEGE_ESCALATION = "privilege_escalation"  # sudo/su -> root or other uid

    # Execution
    EXEC = "exec"                # process execution (EXECVE)

    # Filesystem
    FILE_CHANGE = "file_change"  # create/modify/delete/rename/attr

    # Identity administration
    ACCOUNT_CHANGE = "account_change"  # add/del user, passwd change
    GROUP_CHANGE = "group_change"      # add/del group, membership

    # Software
    PACKAGE_CHANGE = "package_change"  # install/remove/update

    # Network
    NETWORK = "network"          # connect/bind/listen

    # Anything a collector understood but that has no dedicated category yet.
    OTHER = "other"


def _as_utc(dt: datetime) -> datetime:
    """Coerce a datetime to timezone-aware UTC.

    A naive datetime is rejected rather than silently assumed to be UTC or local:
    ambiguous time handling is a correctness hazard for this product, so callers
    must be explicit. Collectors are responsible for attaching the right tzinfo
    when they parse a source's native timestamp.
    """
    if dt.tzinfo is None:
        raise ValueError(
            "Event timestamps must be timezone-aware; got naive datetime "
            f"{dt!r}. Collectors must localize source timestamps explicitly."
        )
    return dt.astimezone(timezone.utc)


@dataclass
class Event:
    """A single normalized, cited fact on a UTC timeline.

    Attributes:
        ts: Primary instant of the event (timezone-aware, stored as UTC).
        type: Semantic category.
        source_id: The collector that produced it.
        summary: Short human-readable description (no interpretation beyond the
            record itself).
        ts_end: Optional end instant for interval events (e.g. a login session).
        auid: The audit/login uid (loginuid) if known. This is the *stable*
            attribution key: it survives ``sudo``/``su`` where ``uid`` changes.
        uid: The effective/real uid at the time of the event, if known.
        actor_name: Resolved username, if identity resolution attached one.
        attrs: Type-specific structured fields (command, argv, path, package,
            remote address, auth method, etc.).
        citations: One or more pointers to the raw record(s) substantiating it.
    """

    ts: datetime
    type: EventType
    source_id: str
    summary: str
    ts_end: Optional[datetime] = None
    auid: Optional[int] = None
    uid: Optional[int] = None
    actor_name: Optional[str] = None
    attrs: Dict[str, Any] = field(default_factory=dict)
    citations: List[Citation] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.ts = _as_utc(self.ts)
        if self.ts_end is not None:
            self.ts_end = _as_utc(self.ts_end)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "ts": self.ts.isoformat(),
            "type": self.type.value,
            "source_id": self.source_id,
            "summary": self.summary,
        }
        if self.ts_end is not None:
            d["ts_end"] = self.ts_end.isoformat()
        if self.auid is not None:
            d["auid"] = self.auid
        if self.uid is not None:
            d["uid"] = self.uid
        if self.actor_name is not None:
            d["actor_name"] = self.actor_name
        if self.attrs:
            d["attrs"] = self.attrs
        d["citations"] = [c.to_dict() for c in self.citations]
        return d
