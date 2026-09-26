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
    LOGIN = "login"
    SESSION = "session"          # a login..logout interval (derived)
    SSH_AUTH = "ssh_auth"        # sshd authentication event (journal)

    # Privilege
    PRIVILEGE_ESCALATION = "privilege_escalation"  # sudo/su -> root or other uid

    # Execution
    EXEC = "exec"                # process execution (EXECVE)

    # Filesystem
    FILE_CHANGE = "file_change"  # create/modify/delete/rename/attr
    FILE_READ = "file_read"      # read/open-for-read/access of a watched path (-p r)

    # Identity administration
    ACCOUNT_CHANGE = "account_change"  # add/del user, passwd change
    GROUP_CHANGE = "group_change"      # add/del group, membership

    # Software
    PACKAGE_CHANGE = "package_change"  # install/remove/update

    # Package configuration / provenance / policy (current-state inventory:
    # configured repositories, version-locks/holds, GPG-signature policy, and which
    # package managers OpenPath captures). Host-level; unattributed unless tied to a
    # file-change act. Answers PK-13/14/15/16.
    PKG_POLICY = "pkg_policy"

    # Persistence / scheduled execution (current-state inventory: cron, at,
    # systemd units/timers, linger, legacy startup). Unattributed unless the
    # artifact names a user (a per-user crontab) or a file-change event ties one.
    PERSISTENCE = "persistence"

    # Authorization / privilege configuration (current-state inventory: privileged
    # group membership, sudoers policy, shadow account status, SSH authorized_keys,
    # SSH auth policy). Attributed to the account a rule/artifact names; host-wide
    # policy (e.g. sshd PermitRootLogin) is unattributed.
    AUTHZ = "authz"

    # System lifecycle (host-level, not per-user): shutdown/poweroff, service
    # unit start/stop/failure, kernel panic/OOM/watchdog, boot target, clock change.
    # Boots come from wtmp as BOOT; these complement them for the lifecycle picture.
    SYSTEM = "system"

    # Interactive shell history (typed commands, from ~/.bash_history etc.).
    # Deliberately DISTINCT from EXEC: it is user-editable, usually un-timestamped,
    # and not proof of execution, so it must never be conflated with audited execs.
    SHELL_HISTORY = "shell_history"

    # Firewall / packet-filter configuration state (nftables/iptables ruleset).
    FIREWALL = "firewall"

    # Network
    NETWORK = "network"          # connect/bind/listen
    # Network flow telemetry from conntrack/netflow: per-flow peers, transport,
    # byte volume, direction -- distinct from the auditd connect/bind NETWORK events
    # so it never alters the audited network answer.
    NETFLOW = "netflow"
    # Network telemetry from logs a bundle may carry: DNS queries, firewall
    # drops/rejects, web/proxy accesses, and socket open/close lifetimes.
    NETLOG = "netlog"

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

    def target(self) -> "tuple[str, str]":
        """The object this action was performed against: ``(kind, value)``.

        This is the thing a client tracks -- the file changed, the command run,
        the endpoint contacted, the account/group/package touched. It is derived
        uniformly from the event so every source exposes the acted-upon object the
        same way, in the narrative and alongside the evidence.
        """
        a = self.attrs
        t = self.type
        if t is EventType.EXEC:
            return ("command", a.get("cmdline") or a.get("exe") or a.get("comm")
                    or self.summary)
        if t is EventType.FILE_CHANGE:
            return ("file", a.get("path") or "?")
        if t is EventType.FILE_READ:
            return ("file-read", a.get("path") or "?")
        if t is EventType.NETFLOW:
            return ("flow", a.get("artifact") or f"{a.get('peer')}:{a.get('dport')}")
        if t is EventType.NETLOG:
            return (a.get("kind") or "netlog", a.get("artifact") or self.summary)
        if t is EventType.NETWORK:
            ai = a.get("addr_info")
            if isinstance(ai, dict):
                if ai.get("family") in ("inet", "inet6"):
                    return ("endpoint", f"{ai.get('addr')}:{ai.get('port')}")
                if ai.get("family") == "unix":
                    return ("endpoint", f"unix:{ai.get('path')}")
            return ("endpoint", a.get("direction") or "network endpoint")
        if t is EventType.ACCOUNT_CHANGE:
            return ("account", a.get("acct")
                    or (f"uid {a.get('id')}" if a.get("id") is not None else "account"))
        if t is EventType.GROUP_CHANGE:
            return ("group", a.get("grp")
                    or (f"gid {a.get('id')}" if a.get("id") is not None else "group"))
        if t is EventType.PACKAGE_CHANGE:
            return ("package", a.get("package") or "?")
        if t is EventType.PERSISTENCE:
            return ("persistence", a.get("artifact") or a.get("path") or self.summary)
        if t is EventType.AUTHZ:
            return ("authz", a.get("artifact") or a.get("subject") or self.summary)
        if t is EventType.SYSTEM:
            return ("system", a.get("artifact") or a.get("unit") or a.get("kind")
                    or self.summary)
        if t is EventType.PKG_POLICY:
            return ("pkg-policy", a.get("artifact") or a.get("kind") or self.summary)
        if t is EventType.SHELL_HISTORY:
            return ("command", a.get("cmdline") or self.summary)
        if t is EventType.FIREWALL:
            return ("firewall-rule", a.get("artifact") or a.get("rule") or self.summary)
        if t is EventType.PRIVILEGE_ESCALATION:
            if a.get("cmd"):
                return ("command", a.get("cmd"))
            return ("privilege", a.get("tool") or "root")
        if t is EventType.SESSION:
            return ("session", f"{a.get('line') or 'tty'} from {a.get('origin') or 'local'}")
        if t is EventType.SSH_AUTH:
            return ("ssh-origin", str(a.get("ip") or "?"))
        if t is EventType.LOGIN:
            return ("login-origin", str(a.get("origin") or "local"))
        if t is EventType.BOOT:
            return ("system", "boot")
        return ("event", self.summary)

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
        target_kind, target_value = self.target()
        d["target_kind"] = target_kind
        d["target"] = target_value
        if self.attrs:
            d["attrs"] = self.attrs
        d["citations"] = [c.to_dict() for c in self.citations]
        return d
