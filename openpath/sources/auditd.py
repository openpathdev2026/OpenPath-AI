"""auditd collector: the workhorse behind privilege, exec, files, accounts, network.

This parses ``/var/log/audit/audit.log`` (plus rotations) directly. Lines are
grouped by their audit event id -- the ``:SERIAL`` inside
``msg=audit(<epoch>:<serial>)`` -- because one logical event (a syscall) is
recorded across several ``type=`` lines (SYSCALL, EXECVE, CWD, PATH, SOCKADDR,
PROCTITLE). Timestamps are epoch seconds and therefore unambiguously UTC.

The other half of this module is the *rules* parser. Whether a host can answer
"what commands did X run" depends entirely on whether an ``execve`` audit rule is
loaded; whether it can answer "what network activity" depends on ``connect``/
``bind`` rules; file questions depend on watch (``-w``) rules. We read
``/etc/audit/audit.rules`` and ``/etc/audit/rules.d/*.rules`` so the coverage
ledger can state, precisely, which questions this host is instrumented to answer
-- turning a would-be false "nothing found" into an honest "not recorded here".
"""

from __future__ import annotations

import binascii
import re
import socket
import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import (
    InstrumentationCheck,
    SourceCoverage,
    SourceStatus,
)
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

_AUDIT_LOG_PATHS = [
    "var/log/audit/audit.log.4",
    "var/log/audit/audit.log.3",
    "var/log/audit/audit.log.2",
    "var/log/audit/audit.log.1",
    "var/log/audit/audit.log",
]
_RULES_MAIN = "etc/audit/audit.rules"
_RULES_DIR = "etc/audit/rules.d"

_FIELD_RE = re.compile(r"""(\w+)=("(?:[^"\\]|\\.)*"|'[^']*'|\S+)""")
_AUDIT_ID_RE = re.compile(r"audit\((\d+)\.(\d+):(\d+)\)")
_TYPE_RE = re.compile(r"\btype=(\S+)")

_UNSET_AUID = 4294967295  # (uint32)-1, an unset loginuid

# Syscall numbers are architecture-specific, so we resolve them against the
# SYSCALL record's own arch= field rather than assuming one machine. The category
# sets below are keyed by *name*, so every facet works across architectures once
# the number is resolved. Add another arch by adding its number->name table.
_SYSCALLS_X86_64 = {
    59: "execve", 322: "execveat",
    42: "connect", 49: "bind", 50: "listen", 43: "accept", 288: "accept4",
    2: "open", 257: "openat", 437: "openat2",
    87: "unlink", 263: "unlinkat",
    82: "rename", 264: "renameat", 316: "renameat2",
    90: "chmod", 268: "fchmodat", 91: "fchmod",
    92: "chown", 260: "fchownat", 93: "fchown", 94: "lchown",
    76: "truncate", 77: "ftruncate", 85: "creat",
    86: "link", 265: "linkat", 88: "symlink", 266: "symlinkat",
    133: "mknod", 259: "mknodat",
}
# aarch64 (and other new arches) use the asm-generic table: only the *at variants
# exist -- no legacy open/creat/chmod/chown/unlink/rename/link/symlink/mknod.
_SYSCALLS_GENERIC = {
    221: "execve", 281: "execveat",
    203: "connect", 200: "bind", 201: "listen", 202: "accept", 242: "accept4",
    56: "openat", 437: "openat2",
    35: "unlinkat",
    38: "renameat", 276: "renameat2",
    53: "fchmodat", 52: "fchmod",
    54: "fchownat", 55: "fchown",
    45: "truncate", 46: "ftruncate",
    37: "linkat", 36: "symlinkat",
    33: "mknodat",
}
# AUDIT_ARCH_* values as they appear (hex) in the audit log's arch= field.
_ARCH_TABLES = {
    "c000003e": _SYSCALLS_X86_64,   # AUDIT_ARCH_X86_64
    "c00000b7": _SYSCALLS_GENERIC,  # AUDIT_ARCH_AARCH64
    "c00000f3": _SYSCALLS_GENERIC,  # AUDIT_ARCH_RISCV64
}


def _syscall_name(arch_hex, num):
    if num is None:
        return None
    table = _ARCH_TABLES.get((arch_hex or "").lower(), _SYSCALLS_X86_64)
    return table.get(num, _SYSCALLS_X86_64.get(num, str(num)))


_EXEC_SYSCALLS = {"execve", "execveat"}
_NET_SYSCALLS = {"connect", "bind", "listen", "accept", "accept4"}
_FILE_WRITE_SYSCALLS = {
    "unlink", "unlinkat", "rename", "renameat", "renameat2",
    "chmod", "fchmodat", "fchmod", "chown", "fchownat", "fchown", "lchown",
    "truncate", "ftruncate", "creat",
    "link", "linkat", "symlink", "symlinkat", "mknod", "mknodat",
}

_ACCOUNT_TYPES = {
    "ADD_USER": "add_user",
    "DEL_USER": "del_user",
    "USER_MGMT": "user_mgmt",
    "USER_CHAUTHTOK": "passwd_change",
    "ACCT_LOCK": "acct_lock",
    "ACCT_UNLOCK": "acct_unlock",
}
_GROUP_TYPES = {
    "ADD_GROUP": "add_group",
    "DEL_GROUP": "del_group",
    "GRP_MGMT": "grp_mgmt",
    "GRP_CHAUTHTOK": "group_passwd_change",
}


# --------------------------------------------------------------------------- #
# Field / value helpers
# --------------------------------------------------------------------------- #

def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def _maybe_hex_decode(v: str) -> str:
    """Decode an unquoted even-length hex field to text; otherwise return as-is."""
    if v and len(v) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", v):
        try:
            return binascii.unhexlify(v).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return v
    return v


def _parse_fields(text: str) -> Dict[str, str]:
    """Parse ``key=value`` pairs, recursing into an inner ``msg='...'`` blob."""
    out: Dict[str, str] = {}
    for key, val in _FIELD_RE.findall(text):
        if key == "msg" and val.startswith("audit("):
            continue  # the event id, handled separately
        uq = _unquote(val)
        if key == "msg" and "=" in uq and not uq.startswith("audit("):
            # USER_* records nest their real fields in a single-quoted msg blob.
            for k2, v2 in _FIELD_RE.findall(uq):
                out.setdefault(k2, _unquote(v2))
            continue
        out.setdefault(key, uq)
    return out


def _int(fields: Dict[str, str], key: str) -> Optional[int]:
    if key not in fields:
        return None
    try:
        return int(fields[key])
    except ValueError:
        return None


def _auid(fields: Dict[str, str]) -> Optional[int]:
    v = _int(fields, "auid")
    if v is None or v == _UNSET_AUID or v < 0:
        return None
    return v


def _decode_saddr(saddr_hex: str) -> Optional[Dict[str, object]]:
    """Decode an auditd SOCKADDR ``saddr=`` hex blob into family/addr/port."""
    try:
        raw = binascii.unhexlify(saddr_hex)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 2:
        return None
    family = struct.unpack_from("<H", raw, 0)[0]  # sa_family, host byte order
    if family == socket.AF_INET and len(raw) >= 8:
        port = struct.unpack_from(">H", raw, 2)[0]
        addr = socket.inet_ntop(socket.AF_INET, raw[4:8])
        return {"family": "inet", "addr": addr, "port": port}
    if family == socket.AF_INET6 and len(raw) >= 28:
        port = struct.unpack_from(">H", raw, 2)[0]
        addr = socket.inet_ntop(socket.AF_INET6, raw[8:24])
        return {"family": "inet6", "addr": addr, "port": port}
    if family == socket.AF_UNIX:
        path = raw[2:].split(b"\x00", 1)[0].decode("utf-8", "replace")
        return {"family": "unix", "path": path}
    return {"family": str(family)}


# --------------------------------------------------------------------------- #
# Rules (instrumentation) parser
# --------------------------------------------------------------------------- #

class AuditRules:
    def __init__(self) -> None:
        self.present = False
        self.syscalls: set = set()
        self.watches: List[Tuple[str, str, Optional[str]]] = []  # (path, perms, key)
        self.raw_lines: List[str] = []

    @property
    def has_execve(self) -> bool:
        return bool(self.syscalls & _EXEC_SYSCALLS) or "all" in self.syscalls

    @property
    def has_connect(self) -> bool:
        return "connect" in self.syscalls or "all" in self.syscalls

    @property
    def has_bind(self) -> bool:
        return "bind" in self.syscalls or "all" in self.syscalls


def parse_audit_rules(env: Env) -> AuditRules:
    rules = AuditRules()
    files: List = []
    main = env.path(_RULES_MAIN)
    if main.exists():
        files.append(main)
    rdir = env.path(_RULES_DIR)
    if rdir.is_dir():
        files.extend(sorted(rdir.glob("*.rules")))
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rules.present = True
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            rules.raw_lines.append(s)
            tokens = s.split()
            if "-S" in tokens:
                i = 0
                while i < len(tokens):
                    if tokens[i] == "-S" and i + 1 < len(tokens):
                        rules.syscalls.add(tokens[i + 1])
                    i += 1
            if s.startswith("-w ") or tokens[:1] == ["-w"]:
                path = perms = None
                key = None
                i = 0
                while i < len(tokens):
                    if tokens[i] == "-w" and i + 1 < len(tokens):
                        path = tokens[i + 1]
                    elif tokens[i] == "-p" and i + 1 < len(tokens):
                        perms = tokens[i + 1]
                    elif tokens[i] in ("-k", "-F") and tokens[i].startswith("-k") and i + 1 < len(tokens):
                        key = tokens[i + 1]
                    elif tokens[i] == "-k" and i + 1 < len(tokens):
                        key = tokens[i + 1]
                    i += 1
                if path:
                    rules.watches.append((path, perms or "", key))
    return rules


# --------------------------------------------------------------------------- #
# Record grouping
# --------------------------------------------------------------------------- #

class _Group:
    __slots__ = ("msgid", "ts", "records")

    def __init__(self, msgid: str, ts: datetime):
        self.msgid = msgid
        self.ts = ts
        self.records: List[Tuple[str, Dict[str, str], str, str]] = []
        # each record: (type, fields, raw_line, locator)


class AuditdCollector(Collector):
    source_id = "auditd"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        rules = parse_audit_rules(env)
        groups, locations = self._read_groups(env)

        auditd_installed = (
            rules.present
            or bool(locations)
            or env.exists("sbin/auditd")
            or env.exists("usr/sbin/auditd")
        )

        if not locations:
            status = SourceStatus.ABSENT if not auditd_installed else SourceStatus.EMPTY
            cov = SourceCoverage(
                source_id=self.source_id,
                status=status,
                detail="no audit.log found under data root",
                instrumentation=self._instrumentation(rules, saw_execve=False,
                                                       saw_net=False, saw_file=False),
            )
            return CollectResult(events=[], coverage=cov)

        all_ts = [g.ts for g in groups]
        hstart, hend = self._span(all_ts)

        events: List[Event] = []
        saw_execve = saw_net = saw_file = False
        for g in groups:
            ev = self._interpret(g, window)
            for e in ev:
                if e.type == EventType.EXEC:
                    saw_execve = True
                elif e.type == EventType.NETWORK:
                    saw_net = True
                elif e.type == EventType.FILE_CHANGE:
                    saw_file = True
            events.extend([e for e in ev if window.contains(e.ts)])

        events.sort(key=lambda e: e.ts)

        status = SourceStatus.AVAILABLE if groups else SourceStatus.EMPTY
        if hstart is not None and hstart > window.end:
            status = SourceStatus.OUT_OF_HORIZON

        cov = SourceCoverage(
            source_id=self.source_id,
            status=status,
            detail=f"{len(groups)} audit events parsed across {len(locations)} file(s)",
            horizon_start=hstart,
            horizon_end=hend,
            record_count=len(groups),
            locations=locations,
            retention_bounded=any("audit.log." in loc for loc in locations),
            instrumentation=self._instrumentation(rules, saw_execve, saw_net, saw_file),
        )
        return CollectResult(events=events, coverage=cov)

    # -- reading / grouping ------------------------------------------------- #

    def _read_groups(self, env: Env) -> Tuple[List[_Group], List[str]]:
        groups: Dict[str, _Group] = {}
        order: List[str] = []
        locations: List[str] = []
        for rel in _AUDIT_LOG_PATHS:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p))
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if "type=" not in line or "audit(" not in line:
                    continue
                m_id = _AUDIT_ID_RE.search(line)
                m_ty = _TYPE_RE.search(line)
                if not m_id or not m_ty:
                    continue
                epoch = int(m_id.group(1))
                usec = int(m_id.group(2))
                serial = m_id.group(3)
                msgid = f"{epoch}.{usec}:{serial}"
                ts = datetime.fromtimestamp(epoch + usec / 1000.0, tz=timezone.utc)
                rtype = m_ty.group(1)
                fields = _parse_fields(line)
                locator = f"{rel}:{lineno}"
                if msgid not in groups:
                    groups[msgid] = _Group(msgid, ts)
                    order.append(msgid)
                groups[msgid].records.append((rtype, fields, line.strip(), locator))
        return [groups[k] for k in order], locations

    # -- interpretation ----------------------------------------------------- #

    def _interpret(self, g: _Group, window: TimeRange) -> List[Event]:
        rtypes = {r[0] for r in g.records}
        # Syscall-based events.
        if "SYSCALL" in rtypes:
            return self._interpret_syscall(g)
        # User-space (PAM/shadow) events.
        events: List[Event] = []
        for rtype, fields, raw, locator in g.records:
            if rtype in ("USER_CMD", "USER_START", "USER_ACCT", "CRED_ACQ") and (
                fields.get("exe", "").endswith(("sudo", "su"))
                or rtype == "USER_CMD"
            ):
                ev = self._privilege_event(g, rtype, fields, raw, locator)
                if ev:
                    events.append(ev)
            elif rtype in _ACCOUNT_TYPES:
                events.append(self._account_event(g, rtype, fields, raw, locator))
            elif rtype in _GROUP_TYPES:
                events.append(self._group_event(g, rtype, fields, raw, locator))
        return events

    def _syscall_record(self, g: _Group):
        for rtype, fields, raw, locator in g.records:
            if rtype == "SYSCALL":
                return fields, raw, locator
        return None, None, None

    def _find(self, g: _Group, rtype: str):
        for rt, fields, raw, locator in g.records:
            if rt == rtype:
                return fields, raw, locator
        return None, None, None

    def _all(self, g: _Group, rtype: str):
        return [(f, raw, loc) for rt, f, raw, loc in g.records if rt == rtype]

    def _citations(self, g: _Group) -> List[Citation]:
        return [
            Citation(self.source_id, loc, raw, record_id=g.msgid)
            for (_rt, _f, raw, loc) in g.records
        ]

    def _interpret_syscall(self, g: _Group) -> List[Event]:
        sfields, sraw, sloc = self._syscall_record(g)
        if sfields is None:
            return []
        sysno = _int(sfields, "syscall")
        sysname = _syscall_name(sfields.get("arch"), sysno)
        auid = _auid(sfields)
        uid = _int(sfields, "uid")
        euid = _int(sfields, "euid")
        success = sfields.get("success")
        key = _maybe_hex_decode(sfields.get("key", "")) if "key" in sfields else None
        base_attrs = {
            "syscall": sysname,
            "arch": sfields.get("arch"),
            "success": success,
            "euid": euid,
            "pid": _int(sfields, "pid"),
            "ppid": _int(sfields, "ppid"),
            "tty": sfields.get("tty"),
            "key": key,
        }
        citations = self._citations(g)

        if sysname in _EXEC_SYSCALLS:
            return [self._exec_event(g, sfields, base_attrs, citations)]
        if sysname in _NET_SYSCALLS:
            ev = self._network_event(g, sfields, sysname, base_attrs, citations)
            return [ev] if ev else []
        # File modification: an explicitly-writing syscall, a create/delete PATH,
        # or a write-watch key that fired.
        paths = self._all(g, "PATH")
        nametypes = {f.get("nametype") for f, _r, _l in paths}
        is_file_change = (
            sysname in _FILE_WRITE_SYSCALLS
            or {"CREATE", "DELETE"} & nametypes
            or (key is not None)
        )
        if is_file_change and paths:
            return [self._file_event(g, sfields, sysname, base_attrs, citations, paths)]
        return []

    def _exec_event(self, g, sfields, base_attrs, citations) -> Event:
        argv = self._argv(g)
        exe = sfields.get("exe")
        comm = sfields.get("comm")
        cwd_fields, _r, _l = self._find(g, "CWD")
        cwd = cwd_fields.get("cwd") if cwd_fields else None
        auid = _auid(sfields)
        uid = _int(sfields, "uid")
        euid = _int(sfields, "euid")
        cmdline = " ".join(argv) if argv else (exe or comm or "")
        as_root = (euid == 0) or (uid == 0)
        switched = auid is not None and uid is not None and auid != uid
        attrs = dict(base_attrs)
        attrs.update({
            "exe": exe, "comm": comm, "argv": argv, "cmdline": cmdline,
            "cwd": cwd, "as_root": as_root, "switched": switched,
        })
        return Event(
            ts=g.ts, type=EventType.EXEC, source_id=self.source_id,
            summary=f"exec {cmdline}" + (" (as root)" if as_root else ""),
            auid=auid, uid=uid, attrs=attrs, citations=citations,
        )

    def _argv(self, g: _Group) -> List[str]:
        fields, _r, _l = self._find(g, "EXECVE")
        if not fields:
            return []
        args: List[Tuple[int, str]] = []
        for k, v in fields.items():
            if re.fullmatch(r"a\d+", k):
                idx = int(k[1:])
                args.append((idx, _maybe_hex_decode(v)))
        args.sort()
        return [v for _i, v in args]

    def _network_event(self, g, sfields, sysname, base_attrs, citations) -> Optional[Event]:
        sock_fields, _r, _l = self._find(g, "SOCKADDR")
        addr_info = None
        if sock_fields and "saddr" in sock_fields:
            addr_info = _decode_saddr(sock_fields["saddr"])
        auid = _auid(sfields)
        uid = _int(sfields, "uid")
        direction = "outbound" if sysname == "connect" else "inbound"
        attrs = dict(base_attrs)
        attrs.update({"direction": direction, "addr_info": addr_info})
        if addr_info and addr_info.get("family") in ("inet", "inet6"):
            target = f"{addr_info['addr']}:{addr_info.get('port')}"
        elif addr_info and addr_info.get("family") == "unix":
            target = f"unix:{addr_info.get('path')}"
        else:
            target = "unknown"
        return Event(
            ts=g.ts, type=EventType.NETWORK, source_id=self.source_id,
            summary=f"{sysname} {direction} {target}",
            auid=auid, uid=uid, attrs=attrs, citations=citations,
        )

    def _file_event(self, g, sfields, sysname, base_attrs, citations, paths) -> Event:
        # Prefer the created/deleted/modified target path.
        target = None
        for f, _r, _l in paths:
            if f.get("nametype") in ("CREATE", "DELETE", "NORMAL"):
                target = _maybe_hex_decode(f.get("name", "")) or target
                if f.get("nametype") in ("CREATE", "DELETE"):
                    break
        if target is None and paths:
            target = _maybe_hex_decode(paths[-1][0].get("name", ""))
        auid = _auid(sfields)
        uid = _int(sfields, "uid")
        attrs = dict(base_attrs)
        attrs.update({"path": target, "op": sysname})
        return Event(
            ts=g.ts, type=EventType.FILE_CHANGE, source_id=self.source_id,
            summary=f"{sysname} {target}",
            auid=auid, uid=uid, attrs=attrs, citations=citations,
        )

    def _privilege_event(self, g, rtype, fields, raw, locator) -> Optional[Event]:
        res = fields.get("res")
        auid = _auid(fields)
        uid = _int(fields, "uid")
        exe = fields.get("exe", "")
        tool = "sudo" if exe.endswith("sudo") or rtype == "USER_CMD" else (
            "su" if exe.endswith("su") else "privilege"
        )
        cmd = fields.get("cmd")
        if cmd:
            cmd = _maybe_hex_decode(cmd)
        attrs = {
            "tool": tool, "res": res, "record_type": rtype,
            "cmd": cmd, "terminal": fields.get("terminal"),
            "cwd": fields.get("cwd"), "exe": exe or None,
        }
        verb = "ran command via sudo" if (tool == "sudo" and cmd) else f"{tool} session"
        summary = f"{verb}" + (f": {cmd}" if cmd else "") + (
            f" ({res})" if res else ""
        )
        return Event(
            ts=g.ts, type=EventType.PRIVILEGE_ESCALATION, source_id=self.source_id,
            summary=summary, auid=auid, uid=uid, attrs=attrs,
            citations=self._citations(g),
        )

    def _account_event(self, g, rtype, fields, raw, locator) -> Event:
        acct = fields.get("acct")
        if acct:
            acct = _maybe_hex_decode(acct)
        target_id = _int(fields, "id")
        action = _ACCOUNT_TYPES[rtype]
        auid = _auid(fields)
        uid = _int(fields, "uid")
        res = fields.get("res")
        attrs = {
            "action": action, "acct": acct, "id": target_id,
            "res": res, "record_type": rtype, "op": fields.get("op"),
        }
        summary = f"{action.replace('_', ' ')} acct={acct} id={target_id}" + (
            f" ({res})" if res else ""
        )
        return Event(
            ts=g.ts, type=EventType.ACCOUNT_CHANGE, source_id=self.source_id,
            summary=summary, auid=auid, uid=uid, attrs=attrs,
            citations=self._citations(g),
        )

    def _group_event(self, g, rtype, fields, raw, locator) -> Event:
        grp = fields.get("grp") or fields.get("acct")
        if grp:
            grp = _maybe_hex_decode(grp)
        target_id = _int(fields, "id")
        action = _GROUP_TYPES[rtype]
        auid = _auid(fields)
        uid = _int(fields, "uid")
        res = fields.get("res")
        attrs = {
            "action": action, "grp": grp, "id": target_id,
            "res": res, "record_type": rtype, "op": fields.get("op"),
        }
        summary = f"{action.replace('_', ' ')} grp={grp} id={target_id}" + (
            f" ({res})" if res else ""
        )
        return Event(
            ts=g.ts, type=EventType.GROUP_CHANGE, source_id=self.source_id,
            summary=summary, auid=auid, uid=uid, attrs=attrs,
            citations=self._citations(g),
        )

    # -- instrumentation checks --------------------------------------------- #

    def _instrumentation(
        self, rules: AuditRules, saw_execve: bool, saw_net: bool, saw_file: bool
    ) -> List[InstrumentationCheck]:
        checks = [
            InstrumentationCheck(
                "auditd rules loaded", rules.present,
                "no audit rules file found; syscall auditing may be off"
                if not rules.present else "",
            ),
            InstrumentationCheck(
                "execve audit rule",
                rules.has_execve or saw_execve,
                "" if (rules.has_execve or saw_execve) else
                "no execve rule loaded; command execution is not recorded",
            ),
            InstrumentationCheck(
                "network (connect/bind) audit rule",
                rules.has_connect or rules.has_bind or saw_net,
                "" if (rules.has_connect or rules.has_bind or saw_net) else
                "no connect/bind rule loaded; network syscalls are not recorded",
            ),
            InstrumentationCheck(
                "file watch/modify audit rule",
                bool(rules.watches) or saw_file,
                "" if (rules.watches or saw_file) else
                "no file watch (-w) or write-syscall rule loaded; file changes are "
                "not recorded",
            ),
        ]
        return checks
