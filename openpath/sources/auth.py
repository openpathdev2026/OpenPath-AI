"""Syslog auth collector: sudo / ssh / su / account events from auth.log|secure.

Most stock Debian/Ubuntu (and un-hardened RHEL) hosts do **not** run auditd, but
they still record the security-relevant events to syslog: ``/var/log/auth.log``
(Debian/Ubuntu) or ``/var/log/secure`` (RHEL/Fedora). This collector makes the
Privilege, Login, and Accounts questions -- and sudo-invoked Commands/Root
activity -- answerable on those hosts, with the same soundness/disclosure
contract.

Important scope note it lets the facets disclose: auth.log records commands run
**via sudo**, not every command. Ordinary (non-sudo) process execution is not in
syslog; that still needs an auditd execve rule. The Commands/Root-activity facets
say so when they fall back to auth.log.

Attribution here is by **name**: the log line names the human (the sudo invoker,
the su caller, the ssh user), so events carry ``actor_name`` directly and match a
subject without needing a uid.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import (
    InstrumentationCheck,
    SourceCoverage,
    SourceStatus,
)
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange, parse_instant
from openpath.sources.base import CollectResult, Collector

_AUTH_PATHS = [
    "var/log/auth.log.1", "var/log/auth.log",   # Debian/Ubuntu
    "var/log/secure.1", "var/log/secure",         # RHEL/Fedora
]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Traditional syslog line: "Sep 25 09:20:01 host proc[pid]: message"
_TRAD_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
# ISO/rsyslog line: "2026-09-25T09:20:01+00:00 host proc[pid]: message"
_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+(?P<host>\S+)\s+"
    r"(?P<rest>.*)$")

# The invoker is a real account name (no parens/colons), which also prevents the
# PAM lines ("sudo: pam_unix(sudo:auth): ...") from matching as a command line.
_SUDO_CMD_RE = re.compile(
    r"sudo(?:\[\d+\])?:\s*(?P<user>[A-Za-z_][A-Za-z0-9._-]*)\s*:\s*(?P<body>.*)$")
_SSH_ACCEPT_RE = re.compile(
    r"sshd(?:\[\d+\])?:\s*Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_FAIL_RE = re.compile(
    r"sshd(?:\[\d+\])?:\s*Failed (?P<method>\S+) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SU_PAM_RE = re.compile(
    r"su(?:\[\d+\])?:.*session opened for user (?P<target>[^\s(]+)"
    r"(?:\(uid=\d+\))? by (?P<by>[^\s(]+)")
_SU_LEGACY_RE = re.compile(
    r"su(?:\[\d+\])?:\s*(?:\(to (?P<target>\S+)\) (?P<by>\S+)"
    r"|\+\s+\S+\s+(?P<by2>[^:\s]+):(?P<target2>\S+))")
_USERADD_RE = re.compile(
    r"useradd(?:\[\d+\])?:.*new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+)")
_USERDEL_RE = re.compile(
    r"userdel(?:\[\d+\])?:.*(?:delete user '(?P<name>[^']+)'|removed user '(?P<name2>[^']+)')")
_GROUPADD_RE = re.compile(
    r"groupadd(?:\[\d+\])?:.*new group: name=(?P<name>[^,]+), GID=(?P<gid>\d+)")
_GROUPDEL_RE = re.compile(
    r"groupdel(?:\[\d+\])?:.*(?:delete group '(?P<name>[^']+)'|removed group '(?P<name2>[^']+)')")
_PASSWD_RE = re.compile(
    r"passwd(?:\[\d+\])?:.*password changed for (?P<name>\S+)")

_SUDO_FAIL_HINTS = ("authentication failure", "command not allowed",
                    "incorrect password", "user NOT in sudoers", "auth could not")


def _parse_traditional_ts(mon: str, day: str, time_s: str,
                          ref_now: datetime, tz) -> Optional[datetime]:
    """Traditional syslog has no year; infer it so the date is not in the future."""
    month = _MONTHS.get(mon)
    if month is None:
        return None
    hh, mm, ss = (int(x) for x in time_s.split(":"))
    year = ref_now.astimezone(tz).year
    try:
        dt = datetime(year, month, int(day), hh, mm, ss, tzinfo=tz)
    except ValueError:
        return None
    # A parsed time later than now means the log is from the previous year.
    if dt.astimezone(timezone.utc) > ref_now + timedelta(hours=26):
        dt = dt.replace(year=year - 1)
    return dt.astimezone(timezone.utc)


class SyslogAuthCollector(Collector):
    source_id = "auth"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        locs: List[Tuple[str, "object"]] = []
        for rel in _AUTH_PATHS:
            p = env.path(rel)
            if p.exists():
                locs.append((rel, p))

        if not locs:
            cov = SourceCoverage(
                source_id=self.source_id, status=SourceStatus.ABSENT,
                detail="no auth.log or secure found under data root",
                instrumentation=[InstrumentationCheck(
                    "auth syslog present", False,
                    "no /var/log/auth.log or /var/log/secure; sudo/ssh/su/account "
                    "events from syslog are unavailable")],
            )
            return CollectResult(events=[], coverage=cov)

        events: List[Event] = []
        count = 0
        hmin = hmax = None

        for rel, p in locs:
            try:
                fh = p.open("r", encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:  # stream line-by-line
                for lineno, line in enumerate(fh, start=1):
                    ts, rest = self._parse_prefix(line, env)
                    if ts is None:
                        continue
                    count += 1
                    if hmin is None or ts < hmin:
                        hmin = ts
                    if hmax is None or ts > hmax:
                        hmax = ts
                    for ev in self._interpret(rest, ts, rel, lineno, line.strip()):
                        if window.contains(ev.ts):
                            events.append(ev)

        events.sort(key=lambda e: e.ts)
        status = SourceStatus.AVAILABLE if count else SourceStatus.EMPTY
        if hmin is not None and hmin > window.end:
            status = SourceStatus.OUT_OF_HORIZON

        cov = SourceCoverage(
            source_id=self.source_id, status=status,
            detail=f"{count} auth syslog lines parsed",
            horizon_start=hmin, horizon_end=hmax, record_count=count,
            records_scanned=count,
            locations=[str(p) for _r, p in locs],
            retention_bounded=any(".log.1" in str(p) or "secure." in str(p)
                                  for _r, p in locs),
            instrumentation=[
                InstrumentationCheck("auth syslog present", True),
                InstrumentationCheck(
                    "full command auditing", False,
                    "auth syslog records sudo-invoked commands only; ordinary "
                    "(non-sudo) command execution needs an auditd execve rule"),
            ],
        )
        return CollectResult(events=events, coverage=cov)

    def _parse_prefix(self, line: str, env: Env):
        m = _ISO_RE.match(line)
        if m:
            try:
                ts = parse_instant(m.group("ts"), env.local_tz)
            except ValueError:
                return None, None
            return ts, m.group("rest")
        m = _TRAD_RE.match(line)
        if m:
            ts = _parse_traditional_ts(m.group("mon"), m.group("day"),
                                       m.group("time"), env.now, env.local_tz)
            if ts is None:
                return None, None
            return ts, m.group("rest")
        return None, None

    def _interpret(self, rest: str, ts, rel, lineno, raw) -> List[Event]:
        cit = [Citation(self.source_id, f"{rel}:{lineno}", raw)]

        m = _SUDO_CMD_RE.match(rest)
        if m:
            body = m.group("body")
            # A denied sudo (not in sudoers / wrong password / command not allowed)
            # also carries a COMMAND= field, so the failure check must come first --
            # a denied attempt must never be reported as a successful escalation.
            if any(h in body for h in _SUDO_FAIL_HINTS):
                return [Event(ts=ts, type=EventType.PRIVILEGE_ESCALATION,
                              source_id=self.source_id,
                              summary=f"sudo attempt by {m.group('user')} FAILED",
                              actor_name=m.group("user"),
                              attrs={"tool": "sudo", "res": "failed"}, citations=cit)]
            if "COMMAND=" in body:
                return self._sudo_command(m.group("user"), body, ts, cit)

        m = _SSH_ACCEPT_RE.search(rest)
        if m:
            return [Event(ts=ts, type=EventType.SSH_AUTH, source_id=self.source_id,
                          summary=f"sshd accepted {m.group('method')} for "
                                  f"{m.group('user')} from {m.group('ip')}",
                          actor_name=m.group("user"),
                          attrs={"result": "accepted", "method": m.group("method"),
                                 "ip": m.group("ip"), "port": int(m.group("port"))},
                          citations=cit)]
        m = _SSH_FAIL_RE.search(rest)
        if m:
            return [Event(ts=ts, type=EventType.SSH_AUTH, source_id=self.source_id,
                          summary=f"sshd failed {m.group('method')} for "
                                  f"{m.group('user')} from {m.group('ip')}",
                          actor_name=m.group("user"),
                          attrs={"result": "failed", "method": m.group("method"),
                                 "ip": m.group("ip"), "port": int(m.group("port"))},
                          citations=cit)]

        m = _SU_PAM_RE.search(rest) or _SU_LEGACY_RE.search(rest)
        if m:
            gd = m.groupdict()
            by = gd.get("by") or gd.get("by2")
            target = gd.get("target") or gd.get("target2") or "root"
            if by:
                return [Event(ts=ts, type=EventType.PRIVILEGE_ESCALATION,
                              source_id=self.source_id,
                              summary=f"su to {target} by {by}",
                              actor_name=by,
                              attrs={"tool": "su", "res": "success",
                                     "target_user": target}, citations=cit)]

        m = _USERADD_RE.search(rest)
        if m:
            return [self._account(ts, cit, "add_user", m.group("name").strip(),
                                  int(m.group("uid")))]
        m = _USERDEL_RE.search(rest)
        if m:
            return [self._account(ts, cit, "del_user",
                                  (m.group("name") or m.group("name2")).strip(), None)]
        m = _PASSWD_RE.search(rest)
        if m:
            return [self._account(ts, cit, "passwd_change", m.group("name"), None)]
        m = _GROUPADD_RE.search(rest)
        if m:
            return [self._group(ts, cit, "add_group", m.group("name").strip(),
                                int(m.group("gid")))]
        m = _GROUPDEL_RE.search(rest)
        if m:
            return [self._group(ts, cit, "del_group",
                                (m.group("name") or m.group("name2")).strip(), None)]
        return []

    def _sudo_command(self, user, body, ts, cit) -> List[Event]:
        target = None
        cmd = None
        mt = re.search(r"USER=(?P<u>\S+)", body)
        if mt:
            target = mt.group("u")
        mc = re.search(r"COMMAND=(?P<c>.*)$", body)
        if mc:
            cmd = mc.group("c").strip()
        as_root = (target == "root") or target is None
        exe = cmd.split()[0] if cmd else None
        # The privilege event (Q5) and the command it ran as root (Q6/Q7).
        priv = Event(
            ts=ts, type=EventType.PRIVILEGE_ESCALATION, source_id=self.source_id,
            summary=f"{user} ran `{cmd}` via sudo"
                    + (f" as {target}" if target else ""),
            actor_name=user,
            attrs={"tool": "sudo", "res": "success", "cmd": cmd,
                   "target_user": target}, citations=cit)
        exec_ev = Event(
            ts=ts, type=EventType.EXEC, source_id=self.source_id,
            summary=f"exec {cmd}" + (" (as root)" if as_root else ""),
            actor_name=user,
            uid=0 if as_root else None,
            attrs={"cmdline": cmd, "exe": exe, "argv": cmd.split() if cmd else [],
                   "as_root": as_root, "euid": 0 if as_root else None,
                   "via_sudo": True, "syscall": "execve"},
            citations=cit)
        return [priv, exec_ev]

    def _account(self, ts, cit, action, acct, uid) -> Event:
        return Event(ts=ts, type=EventType.ACCOUNT_CHANGE, source_id=self.source_id,
                     summary=f"{action.replace('_', ' ')} acct={acct}"
                             + (f" id={uid}" if uid is not None else ""),
                     attrs={"action": action, "acct": acct, "id": uid,
                            "res": "success"}, citations=cit)

    def _group(self, ts, cit, action, grp, gid) -> Event:
        return Event(ts=ts, type=EventType.GROUP_CHANGE, source_id=self.source_id,
                     summary=f"{action.replace('_', ' ')} grp={grp}"
                             + (f" id={gid}" if gid is not None else ""),
                     attrs={"action": action, "grp": grp, "id": gid,
                            "res": "success"}, citations=cit)
