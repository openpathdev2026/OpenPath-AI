"""Synthetic host builder that emits *real-format* evidence logs.

The whole point of the conformance suite is to prove OpenPath answers correctly
for arbitrary and brand-new users. To do that honestly the fixtures must be the
genuine on-disk formats, parsed by exactly the production collectors -- not mock
objects. So:

    * wtmp is written as real 384-byte ``struct utmp`` records (via the collector's
      own struct definition, used in reverse);
    * auditd records are written as real ``audit.log`` text grouped by event serial,
      with hex-encoded fields where the kernel would hex-encode them;
    * dnf.rpm.log / dpkg.log / the sshd journal export use their real line formats.

``HostBuilder`` accumulates events and writes the bundle; a test then points an
:class:`~openpath.env.Env` at the bundle root.
"""

from __future__ import annotations

import binascii
import itertools
import json
import os
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from openpath.sources.wtmp import (
    _UTMP_STRUCT, BOOT_TIME, DEAD_PROCESS, LOGIN_PROCESS, USER_PROCESS,
)

# x86-64 syscall numbers used by fixtures.
SYS = {
    "execve": 59, "connect": 42, "bind": 49, "listen": 50,
    "unlink": 87, "rename": 82, "chmod": 90, "chown": 92,
    "creat": 85, "openat": 257, "truncate": 76,
    "symlink": 88, "symlinkat": 266, "link": 86, "linkat": 265, "mknod": 133,
}


def _epoch_msec(ts: datetime) -> str:
    t = ts.astimezone(timezone.utc).timestamp()
    sec = int(t)
    msec = int(round((t - sec) * 1000))
    if msec == 1000:
        sec += 1
        msec = 0
    return f"{sec}.{msec:03d}"


def _hex(s: str) -> str:
    return binascii.hexlify(s.encode()).decode()


def _saddr_inet(ip: str, port: int) -> str:
    b = struct.pack("<H", socket.AF_INET) + struct.pack(">H", port)
    b += socket.inet_aton(ip) + b"\x00" * 8
    return binascii.hexlify(b).decode()


def _saddr_unix(path: str) -> str:
    b = struct.pack("<H", socket.AF_UNIX) + path.encode() + b"\x00"
    return binascii.hexlify(b).decode()


def _saddr_inet6(ip: str, port: int) -> str:
    b = struct.pack("<H", socket.AF_INET6) + struct.pack(">H", port)
    b += b"\x00" * 4 + socket.inet_pton(socket.AF_INET6, ip) + b"\x00" * 4
    return binascii.hexlify(b).decode()


class HostBuilder:
    def __init__(self, root: Path, tz=timezone.utc):
        self.root = Path(root)
        self.tz = tz
        self._wtmp: List[bytes] = []
        self._wtmp_prev: List[bytes] = []
        self._btmp: List[bytes] = []
        self._audit: List[str] = []
        self._audit_prev: List[str] = []
        self._dnf: List[str] = []
        self._dpkg: List[str] = []
        self._journal: List[dict] = []
        self._journal_gen: List[dict] = []
        self._passwd: List[tuple] = []
        self._group: List[tuple] = []
        self._rules: List[str] = []
        self._authlog: List[str] = []
        self._persist: dict = {}            # rel-path -> list[str] lines
        self._persist_symlinks: List[tuple] = []  # (link rel, target)
        self._serial = itertools.count(1000)
        self.auditd_present = True

    def no_auditd(self):
        """Simulate a host where auditd is not installed/running at all."""
        self.auditd_present = False
        return self

    # -- passwd / group ----------------------------------------------------- #

    def passwd(self, name: str, uid: int, gid: int = None):
        self._passwd.append((name, uid, gid if gid is not None else uid))
        return self

    def group(self, name: str, gid: int, members: List[str] = ()):
        self._group.append((name, gid, list(members)))
        return self

    # -- audit rules -------------------------------------------------------- #

    def enable_execve(self):
        self._rules.append("-a always,exit -F arch=b64 -S execve -S execveat -k exec")
        return self

    def enable_network(self):
        self._rules.append("-a always,exit -F arch=b64 -S connect -S bind -k net")
        return self

    def watch(self, path: str, perms: str = "wa", key: str = "watch"):
        self._rules.append(f"-w {path} -p {perms} -k {key}")
        return self

    def enable_file_syscalls(self):
        self._rules.append(
            "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,"
            "chmod,chown,creat,truncate -k file-change")
        return self

    # -- wtmp --------------------------------------------------------------- #

    def _pack(self, ut_type, pid, line, user, host, ts):
        tv_sec = int(ts.astimezone(timezone.utc).timestamp()) if ts else 0
        return _UTMP_STRUCT.pack(
            ut_type, pid, line.encode()[:31], b"id"[:4], user.encode()[:31],
            host.encode()[:255], 0, 0, 0, tv_sec, 0, 0, 0, 0, 0, b"",
        )

    def login(self, user, at, line="pts/0", host="", pid=2000, until=None):
        self._wtmp.append(self._pack(USER_PROCESS, pid, line, user, host, at))
        if until is not None:
            self._wtmp.append(self._pack(DEAD_PROCESS, pid, line, "", "", until))
        return self

    def boot(self, at, kernel="6.0.0"):
        self._wtmp.append(self._pack(BOOT_TIME, 0, "~", "reboot", kernel, at))
        return self

    def failed_login(self, user, at, host="", line="ssh:notty", pid=0):
        """A failed login attempt, recorded in btmp (same utmp binary format)."""
        self._btmp.append(self._pack(LOGIN_PROCESS, pid, line, user, host, at))
        return self

    # -- sshd journal ------------------------------------------------------- #

    def _journal_entry(self, msg, at):
        usec = int(at.astimezone(timezone.utc).timestamp() * 1_000_000)
        self._journal.append({
            "__REALTIME_TIMESTAMP": str(usec),
            "_COMM": "sshd", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": msg,
        })

    def ssh_accept(self, user, ip, at, method="publickey", port=51000):
        self._journal_entry(
            f"Accepted {method} for {user} from {ip} port {port} ssh2", at)
        return self

    def ssh_fail(self, user, ip, at, method="password", port=51000):
        self._journal_entry(
            f"Failed {method} for {user} from {ip} port {port} ssh2", at)
        return self

    # -- auditd syscall events ---------------------------------------------- #

    def exec(self, auid, uid, argv, exe, at, cwd="/root", euid=None,
             key="exec", comm=None, arch="x86_64", success="yes", exit_code=0,
             pid=None, ppid=1000, ses=3, tty="pts0"):
        euid = uid if euid is None else euid
        comm = comm or (argv[0] if argv else "prog")
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        pid = pid if pid is not None else int(f"3{sid}")
        keyfield = f' key="{key}"' if key else ""
        archhex = "c00000b7" if arch == "aarch64" else "c000003e"
        execno = 221 if arch == "aarch64" else SYS["execve"]
        self._audit.append(
            f"type=SYSCALL msg=audit({aid}): arch={archhex} syscall={execno} "
            f"success={success} exit={exit_code} ppid={ppid} pid={pid} auid={auid} uid={uid} gid=0 "
            f"euid={euid} suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty={tty} ses={ses} "
            f'comm="{comm}" exe="{exe}"{keyfield}')
        argfields = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
        self._audit.append(
            f"type=EXECVE msg=audit({aid}): argc={len(argv)} {argfields}")
        self._audit.append(f'type=CWD msg=audit({aid}): cwd="{cwd}"')
        return self

    def sudo(self, auid, uid, cmd, at, cwd="/home", terminal="pts/0",
             res="success", runas=None):
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        # A runas target (sudo -u <user>) is recorded as acct= in the USER_CMD msg.
        acct = f" acct=\"{runas}\"" if runas else ""
        self._audit.append(
            f"type=USER_CMD msg=audit({aid}): pid=3{sid} uid={uid} auid={auid} "
            f"ses=3 msg='cwd=\"{cwd}\" cmd={_hex(cmd)}{acct} terminal={terminal} "
            f"res={res}' exe=\"/usr/bin/sudo\"")
        return self

    def su(self, auid, uid, at, res="success"):
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        self._audit.append(
            f"type=USER_START msg=audit({aid}): pid=3{sid} uid={uid} auid={auid} "
            f"ses=3 msg='op=PAM:session_open exe=\"/usr/bin/su\" hostname=? "
            f"addr=? terminal=pts/0 res={res}'")
        return self

    def connect(self, auid, uid, ip, port, at, comm="curl",
                exe="/usr/bin/curl", euid=None, v6=False):
        euid = uid if euid is None else euid
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        saddr = _saddr_inet6(ip, port) if v6 else _saddr_inet(ip, port)
        self._audit.append(
            f"type=SYSCALL msg=audit({aid}): arch=c000003e syscall={SYS['connect']} "
            f"success=yes exit=0 pid=3{sid} auid={auid} uid={uid} euid={euid} "
            f'comm="{comm}" exe="{exe}"')
        self._audit.append(f"type=SOCKADDR msg=audit({aid}): saddr={saddr}")
        return self

    def connect_unix(self, auid, uid, path, at, comm="docker", exe="/usr/bin/docker",
                     euid=None):
        """A connect(2) to an AF_UNIX socket (e.g. /var/run/docker.sock)."""
        euid = uid if euid is None else euid
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        self._audit.append(
            f"type=SYSCALL msg=audit({aid}): arch=c000003e syscall={SYS['connect']} "
            f"success=yes exit=0 pid=3{sid} auid={auid} uid={uid} euid={euid} "
            f'comm="{comm}" exe="{exe}"')
        self._audit.append(f"type=SOCKADDR msg=audit({aid}): saddr={_saddr_unix(path)}")
        return self

    def file_read(self, auid, uid, path, at, euid=None, key="shadow-read",
                  comm="cat", exe="/usr/bin/cat"):
        """A read of a watched path under a -p r audit rule (FS-12)."""
        euid = uid if euid is None else euid
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        self._audit.append(
            f"type=SYSCALL msg=audit({aid}): arch=c000003e syscall={SYS['openat']} "
            f"success=yes exit=3 ppid=1000 pid=3{sid} auid={auid} uid={uid} euid={euid} "
            f'comm="{comm}" exe="{exe}" key="{key}"')
        self._audit.append(
            f'type=PATH msg=audit({aid}): item=0 name="{path}" nametype=NORMAL')
        return self

    def bind(self, auid, uid, ip, port, at, comm="nginx", exe="/usr/sbin/nginx"):
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        self._audit.append(
            f"type=SYSCALL msg=audit({aid}): arch=c000003e syscall={SYS['bind']} "
            f"success=yes exit=0 pid=3{sid} auid={auid} uid={uid} euid={uid} "
            f'comm="{comm}" exe="{exe}"')
        self._audit.append(
            f"type=SOCKADDR msg=audit({aid}): saddr={_saddr_inet(ip, port)}")
        return self

    def file_change(self, auid, uid, op, path, at, euid=None,
                    nametype=None, key=None):
        euid = uid if euid is None else euid
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        if nametype is None:
            nametype = {"unlink": "DELETE", "creat": "CREATE"}.get(op, "NORMAL")
        keyfield = f' key="{key}"' if key else ""
        self._audit.append(
            f"type=SYSCALL msg=audit({aid}): arch=c000003e syscall={SYS[op]} "
            f"success=yes exit=0 pid=3{sid} auid={auid} uid={uid} euid={euid} "
            f'comm="prog" exe="/usr/bin/prog"{keyfield}')
        self._audit.append(
            f'type=PATH msg=audit({aid}): item=0 name="{path}" nametype={nametype}')
        return self

    def add_user(self, auid, acct, uid, at, res="success"):
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        self._audit.append(
            f"type=ADD_USER msg=audit({aid}): pid=3{sid} uid=0 auid={auid} ses=3 "
            f"msg='op=add-user acct=\"{acct}\" id={uid} exe=\"/usr/sbin/useradd\" "
            f"hostname=h addr=? terminal=pts/0 res={res}'")
        return self

    def del_user(self, auid, acct, uid, at, res="success"):
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        self._audit.append(
            f"type=DEL_USER msg=audit({aid}): pid=3{sid} uid=0 auid={auid} ses=3 "
            f"msg='op=delete-user acct=\"{acct}\" id={uid} exe=\"/usr/sbin/userdel\" "
            f"hostname=h addr=? terminal=pts/0 res={res}'")
        return self

    def chauthtok(self, auid, acct, uid, at, res="success"):
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        self._audit.append(
            f"type=USER_CHAUTHTOK msg=audit({aid}): pid=3{sid} uid=0 auid={auid} "
            f"ses=3 msg='op=PAM:chauthtok acct=\"{acct}\" id={uid} "
            f"exe=\"/usr/bin/passwd\" hostname=h addr=? terminal=pts/0 res={res}'")
        return self

    def usermod(self, auid, acct, uid, at, res="success"):
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        self._audit.append(
            f"type=USER_MGMT msg=audit({aid}): pid=3{sid} uid=0 auid={auid} ses=3 "
            f"msg='op=modify-account acct=\"{acct}\" id={uid} exe=\"/usr/sbin/usermod\" "
            f"hostname=h addr=? terminal=pts/0 res={res}'")
        return self

    def acct_lock(self, auid, acct, uid, at, lock=True, res="success"):
        rtype = "ACCT_LOCK" if lock else "ACCT_UNLOCK"
        op = "locked-account" if lock else "unlocked-account"
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        self._audit.append(
            f"type={rtype} msg=audit({aid}): pid=3{sid} uid=0 auid={auid} ses=3 "
            f"msg='op={op} acct=\"{acct}\" id={uid} exe=\"/usr/sbin/usermod\" "
            f"hostname=h addr=? terminal=pts/0 res={res}'")
        return self

    def add_group(self, auid, grp, gid, at, res="success"):
        sid = next(self._serial)
        aid = f"{_epoch_msec(at)}:{sid}"
        self._audit.append(
            f"type=ADD_GROUP msg=audit({aid}): pid=3{sid} uid=0 auid={auid} ses=3 "
            f"msg='op=add-group grp=\"{grp}\" id={gid} exe=\"/usr/sbin/groupadd\" "
            f"hostname=h addr=? terminal=pts/0 res={res}'")
        return self

    # -- syslog auth.log (Debian/Ubuntu) ------------------------------------ #

    def _syslog(self, at, proc, msg):
        local = at.astimezone(self.tz)
        # Traditional syslog: "Mon _D HH:MM:SS" (day space-padded to width 2).
        stamp = local.strftime("%b ") + f"{local.day:2d}" + local.strftime(" %H:%M:%S")
        self._authlog.append(f"{stamp} host {proc}: {msg}")

    def auth_sudo(self, user, cmd, at, target="root", tty="pts/0", pwd=None):
        pwd = pwd or f"/home/{user}"
        self._syslog(at, "sudo",
                     f"  {user} : TTY={tty} ; PWD={pwd} ; USER={target} ; "
                     f"COMMAND={cmd}")
        return self

    def auth_sudo_fail(self, user, at, tty="pts/0"):
        self._syslog(at, "sudo",
                     f"  {user} : user NOT in sudoers ; TTY={tty} ; "
                     f"PWD=/home/{user} ; USER=root ; COMMAND=/bin/sh")
        return self

    def auth_ssh_accept(self, user, ip, at, method="publickey", port=51000):
        self._syslog(at, "sshd[1200]",
                     f"Accepted {method} for {user} from {ip} port {port} ssh2")
        return self

    def auth_ssh_fail(self, user, ip, at, method="password", port=51000):
        self._syslog(at, "sshd[1200]",
                     f"Failed {method} for {user} from {ip} port {port} ssh2")
        return self

    def auth_su(self, by, at, target="root", by_uid=1001):
        self._syslog(at, "su[1300]",
                     f"pam_unix(su-l:session): session opened for user "
                     f"{target}(uid=0) by {by}(uid={by_uid})")
        return self

    def auth_useradd(self, name, uid, at, gid=None):
        gid = uid if gid is None else gid
        self._syslog(at, "useradd[1400]",
                     f"new user: name={name}, UID={uid}, GID={gid}, "
                     f"home=/home/{name}, shell=/bin/bash")
        return self

    def auth_userdel(self, name, at):
        self._syslog(at, "userdel[1401]", f"delete user '{name}'")
        return self

    def auth_groupadd(self, name, gid, at):
        self._syslog(at, "groupadd[1402]", f"new group: name={name}, GID={gid}")
        return self

    # -- packages ----------------------------------------------------------- #

    def pkg(self, verb, nevra, at):
        self._dnf.append(f"{at.astimezone(self.tz).strftime('%Y-%m-%dT%H:%M:%S%z')} "
                         f"INFO {verb}: {nevra}")
        return self

    def dpkg(self, action, pkg, vfrom, vto, at, arch="amd64"):
        # Real dpkg.log uses "<none>" for an absent version (fresh install has no
        # from-version; a remove has no to-version) and a pkg:arch qualifier -- never
        # an empty field. Emit that faithfully so the line matches what dpkg actually
        # writes (and what the collector parses).
        vfrom = vfrom or "<none>"
        vto = vto or "<none>"
        name = pkg if ":" in pkg else f"{pkg}:{arch}"
        self._dpkg.append(
            f"{at.astimezone(self.tz).strftime('%Y-%m-%d %H:%M:%S')} "
            f"{action} {name} {vfrom} {vto}")
        return self

    # -- persistence state (cron / systemd / linger / legacy startup) ------- #
    # These write the genuine on-disk state files the PersistenceCollector reads.
    def _persist_add(self, rel, line):
        self._persist.setdefault(rel, []).append(line)
        return self

    def cron_system(self, sched, user, cmd):
        """A line in /etc/crontab (system crontab: has a USER field)."""
        return self._persist_add("etc/crontab", f"{sched} {user} {cmd}")

    def cron_d(self, name, sched, user, cmd):
        """A drop-in under /etc/cron.d (also has a USER field)."""
        return self._persist_add(f"etc/cron.d/{name}", f"{sched} {user} {cmd}")

    def cron_user(self, user, sched, cmd):
        """A per-user crontab under /var/spool/cron (file name = user, no USER field)."""
        return self._persist_add(f"var/spool/cron/{user}", f"{sched} {cmd}")

    def cron_runparts(self, period, name, body="#!/bin/sh"):
        return self._persist_add(f"etc/cron.{period}/{name}", body)

    def at_job(self, name, body="#!/bin/sh\n/tmp/x"):
        return self._persist_add(f"var/spool/at/{name}", body)

    def systemd_unit(self, name, exec_start, enabled=False,
                     wanted_by="multi-user.target"):
        self._persist_add(f"etc/systemd/system/{name}",
                          f"[Unit]\nDescription={name}\n\n[Service]\n"
                          f"ExecStart={exec_start}")
        if enabled:
            self._persist_symlinks.append(
                (f"etc/systemd/system/{wanted_by}.wants/{name}", f"../{name}"))
        return self

    def systemd_timer(self, name, on_calendar, enabled=False,
                      wanted_by="timers.target"):
        self._persist_add(f"etc/systemd/system/{name}",
                          f"[Unit]\nDescription={name}\n\n[Timer]\n"
                          f"OnCalendar={on_calendar}\nPersistent=true")
        if enabled:
            self._persist_symlinks.append(
                (f"etc/systemd/system/{wanted_by}.wants/{name}", f"../{name}"))
        return self

    def systemd_user_unit(self, user, name, exec_start=None):
        exec_start = exec_start or f"/home/{user}/.local/bin/agent"
        return self._persist_add(
            f"home/{user}/.config/systemd/user/{name}",
            f"[Unit]\nDescription={name}\n\n[Service]\nExecStart={exec_start}")

    def linger(self, user):
        """loginctl enable-linger writes an (empty) marker file named for the user."""
        self._persist.setdefault(f"var/lib/systemd/linger/{user}", [])
        return self

    def rc_local(self, *lines):
        self._persist["etc/rc.local"] = ["#!/bin/sh"] + list(lines) + ["exit 0"]
        return self

    # -- package policy / provenance (repos / versionlock / gpg / coverage) -- #
    def yum_repo(self, repo_id, baseurl, enabled=True, gpgcheck=True):
        rel = f"etc/yum.repos.d/{repo_id}.repo"
        self._persist_add(rel, f"[{repo_id}]")
        self._persist_add(rel, f"name={repo_id}")
        self._persist_add(rel, f"baseurl={baseurl}")
        self._persist_add(rel, f"enabled={1 if enabled else 0}")
        self._persist_add(rel, f"gpgcheck={1 if gpgcheck else 0}")
        return self

    def dnf_conf(self, gpgcheck=True):
        self._persist_add("etc/dnf/dnf.conf", "[main]")
        self._persist_add("etc/dnf/dnf.conf", f"gpgcheck={1 if gpgcheck else 0}")
        return self

    def versionlock(self, pkg):
        return self._persist_add("etc/dnf/plugins/versionlock.list", pkg)

    def apt_source(self, line):
        return self._persist_add("etc/apt/sources.list", line)

    def pkg_manager_log(self, rel):
        """Touch a package-manager log OpenPath does not parse (PK-14 coverage)."""
        self._persist.setdefault(rel, ["(present)"])
        return self

    def bash_history(self, user, *cmds):
        rel = f"home/{user}/.bash_history"
        for c in cmds:
            self._persist_add(rel, c)
        return self

    def zsh_history(self, user, *entries):
        """entries are (epoch, cmd) for timestamped, or plain cmd strings."""
        rel = f"home/{user}/.zsh_history"
        for e in entries:
            if isinstance(e, tuple):
                self._persist_add(rel, f": {int(e[0])}:0;{e[1]}")
            else:
                self._persist_add(rel, e)
        return self

    def iptables_rules(self, *lines):
        """Lines of an iptables-save dump (e.g. ':INPUT ACCEPT [0:0]', '-A INPUT ...')."""
        for ln in lines:
            self._persist_add("etc/iptables/rules.v4", ln)
        return self

    def nftables(self, text):
        self._persist["etc/nftables.conf"] = text.splitlines()
        return self

    def dns_query(self, domain, client, at, qtype="A"):
        self._persist_add("var/log/openpath/dns.log",
                          f"{at.astimezone(timezone.utc).isoformat()} {qtype} "
                          f"{domain} {client}")
        return self

    def fw_drop(self, src, dst, dport, at, verdict="DROP"):
        self._persist_add("var/log/openpath/firewall.log",
                          f"{at.astimezone(timezone.utc).isoformat()} kernel: "
                          f"IN=eth0 OUT= SRC={src} DST={dst} PROTO=TCP DPT={dport} "
                          f"{verdict}")
        return self

    def proxy_access(self, client, url, at, verb="GET"):
        self._persist_add("var/log/openpath/proxy.log",
                          f"{at.astimezone(timezone.utc).isoformat()} {client} "
                          f"{verb} {url} 200 1234")
        return self

    def socket_lifetime(self, peer, port, open_at, close_at, held_s, proto="tcp"):
        import json as _json
        self._persist_add("var/log/openpath/socket-lifetimes.jsonl", _json.dumps({
            "peer": peer, "port": port,
            "open": open_at.astimezone(timezone.utc).isoformat(),
            "close": close_at.astimezone(timezone.utc).isoformat(),
            "held_s": held_s, "proto": proto}))
        return self

    def file_diff(self, path, at, actor=None, added=0, removed=0,
                  before=None, after=None, summary=None):
        """A content before/after diff from a file-integrity monitor (FS-13)."""
        import json as _json
        self._persist_add("var/log/openpath/file-diffs.jsonl", _json.dumps({
            "path": path, "ts": at.astimezone(timezone.utc).isoformat(),
            "actor": actor, "lines_added": added, "lines_removed": removed,
            "before": before, "after": after, "summary": summary}))
        return self

    def ip_reputation(self, ip, reputation, country=None, asn=None):
        """An IP reputation / geo feed entry (IA-10)."""
        import json as _json
        self._persist_add("var/log/openpath/ip-reputation.jsonl", _json.dumps({
            "ip": ip, "reputation": reputation, "country": country, "asn": asn}))
        return self

    def conntrack(self, proto, osrc, odst, sport, dport, state="ESTABLISHED",
                  nbytes=None):
        """A tracked flow line (proc/net/nf_conntrack format). nbytes -> accounting."""
        b = (f" bytes={nbytes}" if nbytes is not None else "")
        rb = (f" bytes={nbytes}" if nbytes is not None else "")
        line = (f"ipv4     2 {proto}      6 431999 {state} "
                f"src={osrc} dst={odst} sport={sport} dport={dport}{b} "
                f"src={odst} dst={osrc} sport={dport} dport={sport}{rb} "
                f"[ASSURED] mark=0 use=1")
        self._persist_add("proc/net/nf_conntrack", line)
        return self

    # -- general journal (system lifecycle) ---------------------------------- #
    def journal_msg(self, msg, at, unit="", ident="systemd"):
        usec = int(at.astimezone(timezone.utc).timestamp() * 1_000_000)
        entry = {"__REALTIME_TIMESTAMP": str(usec), "MESSAGE": msg,
                 "SYSLOG_IDENTIFIER": ident}
        if unit:
            entry["_SYSTEMD_UNIT"] = unit
        self._journal_gen.append(entry)
        return self

    def svc_start(self, unit, at, desc=None):
        return self.journal_msg(f"Started {desc or unit}.", at, unit=unit)

    def svc_stop(self, unit, at, desc=None):
        return self.journal_msg(f"Stopped {desc or unit}.", at, unit=unit)

    def svc_fail(self, unit, at, desc=None):
        return self.journal_msg(f"{desc or unit}: Failed with result 'exit-code'.",
                                at, unit=unit)

    def shutdown(self, at, clean=True):
        return self.journal_msg("Reached target Shutdown.", at,
                                ident="systemd") if clean else self

    def kernel_panic(self, at, detail="Fatal exception"):
        return self.journal_msg(f"Kernel panic - not syncing: {detail}", at,
                                ident="kernel")

    def oom_kill(self, at, proc="python"):
        return self.journal_msg(f"Out of memory: Killed process 4242 ({proc})", at,
                                ident="kernel")

    def clock_change(self, at):
        return self.journal_msg("Time has been changed", at, ident="systemd")

    def boot_target(self, at, mode="Rescue Mode"):
        return self.journal_msg(f"Reached target {mode}.", at, ident="systemd")

    def pam_auth(self, user, service, at):
        """A non-SSH PAM authentication (IA-11), e.g. service='cockpit'/'login'/'gdm'."""
        return self.journal_msg(
            f"pam_unix({service}:session): session opened for user {user} by (uid=0)",
            at, ident=service)

    def faillock(self, user, at):
        """An account lockout / faillock trip (PV-12)."""
        return self.journal_msg(
            f"pam_faillock(login:auth): Consecutive login failures for user {user} "
            f"account temporarily locked", at, ident="login")

    # -- authorization state (sudoers / shadow / ssh keys / ssh policy) ------ #
    # (reuses the generic state-file accumulator flushed in write())
    def sudoers(self, line):
        return self._persist_add("etc/sudoers", line)

    def sudoers_d(self, name, line):
        return self._persist_add(f"etc/sudoers.d/{name}", line)

    def shadow(self, acct, pw):
        """A line in /etc/shadow. pw '!'/'*'/'' encode locked/passwordless."""
        return self._persist_add("etc/shadow", f"{acct}:{pw}:19000:0:99999:7:::")

    def authorized_key(self, user, keyline):
        rel = f"home/{user}/.ssh/authorized_keys"
        return self._persist_add(rel, keyline)

    def sshd_config(self, **directives):
        for k, v in directives.items():
            self._persist_add("etc/ssh/sshd_config", f"{k} {v}")
        return self

    def captured_at(self, at):
        """Stamp the bundle capture-time marker (as collect_bundle.sh does).

        Presence of this marker tells OpenPath the evidence is an offline snapshot
        taken at ``at``; a window reaching past it has a not-yet-observed tail.
        """
        iso = at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self._persist_add("var/log/openpath/captured-at", iso)

    def rotate_logs(self):
        """Move everything accumulated so far into rotated (.1) files.

        Used to simulate retention: records already written land in wtmp.1 /
        audit.log.1, and the presence of those rotated files marks the source as
        retention-bounded so a genuine horizon shortfall can be detected.
        """
        self._wtmp_prev += self._wtmp
        self._wtmp = []
        self._audit_prev += self._audit
        self._audit = []
        return self

    # -- materialize -------------------------------------------------------- #

    def write(self) -> Path:
        if self.auditd_present:
            (self.root / "var/log/audit").mkdir(parents=True, exist_ok=True)
            (self.root / "etc/audit/rules.d").mkdir(parents=True, exist_ok=True)
        (self.root / "var/log/openpath").mkdir(parents=True, exist_ok=True)

        if self._wtmp_prev:
            (self.root / "var/log/wtmp.1").write_bytes(b"".join(self._wtmp_prev))
        if self._wtmp:
            (self.root / "var/log/wtmp").write_bytes(b"".join(self._wtmp))
        if self._btmp:
            (self.root / "var/log").mkdir(parents=True, exist_ok=True)
            (self.root / "var/log/btmp").write_bytes(b"".join(self._btmp))
        if self.auditd_present:
            if self._audit_prev:
                (self.root / "var/log/audit/audit.log.1").write_text(
                    "\n".join(self._audit_prev) + "\n")
            if self._audit:
                (self.root / "var/log/audit/audit.log").write_text(
                    "\n".join(self._audit) + "\n")
            # Write a rules file (possibly empty). An empty file still means
            # "auditd running, no syscall rules loaded" -- distinct from absent.
            (self.root / "etc/audit/audit.rules").write_text(
                "\n".join(self._rules) + ("\n" if self._rules else ""))
        if self._dnf:
            (self.root / "var/log/dnf.rpm.log").write_text("\n".join(self._dnf) + "\n")
        if self._dpkg:
            (self.root / "var/log/dpkg.log").write_text("\n".join(self._dpkg) + "\n")
        if self._authlog:
            (self.root / "var/log").mkdir(parents=True, exist_ok=True)
            (self.root / "var/log/auth.log").write_text(
                "\n".join(self._authlog) + "\n")
        if self._journal:
            (self.root / "var/log/openpath/journal-sshd.jsonl").write_text(
                "\n".join(json.dumps(e) for e in self._journal) + "\n")
        if self._journal_gen:
            (self.root / "var/log/openpath").mkdir(parents=True, exist_ok=True)
            (self.root / "var/log/openpath/journal.jsonl").write_text(
                "\n".join(json.dumps(e) for e in self._journal_gen) + "\n")
        if self._passwd:
            (self.root / "etc").mkdir(parents=True, exist_ok=True)
            (self.root / "etc/passwd").write_text(
                "\n".join(f"{n}:x:{u}:{g}::/home/{n}:/bin/bash"
                          for n, u, g in self._passwd) + "\n")
        if self._group:
            (self.root / "etc/group").write_text(
                "\n".join(f"{n}:x:{g}:{','.join(m)}"
                          for n, g, m in self._group) + "\n")
        for rel, lines in self._persist.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(("\n".join(lines) + "\n") if lines else "")
        for linkrel, target in self._persist_symlinks:
            p = self.root / linkrel
            p.parent.mkdir(parents=True, exist_ok=True)
            if not p.exists():
                os.symlink(target, p)
        return self.root
