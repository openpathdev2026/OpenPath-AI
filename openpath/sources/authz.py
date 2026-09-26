"""Authorization collector: current-state inventory of who is privileged and how.

Authorization questions ("who is in a privileged group", "what can {user} do via
sudo", "which accounts are locked/passwordless", "did {user} add an authorized_key",
"is SSH root login permitted") are about the host's *current authorization state*,
not a timestamped act. This collector reads that state from the filesystem under
``data_root`` and emits :class:`Event` objects of type ``AUTHZ``, each cited to the
file (and line) it came from.

Sources read:
  * ``etc/group`` + ``etc/passwd`` -- membership of privileged groups (sudo, wheel,
    docker, adm, lxd, root, and anything with gid 0), by explicit member list and by
    a user's primary gid.
  * ``etc/sudoers`` + ``etc/sudoers.d/*`` -- user and group sudo grants (who may run
    what, as whom).
  * ``etc/shadow`` -- accounts that are locked (``!``/``*`` password), passwordless
    (empty password field), or password-not-required.
  * ``home/*/.ssh/authorized_keys`` (+ root) -- key-based access grants, per account.
  * ``etc/ssh/sshd_config`` -- host SSH auth policy (root login, password auth).

Each artifact is attributed to the account a rule *names* (a group member, a sudo
spec's user, the shadow account, the home-dir owner) -- never guessed. Host-wide
policy (sshd directives) is deliberately unattributed. State is stamped at the
analysis anchor (``env.now``) so it reads as "present now" and is inventoried
regardless of the requested activity window.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import InstrumentationCheck, SourceCoverage, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

# Groups whose membership confers elevated privilege. gid 0 (root) is always in.
_PRIV_GROUPS = {"sudo", "wheel", "root", "docker", "adm", "lxd", "admin", "sudoers"}

_SUDOERS_FILES = ["etc/sudoers"]
_SUDOERS_D = "etc/sudoers.d"
_SSHD_CONFIG = "etc/ssh/sshd_config"

# A sudoers user/group spec: "<who> <host>=<...>" (Defaults/aliases handled apart).
_SUDO_SPEC = re.compile(r"^(%?[\w.@-]+)\s+(\S+)\s*=\s*(.+)$")
_SSHD_ROOT = re.compile(r"^\s*PermitRootLogin\s+(\S+)", re.I)
_SSHD_PW = re.compile(r"^\s*PasswordAuthentication\s+(\S+)", re.I)


class AuthzCollector(Collector):
    source_id = "authz"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        ts = env.now
        events: List[Event] = []
        locations: List[str] = []
        unparseable = 0

        def mk(kind, artifact, summary, rel, raw, *, user=None, extra=None):
            attrs = {"kind": kind, "artifact": artifact}
            if extra:
                attrs.update(extra)
            events.append(Event(
                ts=ts, type=EventType.AUTHZ, source_id=self.source_id,
                summary=summary, actor_name=user, attrs=attrs,
                citations=[Citation(self.source_id, rel, raw)]))

        passwd = self._passwd(env)               # name -> (uid, gid)
        seen_sub = set()                          # which authz sub-sources present
        if env.path("etc/passwd").exists():
            locations.append(str(env.path("etc/passwd")))

        # -- privileged group membership -------------------------------------- #
        groups = self._groups(env)
        if (env.path("etc/group")).exists():
            locations.append(str(env.path("etc/group")))
            seen_sub.add("group")
        priv_gids = {gid for name, (gid, _m) in groups.items()
                     if name in _PRIV_GROUPS or gid == 0}
        for gname, (gid, members) in groups.items():
            if gname not in _PRIV_GROUPS and gid != 0:
                continue
            seen = set()
            # explicit members
            for m in members:
                if m and m not in seen:
                    seen.add(m)
                    mk("priv_group", gname, f"{m} is a member of privileged group "
                       f"'{gname}' (gid {gid})", "etc/group", f"{gname}:x:{gid}:{m}",
                       user=m, extra={"group": gname, "gid": gid, "via": "member-list"})
            # primary-gid members
            for uname, (uid, ugid) in passwd.items():
                if ugid == gid and uname not in seen:
                    seen.add(uname)
                    mk("priv_group", gname, f"{uname} has privileged group '{gname}' "
                       f"as primary group (gid {gid})", "etc/passwd",
                       f"{uname}:x:{uid}:{gid}", user=uname,
                       extra={"group": gname, "gid": gid, "via": "primary-gid"})

        # -- sudoers policy --------------------------------------------------- #
        for rel in _SUDOERS_FILES + [f"{_SUDOERS_D}/*"]:
            for p, r in self._glob(env, rel):
                if p.is_dir():
                    continue
                locations.append(str(p))
                seen_sub.add("sudoers")
                for lineno, line in self._lines(p):
                    s = line.strip()
                    if not s or s.startswith("#") or s.startswith("Defaults"):
                        continue
                    if s.startswith(("User_Alias", "Cmnd_Alias", "Host_Alias",
                                     "Runas_Alias", "@include", "#include")):
                        continue
                    m = _SUDO_SPEC.match(s)
                    if not m:
                        unparseable += 1
                        continue
                    who, hosts, rest = m.group(1), m.group(2), m.group(3)
                    if who.startswith("%"):
                        gname = who[1:]
                        # expand a group spec to its members (attributed each)
                        members = self._group_members(groups, passwd, gname)
                        for mem in members:
                            mk("sudoers", who, f"{mem} may sudo via group {who}: "
                               f"{hosts}={rest}", r, s, user=mem,
                               extra={"who": who, "hosts": hosts, "runas_cmd": rest,
                                      "via": "group"})
                        if not members:
                            mk("sudoers", who, f"group {who} may sudo: {hosts}={rest}",
                               r, s, extra={"who": who, "hosts": hosts,
                                            "runas_cmd": rest, "via": "group-empty"})
                    else:
                        mk("sudoers", who, f"{who} may sudo: {hosts}={rest}", r, s,
                           user=(who if who not in ("ALL",) else None),
                           extra={"who": who, "hosts": hosts, "runas_cmd": rest,
                                  "via": "user"})

        # -- shadow account status (anomalies) -------------------------------- #
        sp = env.path("etc/shadow")
        if sp.exists():
            locations.append(str(sp))
            seen_sub.add("shadow")
            for lineno, line in self._lines(sp):
                s = line.rstrip("\n")
                if not s or s.startswith("#"):
                    continue
                parts = s.split(":")
                if len(parts) < 2:
                    unparseable += 1
                    continue
                acct, pw = parts[0], parts[1]
                status = self._shadow_status(pw)
                if status:  # only anomalies are inventoried
                    mk("shadow", acct, f"account '{acct}' is {status}",
                       f"etc/shadow:{lineno}", f"{acct}:{pw[:3]}...", user=acct,
                       extra={"status": status})

        # -- SSH authorized_keys (per account) -------------------------------- #
        for p, r in self._glob(env, "home/*/.ssh/authorized_keys"):
            if p.is_dir():
                continue
            locations.append(str(p))
            seen_sub.add("ssh_keys")
            owner = r.split("/")[1] if len(r.split("/")) > 1 else None
            self._emit_keys(mk, p, r, owner, lambda: None)
        rk = env.path("root/.ssh/authorized_keys")
        if rk.exists():
            locations.append(str(rk))
            seen_sub.add("ssh_keys")
            self._emit_keys(mk, rk, "root/.ssh/authorized_keys", "root", lambda: None)

        # -- SSH auth policy (host-wide) -------------------------------------- #
        sc = env.path(_SSHD_CONFIG)
        if sc.exists():
            locations.append(str(sc))
            seen_sub.add("ssh_policy")
            text = self._read(sc) or ""
            root_login = pw_auth = None
            for line in text.splitlines():
                mr = _SSHD_ROOT.match(line)
                mp = _SSHD_PW.match(line)
                if mr:
                    root_login = mr.group(1).lower()
                if mp:
                    pw_auth = mp.group(1).lower()
            if root_login is not None:
                mk("ssh_policy", "PermitRootLogin",
                   f"sshd PermitRootLogin = {root_login}", _SSHD_CONFIG,
                   f"PermitRootLogin {root_login}",
                   extra={"directive": "PermitRootLogin", "value": root_login})
            if pw_auth is not None:
                mk("ssh_policy", "PasswordAuthentication",
                   f"sshd PasswordAuthentication = {pw_auth}", _SSHD_CONFIG,
                   f"PasswordAuthentication {pw_auth}",
                   extra={"directive": "PasswordAuthentication", "value": pw_auth})

        events.sort(key=lambda e: (e.attrs.get("kind", ""), e.summary))
        status = SourceStatus.AVAILABLE if locations else SourceStatus.ABSENT
        detail = (f"{len(events)} authorization artifact(s) across {len(locations)} "
                  f"file(s)" if locations else
                  "no authorization state sources found")
        # Per-sub-source instrumentation: each authz question rests on a specific
        # file, so a missing one is disclosed (a "no locked accounts" answer without
        # /etc/shadow read would be a false negative -- Gaps surfaces the MISSING).
        checks = [
            ("privileged-group state (group/passwd)", bool(locations),
             "no /etc/group or /etc/passwd present"),
            ("sudoers policy present", "sudoers" in seen_sub,
             "/etc/sudoers[.d] not present: sudo grants can't be enumerated"),
            ("shadow account state present", "shadow" in seen_sub,
             "/etc/shadow not present: locked/passwordless accounts can't be enumerated"),
            ("SSH authorized_keys readable", "ssh_keys" in seen_sub,
             "no ~/.ssh/authorized_keys read: key-based grants can't be enumerated"),
            ("SSH auth policy present", "ssh_policy" in seen_sub,
             "/etc/ssh/sshd_config not present: SSH auth policy can't be checked"),
        ]
        cov = SourceCoverage(
            source_id=self.source_id, status=status, detail=detail,
            record_count=len(events), records_scanned=len(events) + unparseable,
            unparseable=unparseable,
            unparseable_detail=("unrecognized sudoers/shadow line(s)"
                                if unparseable else ""),
            locations=locations,
            instrumentation=[InstrumentationCheck(n, present, "" if present else d)
                             for (n, present, d) in checks],
        )
        return CollectResult(events=events, coverage=cov)

    # -- helpers ------------------------------------------------------------- #
    def _passwd(self, env: Env) -> Dict[str, Tuple[int, int]]:
        out: Dict[str, Tuple[int, int]] = {}
        p = env.path("etc/passwd")
        if not p.exists():
            return out
        for _n, line in self._lines(p):
            parts = line.rstrip("\n").split(":")
            if len(parts) >= 4 and parts[2].isdigit() and parts[3].isdigit():
                out[parts[0]] = (int(parts[2]), int(parts[3]))
        return out

    def _groups(self, env: Env) -> Dict[str, Tuple[int, List[str]]]:
        out: Dict[str, Tuple[int, List[str]]] = {}
        p = env.path("etc/group")
        if not p.exists():
            return out
        for _n, line in self._lines(p):
            parts = line.rstrip("\n").split(":")
            if len(parts) >= 3 and parts[2].isdigit():
                members = [m for m in parts[3].split(",") if m] if len(parts) > 3 else []
                out[parts[0]] = (int(parts[2]), members)
        return out

    def _group_members(self, groups, passwd, gname) -> List[str]:
        info = groups.get(gname)
        if info is None:
            return []
        gid, members = info
        seen = list(members)
        for uname, (_uid, ugid) in passwd.items():
            if ugid == gid and uname not in seen:
                seen.append(uname)
        return [m for m in seen if m]

    @staticmethod
    def _shadow_status(pw: str) -> Optional[str]:
        if pw == "":
            return "passwordless (empty password field)"
        if pw in ("!", "!!", "*"):
            return "locked (no usable password)"
        if pw.startswith("!"):
            return "locked (password disabled)"
        return None

    def _emit_keys(self, mk, path, rel, owner, _unused):
        for lineno, line in self._lines(path):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            # key type is the first token after any options; keep a short fingerprint
            fields = s.split()
            keytype = next((f for f in fields if f.startswith(("ssh-", "ecdsa-",
                            "sk-"))), fields[0] if fields else "key")
            comment = fields[-1] if len(fields) >= 3 else ""
            mk("ssh_key", f"{owner}:authorized_keys",
               f"{owner} has an authorized SSH key ({keytype}) {comment}".rstrip(),
               f"{rel}:{lineno}", s[:60], user=owner,
               extra={"keytype": keytype, "comment": comment})

    def _glob(self, env: Env, rel: str):
        if "*" in rel:
            root = env.data_root
            for p in sorted(root.glob(rel)):
                try:
                    yield p, str(p.relative_to(root))
                except ValueError:
                    yield p, rel
        else:
            p = env.path(rel)
            if p.exists():
                yield p, rel

    def _lines(self, p):
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    yield i, line
        except OSError:
            return

    def _read(self, p) -> Optional[str]:
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
