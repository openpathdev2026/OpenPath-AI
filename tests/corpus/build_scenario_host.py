"""Materialize a synthetic host that enacts the ten canonical investigation
scenarios, so the Host Truth Corpus has a runnable worked example covering them.

The activity here is the *reality*; `scenarios_ground_truth.json` is what an
investigator would independently write down having observed that reality. Keeping
the two in one directory (but authored to be read independently) lets anyone run:

    python3 tests/corpus/build_scenario_host.py /tmp/scenhost
    python3 scripts/truth_corpus.py --data-root /tmp/scenhost \
        --truth tests/corpus/scenarios_ground_truth.json --now <the printed now>

and see OpenPath's answers checked against the declared truth.

Scenarios enacted (auid 1001 = alice throughout, so attribution survives sudo/su):
  SSH login · sudo escalation · sudo su · user creation · group modification ·
  package install · cron persistence · file modification · network activity · logout
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.conformance.fixtures import HostBuilder


def build(root: Path, now: datetime) -> Path:
    """Enact the ten scenarios under ``root``, anchored to ``now``. Returns root."""
    def ago(**kw):
        return now - timedelta(**kw)

    h = HostBuilder(root)
    h.passwd("root", 0).passwd("alice", 1001)
    h.enable_execve().enable_network().enable_file_syscalls().watch("/etc", "wa", "etc")
    h.boot(ago(hours=6))
    # 1. SSH login (origin + auth method) and the session it opens.
    h.ssh_accept("alice", "203.0.113.7", ago(hours=5, minutes=1))
    h.login("alice", ago(hours=5), line="pts/0", host="203.0.113.7", until=ago(hours=1))
    # 2. sudo escalation (alice runs a package manager as root via sudo).
    h.sudo(1001, 0, "/usr/bin/dnf install -y nginx", ago(hours=4, minutes=40))
    h.exec(1001, 0, ["dnf", "install", "-y", "nginx"], "/usr/bin/dnf",
           ago(hours=4, minutes=40), euid=0, comm="dnf")
    # 3. sudo su (alice becomes root via su; auid stays 1001).
    h.su(1001, 0, ago(hours=4, minutes=35))
    h.exec(1001, 0, ["id"], "/usr/bin/id", ago(hours=4, minutes=34), euid=0, comm="id")
    # 6. package install (transaction log).
    h.pkg("Installed", "nginx-1.24.0-1.fc40.x86_64", ago(hours=4, minutes=39))
    # 9. network activity (outbound connect as root, attributed to alice by auid).
    h.connect(1001, 0, "93.184.216.34", 443, ago(hours=4, minutes=30))
    # 8. file modification.
    h.file_change(1001, 0, "openat", "/etc/hosts", ago(hours=4, minutes=20),
                  euid=0, key="etc")
    # 4. user creation.
    h.add_user(1001, "bob", 1002, ago(hours=4, minutes=10))
    # 5. group modification.
    h.add_group(1001, "deploygrp", 3000, ago(hours=4, minutes=5))
    # 7. cron persistence (alice's cron.d job).
    h.cron_d("deploy", "*/10 * * * *", "alice", "/usr/local/bin/deploy.sh")
    # 10. logout is implicit: the pts/0 session above closed at ago(hours=1).
    h.write()
    return root


def build_extended(root: Path, now: datetime) -> Path:
    """A broader host covering activity categories/variants beyond the base ten:
    auth methods (failed, console, faillock), privilege variants (sudo -i, failed
    sudo), the full file-op set (create/delete/rename/chmod/chown/truncate), apt/dpkg
    packages, inbound network, overlapping + still-open sessions, and more
    persistence types (at, systemd timer, rc.local). Uses existing fixtures only —
    no new questions or collectors."""
    def ago(**kw):
        return now - timedelta(**kw)

    h = HostBuilder(root)
    h.passwd("root", 0).passwd("alice", 1001).passwd("carol", 1003)
    h.enable_execve().enable_network().enable_file_syscalls().watch("/etc", "wa", "etc")
    h.boot(ago(hours=8))
    # -- authentication variants --
    h.failed_login("alice", ago(hours=6), host="198.51.100.9")          # failed login
    h.ssh_fail("alice", "198.51.100.9", ago(hours=6))
    h.ssh_accept("alice", "203.0.113.7", ago(hours=5, minutes=1))       # key login
    h.login("alice", ago(hours=5), line="pts/0", host="203.0.113.7", until=ago(hours=2))
    h.login("carol", ago(hours=5), line="tty1", host="")               # console login
    h.faillock("carol", ago(hours=4, minutes=50))                       # lockout
    # -- overlapping + still-open sessions --
    h.login("alice", ago(hours=4), line="pts/1", host="203.0.113.7")   # still open (overlaps pts/0)
    # -- privilege variants --
    h.sudo(1001, 0, "/bin/bash -i", ago(hours=4, minutes=40))          # sudo -i (root shell)
    h.exec(1001, 0, ["bash", "-i"], "/bin/bash", ago(hours=4, minutes=40), euid=0,
           comm="bash")
    h.auth_sudo_fail("carol", ago(hours=4, minutes=30))                # failed sudo
    # -- full file-op set (as root, attributed to alice) --
    h.file_change(1001, 0, "creat", "/etc/newfile.conf", ago(hours=4, minutes=20), euid=0, key="etc")
    h.file_change(1001, 0, "unlink", "/etc/oldfile.conf", ago(hours=4, minutes=19), euid=0, key="etc")
    h.file_change(1001, 0, "rename", "/etc/a.conf", ago(hours=4, minutes=18), euid=0, key="etc")
    h.file_change(1001, 0, "chmod", "/etc/shadow", ago(hours=4, minutes=17), euid=0, key="etc")
    h.file_change(1001, 0, "chown", "/etc/passwd", ago(hours=4, minutes=16), euid=0, key="etc")
    h.file_change(1001, 0, "truncate", "/var/log/wtmp", ago(hours=4, minutes=15), euid=0, key="etc")
    # -- packages: apt/dpkg install + remove --
    h.dpkg("install", "curl", "", "7.88.1-10", ago(hours=4, minutes=10))
    h.dpkg("remove", "telnet", "0.17-44", "", ago(hours=4, minutes=9))
    # -- network: inbound bind/listen --
    h.bind(1001, 0, "0.0.0.0", 8080, ago(hours=4), comm="nginx")
    # -- persistence variants --
    h.at_job("a0000042")
    h.systemd_timer("backup.timer", "*-*-* 02:00:00", enabled=True)
    h.rc_local("/opt/agent/start.sh")
    h.write()
    return root


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: build_scenario_host.py <dest-dir>", file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc)
    root = build(Path(argv[0]), now)
    print(f"scenario host written to: {root}")
    print(f"analyze with --now {now.isoformat()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
