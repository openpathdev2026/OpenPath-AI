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
