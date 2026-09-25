# Deploying OpenPath-AI

OpenPath is a pure-Python-stdlib CLI with no runtime dependencies. It reads logs;
it does not require a daemon and makes no outbound connections (the only exception
is a best-effort `journalctl` call to export the sshd journal on a live host).

## 1. Install

```
python3 -m pip install -e .        # provides the `openpath-ai` command
# or run without installing:
python3 -m openpath --list-families
```

Requires Python 3.9+. Verify:

```
make test        # unit + conformance baseline (must be green)
```

## 2. Instrument the host (to answer the auditd-backed questions)

Sessions/Login work from wtmp + the sshd journal with no extra setup.
Accounts/groups work whenever auditd is running. Commands, Root activity, Network,
Files, and per-user Package attribution need audit rules:

```
sudo cp contrib/openpath.rules /etc/audit/rules.d/openpath.rules
sudo augenrules --load          # or: sudo auditctl -R /etc/audit/rules.d/openpath.rules
sudo auditctl -l                # confirm loaded
```

If you skip this, OpenPath still runs — it will **disclose** the missing
instrumentation as gaps (with the exact rule to add) rather than return false
negatives. That is the intended degraded mode, not an error.

## 3. Run

Ask a question (natural language, or explicit flags):

```
openpath-ai "What did alice do during the last 24 hours?"
openpath-ai --user alice --facet timeline --window "last 7 days"
openpath-ai --user root --facet root_activity --since 2026-09-24 --until 2026-09-25
```

Sweep every user on the host:

```
openpath-ai --all-users --window "last 24 hours"
openpath-ai --all-users --facet commands --include-inactive
```

JSON for pipelines / SIEM ingestion:

```
openpath-ai --user alice --facet core --format json
```

## 4. Offline analysis (evidence bundles)

Capture a host's evidence into a portable bundle and analyze it elsewhere — the
same collectors run against the bundle unchanged:

```
sudo ./scripts/collect_bundle.sh /tmp/host-evidence
openpath-ai --data-root /tmp/host-evidence --all-users --window "last 24 hours"
```

Use `--now <timestamp>` and `--tz <IANA zone>` for deterministic, reproducible
analysis of a captured bundle.

## 5. Validate on a real instrumented host

The synthetic conformance suite proves correctness for arbitrary users. To confirm
against a live, rule-loaded auditd host (a real VM, not an unprivileged container —
the kernel audit subsystem is host-global and cannot be driven from inside one):

```
sudo ./scripts/live_conformance.sh
```

It loads the rules, performs a known sequence of real actions as a test user,
runs the 13 questions against the live host, and checks the activity is reported
with evidence and root actions attributed to the base user. There is also a live
smoke test that runs against `/` on any host and passes whatever real logs exist:

```
python3 -m unittest tests.live.test_live_host
```

## Root attribution semantics (operational)

- A user who `sudo`/`su`s to root is credited with their root actions (via `auid`).
- Someone who logs in **directly as root** (e.g. `ssh root@host`) is reported as a
  direct root login with its origin IP — not attributed to a base user, because
  nothing ties a human to root's credentials.
- Automated root activity with no login uid (cron, boot, services) is disclosed as
  unattributable.
- `openpath-ai --user root --facet root_activity` gives the host-wide "who became
  root" breakdown.

## Performance & scale

- `audit.log` is streamed; memory is bounded by the in-window result, not log size.
- Scope large investigations with a tight `--window`, and prefer analyzing a
  bundle of only the relevant rotated files for very large fleets/archives.

## Security notes

- Read-only: OpenPath never writes to system logs or modifies host state.
- No network egress except the optional `journalctl` export on a live host.
- Paths are resolved under `--data-root`; run bundle analysis as an unprivileged
  user where possible.

## Known limitations

- Syscall decoding covers x86-64, aarch64, riscv64 (32-bit arm/i386 addable via
  `_ARCH_TABLES`).
- Natural-language routing is best-effort; `--user`/`--facet`/`--window` are
  authoritative.
- Directory-managed users (LDAP/SSSD) not in local `passwd` are resolved only from
  events; unresolved names are disclosed.
