# OpenPath-AI

Evidence-first forensic Q&A over Linux user activity.

Ask 13 fixed questions about **any** user over **any** time range and get an answer
that is either **backed by cited raw evidence** or **explicitly disclosed as a gap** —
never a silent, misleading "nothing happened".

```
openpath-ai "What did alice do during the last 24 hours?"
openpath-ai "Did deploybot become root during the last 24 hours?"
openpath-ai --user j.doe --window "last 7 days" "what files did j.doe change?"
```

**Docs:** [Architecture](docs/ARCHITECTURE.md) · [Deployment](docs/DEPLOYMENT.md) · [Changelog](CHANGELOG.md)

## The one idea that makes "100% accuracy" honest

You cannot prove you captured *everything* a user did on a Linux host — there are
irreducible blind spots (activity before auditd started, unaudited syscalls,
in-memory actions, tampering). So OpenPath does not claim omniscience. It claims
something stronger and actually achievable:

- **Soundness** — every asserted fact carries a citation to a raw source record
  (question family **12 · Evidence**). If a fact cannot be cited, it is not
  asserted.
- **Disclosure** — anything that cannot be determined is reported with a reason
  and a remedy (question family **13 · Gaps**), never returned as an empty result
  that implies "the user did nothing".

Under those two invariants the 13-question demo becomes a **product-readiness
baseline**: for any user and any window, every answer is true and cited, and every
limit is stated.

## The 13 question families

| #  | Family          | Primary evidence                                   |
|----|-----------------|----------------------------------------------------|
| 1  | Core            | all facets federated                               |
| 2  | Timeline        | time-ordered, federated factset                    |
| 3  | Sessions        | wtmp                                               |
| 4  | Login           | wtmp + sshd journal                                |
| 5  | Privilege       | auditd USER_CMD / USER_START                       |
| 6  | Root activity   | auditd SYSCALL+EXECVE (uid/euid 0)                 |
| 7  | Commands        | auditd EXECVE (user / switched / root)             |
| 8  | Files           | auditd file watches / write syscalls               |
| 9  | Accounts/groups | ADD/DEL_USER, ADD/DEL_GROUP, USER_CHAUTHTOK        |
| 10 | Packages        | dnf.rpm.log / dpkg.log ⟂ audited pkg-manager exec  |
| 11 | Network         | auditd connect/bind + SOCKADDR                     |
| 12 | Evidence        | every claim's source record                        |
| 13 | Gaps            | coverage ledger + blind spots + retention horizons |

`openpath-ai --list-families` prints them.

## Why "any user, not just the ones that exist" is the hard part

The naive approach — look up the name in the current `/etc/passwd`, get a UID,
filter records where `uid == that` — is wrong in ways OpenPath handles explicitly:

- **Attribution is keyed on `auid` (login uid), not `uid`.** After `sudo`/`su`, the
  effective `uid` becomes 0 but the audit login uid stays the original user, so a
  user's root actions are still attributed to them — and *not* to a different
  sudoer who also became root.
- **Users created or deleted inside the window** are resolved from account-change
  *events*, not from the present-tense passwd file. Their identity is a
  time-bounded interval.
- **UID reuse** (a UID freed by a deleted user and handed to a new one) never
  cross-attributes, because intervals are time-bounded.
- **Users that don't exist now / never existed** yield a correct evidenced
  negative plus a disclosed limitation (numeric-only records can't be tied to a
  name we can't resolve), instead of a crash or a false blank.

## Root attribution: who became root

Every action performed with root privilege is traced to *who was actually
responsible*:

- **Escalation** — a user who ran `sudo`/`su` keeps their audit login uid
  (`auid`) even though the effective uid becomes 0, so their root actions are
  attributed **to them** ("alice, via sudo/su"), not to a shared "root".
- **Direct root login** — *unless a user logged in directly as root* (e.g.
  `ssh root@host`): then there is no base user, and the action is attributed to
  the **direct root login with its origin** ("root, direct login from
  203.0.113.9"). A person who authenticated *as* root is not credited as their
  own account, because nothing ties the human to it — that is the honest call.
- **Daemon / no login uid** — a root action from cron, boot, or a service with no
  login uid is **disclosed as unattributable**, never blamed on a human.

`openpath-ai "what did root do during the last 24 hours?"` gives the host-wide
breakdown; `"what did alice do as root?"` gives alice's escalated actions only.

## Track every user in one sweep

```
openpath-ai --all-users --window "last 24 hours"          # core, every user
openpath-ai --all-users --facet commands --include-inactive
```

`--all-users` discovers every subject worth analyzing (local accounts plus anyone
who appears in the evidence, including login uids with no name) and runs the facet
for each, collecting the raw evidence a single time. Users with no recorded
activity are listed explicitly as "checked" — so the sweep is provably complete,
not silently partial.

## Live host vs. offline evidence bundle

Collectors never hardcode `/var/log`; they read every source under a configurable
`--data-root`. Point it at `/` to analyze the live host, or at a captured bundle
directory (same layout under it: `var/log/wtmp`, `var/log/audit/audit.log`,
`etc/audit/rules.d/*.rules`, `var/log/dnf.rpm.log`,
`var/log/openpath/journal-sshd.jsonl`, `etc/passwd`, …) for offline forensics. The
exact same parsers run in both cases.

```
# analyze the machine you're on
sudo openpath-ai "what did root do today?"

# analyze a collected bundle, anchored to a fixed 'now', with an explicit tz
openpath-ai --data-root ./bundle --now 2026-09-25T12:00:00Z --tz UTC \
    --format json "what network activity did svc-01 perform in the last 24 hours?"
```

Export the sshd journal into a bundle with:
`journalctl _COMM=sshd -o json > var/log/openpath/journal-sshd.jsonl`
(on a live host with no export present, OpenPath will invoke `journalctl` itself,
best-effort).

## How gap disclosure works (the honest part)

Each collector reports a **coverage** record: whether the source is present, how
far back its retained data reaches, and which instrumentation is enabled. In
particular the auditd collector reads the **loaded audit rules**
(`/etc/audit/audit.rules`, `rules.d/*.rules`) so it knows whether the host is even
capable of answering a question:

- No `execve` rule → Commands / Root-activity become a **disclosed gap** with the
  exact rule to add, not a false "no commands".
- No `connect`/`bind` rule → Network is disclosed as unrecorded.
- No file watch / write-syscall rule → Files is disclosed as unrecorded.
- A retention-bounded log that starts after the window → a **horizon** gap.
- Package logs never name the user, so a package change is attributed to a user
  only when that user's audited execution of a package manager correlates with it;
  otherwise the change is reported at host level and per-user attribution is
  disclosed as impossible.

## Running the conformance baseline

Pure Python standard library, no dependencies.

```
python -m unittest discover -s tests -p 'test_*.py'
# or
make test
```

The conformance suite (`tests/conformance/`) builds synthetic hosts in the **real
on-disk formats** (including a user created inside the window, UID reuse, a
never-existed user, hosts missing audit rules, a rotated log, direct-root-login
attribution, a large streamed audit log, and the multi-user sweep) and asserts the
answers exactly — including the negative and "cannot determine" cases. That suite
is the readiness gate: if it is green, the 13 questions hold for arbitrary users
and windows.

A **live** suite (`tests/live/`) runs against the real host (`--data-root /`) and
validates whatever sources exist, always enforcing that every claim is cited. For
a fully-instrumented auditd host, `scripts/live_conformance.sh` (root, real VM)
loads the rules, drives known activity, and checks the 13 answers end to end.
`scripts/collect_bundle.sh` snapshots a host into an offline evidence bundle.
Large `audit.log` files are streamed, so memory stays bounded regardless of size.

## Known limitations (disclosed, by design)

- auditd syscall numbers are decoded per the record's `arch=` field; x86-64,
  aarch64 and riscv64 are mapped today (32-bit arm/i386 can be added the same
  way). The resolved syscall name is surfaced on every event.
- Natural-language parsing of the question is best-effort; `--user`, `--facet`,
  and `--window`/`--since`/`--until` are the authoritative inputs.
- Directory-managed users (LDAP/SSSD) not present in local `passwd` are resolved
  only from events; unresolved names are disclosed.
- Naive local timestamps in some package logs are interpreted with `--tz` (or the
  host's zone); all internal reasoning is UTC.

## Layout

```
openpath/
  model/      # events, citations, coverage, findings, identity, time (pure logic)
  sources/    # collectors: wtmp (binary), auditd, sshd journal, packages
  facets/     # one analyzer per question family + Core/Evidence/Gaps aggregators
  engine.py   # collect once -> resolve identity -> run facet
  router.py   # natural-language question -> facet + subject + time (convenience)
  render.py   # answer / evidence / gaps, as text or JSON
  cli.py      # openpath-ai entrypoint
tests/
  unit/       # primitives (time, identity, saddr, struct)
  conformance/# the product-readiness baseline (synthetic real-format hosts)
  live/       # live checks against the real host filesystem
scripts/      # collect_bundle.sh, live_conformance.sh
contrib/      # openpath.rules (recommended auditd rules)
docs/         # ARCHITECTURE.md, DEPLOYMENT.md
```
