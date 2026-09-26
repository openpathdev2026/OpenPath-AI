# OpenPath-AI

Evidence-first forensic Q&A over Linux user activity.

Answer a **frozen catalog** of client questions ([15 questions,
`docs/CLIENT-QUESTION-CATALOG.md`](docs/CLIENT-QUESTION-CATALOG.md)) about **any**
user over **any** time range, where every answer is either **backed by cited raw
evidence** or **explicitly disclosed as a gap** — never a silent, misleading
"nothing happened". The catalog *is* the contract; OpenPath is an evidence
narrator, not a general-purpose log search.

```
openpath-ai "What did alice do during the last 24 hours?"
openpath-ai "Did deploybot become root during the last 24 hours?"
openpath-ai --user j.doe --window "last 7 days" "what files did j.doe change?"
openpath-ai --catalog     # print the frozen question catalog (the contract)
```

**Docs:** [Question catalog](docs/CLIENT-QUESTION-CATALOG.md) ·
[Production contract](docs/PRODUCTION-CATALOG.md) ·
[Evidence sources](docs/EVIDENCE-SOURCES.md) ·
[Architecture](docs/ARCHITECTURE.md) · [Limitations](docs/LIMITATIONS.md) ·
[Testing](docs/TESTING.md) · [Changelog](CHANGELOG.md)

**Catalog vs. contract.** The **certified catalog** (15 questions, `--catalog`) is
the original wired federation core. The **production contract** (`--contract`,
[docs/PRODUCTION-CATALOG.md](docs/PRODUCTION-CATALOG.md)) is the full set of
questions OpenPath commits to (153), each with a per-question status. **All 153 are
now CERTIFIED (CONTRACTED 0)** — every question is answered end-to-end through the
shipped CLI with cited, evidence-scoped, gap-disclosing findings. Certification is a
property of a question, not a ceiling on which questions exist; it means the
deterministic evidence path exists and is proven, and runtime confidence still
degrades honestly (UNANSWERABLE with a named remedy) on a host that lacks a given
evidence source. Nothing is ever answered from thin air.

Activity is narrated in flowing sentences that name the **object each action was
performed against**, and every claim is tied to the raw record behind it:

```
WHAT HAPPENED
  At 2026-09-25 09:20:00 UTC, alice ran the command `dnf install -y nginx` as root. [E4]
  At 2026-09-25 09:40:00 UTC, alice modified the file `/etc/hosts` as root. [E7]
  At 2026-09-25 09:50:00 UTC, alice created the account `deploybot` (uid 1500) as root. [E8]

EVIDENCE  (object acted against -> source record)
  [E4] command: dnf install -y nginx  <-  auditd var/log/audit/audit.log:2  (+2 more record(s))
  [E7] file: /etc/hosts               <-  auditd var/log/audit/audit.log:5  (+1 more record(s))
  [E8] account: deploybot             <-  auditd var/log/audit/audit.log:9
```

For root, each action is attributed to the base user who escalated — or to a
direct root login: *"root ran the command `cat /etc/shadow` via a direct root
login from 198.51.100.5."* Use `--verbose` for the full raw records, or
`--format json` for structured `narrative` + object-keyed `evidence`.

## The one idea that makes "100% accuracy" honest

You cannot prove you captured *everything* a user did on a Linux host — there are
irreducible blind spots (activity before auditd started, unaudited syscalls,
in-memory actions, tampering). So OpenPath does not claim omniscience. It claims
something stronger and actually achievable:

- **Soundness** — every asserted fact carries a citation to a raw source record
  (**Q14 · Evidence**). If a fact cannot be cited, it is not asserted.
- **Disclosure** — anything that cannot be determined is reported with a reason
  and a remedy (**Q15 · Gaps**), never returned as an empty result that implies
  "the user did nothing".
- **Conservation** — a record that is read but cannot be decoded is counted and
  disclosed, never silently dropped (`--coverage` ends with an `EVIDENCE
  CONSERVATION: OK/FAIL` verdict).
- **Resilience** — questions are ranked by *which* sources carry the answer, so
  losing a supporting source (e.g. wtmp) keeps the question answerable and the
  confidence line says what was lost. Every answer is labelled **CERTIFIED /
  PARTIAL / UNANSWERABLE**, and that label can never contradict the answer (a
  finding with cited events is never "unanswerable").

Under those invariants the question catalog becomes a **product-readiness
baseline**: for any user and any window, every answer is true and cited, every
limit is stated, and the story survives a missing source.

## The frozen question catalog

The contract is [`docs/CLIENT-QUESTION-CATALOG.md`](docs/CLIENT-QUESTION-CATALOG.md),
generated from `openpath/catalog.py` (the single source of truth). Fifteen
questions, each mapped to the facet that answers it and the evidence it cites:

| Q   | Question (about any {user})               | Facet          | Primary evidence                          |
|-----|-------------------------------------------|----------------|-------------------------------------------|
| Q01 | What did {user} do in the last 24h?       | core           | all facets federated                      |
| Q02 | When did {user} log in?                   | login          | wtmp + sshd journal + auth.log            |
| Q03 | Where did {user} log in from?             | login          | wtmp + journal + auth + btmp (failed)     |
| Q04 | What sessions did {user} have?            | sessions       | wtmp                                      |
| Q05 | Did {user} become root?                   | privilege      | auditd USER_CMD/USER_START + auth (sudo)  |
| Q06 | What did {user} do as root?               | root_activity  | auditd SYSCALL+EXECVE (auid) + auth       |
| Q07 | What commands did {user} run?             | commands       | auditd EXECVE + auth (sudo)               |
| Q08 | What files did {user} modify?             | files          | auditd file watch / write syscall         |
| Q09 | What accounts did {user} create/modify?   | accounts       | auditd ADD/DEL_USER + auth                |
| Q10 | What groups did {user} create/modify?     | groups         | auditd ADD/DEL_GROUP + auth               |
| Q11 | What packages did {user} install/remove?  | packages       | dnf.rpm.log / dpkg.log ⟂ audited exec     |
| Q12 | What network activity did {user} do?      | network        | auditd connect/bind + SOCKADDR            |
| Q13 | What did {user} do before/after an event? | timeline       | all facets, pivoted with `--around`       |
| Q14 | What evidence supports what {user} did?   | evidence       | every claim's source record               |
| Q15 | What could OpenPath not determine?        | gaps           | coverage ledger + blind spots + horizons  |

`openpath-ai --catalog` prints the questions; `--list-families` prints the facet
families that implement them.

## Install & instrument

Pure Python stdlib, no runtime dependencies, Python 3.9+.

```
python3 -m pip install -e .        # provides the `openpath-ai` command
python3 -m openpath --list-families # or run without installing
```

Sessions/Login work from wtmp + the sshd journal with no setup. To answer the
auditd-backed questions (Commands, Root activity, Files, Network, per-user Package
attribution) load the recommended rules once:

```
sudo cp contrib/openpath.rules /etc/audit/rules.d/openpath.rules
sudo augenrules --load && sudo auditctl -l
```

Then check what a host is actually instrumented to answer — no subject required:

```
openpath-ai --coverage                 # each question: answerable or blind, with remedy
openpath-ai --coverage --format json   # for fleet inventory / automation
```

Skipping the rules is a supported degraded mode: OpenPath **discloses** the missing
instrumentation as gaps (with the exact rule to add) rather than returning false
negatives.

### Works with or without auditd

auditd gives the fullest picture, but most stock **Debian/Ubuntu** servers don't
run it. OpenPath also reads syslog `auth.log` / `secure`, so on those hosts it
still answers Login, Privilege, Accounts, and sudo-invoked Commands/Root-activity,
and attributes package changes via the user's sudo command — while **disclosing**
that non-sudo commands and file/network activity need an auditd rule. When both
sources exist, auditd is authoritative and duplicates are dropped.

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

Export the journals into a bundle with
`journalctl _COMM=sshd -o json > var/log/openpath/journal-sshd.jsonl` and
`journalctl -o json > var/log/openpath/journal.jsonl` (on a live host with no export
present, OpenPath invokes `journalctl` itself, best-effort). `scripts/collect_bundle.sh`
does all of this and also stamps `var/log/openpath/captured-at` with the collection
instant.

### "Nothing happened" vs. "not yet observed"

An empty answer must never masquerade as proof of absence. Each source is tagged
`capture_mode` — `live` (read at analysis time; observed up to *now*) or `export`
(loaded from a journald JSON dump; only as fresh as when it was dumped) — and the tag
shows in `--coverage`. A bundle records its own capture instant (`captured-at`); if an
analysis window reaches past it, the coverage ledger discloses the exact
not-yet-observed tail rather than reporting the recent period as quiet. A live host
has no such tail: every source is observed to the analysis instant. Staleness is never
guessed from how old a source's newest record happens to be — a quiet live source
stays a trustworthy negative.

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
is the readiness gate: if it is green, the catalog holds for arbitrary users
and windows. `TestDemoReadiness` asserts every catalog question over a golden host
is correct, cited, and gap-disclosing; `TestRootSessionChain` locks the `sudo su`
→ root-attributed-to-human story.

A **live** suite (`tests/live/`) runs against the real host (`--data-root /`) and
validates whatever sources exist, always enforcing that every claim is cited. For
a fully-instrumented auditd host, `scripts/live_conformance.sh` (root, real VM)
loads the rules, drives known activity, and checks the answers end to end.
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
  sources/    # collectors: wtmp/btmp, auditd, sshd+general journald, packages,
              #   persistence, authz, pkgpolicy, shell_history, firewall, conntrack,
              #   netlogs, file_integrity, ip_reputation
  facets/     # one analyzer per question family + Core/Evidence/Gaps aggregators
  engine.py   # collect once -> resolve identity -> run facet
  catalog.py  # the frozen CERTIFIED 15 (wired) + per-question EvidenceSpec
  contract.py # the full production contract (153) with per-question status
  router.py   # natural-language question -> facet + subject + time (convenience)
  render.py   # answer / evidence / gaps, as text or JSON
  cli.py      # openpath-ai entrypoint
tests/
  unit/       # primitives (time, identity, saddr, struct)
  conformance/# the product-readiness baseline (synthetic real-format hosts)
  live/       # live checks against the real host filesystem
scripts/      # collect_bundle.sh, live_conformance.sh
contrib/      # openpath.rules (recommended auditd rules)
docs/         # CLIENT-QUESTION-CATALOG, PRODUCTION-CATALOG, EVIDENCE-SOURCES,
              # ARCHITECTURE, LIMITATIONS, TESTING (+ CHANGELOG at repo root)
```
