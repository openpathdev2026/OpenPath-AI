# Changelog

All notable changes to OpenPath-AI are documented here. The format is loosely
based on Keep a Changelog; dates are UTC.

## [Unreleased]

### Added
- **Evidence conservation (no silent loss).** Every collector now reports
  `records_scanned` and `unparseable`; a record that is read but cannot be decoded
  is **counted and disclosed** as a `conservation` gap instead of vanishing. Wired
  for the truncated-tail case in the binary wtmp/btmp parser, undecodable audit
  record lines, malformed sshd-journal JSON, and package lines with an unparseable
  timestamp. `--coverage` prints a per-source `! CONSERVATION` warning and an
  `EVIDENCE CONSERVATION: OK/FAIL` verdict (pass = 0 silent loss). The narration
  cap is no longer a hidden loss: text discloses the overflow and `--format json`
  now carries every event and cited evidence entry with no cap. `TestEvidenceConservation`
  proves all of this through the shipped CLI path.
- **Frozen question catalog (`openpath/catalog.py`, `--catalog`).** The 15 client
  questions OpenPath promises to answer are now defined in one place — the
  contract. Each entry ties a question to the facet that answers it, the evidence
  it cites, and a `certified` flag. The routing tests, the demo, and
  `docs/CLIENT-QUESTION-CATALOG.md` / `docs/EVIDENCE-SOURCES.md` all derive from
  it. `openpath-ai --catalog` prints it. A conformance test (`TestCatalog`) keeps
  the catalog, the facets, and the doc in sync.
- **Accounts and Groups are now separate questions/facets.** What was one
  "Accounts/groups" family is split into **Q09 accounts** (ADD/DEL_USER,
  USER_CHAUTHTOK, account-admin execs) and **Q10 groups** (ADD/DEL_GROUP,
  group-admin execs), each independently answerable and disclosed.
- **Before/after-an-event pivot (Q13, `--around`).** `openpath-ai --around
  <timestamp> --user <u>` renders the federated timeline for ±1h around an
  incident, for "what did the user do before and after EVENT".
- **Demo-readiness gate (`TestDemoReadiness`).** Over a golden host, asserts every
  catalog question is correct, cited, and gap-disclosing, that the demo commands
  behave, and that a quiet user yields an evidenced negative — never invented
  activity. `TestRootSessionChain` locks the `sudo su` → root-attributed-to-human
  story with no speculative language.
- **Host readiness self-check (`--coverage`).** Reports, independent of any user,
  which of the catalog questions the host is instrumented to answer over the window,
  which are blind, and the exact remedy for each gap, plus every source's status
  and retention horizon. Text and JSON. Turns the "readiness baseline" idea into a
  runtime operator tool.
- **Failed-login evidence (`btmp`).** Reads `/var/log/btmp` (the source behind
  `lastb`, same `struct utmp` binary format as wtmp) so the Login question also
  answers "who tried and failed to log in as <user>, and from where" — including
  attempts on accounts that never existed. The Login facet now folds failed
  attempts and their origins into the answer, and can be satisfied by btmp alone.
- **Syslog auth collector (`auth`).** Reads `/var/log/auth.log` (Debian/Ubuntu)
  and `/var/log/secure` (RHEL), so hosts **without auditd** still answer Login,
  Privilege, Accounts, and sudo-invoked Commands/Root-activity, and attribute
  package changes via the user's sudo package-manager command. Events are
  attributed by account name (the log line names the human). Facet coverage is
  now "auditd **or** auth" (an `AnyOf` requirement); when both are present auditd
  is authoritative and auth-log duplicates are dropped. What syslog cannot capture
  — non-sudo command execution, file/network activity — is disclosed as a gap.
  Root attribution now credits the named sudo/su user when there is no login uid.
  CI workflow added (`.github/workflows/ci.yml`, Python 3.9/3.11/3.12).
- **Flowing narrative output.** Activity facets now render as flowing sentences
  that name the actor, the action, and the **object acted against** (file,
  command, endpoint, account, group, package), each with an `[E#]` evidence
  marker. A new EVIDENCE section is keyed by that object so a client can trace
  every claim to its raw record. Root actions are narrated with attribution
  (via sudo/su, or a direct root login with origin).
- `Event.target()` — the acted-upon object — surfaced in JSON as
  `target_kind`/`target`; `render_json` now includes `narrative` and object-keyed
  `evidence`.

### Changed
- **Codebase and narration organized around the catalog.** Narration states
  mechanical facts only — no "appears to"/"likely"/speculation — naming the object
  each action was performed against.
- **Docs curated to the catalog set**: `CLIENT-QUESTION-CATALOG.md`,
  `EVIDENCE-SOURCES.md`, `ARCHITECTURE.md`, `LIMITATIONS.md`, `TESTING.md`, and this
  `CHANGELOG.md`. `docs/DEPLOYMENT.md` was removed and its operational essentials
  (install, load audit rules, `--coverage`) folded into the README.
- sshd-journal citations use a relative locator (no absolute bundle path leaked).
- Streamed package-log reads with incremental horizon/count (bounded memory);
  audit event groups are carried across rotation boundaries so a split event is
  reunited; `make test` uses discovery (live suite self-skips via `OPENPATH_LIVE=0`).

## [0.1.0] — 2026-09-25

First deployable baseline. Answers the 13 forensic question families for any user
over any time range under the soundness (every claim cited) and disclosure (every
gap named) contract.

### Added
- **Core model**: normalized UTC `Event` with `Citation`s; `Finding`;
  `CoverageLedger` with per-source status, retention horizons, and
  instrumentation checks.
- **Tolerant time parsing** to closed UTC ranges: relative ("last 24 hours"),
  calendar ("today"/"yesterday"), ISO instants/ranges, epoch, since/until.
- **Identity resolution** keyed on `auid` (audit login uid): time-bounded
  intervals handle users created/deleted in-window, UID reuse, and never-existed
  users; unresolved names are disclosed. Reverse `uid → name` resolver added.
- **Collectors** reading under a configurable `--data-root` (live host or offline
  bundle): wtmp (binary `struct utmp`, session pairing), auditd (grouped records +
  audit-rules instrumentation detection), sshd journal, dnf/dpkg packages.
- **13 facets** + Core/Evidence/Gaps aggregators; a facet with missing
  instrumentation returns a disclosed gap, not a false negative.
- **Root attribution**: escalated actions → base user (via sudo/su); direct root
  login (e.g. `ssh root@host`) → the root session + origin, not a base user;
  daemon/no-login-uid and unresolved uids → disclosed as unattributable.
  Host-wide "who became root" breakdown for the root subject.
- **Multi-user sweep** (`--all-users`): discovers every subject (local accounts +
  evidence-only login uids), runs the facet for each, collecting evidence once;
  inactive users listed as "checked" so the sweep is provably complete.
- **Multi-architecture** syscall decoding (x86-64, aarch64, riscv64) via the
  record's `arch=` field.
- **Streaming** auditd/package reads: memory bounded by the in-window result set,
  not log size (~0.04 MB peak on an 11 MB / 30k-event log).
- **CLI** `openpath-ai` with natural-language routing and text/JSON output.
- **Conformance baseline** (`tests/conformance/`): synthetic hosts in real on-disk
  formats asserting all 13 answers incl. negatives, gaps, and root attribution.
  **Live** suite (`tests/live/`) against the real host. Operator artifacts:
  `contrib/openpath.rules`, `scripts/collect_bundle.sh`,
  `scripts/live_conformance.sh`.
- **Docs**: README, `docs/ARCHITECTURE.md`, `docs/DEPLOYMENT.md`.

### Notes
- Zero runtime dependencies (Python 3.9+ standard library only).
- Read-only; no network egress except an optional `journalctl` export.
