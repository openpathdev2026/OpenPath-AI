# Changelog

All notable changes to OpenPath-AI are documented here. The format is loosely
based on Keep a Changelog; dates are UTC.

## [Unreleased]

### Added
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
