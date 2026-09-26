# Changelog

All notable changes to OpenPath-AI are documented here. The format is loosely
based on Keep a Changelog; dates are UTC.

## [Unreleased]

### Added
- **Five more existing-facet questions certified (123 total).** FS-11 (file
  changes with no interactive session behind them, via the unattributable-actor
  pivot); NW-07 (UNIX-domain socket connections such as `docker.sock`, via the
  auditd AF_UNIX SOCKADDR decode + a `connect_unix` fixture); SL-03 (a reboot that
  terminated a user's session -- the sessions facet now cites the interrupting
  BOOT); IA-08 (brute-force / password-spraying -- a deterministic >=5-failures-
  from-one-origin indicator computed from the evidence, no external feed); and
  SP-16 (persistence acts pivoted around an incident, via `--around` on the
  persistence facet). Each proven through the shipped CLI in
  `TestRemainingProjections`.
- **Projection/query certifications over existing facets (no new collector).**
  Twenty-one contract questions are deterministic filters/pivots/projections the
  wired facets already produce, now each proven end-to-end through the shipped CLI
  in `TestProjectionQuestions` with the specific claim asserted (not merely
  non-empty): EX-03 (via sudo) and PV-06 (sudo to another identity), answered by the
  privilege facet after the auditd collector began carrying `via_sudo`/`target_user`
  on escalation events; EX-04 (full argv) and EX-05 (cwd); IA-01 (auth method),
  IA-07 (remote origins) and PV-02 (direct root login) from login; IA-03
  (local vs remote), IA-04 (still-open session) and IA-05 (overlapping sessions)
  from sessions; PV-01 (escalation method) and PV-07 (escalation → root actions);
  PK-05 (attributed by command), PK-09 (upgrades), PK-10 (unattended change) and
  PK-11 (evidenced clean bill); AC-08 (account created-then-removed) and AC-09
  (daemon/unattributed account change); FS-04 (log/audit-trail tamper); SP-08
  (scheduler-launched root activity surfaced as unattributable) and TM-07 (the
  responsible human via auid attribution). 118 questions now CERTIFIED.
- **System-lifecycle facet + general journald collector (`openpath/facets/
  lifecycle.py`, `openpath/sources/journald.py`).** Answers the host-lifecycle
  cluster: when the host booted/rebooted, how long it has been up, what kernel ran,
  who initiated a reboot, and whether shutdowns were clean or crashes. The facet is
  HOST-level and deliberately NOT folded into the per-user Core overview (a user's
  report must not claim the host's reboots). It reconstructs boot/reboot/uptime
  from the `EventType.BOOT` records `wtmp` already emitted (previously the engine
  kept only the first boot) and ties a reboot to its initiator via the audited
  `systemctl reboot`/`shutdown` command; between-reboot downtime is disclosed as
  unmeasured (an upper bound) unless a shutdown carrier is present, never asserted
  as exact. The general journald collector reads the full `journalctl -o json`
  export (beyond the sshd slice) and emits `EventType.SYSTEM` for clean shutdown /
  power-off, systemd unit start/stop/failure, kernel panic / OOM / watchdog, an
  unusual boot target (rescue/emergency), and system-clock changes -- each cited,
  conservation counted. Thirteen questions move CONTRACTED -> CERTIFIED (97 total):
  SL-01/02/06/07/08/10 (wtmp boot history + initiator) and SL-04/05/09/11/12/13/14
  (journald lifecycle), proven end-to-end in `TestSystemLifecycle` (+ evidenced
  negative when the host was up throughout, downtime-unmeasured disclosure, and
  conservation of a malformed journal line).
- **Authorization-state collector + facet (`openpath/sources/authz.py`,
  `openpath/facets/authorization.py`).** The second current-STATE source: it
  answers "who holds elevated privilege, and did the user grant or change any of
  it?". It inventories privileged group membership (sudo/wheel/docker/... by
  explicit member and by primary gid, from `/etc/group` + `/etc/passwd`), sudoers
  grants (`/etc/sudoers` + `/etc/sudoers.d/*`, expanding `%group` specs to their
  members), locked/passwordless accounts (`/etc/shadow`), SSH `authorized_keys`
  per account, and SSH auth policy (`sshd_config` PermitRootLogin /
  PasswordAuthentication). Each artifact is attributed to the account a rule
  *names* (group member, sudo user, shadow account, key owner); host-wide policy is
  unattributed. Per-sub-source instrumentation checks are recorded so a missing
  `/etc/shadow` is disclosed by Gaps rather than yielding a false "no locked
  accounts". The facet federates state with in-window authorization-change ACTS (a
  FILE_CHANGE to sudoers/group/shadow/authorized_keys/pam.d or an audited
  usermod/gpasswd/visudo execve, attributed by auid); it is the 16th question
  family, federated into Core. Seven contract questions move CONTRACTED ->
  CERTIFIED (84 total): AC-10 privileged group membership, AC-11 locked/passwordless
  accounts, AC-12 SSH authorized_key grants, AC-13 auth-config edits (via the files
  path query), PV-10 sudo grants, PV-11 authorization-change footprint, IA-12 SSH
  auth policy -- each with a CLI-path proving test in `TestAuthorization`
  (+ cross-user isolation, missing-shadow disclosure, and conservation).
- **Persistence-state collector + facet (`openpath/sources/persistence.py`,
  `openpath/facets/persistence.py`).** The first current-STATE evidence source
  (everything prior was time-stamped acts). It inventories what is configured to
  auto-run: cron (`/etc/crontab`, `/etc/cron.d/*`, per-user spools, run-parts dirs,
  anacron), `at` jobs, systemd units/timers (with `ExecStart`/`OnCalendar` and
  `.wants/`-symlink *enabled* state), user units under `~/.config/systemd/user`,
  `linger`, and legacy startup (`rc.local`). State is deliberately **unattributed**
  unless the artifact names a user (a per-user crontab, a linger file, a user unit),
  and the facet federates two dimensions it never conflates: the current-state
  inventory (from the collector) and in-window establishment **acts** (a
  `FILE_CHANGE` under a persistence path or an audited persistence-tool `execve`,
  attributed by auid). A clean bill ("did NOT establish persistence") is an
  *evidenced negative* requiring BOTH the state inventory and act auditing present,
  or it degrades to PARTIAL rather than falsely clearing the user. Conservation is
  counted (records scanned / unparseable); every artifact keeps its file citation.
  Persistence is a first-class question family (15th), federated into the Core
  overview, so `Gaps` no longer claims "no collector for scheduled-task state".
  Six contract questions move CONTRACTED -> CERTIFIED (SP-01 cron/at inventory +
  per-user attribution, SP-06 timer schedule, SP-07 enabled-at-boot, SP-13 user
  units + linger, SP-14 established-in-window, SP-15 clean-bill scoped negative;
  77 total), each with a CLI-path proving test in `TestPersistence`.
- **Deterministic query/filter/pivot layer (`openpath/query.py`).** The single
  highest-leverage capability for the production contract: most projection
  questions ("did {user} delete an account?", "what files under /etc did they
  change?", "who did X host-wide?", "what activity is unattributable?") are
  deterministic filters/pivots over the already-normalized, already-cited event
  set, not new evidence. `QuerySpec` composes actor selection (subject via the
  auid-centric matcher / host-wide `any` / `unattributable`), event-type, source,
  object-path (path-boundary correct), command, action/op, direction, as-root and
  via-sudo filters; `Engine.query` applies them while INHERITING the base facet's
  confidence and gaps, so provenance is preserved (every returned fact keeps its
  citations), negatives stay scoped to the filter AND the evidence covered (never a
  false "nothing happened"), and an un-instrumented host yields UNANSWERABLE, not a
  bare negative. Exposed on the shipped path via `--actor/--object/--path/--action/
  --contains/--direction/--as-root/--not-root/--via-sudo/--no-sudo/--source`.
  `TestQueryLayer` certifies it through the CLI against the adversarial risks
  (wrong-user, cross-session, scoped-negative-not-absolute, provenance, host-wide
  and unattributable pivots, partial/unanswerable inheritance, sudo/root
  attribution). Adversarial review fixes locked by tests: aggregate-facet queries
  are refused (they can't be assess()ed), `--path /etc` no longer over-matches
  `/etcpasswd`, contradictory flags are rejected, and the files facet discloses the
  in-place-content-edit (open+write) blind spot on every answer. Ten contract
  questions (AC-01/03, FS-01/03/05, EX-01/02, NW-01/05, TM-08) move CONTRACTED ->
  CERTIFIED (60 total), each with a proving test; the contract test pins the
  CERTIFIED set so nothing can be silently over-certified. CONTRACTED/PARTIAL are
  temporary build states -- the destination is every legitimate question CERTIFIED
  by building the missing capability, never by weakening the bar.
- **Production question contract (`openpath/contract.py`, `--contract`).** The
  product's catalog is now the full set of user-facing forensic questions OpenPath
  commits to (153, an output of an evidence-surface analysis, not a target), each
  with a per-question certification **status** — CERTIFIED or CONTRACTED — so
  certification is a property of a question, not a limit on which questions exist.
  The 15 wired, conformance-proven questions are the CERTIFIED core; the other 138
  are CONTRACTED (in the contract, but their deterministic evidence path is not yet
  complete) and each names exactly what unblocks it — a specific new collector, or
  the query/filter/pivot subsystem the router does not yet have (the single largest
  unblock, ~77 questions). `openpath-ai --contract` prints the scoreboard (text or
  JSON); `docs/PRODUCTION-CATALOG.md` has the full per-question detail. A CONTRACTED
  question is declared, never answered from thin air. `TestProductionContract`
  asserts CERTIFIED == the wired catalog, every CONTRACTED entry names its need, and
  the certified facets are actually runnable. Built and classified by two staged
  multi-agent analyses (generation + adversarial critique); the critique caught a
  real shipped bug (Q06 below) and corrected an over-optimistic CERTIFIED count.
- **Q06 over-certification fixed.** RootActivity ("what did {user} do as root")
  disclosed a gap only when the execve rule was absent, so an execve-only host
  reported the full extent as root as CERTIFIED while silently dropping root file
  and network activity. It now discloses missing host-wide-file / connect+bind
  rules and degrades to PARTIAL; Q06 is CERTIFIED only with command+file+network
  auditing.
- **Federated evidence model + answer confidence (resilience).** Every catalog
  question now declares, in `openpath/catalog.py`, which sources are its **primary**
  carriers (certified), which yield only a **partial** answer, and which merely
  **corroborate** (supporting/optional) — ranked by SOC evidentiary tier (auditd /
  auth / journal are Tier 0-1 primary; wtmp/btmp are Tier 4 corroboration). Each
  answer now carries a confidence — **CERTIFIED / PARTIAL / UNANSWERABLE** — computed
  finding-aware in `openpath/model/evidence_matrix.py`, with the hard invariant that
  a finding with determined, cited events is *never* UNANSWERABLE (the confidence
  line can never contradict the answer). The result is resilience: losing a
  supporting source (e.g. wtmp) keeps the question answerable and the confidence
  line says which source was gone ("CERTIFIED; corroborating source wtmp absent").
  Core/Timeline/Evidence federate best-of and name every blind slice; Gaps is
  always answerable and now discloses standing unmodeled-source classes
  (cron/systemd, firewall/VPN/cloud, non-sshd journald) so it never hides
  unknown-unknowns. `--coverage` shows a per-question CERT/PART/---- tri-state with
  counts; each answer prints a CONFIDENCE block; JSON gains `confidence` /
  `confidence_note`. Soundness fixes from an adversarial design review: the auditd
  rules parser splits comma-separated `-S a,b,c`; a narrow `-w` watch (no host-wide
  write-syscall rule) downgrades Files to PARTIAL; a connect-only or bind-only rule
  downgrades Network to PARTIAL; the auth-only accounts/groups path discloses its
  no-actor attribution limit. Covered by `TestFederatedEvidence` (drop-any-source
  resilience matrix), `TestConfidenceInvariants` (label never contradicts finding),
  and `TestSpecConsistency` (matrix and facet requirements cannot drift). A second
  adversarial review — of the implementation — found and fixed six more defects,
  each now locked by a regression test: a narrow `-w` watch or connect-only rule
  with zero events was a PARTIAL "see gaps" over an unsound certified negative
  pointing at a gap that did not exist (Files/Network now emit a real scope gap and
  a scope-qualified negative); a consumed-but-not-winning source that dropped
  records no longer stays CERTIFIED; auth-only package attribution is PARTIAL with a
  disclosed sudo-only limit; and the per-answer GAPS section never claims
  completeness under a non-CERTIFIED confidence.
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
