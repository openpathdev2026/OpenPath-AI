# OpenPath-AI — Production Readiness

Status at this milestone: **the full production question contract is CERTIFIED —
153 / 153, CONTRACTED 0, PARTIAL 0 (at the catalog level).**

Every user-facing forensic question OpenPath commits to is answered end-to-end
through the shipped CLI with **cited, evidence-scoped, gap-disclosing** findings.
This document is the readiness matrix: what "CERTIFIED" means, how each question is
proven, the invariants that keep answers honest, and the runtime boundaries.

**Two roadmaps, both required.** The 153/153 certification program is the *feature*
roadmap. The trust matrix below is the *trust* roadmap — cross-cutting properties
that are independent of question count. A system with every question certified but
weak attribution or no real-host validation is still not production-ready, so both
must hold. The narration is only ever as trustworthy as the evidence path behind it.

## Trust roadmap (production-readiness matrix)

Honest status per cross-cutting area, each backed by the test(s) that enforce it.
`GOOD` marks a real, tested property with a stated limitation; it is not a euphemism
for done-enough.

| Area | Status | Evidence / caveat |
|------|--------|-------------------|
| Evidence conservation | STRONG | `records_scanned`/`unparseable` on all 16 collectors; `conservation_gaps()` surfaces any drop; `TestEvidenceConservation` (truncated wtmp tail, unparseable package/journal/cron/sudoers lines counted, consumed-source degrade). |
| Attribution correctness | STRONG | auid-centric `Subject.matches` (survives sudo/su); `TestRootAttribution` + the adversarial `TestAttributionCorpus` covering the full messy-case list: concurrent same-user sessions, multiple sudo chains that must not cross, nested su → login user, overlapping direct root logins (ambiguity **disclosed, not guessed**), a command run in a persistent screen/tmux pane **after logout** (still the base user, by immutable auid), and automation left unattributable; `TestMultiUserSweep` (no cross-attribution); wrong-user isolation in `TestQueryLayer`; TM-06 labels each action high/medium/low. |
| Session correlation | STRONG (with a disclosed boundary) | audit `ses=` id captured and used to group a user's concurrent sessions; the adversarial cases above are proven (`TestAttributionCorpus`); session intervals + overlap (IA-05), still-open (IA-04), reboot-terminated (SL-03), concurrent cross-user (TM-13). *Boundary (disclosed, not silently assumed): `ses` groups audited actions into sessions but is not bridged to the wtmp session's origin, so mapping one audited action to a specific overlapping wtmp login is reported as ambiguous rather than asserted — the honest limit, since no deterministic on-host link exists.* |
| Freshness measurement | STRONG | per-source retention horizon + `freshness_seconds`/`is_stale` (age of newest record vs the analysis anchor), surfaced in `--coverage`; `test_freshness_and_staleness_measure`. A source with no timestamped record reports freshness `None`, never a fabricated "fresh". |
| Capture latency | STRONG | every source is tagged `capture_mode` (`live` = observed now, or `export` = a journald dump) and the tag is surfaced in `--coverage`; an offline bundle stamps its own capture time (`captured-at` marker) and a window reaching past it discloses the not-yet-observed tail (`snapshot_shortfall`); `TestCaptureLatency`. Record *age* is never mistaken for capture staleness — a quiet live source stays a trustworthy negative. |
| Log rotation handling | STRONG | reads rotated `.1` files; `retention_bounded` + `horizon_shortfalls()`; `test_event_split_across_rotation_is_reunited`; a genuine retention gap is disclosed, a merely-quiet log is not. |
| Restart / recovery | STRONG (by design) | stateless CLI (collect → analyze → exit); no persistent state to corrupt or recover; a re-run is byte-identical (`TestResilience.test_rerun_is_idempotent`); a failed output write exits cleanly (broken pipe → 141, IO error → 74, `test_broken_pipe_exits_cleanly` / `test_output_ioerror_exits_nonzero_not_crash`) instead of half-succeeding; `TestStreaming` proves bounded memory on large/rotated logs. |
| Permission-failure degradation | STRONG | a present-but-unreadable root-only source (`audit.log`/`wtmp`/`btmp` under a non-root run) is disclosed **UNREADABLE with a remedy**, never a false "nothing happened"; `Collector._readable` + `TestResilience.test_auditd_permission_denied_is_unreadable_not_false_negative`. |
| Real-host validation | VALIDATED | `tests/live/test_live_host.py` runs every facet against the real `/` filesystem — no facet raises, every event cited, gaps disclosed; run on this container it parsed real `/etc/cron.d`, `/etc/group` (ubuntu in sudo/adm), `/etc/shadow` (`_apt` locked), `/proc/net`. *Caveat: a fully-instrumented, rule-loaded auditd host still needs an operator to drive `scripts/live_conformance.sh`.* |
| Documentation parity | GOOD | docs generated from the contract; `test_docs_parity_with_contract` fails if `PRODUCTION-CATALOG.md` counts drift from `openpath.contract`; `test_scoreboard_renders_and_counts_match` checks the `--contract` output. |
| Catalog completeness | GOOD | 153 questions are an output of an evidence-surface analysis; every collector maps to ≥1 certified question; the contract-completeness principle (below) forbids a permanent CONTRACTED. |
| Container deployment | FUNCTIONAL | ships a non-root, read-only-friendly, zero-dependency `Containerfile` (entrypoint = CLI, `HEALTHCHECK`/CMD = `--selfcheck`), a host-independent health probe (`--selfcheck`: collectors/contract/facets/pipeline, exit 0/non-zero), host readiness (`--coverage`), and a verifiable contract fingerprint for upgrades; `docs/DEPLOYMENT.md` answers all twelve lifecycle questions; `TestDeployment` + `TestResilience`. *Caveat: the image is defined and its install/entrypoint validated, but building/publishing it (and any orchestration manifests) is left to the operator's registry/CI; it remains a batch CLI, by design — no daemon.* |

## Contract-completeness principle

Every question discoverable from the supported evidence surface must resolve to
**exactly one** of two states:

1. **CERTIFIED** — proven end-to-end, or
2. **Excluded** from the guaranteed contract with a documented, principled reason —
   the evidence does not exist on the platform, or answering would require inference
   rather than evidence.

A permanent **CONTRACTED** state is a work item, never a resting place: build the
capability, or exclude the question on the record. At this milestone CONTRACTED is
0 and nothing is excluded — the runtime boundaries below are scope limits on
*hosts*, not exclusions of *questions*.

## Capture latency: "nothing happened" vs. "not yet observed"

The single most dangerous way a forensic answer misleads is an empty result that
*looks* like proof of absence. "No activity found" has two very different meanings,
and OpenPath keeps them apart:

- **Nothing happened.** The source was observed right up to the analysis instant and
  recorded nothing. Trustworthy negative.
- **Not yet observed.** The source's view ends before the analysis instant, so the
  recent tail simply is not in the evidence. An empty result there is *unknown*, not
  *no*.

Two mechanisms make the difference explicit, and neither guesses staleness from how
old a source's newest record happens to be (a quiet source is not a stale one):

1. **Per-source `capture_mode`** — every `SourceCoverage` is tagged `live` (read at
   analysis time: the on-host log/`/proc`/`/etc` artifact, or a live `journalctl`
   call — observed up to *now*) or `export` (loaded from a pre-existing journald JSON
   dump — journald's store is binary and must be exported, so it is only as fresh as
   when it was dumped). The tag is shown per source in `--coverage`, so an analyst can
   see which answers rest on a live read and which on a snapshot.

2. **Bundle capture-time marker** — `scripts/collect_bundle.sh` stamps
   `var/log/openpath/captured-at` with the instant collection finished. That is the
   edge of observation for the whole snapshot. If an analysis window reaches past it,
   `CoverageLedger.snapshot_shortfall` discloses the exact not-yet-observed tail
   (`(captured_at, window.end]`) with a remedy — recapture, or analyze the live host.
   A live analysis has no marker and every source is `live`, so a recent negative is
   trustworthy without caveat.

This is a per-source *and* per-bundle answer to "what is the lifecycle from activity
to answer": a live host is queryable within collector latency (seconds); a bundle is
queryable up to its stamped capture instant, and everything after is disclosed as
unobserved rather than silently reported as quiet.

### Per-source lifecycle (live host)

Where each source sits on "event generated → visible to OpenPath → queryable". On a
**live** run all latencies are effectively the source's own write latency (OpenPath
reads the artifact directly at analysis time); on a **bundle** every row is instead
bounded by the capture instant (above).

| Source | Event generated → recorded | Visible to OpenPath | Notes |
|--------|----------------------------|---------------------|-------|
| `audit.log` | kernel emits the audit event; `auditd` writes it (sub-second, subject to its flush/backlog) | immediate on the next run (direct read) | the freshest source; drives Commands/Root/Files/Network |
| journald (`journal.sshd`, `journald`) | logged to the journal (sub-second) | only after a JSON export — live `journalctl` at analysis time (fresh) or a bundle dump (as-of capture) | the one source with a real extra export step → tagged `capture_mode=export` when read from a dump |
| `auth.log` / `secure` | syslog writes the auth line (sub-second) | immediate on the next run (direct read) | login/sudo auth detail |
| `wtmp` / `btmp` | written on login/logout/boot / failed login | immediate on the next run (direct read) | event-driven, not continuous |
| cron / systemd units (`persistence`) | the schedule *file/unit* reflects current state whenever changed | immediate (state snapshot, stamped at read time) | a job's *establishment* is now-state; a job's *run* is only queryable if it emitted an audit exec or journal line |
| `/etc/shadow`, sudoers, groups (`authz`) | the file reflects current account state whenever changed | immediate (state snapshot, stamped at read time) | the *change act* is queryable only via an audit write-watch on the file |

State-snapshot sources (persistence/authz) describe the present by construction, so
their freshness is ~0 and "not yet observed" never applies to them; the distinction
matters for the event-log sources above.

## What CERTIFIED means (and does not)

CERTIFIED is a property of a **question**: its deterministic evidence path exists
and is proven end-to-end (RAW → parse → normalized `Event` → correlation → query →
answer → provenance → negative behavior → shipped CLI). It is **not** a promise
that every host can answer it. Runtime confidence is separate and per-host:

| Confidence (runtime) | Meaning |
|----------------------|---------|
| CERTIFIED | the sources that record this class of activity were present + instrumented; complete *within the covered evidence scope* |
| PARTIAL | substantive and cited, but a named scope/coverage gap is disclosed |
| UNANSWERABLE | no usable carrier present — "cannot determine (see gaps)" **with a named remedy**, never a false negative |

So a CERTIFIED question on a host that lacks its evidence source returns
UNANSWERABLE with the exact remedy (e.g. "load an execve audit rule") — exactly as
the original wired questions (commands, files, network) already behaved. Nothing is
answered from thin air.

## Evidence surface (16 collectors)

Each collector reads a real on-host format under a configurable `--data-root`
(offline evidence bundles work identically to a live host), normalizes to cited
`Event`s, and reports a `SourceCoverage` with conservation counters.

`wtmp` · `btmp` · `journal.sshd` · `auditd` (+ read watches) · `auth` (syslog) ·
`packages` (dnf/dpkg) · `persistence` (cron/at, systemd units/timers, linger,
startup) · `authz` (group/sudoers/shadow, authorized_keys, sshd_config) · `journald`
(general: lifecycle + non-SSH PAM auth + faillock) · `pkgpolicy` (repos, versionlock,
gpg, coverage) · `shell_history` · `firewall` (nft/iptables) · `conntrack` ·
`netlogs` (DNS / firewall-drop / proxy / socket-lifetime) · `file_integrity` (FIM
content diffs) · `ip_reputation` (geo / threat-intel feed).

## Soundness invariants (enforced by the conformance suite)

- **Soundness** — every asserted fact carries a citation. Guarded by
  `test_every_certified_facet_answerable_and_cited` (every certified facet, on a
  fully-instrumented host, is answerable and emits only cited events) and by the
  per-family evidence assertions.
- **Disclosure** — an absent/narrow/uninstrumented source is a disclosed gap with a
  remedy, never a silent blank. Verified on a **bare host** for every facet.
- **Evidenced negatives** — "the user did NOT do X" is only stated when the source
  that would record X was present and instrumented; otherwise it is UNANSWERABLE.
  Negatives are always scoped ("within the covered evidence scope, not an absolute
  claim").
- **Attribution** — auid-centric (survives sudo/su); host-wide data is never
  presented as user-attributed; scheduler/daemon activity is disclosed as
  unattributable rather than blamed on a human.
- **Conservation** — records scanned vs emitted vs unparseable are counted per
  source; an undecodable record degrades confidence rather than vanishing.
- **Spec ↔ requirement consistency** — each data facet's `EvidenceSpec`
  answerability set equals its facet requirement sources; aggregates' `derived_from`
  equals the federated data facets.
- **Shipped path** — every certification runs through `main()` (the CLI), not a
  test-only shortcut.
- **No silent over-certification** — the certified set is pinned; a question cannot
  flip to CERTIFIED without a proving test and a runnable facet.

## Runtime boundaries (honest scope, not gaps in the contract)

Some questions depend on evidence a default host does not retain. These are
CERTIFIED (the path is built and proven with the evidence present) and degrade to a
remedied UNANSWERABLE without it:

- **Content-level file diffs (FS-13)** need a file-integrity monitor / content
  snapshot — auditd records the change act, never file content.
- **Origin reputation / geo (IA-10)** needs a threat-intel / geo feed — OpenPath is
  deterministic and offline; it reports what the provided feed says, cited.
- **DNS / firewall-drop / proxy / socket-lifetime (NW-08/10/12/15)** need resolver
  logging, firewall LOG rules, a proxy log, or a socket tracer respectively.
- **Data volume (NW-04)** needs conntrack byte accounting (`nf_conntrack_acct`).
- **Process ancestry (EX-11)** reconstructs the exec chain from `pid`/`ppid`; a
  fork/clone that never exec'd is shown as an unresolved parent, not invented.
- **Shell history (EX-12)** is a lead, not proof of execution (user-editable,
  usually un-timestamped) — always disclosed as such.

## Quality metrics

- 153 / 153 questions CERTIFIED (CONTRACTED 0).
- 29 facets, 16 collectors, ~11k LOC, zero third-party dependencies (stdlib only).
- 272 conformance tests green, including adversarial cases (wrong-user isolation,
  scoped-negative-not-absolute, provenance, path-boundary, contradictory flags,
  read-not-a-write, reply-tuple direction, bare-host disclosure, the full
  adversarial attribution corpus incl. post-logout screen/tmux, live-vs-snapshot
  capture latency, permission-denied degradation, health-probe wiring, clean
  output-failure exits).

## How to reproduce

```
python3 -m unittest discover -s tests -p 'test_*.py'   # full conformance suite
openpath-ai --contract                                 # 153 CERTIFIED / 0 CONTRACTED
openpath-ai --coverage --data-root <bundle>            # per-host readiness self-check
openpath-ai --selfcheck                                # host-independent health probe
python3 scripts/measure_capture_latency.py             # measured capture latency
python3 scripts/truth_corpus.py --data-root <host> --truth gt.json   # answers vs ground truth
python3 scripts/gen_evidence_surface.py                # regenerate EVIDENCE-SURFACE.md
python3 scripts/gen_architecture_trace.py              # regenerate ARCHITECTURE-TRACE.md
python3 scripts/gen_evidence_package.py                # regenerate PRODUCTION-EVIDENCE.md
python3 scripts/gen_signoff_package.py                 # regenerate PRODUCTION-SIGNOFF.md
./scripts/reproduce.sh                                 # clean-checkout reproduction (all of the above)
```

## Sign-off & evidence artifacts

Regenerable, code-derived, meant to be checked against the implementation rather
than taken on faith:

- **`docs/PRODUCTION-SIGNOFF.md`** — the v1 sign-off package: evidence surface,
  capture lifecycle + SLA, host-truth-corpus framework, operational-readiness
  matrix, catalog freeze, risk register, release checklist, and an honest Go/No-Go
  (currently NO-GO for GA, pending operator-side runtime + corpus validation).
- **`docs/PRODUCTION-EVIDENCE.md`** — full 153-question catalog with certification
  rationale, source inventory, and executed test results.
- **`docs/EVIDENCE-SURFACE.md`** — the machine-generated evidence inventory.
- **`docs/ARCHITECTURE-TRACE.md`** — walks every answer back Question → Facet →
  Event Types → Collectors → Raw Sources, derived from code.
- **`docs/CATALOG-FREEZE.md`** — the v1 freeze definition and history.
- **`docs/REPRODUCTION.md`** + **`scripts/reproduce.sh`** — the independent-
  reproduction protocol: rebuild the whole sign-off from a clean checkout via the
  documented install path (a Go/No-Go gate is a third-party run of it).

The Host Truth Corpus **framework** (`scripts/truth_corpus.py`) compares OpenPath's
answers to independently-declared ground truth and is tested to detect both
false-negative and false-positive claims. Its worked example
(`tests/corpus/scenarios_ground_truth.json` + `build_scenario_host.py`) covers the
ten canonical investigation scenarios (SSH login, sudo escalation, sudo su, user
creation, group modification, package install, cron persistence, file modification,
network activity, logout), checked 10/10 — populating it on a real host is the
last-mile trust step.
