# OpenPath-AI — Production Sign-Off Package (v1)

_Generated 2026-09-26T15:47:24.948708+00:00 by `scripts/gen_signoff_package.py` — regenerate to re-verify._

Version `0.1.0` · frozen fingerprint `109709966e2b` · CERTIFIED 153 / CONTRACTED 0.

The decision document for "what must be true before OpenPath v1 ships." Machine-generated from the code + real test runs; companion evidence lives in `PRODUCTION-EVIDENCE.md`, `EVIDENCE-SURFACE.md`, `CATALOG-FREEZE.md`, `DEPLOYMENT.md`, and `PRODUCTION-READINESS.md`.

---

## 1. Evidence Surface Report

**16 collectors**, each reading a real on-host format under `--data-root`; the same parser runs live or on an offline bundle. The full machine-generated inventory (paths, capture mode, emitted EventTypes, role, failure-mode behavior) is `docs/EVIDENCE-SURFACE.md`. Summary:

- **Sources:** `wtmp`, `btmp`, `journal.sshd`, `auditd`, `auth`, `packages`, `persistence`, `authz`, `journald`, `pkgpolicy`, `shell_history`, `firewall`, `conntrack`, `netlogs`, `file_integrity`, `ip_reputation`.
- **Mandatory:** none — every source's absence is a disclosed gap, never a crash or false negative. Six *primary* sources back the wired core; ten *enrichment* sources extend the contract.
- **Failure modes (uniform, tested):** absent → `ABSENT`+remedy; unreadable → `UNREADABLE`+remedy; rotation → rotated files read + split events reunited + horizon gap; undecodable record → conservation gap. None ever becomes a silent "nothing happened".
- **Traceability:** `docs/ARCHITECTURE-TRACE.md` walks every answer back Question → Facet → Event Types → Collectors → Raw Sources, derived from code, and `openpath-ai --trace` instantiates that chain live per answer down to the raw record ids (the 'why', and the 'why not' + remedy when UNANSWERABLE).
- **Red-team discipline:** `docs/RED-TEAM.md` reviews each question by asking 'what evidence would make this answer wrong?'; the worked pass on root escalation separates WHO (robust, by auid) from HOW (asserted only when an escalation record exists — setuid/pkexec/LPE disclosed as method-unproven).


---

## 2. Capture Lifecycle Report + freshness SLA

The lifecycle from an event happening to OpenPath being able to report it, with the stages OpenPath controls **measured on this host**, and the upstream OS stages disclosed with the method to measure them on an instrumented host (never fabricated).

### Measured (this host)

| stage | status | seconds | detail |
|-------|--------|---------|--------|
| audit_event_to_observable | not_measurable | — | auditctl absent -- the kernel audit subsystem is host-global and not namespaced, so it is unavailable in this (container) environment |
| journal_event_to_observable | not_measurable | — | marker not visible within 20s (journald may be volatile/rate-limited here) |
| analysis_latency | measured | 0.0251 | 40 events, 16 sources over / |
| bundle_export_latency | measured | 0.0320 | bundle size 495 KiB |
| stage:T_collect_and_parse | measured | 0.0207 |  |
| stage:T_resolve_and_query | measured | 0.0245 |  |
| stage:T_narration | measured | 0.0007 |  |
| stage:T_total | measured | 0.0459 | 40 events, 16 sources |

### Freshness SLA (the commitment)

| stage | target | owner | status |
|-------|--------|-------|--------|
| audit event → on audit.log | ≤ 2 s | OS (auditd flush) | instrumented host |
| journal event → in journal | ≤ 5 s | OS (journald) | instrumented host |
| collection + parse (all sources) | ≤ 5 s | OpenPath | measured |
| full analysis (collect → narration) | ≤ 10 s | OpenPath | measured |
| bundle export | ≤ 60 s | OpenPath | measured |

_Measured analysis and bundle-export times on this host are sub-second, well within target; the two OS-owned upstream targets are validated on a fully-instrumented host via `scripts/measure_capture_latency.py` (audit/journal rows)._

---

## 3. Host Truth Corpus Framework

The framework for earning production *trust*: compare OpenPath's answers to a ground truth an investigator established **independently** (before seeing OpenPath's answer). `scripts/truth_corpus.py` runs the shipped CLI per case against a host/bundle and reports per-case PASS/MISMATCH plus aggregate false-negative / false-positive / misattribution counts; it exits non-zero on any mismatch (CI-gateable).

- **Schema + worked examples:** `tests/corpus/example_ground_truth.json` and `tests/corpus/scenarios_ground_truth.json` — the latter covers the **ten canonical investigation scenarios** (SSH login, sudo escalation, sudo su, user creation, group modification, package install, cron persistence, file modification, network activity, logout), enacted by `tests/corpus/build_scenario_host.py` and checked 10/10 against independently-authored ground truth.
- **Framework is not a rubber stamp:** ✅ framework self-tests: 7/7 passed — it is tested to DETECT both a false-negative claim (OpenPath missed real activity) and a false-positive claim (OpenPath over-reported), on the example and scenario hosts alike.
- **Status:** framework complete, runnable, and exercised over the ten scenarios on a synthetic host; the *populated* corpus (a real host, ~30 days of usage, human-authored ground truth) is an operator activity — the last mile of trust, tracked in the risk register and Go/No-Go below.


---

## 4. Operational Readiness Matrix

✅ health/readiness/upgrade: 4/4 passed  
✅ failure modes: 5/5 passed

| lifecycle event | behavior | automation status |
|-----------------|----------|-------------------|
| Install | `pip install --no-deps .` → `--selfcheck` HEALTHY | automated (validated in a venv; build-time guard in Containerfile) |
| Upgrade | compare `--selfcheck` contract fingerprint across versions | automated (fingerprint is deterministic; `TestDeployment`) |
| Restart | stateless; a re-run is byte-identical | automated (`TestResilience.test_rerun_is_idempotent`) |
| Log rotation | reads rotated files; reunites split events; horizon gap | automated (`test_event_split_across_rotation_is_reunited`) |
| Permission failure | unreadable source → UNREADABLE + gap, not false neg | automated (`TestResilience.test_auditd_permission_denied_*`) |
| Health / readiness | `--selfcheck` (binary) + `--coverage` (host) | automated (`TestDeployment`) |
| Disk full | failed write → clean non-zero exit (141 / 74), no partial | automated (`TestResilience` broken-pipe / IO-error) |
| Fresh-VM install / real upgrade cycle | image build → run → restart → upgrade on a real runtime | operator (no container daemon here to build) |

Full deployment doctrine (all twelve lifecycle questions): `docs/DEPLOYMENT.md`.

---

## 5. Catalog Freeze Definition

**OpenPath v1 = 153 certified questions, frozen at fingerprint `109709966e2b`.** Live contract: CERTIFIED 153, CONTRACTED 0, fingerprint `109709966e2b` — freeze ✅ intact.

The freeze is enforced by `TestCatalogFreeze.test_catalog_v1_frozen`: the v1 catalog cannot grow or change status silently — a change is a deliberate v2 decision (bump the fingerprint, record it in `docs/CATALOG-FREEZE.md`). Prose edits do not move the fingerprint. This is what lets documentation, support, training, demos, and acceptance testing stabilize against a fixed target.


---

## 6. Remaining Risks Register

| # | risk | severity | mitigation / status |
|---|------|----------|---------------------|
| R1 | Trust rests on synthetic + container + adversarial fixtures until a **populated host-truth corpus** exists (real host, real usage, independent ground truth). | High | Framework shipped & tested (§3); populating it is the top open item. Blocks full trust sign-off, not code correctness. |
| R2 | **Container image not built/published** here (no daemon); real install/restart/upgrade cycle unexercised. | Medium | `Containerfile` defined, install+entrypoint validated in a venv, build-time self-check guard; operator must build/run once on a real runtime. |
| R3 | **Upstream capture latency (audit/journal)** not measured here (no auditd; journald not capturing syslog). | Medium | Harness measures it on an instrumented host; SLA targets published (§2). Analysis latency measured and sub-second. |
| R4 | **Session↔wtmp-origin linkage** unresolved: one action mapped to a specific overlapping login is ambiguous. | Low | Disclosed, not guessed (no deterministic on-host link exists); adversarial corpus proves the disclosure. |
| R5 | Host-level evidence (packages, some account/group changes) carries no actor; attribution is correlation-based and can under-attribute. | Low | Disclosed per-question in the catalog rationale; never presented as certain. |
| R6 | Enrichment questions (FS-13, IA-10, NW-08/10/12/15, NW-04) depend on evidence a default host may not retain. | Low | CERTIFIED where present, remedied-UNANSWERABLE where absent; enumerated in §1 / catalog. |
| R7 | Most evidence is generated by the same codebase that makes the claims; **independent reproduction** by a third party is not yet recorded. | Medium | `scripts/reproduce.sh` reproduces the whole sign-off from a clean checkout via the documented install path (green here); a third party must run it on their own machine (see `docs/REPRODUCTION.md`). |


---

## 7. Release Checklist

**13/17 complete.** The three open items are operator/runtime activities that cannot be performed in this build environment; each is tracked in the risk register.

- [x] Full contract CERTIFIED, CONTRACTED 0
- [x] Catalog frozen at a pinned fingerprint + enforcing test
- [x] Conformance suite green (incl. adversarial attribution, capture latency, permission degradation, resilience)
- [x] Real-host validation against `/` via the shipped CLI
- [x] Evidence surface inventory generated from code
- [x] Capture-lifecycle stages measured + freshness SLA published
- [x] Health (`--selfcheck`) and readiness (`--coverage`) probes
- [x] Clean failure-mode behavior (permission, disk-full, rotation)
- [x] Host Truth Corpus **framework** + ten-scenario worked example (10/10 matched, detects wrong answers)
- [x] Architecture Trace (answer → raw source) generated from code
- [x] In-product answer traceability to raw records (`--trace`)
- [x] Red-team review of root-escalation paths (WHO vs HOW, disclosed)
- [x] Reproduction script green from a clean checkout via documented install (`scripts/reproduce.sh`)
- [ ] Host Truth Corpus **populated** on a real host (operator)
- [ ] **Independent reproduction** run by a third party (operator)
- [ ] Container image built, published, and a real start/restart/upgrade cycle exercised (operator)
- [ ] Upstream audit/journal capture latency measured on an instrumented host (operator)

---

## 8. Go / No-Go Criteria

**Ship OpenPath v1 when ALL of the following hold:**

1. ✅ Contract frozen, CERTIFIED = frozen count, CONTRACTED = 0, freeze test green.
2. ✅ Full conformance + live suite green on the release commit.
3. ✅ `--selfcheck` HEALTHY; evidence-surface & sign-off packages regenerate cleanly.
4. ⛔ **GATE:** container image built and a real install→restart→upgrade cycle passes on the target runtime (R2).
5. ⛔ **GATE:** a populated host-truth corpus of representative cases passes with **zero unexplained mismatches** — every mismatch is either fixed or recorded as a known limitation (R1).
6. ⛔ **GATE:** `scripts/reproduce.sh` passes on a clean checkout run by a **third party** who did not write the code (R7).
7. ◻ **RECOMMENDED:** upstream audit/journal capture latency measured on an instrumented host and within SLA (R3).

**Current verdict: NO-GO for GA — engineering-complete, pending operational validation.** Criteria 1–3 are met and machine-verifiable in this repo (and the reproduction script itself passes here from a clean venv). Criteria 4–6 are the true remaining gates: a real runtime, a populated corpus, and a third-party reproduction — operator activities by nature. This is the honest line between *implemented/proven-in-repo* and *operationally-signed-off*.

