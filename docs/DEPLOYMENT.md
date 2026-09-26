# OpenPath-AI — Deployment doctrine

OpenPath is a **stateless batch CLI**, not a long-running service: it collects
evidence, answers, and exits. It keeps no state between runs, opens no port, and
needs no network or database. "Deployable" therefore does not mean "a daemon that
stays up" — it means the operational lifecycle questions below each have a concrete,
tested answer, and the container reflects the batch model honestly rather than
pretending to be a service.

Read this together with `PRODUCTION-READINESS.md` (the trust matrix). This document
is the *operations* contract; that one is the *evidence* contract.

## The container

`Containerfile` builds a minimal, non-root, read-only-friendly image with no
third-party dependencies (pure stdlib — the copy is the install). Its entrypoint is
the CLI, its default command and `HEALTHCHECK` are `--selfcheck`.

```
docker build -f Containerfile -t openpath-ai:0.1.0 .

# health probe (host-independent; no privilege, no network)
docker run --rm openpath-ai:0.1.0 --selfcheck

# analyze a live host: mount it read-only; grant read of root-only logs with a
# capability instead of running privileged
docker run --rm --read-only --tmpfs /tmp --cap-add DAC_READ_SEARCH \
  -v /:/host:ro openpath-ai:0.1.0 --data-root /host --coverage

# analyze an offline evidence bundle
docker run --rm --read-only --tmpfs /tmp -v "$PWD/bundle:/evidence:ro" \
  openpath-ai:0.1.0 --data-root /evidence --all-users -w "last 24 hours"
```

## Operational lifecycle — every question answered

| Question | Answer for a stateless batch CLI | Command / evidence | Proven by |
|----------|----------------------------------|--------------------|-----------|
| **Start** | The entrypoint is the CLI; a run is one `docker run`. There is no boot sequence, no warm-up, no port to wait on. | `docker run … openpath-ai …` | build-time `--selfcheck`; `TestDeployment.test_selfcheck_*` |
| **Discover** | Collectors probe every source under `--data-root` and report what they found; `--coverage` lists which questions this host can answer. Nothing to configure or register. | `--coverage` | `Engine.readiness`; `test_tm10_readiness_coverage` |
| **Persist** | Nothing to persist — the answer *is* the output. Reports are written to stdout (or a mounted volume) by the caller; OpenPath holds no internal state. | `--format json > report.json` | stateless by design; `TestStreaming` (bounded memory) |
| **Recover** | Recovery = re-run. A run is idempotent and side-effect-free; a crashed or killed run leaves nothing to repair. | re-invoke | `TestResilience.test_rerun_is_idempotent` |
| **Upgrade** | Pull a new image. The question contract carries a deterministic fingerprint, so an upgrade is verifiable without diffing docs: same fingerprint ⇒ same questions at the same certification. | `--selfcheck` prints `fingerprint …`; `--contract` | `contract_fingerprint()`; `TestDeployment.test_contract_fingerprint_stable` |
| **Permission failure** | A source that exists but cannot be read (root-only `audit.log`/`btmp`/`shadow` under a non-root run) is disclosed as **UNREADABLE with a remedy**, never reported as a false "nothing happened". | run non-root → `--coverage` shows `unreadable` | `TestResilience.test_auditd_permission_denied_*` |
| **Health** | `--selfcheck` runs host-independent integrity checks (collectors, contract, facets, full pipeline over an empty root) and exits 0/non-zero. This is the container `HEALTHCHECK` / k8s liveness probe. | `--selfcheck` | `TestDeployment.test_selfcheck_healthy` |
| **Readiness** | `--coverage` answers "can THIS host answer question X" from real instrumentation state (audit rules loaded, sources present, in-horizon). Distinct from health: health checks the *binary*, readiness checks the *host*. | `--coverage` | `Engine.readiness` |
| **Restart** | Stateless, so a restart is just the next run. No recovery, no replay, no lock to clear. | re-invoke | `TestResilience.test_rerun_is_idempotent` |
| **Reboot (of the analyzed host)** | The *host's* reboot is first-class evidence: boot records bound sessions and mark the down-interval as not-a-blind-spot (SL-03, boot-awareness). A *container* reboot is just a restart. | analyzed automatically | boot-awareness in `Engine.collect`; `TestSystemLifecycle` |
| **Log rotation** | Rotated `.1`/`.2` files are read oldest-first; an event split across a rotation boundary is reunited; a genuine retention shortfall is a disclosed horizon gap, a merely-quiet log is not. | automatic | `test_event_split_across_rotation_is_reunited`; `horizon_shortfalls()` |
| **Disk full** | Reads never write, so analysis is unaffected. Writing a report to a full volume fails cleanly: a broken pipe exits 141, an `ENOSPC`/IO error exits 74 with a stderr message — never a partial "success" or a raw traceback. | any output path | `TestResilience.test_broken_pipe_exits_cleanly` |

## Capture freshness in deployment

A **live** run (`--data-root /host`) observes every source up to the analysis
instant. An **offline bundle** is observed only up to when it was captured;
`scripts/collect_bundle.sh` stamps `var/log/openpath/captured-at`, and a window
reaching past that instant discloses the not-yet-observed tail (see the capture
latency section of `PRODUCTION-READINESS.md`). Schedule bundle capture so its window
ends at (or after) analysis time, or analyze live.

## What OpenPath is NOT

- **Not a daemon.** No supervisor, no port, no persistent process to monitor. If you
  want periodic analysis, drive it from cron / a Kubernetes `CronJob` / a systemd
  timer — one batch run per tick.
- **Not stateful.** No database, no cache, no write-ahead log. This is why recovery
  and restart are trivial and why there is nothing to corrupt.
- **Not network-dependent.** It reads local files (or a mounted bundle). Origin
  reputation (IA-10) reads a *provided* feed file; it makes no outbound calls.
