# C. Container Lifecycle Validation — RED

_Generated 2026-09-26T15:48:39.126647+00:00 by scripts/run_release_gates.py — computed from executed checks._

## Executable checks

| check | result | evidence |
|-------|--------|----------|
| Containerfile present | PASS | Containerfile |
| pinned base image (FROM ... :tag) | PASS | FROM python:3.12-slim |
| runs non-root (USER) | PASS | USER 65532 |
| declares HEALTHCHECK | PASS | HEALTHCHECK --selfcheck |
| declares ENTRYPOINT | PASS | ENTRYPOINT python -m openpath |
| no remote ADD (supply-chain footgun) | PASS | no ADD http |
| build-time self-check guard | PASS | selfcheck in build |
| health probe HEALTHY (container HEALTHCHECK) | PASS | 5/5 probes pass |
| restart is idempotent (stateless — identical health) | PASS | two selfcheck runs identical |
| upgrade is verifiable (contract fingerprint stable) | PASS | fingerprint 109709966e2b == frozen |

## Unmet blockers (keep this gate RED — not fabricated)

- **OCI image build + run + restart + upgrade on a real runtime**
  - why: no container daemon available in this environment (docker info fails / not installed)
  - closes when: `docker build -f Containerfile -t openpath-ai:v1 . && docker run --rm openpath-ai:v1 --selfcheck  (then restart + pull-new-tag upgrade, re-run --selfcheck)`

**Status: RED.** Executable checks above are real evidence; the gate stays RED until the blocker's closing command is run and recorded.
