# OpenPath v1 — Production Sign-Off (release gates)

_Generated 2026-09-26T15:35:27.940460+00:00 — computed by scripts/run_release_gates.py, not declared._

**Verdict: NOT READY.** 2/5 gates GREEN.

| gate | status | executable checks | blocker |
|------|--------|-------------------|---------|
| A. Truth Corpus | GREEN | 4/4 pass | — |
| B. Attribution Certification | GREEN | 1/1 pass | — |
| C. Container Lifecycle Validation | RED | 10/10 pass | OCI image build + run + restart + upgrade on a real runtime |
| D. 30-Day Host Trial | RED | 4/4 pass | 30-day CONTINUOUS trial (the irreducible wall-clock duration) |
| E. Independent Reproduction | RED | 3/3 pass | reproduction by a DIFFERENT HUMAN operator in a fresh environment |

GREEN gates are backed by the executable checks in their per-gate report. RED gates have real executable evidence too, but retain an **irreducible real-world blocker** (a container daemon, 30 days of wall-clock, or a third-party human) that must not be simulated — each names the exact command that closes it. OpenPath v1 is declared ready only when every gate is GREEN and independently verifiable.

Companion evidence: `../PRODUCTION-EVIDENCE.md`, `../EVIDENCE-SURFACE.md`, `../ARCHITECTURE-TRACE.md`, `../RED-TEAM.md`, `../CATALOG-FREEZE.md`.
