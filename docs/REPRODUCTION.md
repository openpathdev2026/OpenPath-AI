# OpenPath-AI — Independent Reproduction

Self-verification can miss systemic assumptions; independent reproduction finds them.
Before GA, the sign-off claims must be reproduced **from a clean checkout, using the
documented install path only, by someone who did not write the code.**

## The protocol

```
git clone <repo>            # a fresh checkout, no local state
cd OpenPath-AI
./scripts/reproduce.sh      # no network, no root required
```

`scripts/reproduce.sh` performs, and reports PASS/FAIL for, each step:

1. **Install by instructions** — `pip install --no-deps .` into a throwaway venv
   (zero third-party dependencies, so nothing is fetched).
2. **Health + contract** — the installed `openpath-ai --selfcheck` is HEALTHY and
   `--contract` reports 153 CERTIFIED / 0 CONTRACTED.
3. **Full suite** — `python3 -m unittest discover -s tests` is green (conformance +
   live, including the adversarial attribution corpus, capture-latency, resilience,
   catalog freeze, and truth-corpus framework tests).
4. **Artifacts regenerate** — every evidence/sign-off generator
   (`gen_evidence_surface`, `gen_architecture_trace`, `gen_evidence_package`,
   `gen_signoff_package`) runs clean, so the packages are reproducible, not
   hand-maintained.
5. **Truth corpus** — the ten-scenario worked example is built and OpenPath's answers
   are checked against the independently-authored ground truth: **10/10 matched**.

Exit code 0 means every step passed. The run prints a `REPRODUCTION: OK` / `FAILED`
line.

## What a passing reproduction establishes

- The build installs and runs from its own instructions on a clean machine.
- The certification count, health, and freeze are not artifacts of the author's
  environment.
- The evidence, sign-off, evidence-surface, and architecture-trace documents are
  regenerable from the code (so they can be re-derived and checked, not trusted).
- OpenPath's answers to the ten canonical investigation scenarios match ground truth
  authored independently of the code.

## What it does NOT establish (still operator-side)

- **A populated real-host truth corpus** — the ten scenarios are enacted on a
  synthetic host; earning full trust requires a real host with human-authored ground
  truth (see `docs/PRODUCTION-SIGNOFF.md` §3 and risk R1).
- **A real container lifecycle** — build/run/restart/upgrade on a real runtime
  (risk R2).
- **Upstream capture latency** on an instrumented auditd host (risk R3).

These, plus this independent reproduction performed by a third party, are the
remaining Go/No-Go gates in the sign-off package.
