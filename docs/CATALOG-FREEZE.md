# OpenPath-AI — Catalog Freeze (v1)

**OpenPath v1 = 153 certified questions, frozen at contract fingerprint
`109709966e2b`.**

## Why freeze

A question catalog that keeps growing (153 → 175 → 220 → 300 …) can never reach
production readiness, because documentation, support, training, demos, and
acceptance testing all chase a moving target. The freeze stops the target moving so
those can stabilize. It is a *temporary* freeze on the v1 line, not an end to the
roadmap — new capability lands in v2.

## What is frozen

The **question contract**: the set of question ids and each one's certification
status, captured by `contract_fingerprint()` (a deterministic SHA-256 over
`id=status` pairs). The freeze pins:

- `openpath.contract.FROZEN_V1_FINGERPRINT = "109709966e2b"`
- `openpath.contract.FROZEN_V1_QUESTION_COUNT = 153`

Prose edits (rewording a question, expanding a blind-spot note) do **not** move the
fingerprint. Adding, removing, or re-statusing a question **does** — and that is
exactly the event the freeze is meant to make deliberate.

## Enforcement

`tests/conformance/test_conformance.py::TestCatalogFreeze.test_catalog_v1_frozen`
fails if the live contract's fingerprint or count no longer matches the frozen
values. A failing freeze test is not a bug to patch away — it is the signal that a
change to the v1 catalog was made, and the reviewer must decide:

1. **The change was unintended** → revert it; v1 stays as shipped.
2. **The change is wanted** → it is a v2 decision. Cut the v2 line: update
   `FROZEN_V1_FINGERPRINT`/`FROZEN_V1_QUESTION_COUNT`, bump the package version, and
   add a dated entry to the change log below.

## Freeze history

| Line | Fingerprint | Questions | Date | Notes |
|------|-------------|-----------|------|-------|
| v1 | `109709966e2b` | 153 | 2026-09-26 | Initial freeze: full production contract CERTIFIED, CONTRACTED 0. |

## What the freeze does NOT do

- It does not freeze the *code* — bug fixes, new collectors, better parsing, and
  hardening continue on v1 as long as they do not change which questions exist or
  their certification status.
- It does not freeze *host readiness* — a given host still answers a frozen question
  as CERTIFIED / PARTIAL / UNANSWERABLE depending on its own evidence.
- It does not exclude any question. CONTRACTED is 0; the freeze locks a complete
  contract, not a partial one.
