# OpenPath-AI — Testing

Testing exists to certify one thing: **every catalog question is answered
correctly, with evidence, every time.** Coverage of event types is secondary to
correctness of the answers.

## Run it
```
make test    # readiness gate: unit + conformance (host-independent)
make live    # live checks against the real host (read-only)
```
CI (`.github/workflows/ci.yml`) runs the gate on Python 3.9 / 3.11 / 3.12.

## What the suites are
- **Unit** (`tests/unit/`) — the primitives: time parsing, identity resolution,
  the utmp struct, auditd field/saddr parsing, syslog year inference.
- **Conformance** (`tests/conformance/`) — the product-readiness baseline. It
  builds synthetic hosts in the **real on-disk formats** (binary wtmp/btmp,
  grouped auditd records, syslog auth.log, dnf/dpkg) and asserts the answers
  **exactly**, including the negative and "cannot determine" cases. Notable
  guarantees it locks in:
  - `TestRootSessionChain` — the flagship: `sudo su` → root actions are
    attributed to the human (auid), and the narrative says so, with no speculation.
  - `TestDemoReadiness` — every catalog question over a golden host is sound
    (cited), disclosed (gap or evidenced-negative, never silent), and invents
    nothing for a quiet user.
  - `TestEvidenceConservation` — through the shipped CLI (`main`): a clean host
    reports 0 silent loss; a truncated wtmp, an undecodable audit line, a bad
    package timestamp, and a malformed journal line are each **counted and
    disclosed** rather than dropped; and a >60-event result is capped-but-disclosed
    in text while `--format json` stays complete.
  - Root attribution incl. the ssh-as-root exception; missing-rule gap
    disclosure; UID reuse; new/never-existed users; auditd-less (auth.log) hosts;
    failed logins (btmp); streaming memory bound; multi-arch; the `--coverage`
    readiness report.
- **Live** (`tests/live/`) — runs against `--data-root /`; passes on any host and
  always enforces that every claim it makes on the real machine is cited.

## Demo-readiness checklist
Before a demo, these must all hold (asserted by `TestDemoReadiness`):
1. every answer is factually correct,
2. it cites the correct evidence,
3. it discloses limitations,
4. it never invents activity.

## Adding a certified question
1. Add it to `openpath/catalog.py` (the contract) with its facet and sources.
2. Implement/point it at a facet.
3. Add a conformance test asserting a correct, cited, gap-disclosing answer.
4. Regenerate the catalog docs and run `make test`. Only then mark it certified.
