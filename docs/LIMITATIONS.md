# OpenPath-AI — Limitations

OpenPath is an **evidence narrator**, not a reasoning engine. It states facts
grounded in raw records and discloses what it cannot establish. These are the
boundaries, stated plainly.

## By design (not bugs)
- **No speculation.** Answers never say "appears to", "likely", "probably", or
  construct an attack narrative. Every sentence is a fact tied to a record, or a
  disclosed gap.
- **No inference beyond the record.** OpenPath does not guess intent, cause, or
  outcome. It reports what the logs show and who is responsible for it.
- **The contract is the catalog.** OpenPath answers the questions in
  `CLIENT-QUESTION-CATALOG.md`. It is not a general-purpose log search.

## Coverage limits (disclosed at runtime via `--coverage` and per-answer gaps)
- **Without auditd**, file changes (Q08) and network activity (Q12) cannot be
  determined; the syslog `auth.log` path captures **sudo-invoked** commands only,
  not ordinary process execution (Q06/Q07 are partial and say so).
- **Scheduled/automated root activity** (cron, systemd timers, service managers)
  has no login uid, so it is disclosed as *unattributable to a human* rather than
  attributed. Correlating it to a scheduler is future work.
- **Directory-managed users** (LDAP/SSSD) not present in local `passwd` are
  resolved only from events; unresolved names are disclosed.
- **Retention horizons.** If a source's retained data does not reach the window
  start (rotated/truncated), the pre-horizon interval is a disclosed blind spot.
- **Architectures.** Syscall decoding covers x86-64, aarch64, and riscv64; other
  arches need a per-arch table (the `arch=` field is preserved on every event).
- **Natural-language parsing** of a question is best-effort; `--user`, `--facet`,
  `--window`/`--since`/`--until`, and `--around` are the authoritative inputs.

## What "100% accuracy" means here
Not omniscience — that is impossible on any host. It means **soundness** (every
asserted fact is true and cited) plus **disclosure** (every limit is stated). An
answer is correct when it invents nothing and hides nothing.
