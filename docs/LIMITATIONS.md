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

## Evidence conservation (no silent loss)
A record OpenPath reads must be either turned into a cited event or explicitly
counted as undecodable — it may never just vanish. Each collector reports
`records_scanned` and `unparseable`; any `unparseable > 0` is surfaced as a
`conservation` gap and as a **FAIL** line in `--coverage`. What each source counts:

- **wtmp / btmp** — a truncated or corrupt trailing record (a file whose size is
  not a whole multiple of the 384-byte `struct utmp`), and an existing-but-unreadable
  file. Fully conserved.
- **auditd** — a line that looks like an audit record (`type=` + `audit(...)`) but
  whose event id/type cannot be decoded.
- **sshd journal** — a JSONL line that is not valid JSON.
- **packages** — a transaction line (matches the `Installed:`/`install` shape) whose
  timestamp cannot be parsed.
- **auth (syslog)** — counts lines carrying a parseable timestamp. Lines with no
  recognizable syslog timestamp are treated as noise, not loss; conservation here
  covers timestamp-bearing lines only (documented so the guarantee is not overstated).

The narration cap (60 events in text output) is **not** loss: the text output
discloses the overflow, and `--format json` carries every event and every cited
evidence entry with no cap.

## What "100% accuracy" means here
Not omniscience — that is impossible on any host. It means **soundness** (every
asserted fact is true and cited) plus **disclosure** (every limit is stated) plus
**conservation** (no record read is dropped without being counted and disclosed).
An answer is correct when it invents nothing and hides nothing.
