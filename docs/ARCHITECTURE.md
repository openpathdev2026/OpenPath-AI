# OpenPath-AI Architecture

## The contract

OpenPath answers a frozen catalog of questions (`openpath/catalog.py`, rendered in
[CLIENT-QUESTION-CATALOG.md](CLIENT-QUESTION-CATALOG.md)) about Linux user activity
under two invariants:

1. **Soundness** — every asserted fact carries a `Citation` to a raw source
   record. If a fact cannot be cited, it is not asserted.
2. **Disclosure** — anything that cannot be determined is reported as a `Gap`
   with a reason (and, where one exists, a remedy). Absence of evidence is never
   rendered as "the user did nothing".

Everything below exists to uphold those two properties for *any* user over *any*
time range, on *any* Linux host.

## Data flow

```
                data_root (/ or a bundle)
                          │
        ┌─────────────────┼───────────────────────────┐
        ▼                 ▼                            ▼
   collectors        audit rules                  passwd/group
  (one per source)   (instrumentation)            (identity snapshot)
        │                 │                            │
        ▼                 ▼                            │
  normalized Events   SourceCoverage                   │
  (UTC, cited)        (status, horizon,                │
        │              instrumentation)                │
        └───────┬───────────┘                          │
                ▼                                       ▼
          CoverageLedger  ◄───── boot-awareness    resolve_identity
                │                                   (auid-centric,
                │                                    time-bounded intervals)
                ▼                                       │
          AnalysisContext (events + ledger + subject + passwd)
                │
                ▼
             Facet.analyze  ──►  Finding (summary + cited events + gaps)
                │
                ▼
          render (text / JSON)
```

The engine **collects once** and shares the context across facets, so the
per-family answers, the federated overview, the evidence list, and the gap ledger
can never disagree. A multi-user sweep (`analyze_all`) collects once and resolves
each subject against the shared event set.

## Modules

| Module | Responsibility |
|---|---|
| `model/event.py` | `Event`: normalized, UTC, cited fact. `EventType`. |
| `model/citation.py` | `Citation`: verifiable pointer to a raw record. |
| `model/timerange.py` | Tolerant time parsing → closed UTC `TimeRange`. |
| `model/identity.py` | `resolve_identity` (name→subject) and `resolve_name_for_uid` (uid→name), both time-bounded. |
| `model/coverage.py` | `SourceCoverage`, `Gap`, `CoverageLedger`; horizon + retention + conservation logic; `ledger_source_met`. |
| `model/evidence_matrix.py` | `EvidenceSpec` (per-question source tiers), `Confidence`, `assess` (finding-aware CERTIFIED/PARTIAL/UNANSWERABLE), `derive_aggregate` (best-of). |
| `model/finding.py` | `Finding`: a facet's answer (summary + events + gaps + confidence). |
| `sources/` | Collectors: `wtmp` (binary), `btmp` (failed logins, shares the utmp parser), `auditd` (streaming), `auth` (syslog auth.log/secure), `journal_sshd`, `packages` (dnf/dpkg), `persistence` (cron/at, systemd units/timers, linger, legacy startup — current-state inventory). |
| `facets/` | One analyzer per question family + `attribution` + Core/Evidence/Gaps aggregators. |
| `engine.py` | Collect → resolve identity → run facet; single- and multi-user. |
| `router.py` | Natural-language question → facet + subject + time (convenience). |
| `narrate.py` | Turns a finding's events into flowing sentences naming the object acted against, plus object-keyed evidence entries. |
| `render.py` / `cli.py` | Output and the `openpath-ai` entrypoint. |

### Rendering & narration

Activity facets render as flowing prose: each event becomes a sentence naming the
actor, the action, and the **object acted against** (`Event.target()` → the file,
command, endpoint, account, group, or package), with an `[E#]` marker. The EVIDENCE
section is keyed by that object and points at the raw record, so every claim is
traceable to both its proof and the thing it acted on. Root-activity narration
credits the base user who escalated, or a direct root login with its origin.
Aggregator facets (Core, Gaps) keep a structured overview instead.

## Identity & attribution model

- **Attribution key is `auid` (audit login uid), not `uid`.** After `sudo`/`su`
  the effective uid becomes 0 but `auid` stays the original user, so root actions
  are attributed to the human who escalated.
- **Time-bounded intervals.** A username maps to a uid over intervals derived from
  the passwd snapshot and `ADD_USER`/`DEL_USER` events. This handles users created
  or deleted inside the window and prevents UID-reuse cross-attribution.
- **Reverse resolution** (`resolve_name_for_uid`) powers root attribution: a root
  action's `auid` is mapped back to the account that held it at that instant.
- **Root attribution** (`facets/attribution.py`) classifies every root (uid/euid 0)
  action as: `escalated` (base user via sudo/su), `direct_root_login` (someone
  logged in directly as root — attributed to that session + origin, *not* a base
  user), `root_no_session` (loginuid 0, cron/boot), or `daemon` (no login uid).
  Unresolvable login uids are disclosed, never claimed as a confident actor.

## Coverage & gap model

- Each collector reports `SourceCoverage`: status (`available`/`empty`/
  `absent`/`not_configured`/`out_of_horizon`/`unreadable`), the retained horizon
  (earliest/latest record), record count, and **instrumentation checks**.
- The auditd collector reads the **loaded audit rules** so it knows whether the
  host can even answer a question. No `execve` rule ⇒ Commands/Root-activity are a
  disclosed gap, not a false negative.
- **Boot-awareness**: the first boot inside the window marks when the machine came
  up; the interval before it is not a blind spot.
- **Retention horizon**: a gap is raised only for a genuinely retention-bounded
  source (a rotated file present) whose earliest record is after the window start
  — a merely-quiet continuous log is not a gap.

## Streaming & performance

The auditd collector streams `audit.log` line-by-line and finalizes each event at
its `msgid` boundary (auditd writes an event's records contiguously). Horizon and
instrumentation flags are accumulated incrementally; only in-window events are
retained. Memory is bounded by the in-window result set, not the log size
(measured: ~0.04 MB peak parsing an 11 MB / 30k-event log). Package logs stream
the same way.

## Extension points

- **New source**: implement `Collector.collect(env, window) -> CollectResult`
  (events + `SourceCoverage`) and add it to `sources.default_collectors()`.
- **New architecture**: add a syscall number→name table to `auditd._ARCH_TABLES`
  keyed by the `arch=` hex value. Category sets are name-based, so facets need no
  change.
- **New question**: add a `Facet` and register it in `facets.FAMILIES`.
