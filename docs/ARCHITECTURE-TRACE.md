# OpenPath-AI — Architecture Trace

_Generated 2026-09-26T10:22:42.406154+00:00 by `scripts/gen_architecture_trace.py` — regenerate to re-verify._

Walk any user-visible answer back to the raw evidence it rests on:

```
Question → Facet → Event Types → Collectors → Raw Sources
```

Every link is derived from the shipped code (the facet↔EventType map, the EventTypes each collector emits, the files each collector reads), so this trace is verifiable against the implementation, not asserted.

## Per-facet trace

| facet | kind | event types | collectors | raw sources | # questions |
|-------|------|-------------|------------|-------------|-------------|
| `core` | aggregate | _federates the 12 data facets_ | _(union of data-facet collectors)_ | _(union of data-facet sources)_ | 2 |
| `timeline` | aggregate | _federates the 12 data facets_ | _(union of data-facet collectors)_ | _(union of data-facet sources)_ | 5 |
| `sessions` | data | `SESSION` | `wtmp` | `var/log/wtmp` | 5 |
| `login` | data | `SESSION`, `SSH_AUTH`, `LOGIN` | `wtmp`, `journal.sshd`, `auth`, `btmp` | `var/log/wtmp`, `var/log/openpath/journal-sshd.jsonl`, `var/log/auth.log`, `var/log/btmp` | 11 |
| `privilege` | data | `PRIVILEGE_ESCALATION`, `SESSION` | `auditd`, `auth`, `wtmp` | `var/log/audit/audit.log`, `var/log/auth.log`, `var/log/wtmp` | 6 |
| `root_activity` | data | `EXEC`, `FILE_CHANGE`, `NETWORK` | `auditd`, `auth` | `var/log/audit/audit.log`, `var/log/auth.log` | 7 |
| `commands` | data | `EXEC` | `auditd`, `auth` | `var/log/audit/audit.log`, `var/log/auth.log` | 17 |
| `files` | data | `FILE_CHANGE` | `auditd` | `var/log/audit/audit.log` | 17 |
| `accounts` | data | `ACCOUNT_CHANGE` | `auditd`, `auth` | `var/log/audit/audit.log`, `var/log/auth.log` | 8 |
| `groups` | data | `GROUP_CHANGE` | `auditd`, `auth` | `var/log/audit/audit.log`, `var/log/auth.log` | 2 |
| `packages` | data | `PACKAGE_CHANGE` | `packages` | `var/log/dnf.rpm.log` | 12 |
| `network` | data | `NETWORK` | `auditd` | `var/log/audit/audit.log` | 7 |
| `persistence` | data | `PERSISTENCE` | `persistence` | `(dynamic)` | 7 |
| `authorization` | data | `AUTHZ` | `authz` | `(dynamic)` | 6 |
| `system_lifecycle` | data | `BOOT`, `SYSTEM` | `wtmp`, `journald` | `var/log/wtmp`, `var/log/openpath/journal.jsonl` | 13 |
| `pkg_policy` | data | `PKG_POLICY` | `pkgpolicy` | `(dynamic)` | 4 |
| `process_tree` | data | `EXEC` | `auditd`, `auth` | `var/log/audit/audit.log`, `var/log/auth.log` | 1 |
| `shell_history` | data | `SHELL_HISTORY` | `shell_history` | `(dynamic)` | 1 |
| `firewall` | data | `FIREWALL` | `firewall` | `(dynamic)` | 1 |
| `file_access` | data | `FILE_READ` | `auditd` | `var/log/audit/audit.log` | 1 |
| `netflow` | data | `NETFLOW` | `conntrack` | `proc/net/nf_conntrack` | 3 |
| `netlogs` | data | `NETLOG` | `netlogs` | `var/log/openpath/dns.log` | 4 |
| `host_changes` | aggregate | _federates the 12 data facets_ | _(union of data-facet collectors)_ | _(union of data-facet sources)_ | 1 |
| `attribution` | aggregate | _federates the 12 data facets_ | _(union of data-facet collectors)_ | _(union of data-facet sources)_ | 1 |
| `concurrent` | aggregate | _federates the 12 data facets_ | _(union of data-facet collectors)_ | _(union of data-facet sources)_ | 1 |
| `file_integrity` | data | `FILE_DIFF` | `file_integrity` | `var/log/openpath/file-diffs.jsonl` | 1 |
| `origin_reputation` | data | `SESSION`, `SSH_AUTH` | `wtmp`, `journal.sshd`, `auth` | `var/log/wtmp`, `var/log/openpath/journal-sshd.jsonl`, `var/log/auth.log` | 1 |
| `evidence` | aggregate | _federates the 12 data facets_ | _(union of data-facet collectors)_ | _(union of data-facet sources)_ | 2 |
| `gaps` | aggregate | _federates the 12 data facets_ | _(union of data-facet collectors)_ | _(union of data-facet sources)_ | 6 |

## Worked examples

```
"What did USER do as root?"
  → RootActivityFacet (facet: root_activity)
  → EXEC + FILE_CHANGE + NETWORK events, attributed by auid (survives sudo/su)
  → auditd collector
  → /var/log/audit/audit.log*
```

```
"Who logged into this host, and from where?"
  → Login / Sessions facets (facets: login, sessions)
  → SESSION + SSH_AUTH + LOGIN events
  → wtmp collector + journal.sshd collector + btmp collector
  → /var/log/wtmp*  +  journalctl _COMM=sshd export  +  /var/log/btmp*
```

## Question → facet index

Every one of the frozen questions, and the facet whose trace (above) answers it. Combine with the per-facet trace to reach the raw source for any question.

| facet | questions |
|-------|-----------|
| `core` | Q01, TM-08 |
| `timeline` | Q13, AC-07, FS-10, TM-01, TM-04 |
| `sessions` | Q04, IA-03, IA-04, IA-05, SL-03 |
| `login` | Q02, Q03, IA-01, IA-02, IA-06, IA-07, IA-08, IA-09, IA-11, PV-02, PV-12 |
| `privilege` | Q05, EX-03, PV-01, PV-03, PV-06, PV-08 |
| `root_activity` | Q06, PV-05, PV-07, PV-09, SP-08, TM-05, TM-07 |
| `commands` | Q07, EX-01, EX-02, EX-04, EX-05, EX-06, EX-07, EX-08, EX-09, EX-10, PV-04, SP-03, SP-04, SP-09, SP-10, SP-11, TM-02 |
| `files` | Q08, AC-13, FS-01, FS-02, FS-03, FS-04, FS-05, FS-06, FS-07, FS-08, FS-09, FS-11, FS-14, NW-11, SP-02, SP-05, SP-12 |
| `accounts` | Q09, AC-01, AC-02, AC-03, AC-04, AC-06, AC-08, AC-09 |
| `groups` | Q10, AC-05 |
| `packages` | Q11, PK-01, PK-02, PK-03, PK-04, PK-05, PK-06, PK-07, PK-08, PK-09, PK-10, PK-11 |
| `network` | Q12, NW-01, NW-02, NW-03, NW-05, NW-07, NW-13 |
| `persistence` | SP-01, SP-06, SP-07, SP-13, SP-14, SP-15, SP-16 |
| `authorization` | AC-10, AC-11, AC-12, IA-12, PV-10, PV-11 |
| `system_lifecycle` | SL-01, SL-02, SL-04, SL-05, SL-06, SL-07, SL-08, SL-09, SL-10, SL-11, SL-12, SL-13, SL-14 |
| `pkg_policy` | PK-13, PK-14, PK-15, PK-16 |
| `process_tree` | EX-11 |
| `shell_history` | EX-12 |
| `firewall` | NW-09 |
| `file_access` | FS-12 |
| `netflow` | NW-04, NW-06, NW-14 |
| `netlogs` | NW-08, NW-10, NW-12, NW-15 |
| `host_changes` | TM-03 |
| `attribution` | TM-06 |
| `concurrent` | TM-13 |
| `file_integrity` | FS-13 |
| `origin_reputation` | IA-10 |
| `evidence` | Q14, TM-09 |
| `gaps` | Q15, PK-12, TM-10, TM-11, TM-12, TM-14 |
