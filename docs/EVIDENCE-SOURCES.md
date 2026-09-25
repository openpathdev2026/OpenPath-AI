# OpenPath-AI — Evidence Sources

Generated from `openpath/catalog.py`. Each catalog question maps to the raw
sources that substantiate it. If a source is not used by any question, it does
not belong in the product.

| # | Question | Sources | Certified |
|---|----------|---------|-----------|
| Q01 | What did USER do during the last 24 hours? | all facets federated | ✅ |
| Q02 | When did USER log in during the last 24 hours? | wtmp; journal.sshd; auth | ✅ |
| Q03 | Where did USER log in from? | wtmp; journal.sshd; auth; btmp | ✅ |
| Q04 | What sessions did USER have during the last 24 hours? | wtmp | ✅ |
| Q05 | Did USER become root during the last 24 hours? | auditd; auth | ✅ |
| Q06 | What did USER do as root during the last 24 hours? | auditd (execve); auth (sudo) | ✅ |
| Q07 | What commands did USER run during the last 24 hours? | auditd (execve); auth (sudo) | ✅ |
| Q08 | What files did USER modify during the last 24 hours? | auditd (PATH+SYSCALL / watch) | ✅ |
| Q09 | What accounts did USER create or modify during the last 24 hours? | auditd (ADD/DEL_USER); auth | ✅ |
| Q10 | What groups did USER create or modify during the last 24 hours? | auditd (ADD/DEL_GROUP); auth | ✅ |
| Q11 | What packages did USER install or remove during the last 24 hours? | dnf.rpm.log / dpkg.log; exec correlation | ✅ |
| Q12 | What network activity did USER perform during the last 24 hours? | auditd (connect/bind + SOCKADDR) | ✅ |
| Q13 | What did USER do before and after the incident? | all facets federated (pivoted with --around) | ✅ |
| Q14 | What evidence supports what USER did during the last 24 hours? | every claim's cited source record | ✅ |
| Q15 | What could OpenPath not determine about USER during the last 24 hours? | coverage ledger + blind spots + horizons | ✅ |

## Collectors and the questions they power

| Collector | Powers |
|-----------|--------|
| `wtmp` (binary struct utmp) | Q02 Q03 Q04 (sessions/login) |
| `btmp` (failed logins) | Q03 (where from, incl. failed attempts) |
| `journal.sshd` | Q02 Q03 (ssh auth method/origin) |
| `auth` (auth.log / secure) | Q02 Q03 Q05 Q06 Q07 Q09 Q10 (auditd-less hosts) |
| `auditd` (audit.log + rules) | Q05 Q06 Q07 Q08 Q09 Q10 Q12 |
| `packages` (dnf.rpm/dpkg) | Q11 |

Every collector is used by at least one certified question. There is no source
in the codebase that no catalog question requires.
