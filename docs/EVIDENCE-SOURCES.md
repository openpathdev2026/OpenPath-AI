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
| `persistence` (cron/at, systemd units/timers, linger, legacy startup) | SP-01 SP-06 SP-07 SP-13 SP-14 SP-15 |
| `authz` (group/sudoers/shadow, ~/.ssh/authorized_keys, sshd_config) | AC-10 AC-11 AC-12 PV-10 PV-11 IA-12 |
| `journald` (general journal: shutdown/service/crash/clock/boot-target) | SL-04 SL-05 SL-09 SL-11 SL-12 SL-13 SL-14 |

Boot/reboot history (SL-01/02/06/07/08/10) is reconstructed by the
`system_lifecycle` facet from the `EventType.BOOT` records `wtmp` already emits,
plus the audited reboot command (who initiated it) — no dedicated collector.

Every collector is used by at least one certified question. There is no source
in the codebase that no catalog question requires.

## Evidentiary tiers (ranked by value to an investigation)

Sources are not equal. OpenPath ranks them by SOC evidentiary value, so a question
degrades gracefully when a low-tier source is missing but stays honest about what a
high-tier one carries. When audit and wtmp disagree, audit is authoritative.

| Tier | Role | OpenPath sources | Answers |
|------|------|------------------|---------|
| 0 | Identity / attribution (WHO / HOW / WHEN) | `auditd`, `auth`, `journal.sshd` | who acted, how they authenticated; `auid` survives sudo/su |
| 1 | Activity (WHAT ran / files touched) | `auditd` (EXECVE/PATH/CWD), `auth` (sudo-only) | commands, files, root actions |
| 2 | System state changes (WHAT changed) | `packages`, `auditd` (ADD/DEL user/group), `auth` | software, accounts, groups |
| 2 | Persistence state (WHAT is configured to auto-run) | `persistence` (cron/at, systemd units/timers, linger, rc.local), `auditd`/`auth` (establishment acts) | scheduled jobs, enabled units, boot persistence |
| 2 | Authorization state (WHO holds privilege) | `authz` (group/sudoers/shadow, authorized_keys, sshd_config), `auditd`/`auth` (grant-change acts) | privileged group membership, sudo grants, locked/passwordless accounts, SSH key access, SSH auth policy |
| 4 | Host lifecycle (WHEN up/down, WHY) | `wtmp` (BOOT), `journald` (shutdown/service/crash/clock), `auditd` (reboot command) | boot/reboot/uptime, clean vs crash, service transitions, kernel, clock changes |
| 3 | Network (WHERE from / to) | `auditd` (connect/bind + SOCKADDR), `auth`/`journal.sshd` (ssh origin) | egress/ingress, remote origin |
| 4 | Session corroboration (SUPPORTING) | `wtmp`, `btmp` | confirms a login happened / from where; session-duration intervals; failed logins |

`auditd` spans Tiers 0-3 and is the backbone; `auth` is the audit-absent fallback
across the same tiers (sudo-scoped for activity); `wtmp`/`btmp` are Tier 4
corroboration, rarely the primary carrier. Not modeled yet (disclosed as standing
gaps by the Gaps question): cron/systemd/service state, firewall/VPN/cloud/proxy
logs, and non-sshd journald.

Per-question source **roles** (primary / partial / supporting / optional) and the
resulting confidence are defined in `openpath/catalog.py` and explained in
`LIMITATIONS.md`.
