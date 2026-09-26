# OpenPath-AI — Evidence Surface

_Generated 2026-09-26T05:50:02.857713+00:00 by `scripts/gen_evidence_surface.py` — regenerate to re-verify._

The exact evidence surface, derived from the shipped collectors. This is a production artifact: OpenPath's answers are only ever as good as the evidence below, and every claim it makes cites one of these sources.

## Sources

| # | source | collector | reads (under --data-root) | capture | EventTypes emitted | role | tested |
|---|--------|-----------|---------------------------|---------|--------------------|------|--------|
| 1 | `wtmp` | WtmpCollector | `var/log/wtmp.1`, `var/log/wtmp` | live | `SESSION`, `BOOT` | primary | yes |
| 2 | `btmp` | BtmpCollector | `var/log/btmp.1`, `var/log/btmp` | live | `LOGIN` | primary | yes |
| 3 | `journal.sshd` | SshdJournalCollector | `var/log/openpath/journal-sshd.jsonl`, `var/log/openpath/journal-sshd.json`, `var/log/journal-sshd.jsonl` | live / export | `SSH_AUTH` | primary | yes |
| 4 | `auditd` | AuditdCollector | `var/log/audit/audit.log.4`, `var/log/audit/audit.log.3`, `var/log/audit/audit.log.2`, `var/log/audit/audit.log.1` (+1) | live | `EXEC`, `NETWORK`, `FILE_CHANGE`, `FILE_READ`, `PRIVILEGE_ESCALATION`, `ACCOUNT_CHANGE`, `GROUP_CHANGE` | primary | yes |
| 5 | `auth` | SyslogAuthCollector | `var/log/auth.log.1`, `var/log/auth.log`, `var/log/secure.1`, `var/log/secure` | live | `PRIVILEGE_ESCALATION`, `SSH_AUTH`, `EXEC`, `ACCOUNT_CHANGE`, `GROUP_CHANGE` | primary | yes |
| 6 | `packages` | PackageCollector | `var/log/dnf.rpm.log.4`, `var/log/dnf.rpm.log.3`, `var/log/dnf.rpm.log.2`, `var/log/dnf.rpm.log.1` (+3) | live | `PACKAGE_CHANGE` | primary | yes |
| 7 | `persistence` | PersistenceCollector | _(dynamic)_ | live | `PERSISTENCE` | enrichment | yes |
| 8 | `authz` | AuthzCollector | _(dynamic)_ | live | `AUTHZ` | enrichment | yes |
| 9 | `journald` | GeneralJournaldCollector | `var/log/openpath/journal.jsonl`, `var/log/openpath/journal.json`, `var/log/journal.jsonl` | live / export | `SYSTEM` | enrichment | yes |
| 10 | `pkgpolicy` | PkgPolicyCollector | _(dynamic)_ | live | `PKG_POLICY` | enrichment | yes |
| 11 | `shell_history` | ShellHistoryCollector | _(dynamic)_ | live | `SHELL_HISTORY` | enrichment | yes |
| 12 | `firewall` | FirewallCollector | _(dynamic)_ | live | `FIREWALL` | enrichment | yes |
| 13 | `conntrack` | ConntrackCollector | `proc/net/nf_conntrack`, `var/log/openpath/conntrack.txt` | live | `NETFLOW` | enrichment | yes |
| 14 | `netlogs` | NetLogsCollector | `var/log/openpath/dns.log`, `var/log/dnsmasq.log`, `var/log/openpath/firewall.log`, `var/log/squid/access.log` (+2) | live | `NETLOG` | enrichment | yes |
| 15 | `file_integrity` | FileIntegrityCollector | `var/log/openpath/file-diffs.jsonl`, `var/log/openpath/file-diffs.json` | live | `FILE_DIFF` | enrichment | yes |
| 16 | `ip_reputation` | IpReputationCollector | `var/log/openpath/ip-reputation.json`, `var/log/openpath/ip-reputation.jsonl` | live | `OTHER` | enrichment | yes |

**tested** = exercised by the conformance suite AND by `tests/live` against the real `/` (every source's status + capture_mode is asserted valid there).

## Mandatory vs optional

**No source is mandatory.** OpenPath never requires a source to be present; its absence is a disclosed gap, never a crash and never a false negative. Sources divide by *role*:

- **primary** — back the wired core question set (sessions, login, privilege, commands, files, accounts, packages, network, evidence, gaps). If all are absent, OpenPath answers nothing affirmatively but discloses that fully.
- **enrichment** — extend the contract (persistence, authorization, system lifecycle, package policy, shell history, firewall, netflow, network logs, file integrity, origin reputation). Each is independently optional.

## Failure-mode behavior (uniform, tested)

| condition | behavior | proven by |
|-----------|----------|-----------|
| source **absent** | status `ABSENT`; the dependent question degrades to UNANSWERABLE with a named remedy — never a false "nothing happened" | bare-host disclosure across every facet (`TestBareHost*` / disclosure tests) |
| source **present but unreadable** (permission) | status `UNREADABLE` with a remedy; dependent question UNANSWERABLE, not a false negative | `TestResilience.test_auditd_permission_denied_is_unreadable_not_false_negative` |
| **rotation** mid-history | rotated `.1`/`.2` read oldest-first; an event split across the boundary is reunited; a real retention shortfall is a disclosed horizon gap | `test_event_split_across_rotation_is_reunited`, `horizon_shortfalls()` |
| record **undecodable** | counted in `unparseable`; surfaced as a conservation gap — a record never vanishes silently | `TestEvidenceConservation`, live `test_conservation_no_silent_drops_on_real_data` |
| source **out of horizon** (predates window) | status `OUT_OF_HORIZON`; a horizon gap with a remedy | `horizon_shortfalls()` |

**EventType vocabulary (22):** `BOOT`, `LOGIN`, `SESSION`, `SSH_AUTH`, `PRIVILEGE_ESCALATION`, `EXEC`, `FILE_CHANGE`, `FILE_READ`, `FILE_DIFF`, `ACCOUNT_CHANGE`, `GROUP_CHANGE`, `PACKAGE_CHANGE`, `PKG_POLICY`, `PERSISTENCE`, `AUTHZ`, `SYSTEM`, `SHELL_HISTORY`, `FIREWALL`, `NETWORK`, `NETFLOW`, `NETLOG`, `OTHER`.
