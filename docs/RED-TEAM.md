# OpenPath-AI — Red-Team Evidence Reviews

Question certification proves an answer *can* be produced. Red-team review proves the
answer *cannot quietly be wrong*. It is a permanent process, not a one-time gate.

## The discipline

For every certified question, do not ask "does the answer look correct?" Ask:

> **What evidence would make this answer wrong — and can OpenPath tell?**

Enumerate every path that could produce the observed activity, then check, for each,
whether OpenPath **distinguishes** it, **attributes it correctly but cannot name the
mechanism**, or **cannot see it at all**. Any path OpenPath cannot handle is either
fixed or **disclosed** — never left as a silent overclaim. A question is "fully
certified" only when every enumerated path is in one of those states on the record.

This is the same principle the tool applies to its own answers (soundness +
disclosure), turned on the *catalog*.

## Worked review: "How did USER become root?" (privilege / EX-05, Q05)

The paths a human uses to reach root, and what OpenPath does with each. WHO (which
principal) and HOW (the mechanism) are judged separately — attribution can be certain
while the mechanism is not.

| Escalation path | WHO (attribution) | HOW (mechanism) | Status | Test |
|-----------------|-------------------|-----------------|--------|------|
| `sudo <cmd>` | base user, by `auid` | proven — a sudo record backs it | **distinguished** | `test_sudo_path_is_attributed_and_method_evidenced` |
| `su` / `su -` | base user, by `auid` | proven — a su session record | **distinguished** | `test_su_path_is_attributed` |
| `sudo -i` / `sudo su` | base user, by `auid` | seen as sudo + a root shell; the `-i`/`su`-under-sudo nuance is not separately labelled | attributed; mechanism = "sudo" | (covered by sudo path) |
| direct root login (`ssh root@`, console) | root login itself, `auid 0` | the login session is the origin | **distinguished** (not blamed on a base user) | `test_direct_root_login_is_distinguished_from_escalation` |
| cron / systemd as root (no login uid) | none — unattributable | daemon/scheduler, no human | **distinguished** (disclosed, not blamed) | `test_cron_root_is_unattributable_not_a_human` |
| setuid-root binary | base user, by `auid` | **NOT proven as sudo** — no escalation record exists | attributed WHO; HOW **disclosed as unproven** | `test_setuid_escalation_attributes_who_but_cannot_name_the_method` |
| `pkexec` (Polkit) | base user, by `auid` | same as setuid — no sudo/su record; pkexec not separately parsed | attributed WHO; HOW **disclosed as unproven** | same test |
| exploit / LPE to root (same `auid`) | base user, by `auid` | indistinguishable from setuid without extra evidence | attributed WHO; HOW **disclosed as unproven** | same finding |
| container escape to host root | — | host auditd may not see the escape path | **out of scope** (disclosed) | — |

### The honest finding

- **Attribution (WHO) is robust.** Across sudo, su, sudo -i, setuid, pkexec, and LPE,
  the root action is attributed to the base user by the immutable `auid`, which no
  in-session identity change alters. Direct root logins and daemon/cron root are
  distinguished and never misattributed to a human.
- **Mechanism (HOW) is only asserted when an escalation record exists.** A root
  action carrying a user's `auid` but **no** sudo/su record (setuid-root, pkexec, an
  LPE exploit) is reported as "escalated by some means" with **`escalation = None`** —
  OpenPath does not fabricate a sudo it cannot see. The `--trace` output shows exactly
  this: the root action attributed to the user, with no escalation record beneath it.
- **Consequence for certification:** Q05 is CERTIFIED for *who became root*, with the
  *mechanism* certified only when its record is present. This boundary is disclosed
  here and in the contract's Q05 blind-spots ("Setuid/exploit root not counted as
  escalation here").

## Applying the discipline to the rest of the catalog

The same enumerate-and-check pass is owed to every question family. High-value next
reviews (each an enumerate-the-paths exercise like the one above):

- **Files (FS):** create / delete / rename / move / chmod / chown / truncate / append
  / in-place overwrite — which produce a watched syscall vs. which are invisible
  without a specific rule (in-place `write` to an existing file is the known gap).
- **Network (NW):** connect / bind / listen / accept / raw sockets / DNS — which need
  which audit rule; no bytes/URL without enrichment.
- **Persistence (SP):** cron / at / systemd unit / systemd timer / rc.local / profile
  scripts / linger — the persistence collector enumerates these as current state.
- **Authentication (IA):** password / key / kerberos / LDAP / SSSD / console / sudo
  chains — which carry an origin/method and which do not.

Each review's result belongs in this document as another matrix, and any path found
indistinguishable becomes a disclosed limitation in the contract, not a silent gap.
