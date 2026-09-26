# OpenPath-AI — Production Question Contract

The full set of user-facing forensic questions OpenPath commits to, each with a
**certification status**. Generated from the evidence-surface catalog build; the
count is an output of the analysis, not a target. Certification is a property of
a question, not a limit on which questions exist.

**153 questions** — CERTIFIED 151, CONTRACTED 2.

- **CERTIFIED** — wired and proven end-to-end today (see `catalog.py` + the
  conformance suite). Complete *within the covered evidence scope*, never absolute.
- **CONTRACTED** — in the contract, but its deterministic evidence path /
  certification is not complete. Each names the collector or subsystem it needs.
  A CONTRACTED question is never answered from thin air.

> The deterministic **query/filter/pivot subsystem** (`openpath/query.py`) and the
> **persistence-state collector** (cron/at, systemd units/timers, linger, legacy
> startup) are now shipped and proven. The remaining CONTRACTED questions are
> grouped below by the collector or subsystem each still needs; that list is the
> roadmap to the full contract.

## CERTIFIED (answerable today)

| ID | Question | Facet | Sources |
|----|----------|-------|---------|
| Q01 | What did {user} do during the window? (federated overview) | `core` | auditd, wtmp, packages, auth, journal.sshd, btmp |
| Q02 | When did {user} log in during the window? | `login` | wtmp, journal.sshd, auth, btmp |
| Q03 | Where did {user} log in from (source IP / remote host)? | `login` | wtmp, journal.sshd, auth, btmp |
| Q04 | What login sessions did {user} have, and how long did each last? | `sessions` | wtmp |
| Q05 | Did {user} become root or switch identity (su / sudo) to gain elevated privilege? | `privilege` | auditd, auth, wtmp, journal.sshd |
| Q06 | What did {user} do while operating as root (full extent: commands, files, network)? | `root_activity` | auditd(execve audit rule), auth, wtmp |
| Q07 | What commands did {user} run during the window? | `commands` | auditd(execve audit rule), auth, wtmp |
| Q08 | What files did {user} create, modify, or delete during the window? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| Q09 | What user accounts did {user} create or modify during the window? | `accounts` | auditd, auth, wtmp |
| Q10 | What groups did {user} create, delete, or modify during the window? | `groups` | auditd, auth, wtmp |
| Q11 | What packages did {user} install, remove, or upgrade during the window? | `packages` | packages, auditd(execve audit rule), auth |
| Q12 | What network activity did {user} perform overall (both outbound and inbound) during the window? | `network` | auditd(connect audit rule), auditd(bind audit rule) |
| Q13 | What did {user} do in the hour before and after a given incident time? | `timeline` | auditd, wtmp, auth, packages, journal.sshd, btmp |
| Q14 | What evidence supports what {user} did during the window? | `evidence` | auditd, wtmp, journal.sshd, auth, packages, btmp |
| Q15 | What could OpenPath NOT determine about {user} in this window? | `gaps` | auditd, wtmp, btmp, journal.sshd, auth, packages |
| AC-01 | Did {user} delete or remove any accounts (anti-forensics, or disabling a defender's account)? | `accounts` | auditd, auth, wtmp |
| AC-02 | Did {user} alter an existing account's properties (login shell, home directory, UID, or primary group)? | `accounts` | auditd, auth, wtmp |
| AC-03 | Did {user} set or change the password of any account? | `accounts` | auditd, auth |
| AC-04 | Did {user} lock or unlock any account? | `accounts` | auditd, auth |
| AC-05 | Did {user} add any account (including themselves) to a privileged group such as sudo, wheel, docker, or root? | `groups` | auditd, auth, wtmp |
| AC-06 | Did {user} attempt an account or group change that failed or was denied? | `accounts` | auditd, auth |
| AC-07 | When did {user} make each account/group change, relative to their login and to the incident? | `timeline` | auditd, auth, wtmp |
| AC-08 | Is the account {user} newly created within the window (and was it subsequently removed)? | `accounts` | auditd, auth |
| AC-09 | Were any account or group changes made without an attributable human (daemon, cron, or unattended process)? | `accounts` | auditd |
| AC-10 | Who is currently a member of a privileged group (sudo, wheel, docker, root)? | `authorization` | /etc/group + /etc/passwd state collector, auditd |
| AC-11 | Which accounts are currently locked, passwordless, or have password/expiry anomalies (e.g. a second UID-0 account)? | `authorization` | shadow-state + faillock/faillog collector, auditd |
| AC-12 | Did {user} install an SSH authorized_key (or otherwise grant key-based access) for any account? | `authorization` | authorized_keys / SSH-authz collector, auditd(host-wide file-change rule) |
| AC-13 | Did {user} modify authentication or authorization configuration (/etc/pam.d, /etc/nsswitch.conf, /etc/security)? | `files` | PAM / auth-config collector, auditd(host-wide file-change rule) |
| EX-01 | Did {user} run a specific command or binary (curl, wget, nc, base64, a named tool)? | `commands` | auditd(execve audit rule), auth |
| EX-02 | What ordinary (non-sudo) commands did {user} run? | `commands` | auditd(execve audit rule), wtmp |
| EX-03 | What did {user} run specifically via sudo? | `privilege` | auditd(execve audit rule), auth, wtmp |
| EX-04 | What were the full command-line arguments (argv) of {user}'s commands, not just the binary? | `commands` | auditd(execve audit rule), auth |
| EX-05 | From which working directory (cwd) did {user} run each command? | `commands` | auditd(execve audit rule) |
| EX-06 | From what terminal/TTY did {user} run commands (interactive vs non-interactive)? | `commands` | auditd(execve audit rule), wtmp |
| EX-07 | Did {user} execute binaries from suspicious/non-standard locations (/tmp, /dev/shm, home dirs)? | `commands` | auditd(execve audit rule), auth |
| EX-08 | When did {user} run commands — first, last, and the execution timeline? | `commands` | auditd(execve audit rule), auth, wtmp |
| EX-09 | Did {user}'s command executions succeed or fail (and which errored)? | `commands` | auditd(execve audit rule) |
| EX-10 | What scripts or interpreted programs did {user} execute (python/bash/perl scripts)? | `commands` | auditd(execve audit rule), auth |
| EX-11 | What was the parent process and process ancestry of {user}'s commands (reconstruct the process tree)? | `process_tree` | auditd(execve audit rule), wtmp |
| EX-12 | What commands did {user} type in their shell (interactive shell history)? | `shell_history` | shell-history collector, auditd(execve audit rule) |
| FS-01 | Did {user} modify sensitive system or authentication config files (/etc/passwd, /etc/shadow, /etc/sudoers(.d), /etc/ssh/sshd_config, /etc/pam.d, cron files)? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| FS-02 | Did {user} create or drop files in suspicious/transient locations (/tmp, /dev/shm, /var/tmp, web roots, another user's home)? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| FS-03 | Did {user} delete, truncate, or wipe files (data destruction / evidence removal)? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| FS-04 | Did {user} tamper with logs or the audit trail itself (delete/truncate /var/log/*, wtmp/btmp, or audit rule files)? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| FS-05 | Did {user} weaken file permissions or ownership (chmod/chown) — world-writable, or setuid/setgid? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule) |
| FS-06 | Did {user} rename or move files (masquerading, hiding artifacts, swapping a trojaned binary) — from where to where? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule) |
| FS-07 | Did {user} create symbolic or hard links (link-based evasion, watch bypass, symlink attacks)? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule) |
| FS-08 | What files did {user} modify while acting as root (via sudo/su)? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| FS-09 | Who modified a specific file (e.g. who changed /etc/shadow or /etc/sudoers)? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| FS-10 | When did {user}'s file changes occur relative to the incident (file-activity timeline)? | `timeline` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| FS-11 | Did file changes occur with no interactive session behind them (unattended, automated, cron/daemon-driven)? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| FS-12 | What sensitive files did {user} read or access, not modify (reading /etc/shadow, SSH keys, credential stores)? | `file_access` | auditd(file watch/modify audit rule) |
| FS-14 | Did {user} modify files they do not own or that fall outside their normal scope (another user's data, system-owned files)? | `files` | filesystem ownership/state baseline collector, auditd(host-wide file-change rule) |
| IA-01 | How did {user} authenticate (password, public key, or another method)? | `login` | journal.sshd, auth |
| IA-02 | Did {user} fail to authenticate — how many failed attempts, and from where? | `login` | btmp, journal.sshd, auth |
| IA-03 | Did {user} access the host locally (console) or remotely (network)? | `sessions` | wtmp, journal.sshd |
| IA-04 | Does {user} currently have any open/active session? | `sessions` | wtmp |
| IA-05 | Did {user} have concurrent/overlapping sessions from different origins (account sharing/hijack)? | `sessions` | wtmp, journal.sshd |
| IA-06 | Who accessed this host during the window (all authenticated principals)? | `login` | wtmp, journal.sshd, auth, btmp |
| IA-07 | Which remote IPs/hosts connected and authenticated to this host? | `login` | wtmp, journal.sshd, auth, btmp |
| IA-08 | Were there brute-force or password-spraying attempts against the host or {user}? | `login` | btmp, journal.sshd, auth, wtmp |
| IA-09 | Did {user} log in at unusual or off-hours times? | `login` | wtmp, journal.sshd, auth |
| IA-11 | Did authentication occur to a non-SSH service (VPN, display manager, cockpit, or other PAM service)? | `login` | general (non-sshd) journald collector, wtmp |
| IA-12 | Is SSH root login or password authentication even permitted on this host (auth policy)? | `authorization` | sshd config collector, journal.sshd, auth |
| NW-01 | What outbound network connections did {user} make, and to which destinations and ports? | `network` | auditd(connect audit rule) |
| NW-02 | Did {user} connect to a specific known-bad IP, host, or port (IOC match)? | `network` | auditd(connect audit rule), auditd(bind audit rule) |
| NW-03 | Did {user} exhibit anomalous outbound behavior — beaconing, connection fan-out (scanning), or rare/high ports? | `network` | auditd(connect audit rule) |
| NW-04 | How much data did {user} transfer, and is there evidence of data exfiltration over a connection? | `netflow` | netflow / conntrack byte-accounting collector, auditd(connect audit rule) |
| NW-05 | What ports or sockets did {user} bind or listen on — any new listeners or backdoors? | `network` | auditd(bind audit rule) |
| NW-06 | What remote hosts established inbound connections to this system (source IPs of incoming flows)? | `netflow` | connection-tracking / inbound-flow collector, journal.sshd, auth, auditd(bind audit rule) |
| NW-07 | What local (UNIX-domain) socket connections did {user} make — e.g. to docker.sock or D-Bus/systemd sockets? | `network` | auditd(connect audit rule) |
| NW-08 | What DNS lookups / name-resolution queries did {user} perform (C2 domains, DNS tunneling)? | `netlogs` | DNS/resolver query-log collector, auditd(connect audit rule) |
| NW-09 | What firewall / packet-filter rules are in place, and did {user} change them? | `firewall` | nftables/iptables collector, auditd(execve audit rule) |
| NW-10 | Were {user}'s connections (or an attacker's) blocked or dropped by the firewall? | `netlogs` | firewall-log collector |
| NW-11 | Did {user} change network interface, routing, VPN, or NetworkManager configuration? | `files` | NetworkManager/VPN collector, auditd(execve audit rule), auditd(host-wide file-change rule) |
| NW-12 | What external web or cloud resources did {user} access — which URLs, hosts, or cloud API actions? | `netlogs` | web/proxy/cloud audit-log collector, auditd(connect audit rule) |
| NW-13 | Can {user} be affirmatively cleared of network activity (an evidenced negative)? | `network` | auditd(connect audit rule), auditd(bind audit rule) |
| NW-14 | Over what protocol/transport did {user} communicate (TCP vs UDP, or a raw socket)? | `netflow` | auditd(connect audit rule) |
| NW-15 | When did a given connection open and close, and how long was it held open (persistent channel)? | `netlogs` | connection-close/disconnect collector, auditd(connect audit rule) |
| PK-01 | What software changed on this host overall during the window, and when — regardless of who did it? | `packages` | packages |
| PK-02 | When was a specific package (e.g. nginx) installed, upgraded, or removed on this host? | `packages` | packages |
| PK-03 | What version was a package upgraded or downgraded from and to? | `packages` | packages |
| PK-04 | Who installed or removed package X? | `packages` | auditd(execve audit rule), auth, packages |
| PK-05 | By what command, and via sudo or as root directly, did {user} change packages? | `packages` | auditd(execve audit rule), auth, packages |
| PK-06 | Did {user} remove or purge any packages (possible defense evasion / removal of security tooling)? | `packages` | packages, auditd(execve audit rule), auth |
| PK-07 | Was any package downgraded (a rollback to a potentially vulnerable version)? | `packages` | packages, auditd(execve audit rule), auth |
| PK-08 | Did {user} install a specific suspicious or known-bad package (e.g. netcat, a cryptominer)? | `packages` | packages, auditd(execve audit rule), auth |
| PK-09 | Did {user} apply system upgrades or patches (and were they security updates)? | `packages` | packages, auditd(execve audit rule), auth |
| PK-10 | Which package changes were NOT initiated by an interactive user (dnf-automatic, unattended-upgrades, cron)? | `packages` | packages, auditd(execve audit rule), auth |
| PK-11 | Can we confirm {user} installed or changed NO software during the window (evidenced negative)? | `packages` | packages, auditd(execve audit rule), auth |
| PK-12 | How far back does package-change history extend, and did OpenPath lose or fail to parse any package records? | `gaps` | packages |
| PK-13 | From what repository or source was a package installed (trusted distro repo vs a rogue repo)? | `pkg_policy` | dnf history / repository collector, packages |
| PK-14 | Does OpenPath capture software changes made through yum, zypper, pacman, snap, or flatpak — or only dnf(rpm) and dpkg? | `pkg_policy` | PackageCollector extension, packages |
| PK-15 | Are any packages pinned, held, or version-locked (blocking updates / freezing a vulnerable version)? | `pkg_policy` | package-state collector |
| PK-16 | Were any unsigned or untrusted-key packages installed (GPG signature verification)? | `pkg_policy` | signature/integrity collector, packages |
| PV-01 | How did {user} escalate — via sudo, su, or a direct root login? | `privilege` | auditd, auth, wtmp, journal.sshd |
| PV-02 | Did anyone log in directly as root, and from where? | `login` | wtmp, journal.sshd, auth |
| PV-03 | Did {user} attempt to escalate and get denied or fail (wrong password, not in sudoers, command not allowed)? | `privilege` | auditd, auth |
| PV-04 | What exact commands did {user} run as root (full command lines)? | `commands` | auditd(execve audit rule), auth |
| PV-05 | Did {user} obtain an interactive root shell (sudo -i, sudo su -, sudo bash)? | `root_activity` | auditd(execve audit rule), auth |
| PV-06 | Did {user} run commands as another (non-root) identity via sudo -u / su, and as whom? | `privilege` | auditd(execve audit rule), auth |
| PV-07 | Which escalation event led to which subsequent root actions (link a sudo/su to the activity it enabled)? | `root_activity` | auditd(execve audit rule) |
| PV-08 | When did {user} first and last escalate, and how often (escalation timeline)? | `privilege` | auditd, auth, wtmp |
| PV-09 | Did {user} gain root by means other than sudo/su — a setuid binary, an exploit, or an LPE? | `root_activity` | auditd(execve audit rule) |
| PV-10 | What is {user} permitted to do via sudo, and who else is allowed to escalate on this host (sudoers policy)? | `authorization` | sudoers collector, auditd, auth |
| PV-11 | Did someone grant {user} sudo rights or modify the sudoers policy (privilege persistence)? | `authorization` | sudoers collector, auditd(host-wide file-change rule), auth |
| PV-12 | Was {user}'s account locked out, or did failed escalations trip a faillock/pam_tally threshold? | `login` | faillock/faillog collector, btmp, auditd, auth |
| SL-01 | When did this host last boot / come up? | `system_lifecycle` | wtmp, auditd |
| SL-02 | How many times did the host reboot during the window, and how frequently? | `system_lifecycle` | wtmp |
| SL-03 | Did a reboot terminate {user}'s active login session, and at what time? | `sessions` | wtmp |
| SL-04 | When did the host shut down or power off, and was it a clean shutdown or a crash? | `system_lifecycle` | general (non-sshd) journald collector, wtmp |
| SL-05 | Was there an unexpected or unplanned reboot / crash during the window? | `system_lifecycle` | general (non-sshd) journald / kmsg collector, wtmp, auditd, auth |
| SL-06 | What were the host's uptime windows — how long was it up between reboots, and current uptime? | `system_lifecycle` | wtmp |
| SL-07 | Was the host offline or down during any part of the window (a blind interval where nothing could be recorded)? | `system_lifecycle` | wtmp |
| SL-08 | Who initiated the reboot or shutdown? | `system_lifecycle` | auditd(execve audit rule), auth, wtmp |
| SL-09 | Why did the system reboot — kernel panic, OOM, watchdog, power loss, a kernel/package update, or an admin action? | `system_lifecycle` | general (non-sshd) journald / kmsg collector, packages, auditd, auth |
| SL-10 | What kernel was the host running, and did the kernel change (installed and/or booted) during the window? | `system_lifecycle` | wtmp, packages |
| SL-11 | What systemd services / units started or stopped during the window? | `system_lifecycle` | general (non-sshd) journald collector |
| SL-12 | Did any service crash, fail, or restart repeatedly (flapping) during the window? | `system_lifecycle` | general (non-sshd) journald collector |
| SL-13 | Did the host boot into an unusual target/mode (rescue, emergency, single-user), or did the default boot target change? | `system_lifecycle` | general (non-sshd) journald collector, systemd-unit collector, auditd(host-wide file-change rule) |
| SL-14 | Was the system clock or time zone changed during the window (timestamp tampering)? | `system_lifecycle` | wtmp, auditd, auditd(execve audit rule), auth |
| SP-01 | What cron and at scheduled jobs are currently configured on this host, and which are attributable to {user}? | `persistence` | cron/at collector, auditd(execve audit rule), auditd, auth |
| SP-02 | Did {user} modify any cron configuration files (user crontab, /etc/crontab, /etc/cron.d, /etc/cron.* run-parts)? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| SP-03 | Did {user} run crontab or at commands to schedule tasks (crontab -e, crontab -, at, batch)? | `commands` | auditd(execve audit rule), auth, wtmp |
| SP-04 | Did {user} enable or disable any services or timers to persist across reboot (systemctl enable/disable, chkconfig, update-rc.d)? | `commands` | auditd(execve audit rule), auth, wtmp |
| SP-05 | Did {user} create, modify, or drop-in a systemd unit (.service/.socket/.timer/.path or a drop-in under /etc/systemd/system, /run/systemd/system, or ~/.config/systemd/user)? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| SP-06 | Did {user} create or change any systemd timer, and what schedule does it fire on? | `persistence` | systemd-unit collector, auditd(host-wide file-change rule), auditd(execve audit rule), auditd |
| SP-07 | What services and timers are currently enabled to start at boot, and which did {user} configure? | `persistence` | systemd-unit collector, auditd(execve audit rule), auditd, auth |
| SP-08 | What commands were executed by scheduled tasks (cron/at/systemd timers) as root during the window, and can any be tied to {user}? | `root_activity` | auditd(execve audit rule), auth, wtmp |
| SP-09 | Did {user} start, stop, or restart any service (systemctl start/stop/restart, or the service command)? | `commands` | auditd(execve audit rule), auth, wtmp |
| SP-10 | Did {user} create transient units or scheduled one-off runs via systemd-run (--on-calendar / --scope)? | `commands` | auditd(execve audit rule), auth, wtmp |
| SP-11 | Did {user} mask/unmask units or change the default boot target (systemctl mask/unmask, set-default, isolate)? | `commands` | auditd(execve audit rule), auth, wtmp |
| SP-12 | Did {user} modify legacy startup files (/etc/rc.local, /etc/init.d, /etc/rc.d, upstart /etc/init) for boot persistence? | `files` | auditd(host-wide file-change rule), auditd(file watch/modify audit rule), wtmp |
| SP-13 | Did {user} install user-level systemd units (~/.config/systemd/user) or enable lingering to persist without an active login? | `persistence` | systemd-unit collector, auditd(execve audit rule), auditd(host-wide file-change rule), auditd |
| SP-14 | Did {user} establish ANY persistence mechanism during the window, across cron, at, systemd units/timers, and startup config? | `persistence` | cron collector, systemd-unit collector, auditd(execve audit rule), auditd(host-wide file-change rule), auditd, auth, wtmp |
| SP-15 | Can we confirm {user} did NOT install or alter any persistence in the window (a clean-bill scoped negative)? | `persistence` | cron collector, systemd-unit collector, auditd(execve audit rule), auditd(host-wide file-change rule), auditd, auth |
| SP-16 | What persistence-related actions did {user} take immediately before and after the incident? | `persistence` | auditd, auditd(execve audit rule), auditd(host-wide file-change rule), auth, wtmp |
| TM-01 | Give me a full chronological timeline of everything {user} did in the window, in order. | `timeline` | auditd, wtmp, auth, packages, journal.sshd, btmp |
| TM-02 | What did {user} do during a specific login session (the session on tty X that started at T)? | `commands` | wtmp, auditd, auth, journal.sshd, packages |
| TM-03 | What changed on the host between time T1 and T2 (across all users)? | `host_changes` | auditd, wtmp, packages, auth, journal.sshd, btmp |
| TM-04 | When did {user} first and last appear in the window, and how long were they active (dwell time)? | `timeline` | wtmp, auditd, auth, journal.sshd, packages, btmp |
| TM-05 | Was unattributable activity caused by a scheduled task or service (cron/systemd timer/unit), and which one? | `root_activity` | cron/timer/unit collector, auditd |
| TM-06 | Which of {user}'s recorded actions are attributable to them with high confidence, and how? | `attribution` | auditd, auth, packages, wtmp, journal.sshd |
| TM-07 | Who is the human responsible for a specific action (a command, file change, connection, or account/group change), across sudo/su? | `root_activity` | auditd, auth, wtmp, journal.sshd |
| TM-08 | What activity on this host cannot be attributed to any human (daemon/service, cron/boot-time, or unset loginuid)? | `core` | auditd, wtmp |
| TM-09 | What is the exact provenance of one fact — which log, offset, and raw record does it come from? | `evidence` | auditd, wtmp, journal.sshd, auth, packages, btmp |
| TM-10 | Is this host instrumented to answer forensic questions about {user} over the window (readiness / coverage)? | `gaps` | auditd, wtmp, btmp, journal.sshd, auth, packages |
| TM-11 | How far back does the evidence reach for {user} — does coverage actually span the incident time? | `gaps` | wtmp, auditd, auth, packages, btmp, journal.sshd |
| TM-12 | Were any evidence records dropped, truncated, or unparseable (is the record set intact)? | `gaps` | auditd, wtmp, btmp, journal.sshd, auth, packages |
| TM-13 | What were OTHER users doing around the time of {user}'s action (concurrent/lateral activity)? | `concurrent` | auditd, wtmp, auth, packages, journal.sshd, btmp |
| TM-14 | Were there periods when {user} was demonstrably present but their activity is invisible to us? | `gaps` | wtmp, auth, auditd, journal.sshd |

## CONTRACTED (roadmap)

### Needs: file-integrity / content-baseline collector (AIDE/tripwire DB, content-capturing FIM, backup/snapshot diffs, or git/etckeeper history of /etc)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| FS-13 | What exactly changed inside a modified file (content, before/after diff, which lines/keys)? | NEW:file_integrity | auditd records syscall metadata (path/op/actor/time), never file bytes — no content, hashes, size deltas, or line-level diff anywhere in ... |

### Needs: geo/threat-intel enrichment + historical login baseline store (and cloud/web/proxy ingestion for access that never hits a local login carrier)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| IA-10 | Did a login originate from a new, geographically unexpected, or known-malicious IP? | NEW:origin_reputation | Raw origin IPs are CERTIFIED as origins; the new/geo/malicious classification is entirely unmodeled; 24h window gives no baseline. |
