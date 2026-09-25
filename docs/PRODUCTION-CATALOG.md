# OpenPath-AI — Production Question Contract

The full set of user-facing forensic questions OpenPath commits to, each with a
**certification status**. Generated from the evidence-surface catalog build; the
count is an output of the analysis, not a target. Certification is a property of
a question, not a limit on which questions exist.

**153 questions** — CERTIFIED 15, CONTRACTED 138.

- **CERTIFIED** — wired and proven end-to-end today (see `catalog.py` + the
  conformance suite). Complete *within the covered evidence scope*, never absolute.
- **CONTRACTED** — in the contract, but its deterministic evidence path /
  certification is not complete. Each names the collector or subsystem it needs.
  A CONTRACTED question is never answered from thin air.

> The largest single unblock is a **query/filter/pivot subsystem** (~77 questions):
> the router answers whole-facet questions today, not filtered/pivoted projections
> ("which X", "who did Y", by path/name/time). That subsystem, plus the named
> collectors below, is the roadmap from 15 certified to the full contract.

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

## CONTRACTED (roadmap)

### Needs: query/filter/pivot subsystem (projection over an existing facet)  (77)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| AC-01 | Did {user} delete or remove any accounts (anti-forensics, or disabling a defender's account)? | accounts | A create-then-delete throwaway is reconstructable only if BOTH records are in-horizon; unattributed on auth-only hosts absent a sudo user... |
| AC-02 | Did {user} alter an existing account's properties (login shell, home directory, UID, or primary group)? | accounts | auth has NO usermod parser — a non-sudo usermod is invisible on an auth-only host; the specific attribute changed is only in the raw op= ... |
| AC-03 | Did {user} set or change the password of any account? | accounts | Shows WHOSE (acct) and WHO (auid) but never the value; self-service vs admin reset only by comparing acct to actor; chpasswd/newusers bul... |
| AC-04 | Did {user} lock or unlock any account? | accounts | ACCT_LOCK/UNLOCK are auditd-only; auth-only sees a lock only if via sudo passwd -l/usermod -L; the account's CURRENT lock state (shadow !... |
| AC-05 | Did {user} add any account (including themselves) to a privileged group such as sudo, wheel, docker, or root? | groups | auth has NO gpasswd/usermod parser (membership grant visible only via a sudo exec); the precise member↔group tuple is only in raw op=/acc... |
| AC-06 | Did {user} attempt an account or group change that failed or was denied? | accounts | auth._account/_group hardcode res='success' with no failed-account parser, so the only auth failure signal is a denied sudo of the admin ... |
| AC-07 | When did {user} make each account/group change, relative to their login and to the incident? | timeline | auth traditional timestamps year-inferred vs auditd epoch-exact, so cross-source ordering within the same second can be ambiguous. |
| AC-08 | Is the account {user} newly created within the window (and was it subsequently removed)? | accounts | An account created before the retention horizon appears pre-existing; a directory/LDAP account never shows local creation events yet exis... |
| EX-01 | Did {user} run a specific command or binary (curl, wget, nc, base64, a named tool)? | commands | A tool renamed or invoked via an interpreter (python -c) evades a name filter — match exe path too; no binary hashing so a trojaned same-... |
| EX-02 | What ordinary (non-sudo) commands did {user} run? | commands | No fallback: on an auth-only host ('full command auditing' always False) ordinary execution is a disclosed blind spot, never a negative. ... |
| EX-03 | What did {user} run specifically via sudo? | commands | Strong PARTIAL on auth-only (via_sudo EXEC from COMMAND=; denied sudo reported FAILED, never run). sudo policy (who MAY escalate) not mod... |
| EX-04 | What were the full command-line arguments (argv) of {user}'s commands, not just the binary? | commands | argv from EXECVE only; PROCTITLE (parsed-but-unused) is the omitted fallback, so truncated/self-rewritten argv degrades to exe/comm; env ... |
| EX-05 | From which working directory (cwd) did {user} run each command? | commands | cwd needs the CWD record in the SYSCALL group; the auth-only synthesized sudo EXEC carries no cwd at all. |
| EX-06 | From what terminal/TTY did {user} run commands (interactive vs non-interactive)? | commands | auth fallback has no tty; tty=(none) does not by itself prove automation; tty→session mapping relies on wtmp. |
| EX-07 | Did {user} execute binaries from suspicious/non-standard locations (/tmp, /dev/shm, home dirs)? | commands | A binary run via an interpreter has exe=python — filter argv too; auth sudo exe is a bare name, unreliable for path filtering; no hashing... |
| EX-08 | When did {user} run commands — first, last, and the execution timeline? | commands | Traditional auth.log timestamps are year-inferred; rotation/retention truncates the horizon; sub-second ordering relies on the audit serial. |
| EX-09 | Did {user}'s command executions succeed or fail (and which errored)? | commands | base_attrs.success carries only whether execve() itself succeeded (captured but not surfaced/filtered); the executed PROGRAM's exit code ... |
| EX-10 | What scripts or interpreted programs did {user} execute (python/bash/perl scripts)? | commands | Interpreter-internal behaviour beyond further execve/audited syscalls is unseen; a script piped via stdin shows argv=[python] with the bo... |
| FS-01 | Did {user} modify sensitive system or authentication config files (/etc/passwd, /etc/shadow, /etc/sudoers(.d), /etc/ssh/sshd_config, /etc/pam.d, cron files)? | files | Confirms THAT and WHEN and by whom, not WHAT changed inside (no content diff) — a one-line edit and a rewrite look identical. |
| FS-02 | Did {user} create or drop files in suspicious/transient locations (/tmp, /dev/shm, /var/tmp, web roots, another user's home)? | files | Creation captured; subsequent pure-content writes into the file are not (unless watched); file type/content/hash not captured, so a websh... |
| FS-03 | Did {user} delete, truncate, or wipe files (data destruction / evidence removal)? | files | Records that a delete/truncate occurred on a path, not the deleted content or prior size; an overwrite via fresh create may surface as CR... |
| FS-05 | Did {user} weaken file permissions or ownership (chmod/chown) — world-writable, or setuid/setgid? | files | The FACT of a chmod/chown is certified, but the resulting mode bits / new owner (world-writable, setuid, chown-to-root) live in the cited... |
| FS-06 | Did {user} rename or move files (masquerading, hiding artifacts, swapping a trojaned binary) — from where to where? | files | The FACT of a rename is certified, but _file_event surfaces a SINGLE target path — the source→dest pair is in the citation (both PATH rec... |
| FS-07 | Did {user} create symbolic or hard links (link-based evasion, watch bypass, symlink attacks)? | files | The surfaced path may be the link, not its target (single-path limitation); a hard link to a watched file that then bypasses a -w watch i... |
| FS-08 | What files did {user} modify while acting as root (via sudo/su)? | files | Root file writes with unset loginuid (cron/boot/daemon) are recorded but unattributable — must not be blamed on the user. |
| FS-09 | Who modified a specific file (e.g. who changed /etc/shadow or /etc/sudoers)? | files | Writes with unset loginuid unattributable by design; reverse uid→name depends on passwd history; a numeric-only loginuid reports as uid:N. |
| FS-10 | When did {user}'s file changes occur relative to the incident (file-activity timeline)? | timeline | Granularity/completeness inherit every files blind spot (missed in-place writes, watch scope, audit horizon). |
| FS-12 | What sensitive files did {user} read or access, not modify (reading /etc/shadow, SSH keys, credential stores)? | files | Reads captured ONLY when a read-perm watch (-w -p r) fires, and even then typed FILE_CHANGE op=openat (read vs write not distinguished); ... |
| IA-01 | How did {user} authenticate (password, public key, or another method)? | login | Method exists ONLY for SSH; console/tty/display-manager logins carry no method anywhere; wtmp-only host has none. Discloses 'sshd journal... |
| IA-02 | Did {user} fail to authenticate — how many failed attempts, and from where? | login | btmp is a supporting (non-certifying) carrier for failures; empty-btmp ambiguity; no lockout/threshold state; non-SSH PAM failures beyond... |
| IA-03 | Did {user} access the host locally (console) or remotely (network)? | sessions | Empty ut_host on some network logins can mask remote origin; physical console vs local pseudo-terminal not always separable. |
| IA-04 | Does {user} currently have any open/active session? | sessions | 'Open' reflects the end of the wtmp log, not a real-time check; a crashed session looks open until a boot closes it. |
| IA-05 | Did {user} have concurrent/overlapping sessions from different origins (account sharing/hijack)? | sessions | Intervals+origins are CERTIFIED from wtmp, but the shipped facet does NOT compute overlap/simultaneity — the concurrency verdict is analy... |
| IA-06 | Who accessed this host during the window (all authenticated principals)? | login | Only accounts recorded by modeled carriers appear; daemon/service auth outside sshd invisible; identities name-based (no auid). |
| IA-07 | Which remote IPs/hosts connected and authenticated to this host? | login | No geo/reputation; local logins have no IP; connections dropped at a firewall never reach these logs (firewall unmodeled). |
| IA-09 | Did {user} log in at unusual or off-hours times? | login | Login instants are CERTIFIED but 'unusual/off-hours' requires a behavioral baseline the tool does not hold — the anomaly verdict is analy... |
| NW-01 | What outbound network connections did {user} make, and to which destinations and ports? | network | No bytes/volume, no transport (TCP/UDP), no close/duration; destination is the resolved IP only (never hostname/URL/SNI); AF_UNIX/unknown... |
| NW-02 | Did {user} connect to a specific known-bad IP, host, or port (IOC match)? | network | Domain-name IOCs are not matchable (only the post-resolution IP:port is recorded) — the indicator must be supplied as an IP; a contact be... |
| NW-03 | Did {user} exhibit anomalous outbound behavior — beaconing, connection fan-out (scanning), or rare/high ports? | network | Reclassified from the generated CERTIFIED: raw connects are certified but the shipped facet does NOT score beaconing/fan-out/rare-port pa... |
| NW-05 | What ports or sockets did {user} bind or listen on — any new listeners or backdoors? | network | bind SOCKADDR is the LOCAL bind address, not a remote peer; listen() recorded only with a -S listen rule or if observed; a listener opene... |
| NW-07 | What local (UNIX-domain) socket connections did {user} make — e.g. to docker.sock or D-Bus/systemd sockets? | network | Only the socket path is recorded, not the identity of the process listening on the other end; abstract (leading-null) names render awkwar... |
| NW-13 | Can {user} be affirmatively cleared of network activity (an evidenced negative)? | network | Non-syscall flows (firewall-dropped, DNS-only, proxied web) are out of scope, so the negative is bounded to audited connect/bind syscalls... |
| PK-01 | What software changed on this host overall during the window, and when — regardless of who did it? | packages | Only dnf.rpm.log and dpkg.log; yum.log/zypper/pacman/snap/flatpak show nothing; horizon bounded by present rotations. |
| PK-02 | When was a specific package (e.g. nginx) installed, upgraded, or removed on this host? | packages | History bounded by retention; dnf gives no structured prior version; the log never records the repo the version came from. |
| PK-03 | What version was a package upgraded or downgraded from and to? | packages | dpkg carries version_from/to; dnf.rpm.log carries a single NEVRA string with NO structured prior version — recovering dnf 'from' versions... |
| PK-04 | Who installed or removed package X? | packages | 30-min window + first-match: a transaction >30min after its invoking exec is unattributed and any pkg-manager exec (even a read-only 'dnf... |
| PK-05 | By what command, and via sudo or as root directly, did {user} change packages? | packages | Only the manager exec is captured, not shell wrappers/scripts; same 30-min correlation hazards; apt/term.log session context unread. |
| PK-06 | Did {user} remove or purge any packages (possible defense evasion / removal of security tooling)? | packages | A package removed via an unmodeled manager is invisible; removing the audit/logging package can blind subsequent evidence (a downstream c... |
| PK-07 | Was any package downgraded (a rollback to a potentially vulnerable version)? | packages | dnf gives no structured from-version to prove direction beyond the verb; whether the target is actually vulnerable needs advisory data (d... |
| PK-08 | Did {user} install a specific suspicious or known-bad package (e.g. netcat, a cryptominer)? | packages | A package installed by an unmodeled manager, from source, or via snap/flatpak/pip is invisible; the log does not record the originating r... |
| PK-11 | Can we confirm {user} installed or changed NO software during the window (evidenced negative)? | packages | An install via an unmodeled manager or from source would not appear, so the negative is scoped to dnf(rpm)/dpkg; retention horizon disclo... |
| PK-12 | How far back does package-change history extend, and did OpenPath lose or fail to parse any package records? | gaps | Can only report retention for rotations present on disk; a log rotated-and-deleted beyond .4 (dnf)/.1 (dpkg) leaves an unknown-length bli... |
| PV-01 | How did {user} escalate — via sudo, su, or a direct root login? | privilege | 'sudo -i'/'sudo su -' surface as sudo with a shell cmd (nuance inferred from text); su-to-root vs su-to-other share tool='su' (target onl... |
| PV-02 | Did anyone log in directly as root, and from where? | privilege | Without auditd auid a root session cannot always be distinguished from an su-to-root reusing the tty; console root shows origin 'local'; ... |
| PV-03 | Did {user} attempt to escalate and get denied or fail (wrong password, not in sudoers, command not allowed)? | privilege | Counts attempts, not lockout/threshold state (faillock unmodeled); auth checks _SUDO_FAIL_HINTS before success so a denial is never repor... |
| PV-04 | What exact commands did {user} run as root (full command lines)? | commands | Without an execve rule, non-sudo root commands invisible; auth captures only the sudo COMMAND= string; prefer_primary drops auth duplicat... |
| PV-05 | Did {user} obtain an interactive root shell (sudo -i, sudo su -, sudo bash)? | root_activity | OpenPath does not semantically flag 'this exec was an interactive shell' — analyst reads it from argv; children of an auth-only sudo shel... |
| PV-06 | Did {user} run commands as another (non-root) identity via sudo -u / su, and as whom? | commands | switched (auid≠uid) count is CERTIFIED, but no facet field enumerates the TARGET account (derive from euid+uid→name); auth _sudo_command ... |
| PV-07 | Which escalation event led to which subsequent root actions (link a sudo/su to the activity it enabled)? | root_activity | Links by auid + recency, not kernel session id (ses) or process ancestry, so two overlapping escalations by the same user can bind an act... |
| PV-08 | When did {user} first and last escalate, and how often (escalation timeline)? | privilege | States times deterministically but does NOT judge them 'unusual' (no baseline); auth traditional timestamps year-inferred; pre-horizon es... |
| PV-09 | Did {user} gain root by means other than sudo/su — a setuid binary, an exploit, or an LPE? | root_activity | An as_root exec (auid≠uid) with NO backing escalation is a citable signal, but OpenPath cannot prove HOW euid reached 0 (setuid bit vs ca... |
| SL-03 | Did a reboot terminate {user}'s active login session, and at what time? | sessions | Captures only reboots that interrupted an OPEN session; a reboot while {user} was logged out lives in the unsurfaced BOOT stream; wtmp-only. |
| SP-03 | Did {user} run crontab or at commands to schedule tasks (crontab -e, crontab -, at, batch)? | commands | Shows the tool was invoked, not the job created or whether it succeeded; editing the spool file directly (not via crontab) is missed here... |
| SP-09 | Did {user} start, stop, or restart any service (systemctl start/stop/restart, or the service command)? | commands | A runtime action, not persistence itself; success/failure not captured; kill/D-Bus-triggered restarts bypass the systemctl exec. |
| TM-01 | Give me a full chronological timeline of everything {user} did in the window, in order. | timeline | Ordering is by timestamp only — no causal/parent-child sequencing; sub-second/clock-skewed events may misorder; non-sshd service and cron... |
| TM-02 | What did {user} do during a specific login session (the session on tty X that started at T)? | timeline | No pid→sid→session-leader lineage: concurrent same-user sessions cannot be separated; the session→action binding is by timestamp overlap ... |
| TM-03 | What changed on the host between time T1 and T2 (across all users)? | core | Only subjects discoverable from passwd or the evidence are enumerated; config/state changes with no audited syscall (cron, sudoers, firew... |
| TM-04 | When did {user} first and last appear in the window, and how long were they active (dwell time)? | timeline | First/last reflect only recorded, attributable events — earlier activity beyond retention or under a missing rule is not counted; dwell t... |
| TM-06 | Which of {user}'s recorded actions are attributable to them with high confidence, and how? | core | auid is the only true auid-centric key (survives sudo/su); auth/wtmp/journal.sshd attribute by name; packages by 30-min correlation — eac... |
| TM-07 | Who is the human responsible for a specific action (a command, file change, connection, or account/group change), across sudo/su? | root_activity | Classifies ESCALATED(auid) / DIRECT_ROOT_LOGIN(origin) / ROOT_NO_SESSION / DAEMON; unset loginuid → unattributable, never guessed; auth-o... |
| TM-08 | What activity on this host cannot be attributed to any human (daemon/service, cron/boot-time, or unset loginuid)? | core | The root-scope disclosure is CERTIFIED (RootActivityFacet counts and discloses); a comprehensive host-wide rollup of non-root daemon acti... |
| TM-09 | What is the exact provenance of one fact — which log, offset, and raw record does it come from? | evidence | Provenance is to the parsed record and its locator, not a tamper-evident hash; if the source log was altered before ingest OpenPath canno... |
| TM-10 | Is this host instrumented to answer forensic questions about {user} over the window (readiness / coverage)? | gaps | Bounded to the modeled catalog and sources; cannot flag missing instrumentation for evidence classes it has no collector for beyond the s... |
| TM-11 | How far back does the evidence reach for {user} — does coverage actually span the incident time? | gaps | A merely-quiet continuous log is treated as covering (a late first record is not a gap); horizon is per-source; assumes source timestamps... |
| TM-12 | Were any evidence records dropped, truncated, or unparseable (is the record set intact)? | gaps | Detects only records the parser SAW-but-could-not-decode; cannot detect records that never reached the log (upstream loss, rotation dropp... |
| TM-13 | What were OTHER users doing around the time of {user}'s action (concurrent/lateral activity)? | core | Only users discoverable from passwd/evidence are enumerated; correlation is temporal co-occurrence, NOT proof of coordination; no cross-h... |
| TM-14 | Were there periods when {user} was demonstrably present but their activity is invisible to us? | gaps | No facet computes 'session minus visibility' as a bounded interval; no idle-vs-active distinction within a session (no keystroke/tty-acti... |

### Needs: /etc/group + /etc/passwd state collector (current roster + primary GID)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| AC-10 | Who is currently a member of a privileged group (sudo, wheel, docker, root)? | NEW:group-state | Only membership ADDITIONS within the window are visible (Q10/GRP_MGMT); no roster is read; membership granted before the horizon is invis... |

### Needs: DNS/resolver query-log collector (systemd-resolved via general journald, dnsmasq/unbound/BIND query logs, or packet-level DNS)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| NW-08 | What DNS lookups / name-resolution queries did {user} perform (C2 domains, DNS tunneling)? | NEW:dns | Query names/answers unmodeled; only post-resolution IPs surface, and only if the resolved host was subsequently connected to; a connect t... |

### Needs: NO new collector for basic windows — needs a system_lifecycle facet pairing consecutive wtmp BOOT events. A general-journald _BOOT_ID collector would give authoritative boot-session grouping.  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-06 | What were the host's uptime windows — how long was it up between reboots, and current uptime? | NEW:system_lifecycle | Downtime between a shutdown and the next boot is not measurable (no shutdown carrier); boots lost to rotation break interval math; no _BO... |

### Needs: NO new collector for the boot half — wtmp already captures the kernel release in BOOT.attrs['kernel'] (captured-but-unused); needs a facet to surface it. Running/authoritative kernel needs general journald. The install half is answerable via the packages facet.  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-10 | What kernel was the host running, and did the kernel change (installed and/or booted) during the window? | NEW:system_lifecycle | Kernel release recorded in BOOT.attrs['kernel'] never reported; no correlation between a kernel package install and the subsequent boot; ... |

### Needs: NO new collector — needs a system_lifecycle facet to enumerate/count the wtmp BOOT events (today the engine keeps only boots[0] as first_boot).  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-02 | How many times did the host reboot during the window, and how frequently? | NEW:system_lifecycle | No facet counts BOOT events; rotation/truncation undercounts silently; reboots before wtmp's retained horizon are invisible. |

### Needs: NO new collector — wtmp already emits EventType.BOOT with a citation and the engine computes first_boot. Needs only a NEW host-level system_lifecycle FACET (and a non-subject axis) to surface it. General journald _BOOT_ID would add corroboration.  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-01 | When did this host last boot / come up? | NEW:system_lifecycle | BOOT events are collected but surfaced by no facet and excluded from _TIMELINE_TYPES; kernel version in BOOT.attrs['kernel'] never report... |

### Needs: NetworkManager/VPN collector (/etc/NetworkManager/system-connections/*, nmcli state, /etc/wireguard/*, ip route, journald NM logs)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| NW-11 | Did {user} change network interface, routing, VPN, or NetworkManager configuration? | NEW:netconfig | auditd can show nmcli/ip/wg run as commands or a write to a watched config path, but no interface/route/VPN/NM state is modeled. |

### Needs: No new external source — leaf pid/ppid/tty are already captured — but requires a NEW process-ancestry facet AND a fork/clone (and ideally exit) audit rule + syscall-table entries so fork-only intermediaries do not break lineage.  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| EX-11 | What was the parent process and process ancestry of {user}'s commands (reconstruct the process tree)? | NEW:process_tree | fork/clone syscalls are NOT in the auditd syscall tables and no facet chains pid→ppid; PID reuse; kernel-thread/daemon roots have no logi... |

### Needs: PAM / auth-config collector (/etc/pam.d/*, /etc/nsswitch.conf, /etc/security/*)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| AC-13 | Did {user} modify authentication or authorization configuration (/etc/pam.d, /etc/nsswitch.conf, /etc/security)? | NEW:auth-config | An edit is detectable only as a generic FILE_CHANGE if a watch covers the path; OpenPath cannot tell a hardening change from a backdoor (... |

### Needs: PackageCollector extension (/var/log/yum.log, /var/log/zypp/history, /var/log/pacman.log, snap/flatpak history; + apt/history.log + term.log for apt's native Requested-By)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| PK-14 | Does OpenPath capture software changes made through yum, zypper, pacman, snap, or flatpak — or only dnf(rpm) and dpkg? | NEW:package_coverage | zypper/pacman/yum are in the exec-correlation NAME set but their TRANSACTION logs are unread, so an audited 'pacman -S' has no transactio... |

### Needs: Two mostly group-b fixes: surface wtmp NEW_TIME/OLD_TIME (parsed into _Record today but dropped by both _build_sessions and _build_boots) via a facet, AND map auditd clock syscalls (settimeofday/clock_settime/adjtimex) + TIME_* records in the existing auditd collector.  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-14 | Was the system clock or time zone changed during the window (timestamp tampering)? | NEW:system_lifecycle | Dedicated clock-change evidence is captured-but-unused or unmapped; the only path today is a weak command proxy (audited date/timedatectl... |

### Needs: auditd socket() syscall collection (record the socket type/protocol at creation) — within auditd's reach but not currently parsed or gated  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| NW-14 | Over what protocol/transport did {user} communicate (TCP vs UDP, or a raw socket)? | network | socket() is never collected, so SOCK_STREAM/DGRAM/RAW is unknown; only connect/bind + SOCKADDR (family+port) available and port is a hint... |

### Needs: authorized_keys / SSH-authz collector (~/.ssh/authorized_keys, sshd AuthorizedKeysFile drop-ins)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| AC-12 | Did {user} install an SSH authorized_key (or otherwise grant key-based access) for any account? | NEW:ssh-authz | A write is detectable only as a generic FILE_CHANGE if an auditd watch covers the path; the key type/fingerprint, the account authorized,... |

### Needs: both a cron collector and a systemd-unit collector; a dedicated persistence facet federating their state with the auditd/auth act-level proxies  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-14 | Did {user} establish ANY persistence mechanism during the window, across cron, at, systemd units/timers, and startup config? | NEW:persistence | Aggregates every per-surface blind spot: no current-state enumeration, no payload/definition content, no symlink/generator/preset visibil... |

### Needs: connection-close events (auditd socket close/shutdown syscall collection, or wiring up the parsed-but-unused sshd Disconnect/Connection-closed parsing)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| NW-15 | When did a given connection open and close, and how long was it held open (persistent channel)? | NEW:socketclose | The sshd _DISCONNECT_RE is defined but UNUSED so even SSH session-close is not emitted; close/shutdown syscalls not collected; only the o... |

### Needs: connection-tracking / netflow / firewall-accept collector (conntrack table, nftables/iptables accept logging, netflow/IPFIX)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| NW-06 | What remote hosts established inbound connections to this system (source IPs of incoming flows)? | NEW:conntrack | accept/accept4 peer identity is not reliably decoded and accept is not a gated instrument; SSH inbound origins ARE recoverable via journa... |

### Needs: cron + systemd-unit collector to identify WHICH job/unit spawned each process and thus attribute the automated activity  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-08 | What commands were executed by scheduled tasks (cron/at/systemd timers) as root during the window, and can any be tied to {user}? | root_activity | auditd captures the commands but scheduler-spawned processes have unset loginuid → disclosed as root_no_session/daemon (unattributable); ... |

### Needs: cron + systemd-unit collectors (a full state inventory) plus in-horizon act auditing  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-15 | Can we confirm {user} did NOT install or alter any persistence in the window (a clean-bill scoped negative)? | NEW:persistence | Without state collectors a true clean bill is impossible — the strongest honest statement is a scope-bounded 'no observed act', which nev... |

### Needs: cron + systemd-unit collectors to place STATE changes (not just acts) on the timeline  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-16 | What persistence-related actions did {user} take immediately before and after the incident? | timeline | Only ACTS with a syscall/log footprint appear; state transitions (a unit becoming enabled, a timer's next fire) are not placeable without... |

### Needs: cron collector to recover the resulting job content  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-02 | Did {user} modify any cron configuration files (user crontab, /etc/crontab, /etc/cron.d, /etc/cron.* run-parts)? | files | FILE_CHANGE carries path+op only, never the new content, so the actual scheduled command is invisible; no auth fallback for file changes. |

### Needs: cron/at & systemd-timer collector to positively ATTRIBUTE unattended writes to a specific job (today disclosed only as unattributable)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| FS-11 | Did file changes occur with no interactive session behind them (unattended, automated, cron/daemon-driven)? | files | Can say 'no human loginuid behind this write' but cannot name WHICH job/timer/service; wtmp absent weakens the covering-session distinction. |

### Needs: cron/at collector (/var/spool/cron/*, /etc/crontab, /etc/cron.{d,daily,hourly,weekly,monthly}/*, /etc/anacrontab, /var/spool/at/*, atq, at/cron.{allow,deny})  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-01 | What cron and at scheduled jobs are currently configured on this host, and which are attributable to {user}? | NEW:scheduled_tasks | The auditd proxy shows a cron file was edited or crontab/at was run but not the resulting job/payload; system cron.d/anacron entries name... |

### Needs: cron/at/systemd-timer & unit-state collector to reconstruct WHICH scheduler/service caused an unattributed change  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| AC-09 | Were any account or group changes made without an attributable human (daemon, cron, or unattended process)? | accounts | Detecting an unattributed change does not identify its scheduler/service; on auth-only hosts ALL account lines are unattributed so the si... |

### Needs: cron/at/systemd-timer collector + general (non-sshd) journald collector to positively name the automation  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| PK-10 | Which package changes were NOT initiated by an interactive user (dnf-automatic, unattended-upgrades, cron)? | packages | Can enumerate transactions with no correlating user exec and disclose them as automated, but cannot name the scheduler/service that ran t... |

### Needs: cron/timer/unit collector (/var/spool/cron/*, /etc/crontab, /etc/cron.*, /etc/at.*, systemctl list-timers/list-unit-files, /etc/systemd/system/*, CRON lines in general journald) correlating schedule/exec against the audited action's time/pid  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| TM-05 | Was unattributable activity caused by a scheduled task or service (cron/systemd timer/unit), and which one? | NEW:scheduled_tasks | auditd today marks such actions ROOT_NO_SESSION/DAEMON (correctly refusing to blame a human) but cannot name the job, schedule, or persis... |

### Needs: dnf history / repository collector (/var/log/dnf.log, dnf history DB, /etc/yum.repos.d/*, /etc/apt/sources.list*, apt/history.log)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| PK-13 | From what repository or source was a package installed (trusted distro repo vs a rogue repo)? | NEW:package_provenance | dnf.rpm.log/dpkg.log carry only NEVRA/version, never the repository or origin URL — a malicious package from a rogue repo is indistinguis... |

### Needs: dnf updateinfo / advisory-metadata collector (to classify upgrades as security fixes and map to CVE/advisory)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| PK-09 | Did {user} apply system upgrades or patches (and were they security updates)? | packages | Cannot classify which upgrades close a security advisory; the 'were they SECURITY updates' sub-question is always degraded; unattended-up... |

### Needs: faillock/faillog collector (/var/log/faillog, /var/run/faillock/*, pam_faillock/pam_tally2 threshold/deny-count/unlock-time)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| PV-12 | Was {user}'s account locked out, or did failed escalations trip a faillock/pam_tally threshold? | NEW:faillock | btmp/auditd/auth give failed ATTEMPTS and timing but never the lockout decision, threshold, or reset; cannot tell an operator-cleared loc... |

### Needs: faillog/faillock collector (lockout/threshold correlation); optionally a longer-retention baseline store for slow campaigns  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| IA-08 | Were there brute-force or password-spraying attempts against the host or {user}? | login | Raw failures+successes are cited but the tool does NOT score velocity/threshold/spray or failure→success correlation; default window miss... |

### Needs: file-integrity / content-baseline collector (AIDE/tripwire DB, content-capturing FIM, backup/snapshot diffs, or git/etckeeper history of /etc)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| FS-13 | What exactly changed inside a modified file (content, before/after diff, which lines/keys)? | NEW:file_integrity | auditd records syscall metadata (path/op/actor/time), never file bytes — no content, hashes, size deltas, or line-level diff anywhere in ... |

### Needs: filesystem ownership/state baseline collector (stat-tree snapshot: owner uid/gid, mode, inode; or FIM baseline)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| FS-14 | Did {user} modify files they do not own or that fall outside their normal scope (another user's data, system-owned files)? | NEW:fs_baseline | The WRITER is auditd-attributable and a path-prefix heuristic ('changes outside /home/{user}') is answerable, but the true OWNER of a tar... |

### Needs: firewall-log collector (nftables/iptables LOG/NFLOG output via kernel log or general journald)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| NW-10 | Were {user}'s connections (or an attacker's) blocked or dropped by the firewall? | NEW:firewall | Syscall-layer success is not network-layer success — a connect syscall observed in auditd does not mean the packet was delivered; dropped... |

### Needs: general (non-sshd) journald collector (+ NetworkManager/VPN collectors)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| IA-11 | Did authentication occur to a non-SSH service (VPN, display manager, cockpit, or other PAM service)? | NEW:general_journald | Only the sshd slice + wtmp/btmp/auth modeled; VPN/WireGuard/cockpit/GDM auth invisible except a resulting wtmp session with no service/me... |

### Needs: general journald / kmsg collector (kernel panic, OOM-killer, watchdog, and presence/absence of a clean-shutdown marker)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-05 | Was there an unexpected or unplanned reboot / crash during the window? | NEW:system_lifecycle | A reboot/shutdown command via commands facet is a weak planned-vs-unplanned proxy; no panic/clean-shutdown evidence collected; init/sched... |

### Needs: general journald / kmsg collector for panic/OOM/watchdog/clean-shutdown evidence  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-09 | Why did the system reboot — kernel panic, OOM, watchdog, power loss, a kernel/package update, or an admin action? | NEW:system_lifecycle | Only weak proxies today: a kernel package upgrade near the boot (packages) or an audited reboot command (commands); neither is correlated... |

### Needs: general journald collector (reached target rescue/emergency, kernel cmdline) and/or a systemd-state collector (default.target)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-13 | Did the host boot into an unusual target/mode (rescue, emergency, single-user), or did the default boot target change? | NEW:system_lifecycle | A files-facet proxy can show the default.target symlink changed if watched, but not which target the host actually booted into; a one-off... |

### Needs: general journald collector (systemd 'Reached target Shutdown', systemd-shutdown, 'Powering off') OR an auditd SYSTEM_SHUTDOWN emitter OR wtmp RUN_LVL handling (currently parsed but never emitted)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-04 | When did the host shut down or power off, and was it a clean shutdown or a crash? | NEW:system_lifecycle | wtmp records only BOOT_TIME (the next boot), not shutdowns; no clean-vs-crash marker; the only signal is the next reboot (itself unsurfac... |

### Needs: general journald collector (unit 'Failed with result', Result=exit-code, start-limit/flapping messages) — standing unmodeled gap  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-12 | Did any service crash, fail, or restart repeatedly (flapping) during the window? | NEW:system_lifecycle | No modeled source carries service failure/restart signals; even sshd failures beyond auth (crash/restart) are not emitted — journal.sshd ... |

### Needs: general journald collector (unit start/stop/activation messages) or a systemd-state collector — a standing unmodeled gap (only the sshd slice is read)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-11 | What systemd services / units started or stopped during the window? | NEW:system_lifecycle | A systemctl start/stop command is visible via the commands facet, but that is the invocation, not the unit's state transition, and misses... |

### Needs: geo/threat-intel enrichment + historical login baseline store (and cloud/web/proxy ingestion for access that never hits a local login carrier)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| IA-10 | Did a login originate from a new, geographically unexpected, or known-malicious IP? | NEW:origin_reputation | Raw origin IPs are CERTIFIED as origins; the new/geo/malicious classification is entirely unmodeled; 24h window gives no baseline. |

### Needs: init/startup-config collector to read script content and enumerate SysV run-level links  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-12 | Did {user} modify legacy startup files (/etc/rc.local, /etc/init.d, /etc/rc.d, upstart /etc/init) for boot persistence? | files | Content of the modified script (injected command) not captured; run-level symlink graph (/etc/rc?.d) not enumerated; vendor init scripts ... |

### Needs: netflow / conntrack byte-accounting collector (nftables counters, /proc/net or ss byte stats, netflow/IPFIX, or forward-proxy transfer logs)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| NW-04 | How much data did {user} transfer, and is there evidence of data exfiltration over a connection? | NEW:netflow | auditd records the connect syscall (that a channel opened and to where), never how many bytes flowed, in which direction, or for how long. |

### Needs: nftables/iptables collector (nft list ruleset, iptables-save/ip6tables-save, /etc/nftables.conf, ipset)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| NW-09 | What firewall / packet-filter rules are in place, and did {user} change them? | NEW:firewall | The network facet sees connect/bind syscalls only — never filter policy, chains, or whether a rule would allow/deny a flow; a rule-changi... |

### Needs: package-state collector (apt-mark showhold, /etc/apt/preferences.d/*, dnf versionlock list, /etc/dnf/plugins/versionlock.list)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| PK-15 | Are any packages pinned, held, or version-locked (blocking updates / freezing a vulnerable version)? | NEW:package_policy | Hold/lock state lives in configuration, not in the transaction logs read; OpenPath sees the resulting absence-of-upgrade only as 'no upgr... |

### Needs: service-state / general journald collector for RUNTIME audit disable (auditctl -D, systemctl stop auditd) which is NOT a file write  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| FS-04 | Did {user} tamper with logs or the audit trail itself (delete/truncate /var/log/*, wtmp/btmp, or audit rule files)? | files | Only FILE modifications of log/rule files are seen; runtime audit disable, service stop, or in-memory rule flush are not file events; a s... |

### Needs: shadow-state + faillock/faillog collector (/etc/shadow lock/passwordless/expiry; faillock)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| AC-11 | Which accounts are currently locked, passwordless, or have password/expiry anomalies (e.g. a second UID-0 account)? | NEW:shadow-state | Lock/unlock EVENTS in-window are a partial proxy; a pre-existing empty-password or !!-locked backdoor account is invisible to change-even... |

### Needs: shell-history collector (~/.bash_history, ~/.zsh_history, fish_history, incl. root; HISTTIMEFORMAT timestamps)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| EX-12 | What commands did {user} type in their shell (interactive shell history)? | NEW:shell_history | History is untrusted (editable, HISTSIZE-bounded, often timestamp-less), misses builtins vs external; process-level execution via the com... |

### Needs: signature/integrity collector (dnf.log GPG-check outcomes, rpm -V/--checksig, apt signature results, gpgcheck config)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| PK-16 | Were any unsigned or untrusted-key packages installed (GPG signature verification)? | NEW:package_integrity | A package installed with --nogpgcheck / from an untrusted key looks identical to a signed one in the transaction log — sideloading/tamper... |

### Needs: sshd config collector (/etc/ssh/sshd_config + /etc/ssh/sshd_config.d/*, effective sshd -T)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| IA-12 | Is SSH root login or password authentication even permitted on this host (auth policy)? | NEW:ssh_policy | OpenPath reads auth USE, never sshd POLICY; observed root/password logins prove a method was permitted at that moment, not the configured... |

### Needs: sudoers collector (/etc/sudoers + /etc/sudoers.d/*, runas/NOPASSWD/command allowlists, group membership)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| PV-10 | What is {user} permitted to do via sudo, and who else is allowed to escalate on this host (sudoers policy)? | NEW:sudoers | Sees sudo USE (auditd/auth), never sudo POLICY; NOPASSWD, command restrictions, runas targets, group-based grants unmodeled — an authoriz... |

### Needs: sudoers collector (before/after policy semantics); detecting the raw write is a files-facet fallback  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| PV-11 | Did someone grant {user} sudo rights or modify the sudoers policy (privilege persistence)? | NEW:sudoers | With an auditd file rule on /etc/sudoers* the FILE_CHANGE is detected and attributed by auid, but only as 'this path was modified', not t... |

### Needs: system_lifecycle facet correlating an audited reboot command with the subsequent BOOT; general journald for non-command reboots (power/watchdog/init/scheduler)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-08 | Who initiated the reboot or shutdown? | commands | Proves a reboot command was RUN, not that it caused the observed boot; a direct/scheduled reboot or a hardware/power event is unattributa... |

### Needs: system_lifecycle facet to surface down intervals (the pre-first-boot span is handled internally today via effective_start but never reported); between-reboot downtime additionally needs a shutdown carrier (general journald)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SL-07 | Was the host offline or down during any part of the window (a blind interval where nothing could be recorded)? | NEW:system_lifecycle | Only the pre-first-boot interval is accounted (and only internally, to adjust gap math); between-reboot downtime is invisible; the adjust... |

### Needs: systemd unit-state collector to confirm resulting enabled state and catch enablement done without systemctl  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-04 | Did {user} enable or disable any services or timers to persist across reboot (systemctl enable/disable, chkconfig, update-rc.d)? | commands | execve confirms the command, not that it succeeded or that the unit is now enabled; enabling by hand-creating .wants/ symlinks bypasses s... |

### Needs: systemd-unit collector (systemctl list-timers; *.timer [Timer] OnCalendar/OnBootSec/Persistent; paired *.service ExecStart)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-06 | Did {user} create or change any systemd timer, and what schedule does it fire on? | NEW:systemd_units | OnCalendar cadence and the triggered service are unmodeled today; a FILE_CHANGE on a *.timer never yields the schedule; a timer shipped i... |

### Needs: systemd-unit collector (systemctl list-unit-files --state=enabled, is-enabled, get-default; .wants/ symlink graph; SysV/chkconfig)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-07 | What services and timers are currently enabled to start at boot, and which did {user} configure? | NEW:systemd_units | Current state vs change-history differ; the proxy gives only change history within the audit horizon; symlink-based enablement, presets, ... |

### Needs: systemd-unit collector (~/.config/systemd/user/*, /etc/systemd/user/*, loginctl show-user Linger / /var/lib/systemd/linger/*)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-13 | Did {user} install user-level systemd units (~/.config/systemd/user) or enable lingering to persist without an active login? | NEW:systemd_units | Home-directory unit dirs are typically unwatched by auditd so the file proxy usually sees nothing; linger and per-user enabled state unmo... |

### Needs: systemd-unit collector to confirm resulting masked state / default target  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-11 | Did {user} mask/unmask units or change the default boot target (systemctl mask/unmask, set-default, isolate)? | commands | Resulting state not confirmed here; masking by hand-linking a unit to /dev/null bypasses systemctl and needs a file watch or unit collector. |

### Needs: systemd-unit collector to confirm the transient unit still exists / its schedule  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-10 | Did {user} create transient units or scheduled one-off runs via systemd-run (--on-calendar / --scope)? | commands | No file artifact to cross-check; whether the transient unit is still scheduled/active is not confirmable; argv shows intent, not eventual... |

### Needs: systemd-unit collector to read unit contents (ExecStart) and inventory  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| SP-05 | Did {user} create, modify, or drop-in a systemd unit (.service/.socket/.timer/.path or a drop-in under /etc/systemd/system, /run/systemd/system, or ~/.config/systemd/user)? | files | The unit's directives (ExecStart/ExecStartPre payload) are never captured — only path+op; vendor units under /usr/lib and per-user units ... |

### Needs: web/proxy/cloud audit-log collector (nginx/apache access logs, forward-proxy logs, cloud provider audit trail)  (1)

| ID | Question | Facet | Blind spots |
|----|----------|-------|-------------|
| NW-12 | What external web or cloud resources did {user} access — which URLs, hosts, or cloud API actions? | NEW:webproxy | Everything above the socket layer — HTTP host/path, TLS SNI, cloud API action/resource — is invisible; the facet shows only the TCP endpo... |
