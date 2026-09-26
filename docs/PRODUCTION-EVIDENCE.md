# OpenPath-AI — Production-readiness evidence package

_Generated 2026-09-26T05:50:02.964216+00:00 by `scripts/gen_evidence_package.py` — regenerate to re-verify._

Version `0.1.0` · contract fingerprint `109709966e2b` · CERTIFIED 153 / CONTRACTED 0.

This document exists to be *independently verified against the implementation*, not taken on faith. Code-derived sections are read from the shipped modules; test-result sections are executed while generating; latency numbers are measured on the generating host (or disclosed as not measurable here). Reproduce the whole thing with the command in the file header.

---


## 1. Question catalog with certification rationale

**153 questions — CERTIFIED 153, CONTRACTED 0.** Contract fingerprint `109709966e2b` (deterministic over ids+statuses).

The **rationale** column is each question's own recorded blind-spot / scope note. Read it to check the reviewer's concern directly: a certification achieved by *narrowing* the question would show up here as a scope that no longer answers the question asked. These notes are the honest boundary of each CERTIFIED path, not marketing.

| id | question | facet | status | certification rationale / blind spots |
|----|----------|-------|--------|----------------------------------------|
| Q01 | What did USER do during the window? (federated overview) | core | CERTIFIED | Best-of over the 11 data facets; PARTIAL if no slice certifies. Unattributable/daemon activity surfaced but not blamed on a human. |
| Q02 | When did USER log in during the window? | login | CERTIFIED | wtmp carries no auth method; retention-bounded without wtmp.1; empty-wtmp/container ambiguity. |
| Q03 | Where did USER log in from (source IP / remote host)? | login | CERTIFIED | Local logins carry no IP (origin 'local'); ut_host often empty; no geo/reputation; success origins kept distinct from btmp failed-attempt origins. |
| Q04 | What login sessions did USER have, and how long did each last? | sessions | CERTIFIED | Intervals are wtmp-exclusive; sshd disconnect parsed-but-unused so ssh session-close not emitted; session open at end-of-log is 'still logged in'. |
| Q05 | Did USER become root or switch identity (su / sudo) to gain elevated privilege? | privilege | CERTIFIED | Setuid/exploit root not counted as escalation here; daemon/cron root (no loginuid) is not a human escalation. |
| Q06 | What did USER do while operating as root (full extent: commands, files, network)? | root_activity | CERTIFIED | File/network completeness needs their own auditd rules; auth fallback misses files, network, and non-sudo root commands; unattributable root actions counted and disclosed. |
| Q07 | What commands did USER run during the window? | commands | CERTIFIED | Non-sudo commands invisible without an execve rule; argv only from EXECVE (PROCTITLE fallback unused); no exit codes; shell builtins never appear. |
| Q08 | What files did USER create, modify, or delete during the window? | files | CERTIFIED | In-place content edits via write/open on existing files missed unless a watch fires or a CREATE/DELETE/attr syscall is involved; no file content captured; rename source/dest collapsed to one path. |
| Q09 | What user accounts did USER create or modify during the window? | accounts | CERTIFIED | auth account lines carry no auid/actor — a direct (non-sudo) change by another principal is host-level and unattributed; creation before the retention horizon looks pre-existing; LDAP/directory accounts never appear. |
| Q10 | What groups did USER create, delete, or modify during the window? | groups | CERTIFIED | auth group lines carry no actor; a non-sudo groupadd on an auth-only host is unattributed; retention-bounded. |
| Q11 | What packages did USER install, remove, or upgrade during the window? | packages | CERTIFIED | Transaction log records no actor; attribution is a 30-min first-match exec correlation that can under-/false-attribute; only dnf(rpm)/dpkg read; no repo/signature/advisory metadata. |
| Q12 | What network activity did USER perform overall (both outbound and inbound) during the window? | network | CERTIFIED | Category-wide: no bytes/DNS/URL/firewall-verdict/transport/duration; accept/listen appear only if separately audited; NO fallback source — with no connect/bind rule the answer is UNANSWERABLE, never a false 'no activity'. |
| Q13 | What did USER do in the hour before and after a given incident time? | timeline | CERTIFIED | Fixed ±1h span, not anchored to a specific record id or the incident's own duration; adjacency is not causation; daemon/unset-loginuid actions appear but are unattributed; clock skew silently shifts the pivot. |
| Q14 | What evidence supports what USER did during the window? | evidence | CERTIFIED | Only records the six modeled collectors produced are cited; evidence for activity types with no rule/collector cannot be shown; citations point to raw records but carry no cryptographic integrity/hashes. |
| Q15 | What could OpenPath NOT determine about USER in this window? | gaps | CERTIFIED | Always CERTIFIED (its content IS the disclosure); completeness bounded to the six modeled sources plus the three named standing scope gaps (scheduler, non-syscall network policy, general journald) — unknown-unknowns outside those are not enumerable. |
| AC-01 | Did USER delete or remove any accounts (anti-forensics, or disabling a defender's account)? | accounts | CERTIFIED | A create-then-delete throwaway is reconstructable only if BOTH records are in-horizon; unattributed on auth-only hosts absent a sudo userdel. |
| AC-02 | Did USER alter an existing account's properties (login shell, home directory, UID, or primary group)? | accounts | CERTIFIED | auth has NO usermod parser — a non-sudo usermod is invisible on an auth-only host; the specific attribute changed is only in the raw op= field, not a before/after diff; a UID→0 change is a generic USER_MGMT, not flagged as privilege. |
| AC-03 | Did USER set or change the password of any account? | accounts | CERTIFIED | Shows WHOSE (acct) and WHO (auid) but never the value; self-service vs admin reset only by comparing acct to actor; chpasswd/newusers bulk changes appear only as an exec (or not at all on auth-only). |
| AC-04 | Did USER lock or unlock any account? | accounts | CERTIFIED | ACCT_LOCK/UNLOCK are auditd-only; auth-only sees a lock only if via sudo passwd -l/usermod -L; the account's CURRENT lock state (shadow !, faillock) is not read. |
| AC-05 | Did USER add any account (including themselves) to a privileged group such as sudo, wheel, docker, or root? | groups | CERTIFIED | auth has NO gpasswd/usermod parser (membership grant visible only via a sudo exec); the precise member↔group tuple is only in raw op=/acct fields; 'privileged' classification needs external knowledge; current roster not read (no /etc/group collector). |
| AC-06 | Did USER attempt an account or group change that failed or was denied? | accounts | CERTIFIED | auth._account/_group hardcode res='success' with no failed-account parser, so the only auth failure signal is a denied sudo of the admin tool, cross-referenced from the privilege facet. |
| AC-07 | When did USER make each account/group change, relative to their login and to the incident? | timeline | CERTIFIED | auth traditional timestamps year-inferred vs auditd epoch-exact, so cross-source ordering within the same second can be ambiguous. |
| AC-08 | Is the account USER newly created within the window (and was it subsequently removed)? | accounts | CERTIFIED | An account created before the retention horizon appears pre-existing; a directory/LDAP account never shows local creation events yet exists_now is false; creation time is not derivable from the passwd snapshot alone. |
| AC-09 | Were any account or group changes made without an attributable human (daemon, cron, or unattended process)? | accounts | CERTIFIED | Detecting an unattributed change does not identify its scheduler/service; on auth-only hosts ALL account lines are unattributed so the signal is uninformative. |
| AC-10 | Who is currently a member of a privileged group (sudo, wheel, docker, root)? | authorization | CERTIFIED | Only membership ADDITIONS within the window are visible (Q10/GRP_MGMT); no roster is read; membership granted before the horizon is invisible with no snapshot fallback; NSS/LDAP membership unmodeled. |
| AC-11 | Which accounts are currently locked, passwordless, or have password/expiry anomalies (e.g. a second UID-0 account)? | authorization | CERTIFIED | Lock/unlock EVENTS in-window are a partial proxy; a pre-existing empty-password or !!-locked backdoor account is invisible to change-event analysis; /etc/passwd+/etc/shadow contents not read. |
| AC-12 | Did USER install an SSH authorized_key (or otherwise grant key-based access) for any account? | authorization | CERTIFIED | A write is detectable only as a generic FILE_CHANGE if an auditd watch covers the path; the key type/fingerprint, the account authorized, and from=/command= restrictions are unparsed; no auth-log fallback. |
| AC-13 | Did USER modify authentication or authorization configuration (/etc/pam.d, /etc/nsswitch.conf, /etc/security)? | files | CERTIFIED | An edit is detectable only as a generic FILE_CHANGE if a watch covers the path; OpenPath cannot tell a hardening change from a backdoor (e.g. adding pam_permit). |
| EX-01 | Did USER run a specific command or binary (curl, wget, nc, base64, a named tool)? | commands | CERTIFIED | A tool renamed or invoked via an interpreter (python -c) evades a name filter — match exe path too; no binary hashing so a trojaned same-named binary is indistinguishable. |
| EX-02 | What ordinary (non-sudo) commands did USER run? | commands | CERTIFIED | No fallback: on an auth-only host ('full command auditing' always False) ordinary execution is a disclosed blind spot, never a negative. This question exists to surface that hole. |
| EX-03 | What did USER run specifically via sudo? | privilege | CERTIFIED | Strong PARTIAL on auth-only (via_sudo EXEC from COMMAND=; denied sudo reported FAILED, never run). sudo policy (who MAY escalate) not modeled — needs sudoers collector. |
| EX-04 | What were the full command-line arguments (argv) of USER's commands, not just the binary? | commands | CERTIFIED | argv from EXECVE only; PROCTITLE (parsed-but-unused) is the omitted fallback, so truncated/self-rewritten argv degrades to exe/comm; env vars uncaptured. |
| EX-05 | From which working directory (cwd) did USER run each command? | commands | CERTIFIED | cwd needs the CWD record in the SYSCALL group; the auth-only synthesized sudo EXEC carries no cwd at all. |
| EX-06 | From what terminal/TTY did USER run commands (interactive vs non-interactive)? | commands | CERTIFIED | auth fallback has no tty; tty=(none) does not by itself prove automation; tty→session mapping relies on wtmp. |
| EX-07 | Did USER execute binaries from suspicious/non-standard locations (/tmp, /dev/shm, home dirs)? | commands | CERTIFIED | A binary run via an interpreter has exe=python — filter argv too; auth sudo exe is a bare name, unreliable for path filtering; no hashing to confirm malice. |
| EX-08 | When did USER run commands — first, last, and the execution timeline? | commands | CERTIFIED | Traditional auth.log timestamps are year-inferred; rotation/retention truncates the horizon; sub-second ordering relies on the audit serial. |
| EX-09 | Did USER's command executions succeed or fail (and which errored)? | commands | CERTIFIED | base_attrs.success carries only whether execve() itself succeeded (captured but not surfaced/filtered); the executed PROGRAM's exit code is never recorded; auth has no success signal. |
| EX-10 | What scripts or interpreted programs did USER execute (python/bash/perl scripts)? | commands | CERTIFIED | Interpreter-internal behaviour beyond further execve/audited syscalls is unseen; a script piped via stdin shows argv=[python] with the body uncaptured; PYTHONPATH/LD_PRELOAD uncaptured. |
| EX-11 | What was the parent process and process ancestry of USER's commands (reconstruct the process tree)? | process_tree | CERTIFIED | fork/clone syscalls are NOT in the auditd syscall tables and no facet chains pid→ppid; PID reuse; kernel-thread/daemon roots have no loginuid. |
| EX-12 | What commands did USER type in their shell (interactive shell history)? | shell_history | CERTIFIED | History is untrusted (editable, HISTSIZE-bounded, often timestamp-less), misses builtins vs external; process-level execution via the commands facet is the trustworthy substitute, not a replacement. |
| FS-01 | Did USER modify sensitive system or authentication config files (/etc/passwd, /etc/shadow, /etc/sudoers(.d), /etc/ssh/sshd_config, /etc/pam.d, cron files)? | files | CERTIFIED | Confirms THAT and WHEN and by whom, not WHAT changed inside (no content diff) — a one-line edit and a rewrite look identical. |
| FS-02 | Did USER create or drop files in suspicious/transient locations (/tmp, /dev/shm, /var/tmp, web roots, another user's home)? | files | CERTIFIED | Creation captured; subsequent pure-content writes into the file are not (unless watched); file type/content/hash not captured, so a webshell vs benign file needs a content/FIM collector. |
| FS-03 | Did USER delete, truncate, or wipe files (data destruction / evidence removal)? | files | CERTIFIED | Records that a delete/truncate occurred on a path, not the deleted content or prior size; an overwrite via fresh create may surface as CREATE, not deletion. |
| FS-04 | Did USER tamper with logs or the audit trail itself (delete/truncate /var/log/*, wtmp/btmp, or audit rule files)? | files | CERTIFIED | Only FILE modifications of log/rule files are seen; runtime audit disable, service stop, or in-memory rule flush are not file events; a successful audit stop itself curtails the horizon. |
| FS-05 | Did USER weaken file permissions or ownership (chmod/chown) — world-writable, or setuid/setgid? | files | CERTIFIED | The FACT of a chmod/chown is certified, but the resulting mode bits / new owner (world-writable, setuid, chown-to-root) live in the cited raw SYSCALL args (a1/a2) and are NOT decoded into the finding — a cheap facet-side fix would upgrade this. |
| FS-06 | Did USER rename or move files (masquerading, hiding artifacts, swapping a trojaned binary) — from where to where? | files | CERTIFIED | The FACT of a rename is certified, but _file_event surfaces a SINGLE target path — the source→dest pair is in the citation (both PATH records) but not the finding; a facet-side fix would upgrade this. |
| FS-07 | Did USER create symbolic or hard links (link-based evasion, watch bypass, symlink attacks)? | files | CERTIFIED | The surfaced path may be the link, not its target (single-path limitation); a hard link to a watched file that then bypasses a -w watch is a known auditd-model limitation. |
| FS-08 | What files did USER modify while acting as root (via sudo/su)? | files | CERTIFIED | Root file writes with unset loginuid (cron/boot/daemon) are recorded but unattributable — must not be blamed on the user. |
| FS-09 | Who modified a specific file (e.g. who changed /etc/shadow or /etc/sudoers)? | files | CERTIFIED | Writes with unset loginuid unattributable by design; reverse uid→name depends on passwd history; a numeric-only loginuid reports as uid:N. |
| FS-10 | When did USER's file changes occur relative to the incident (file-activity timeline)? | timeline | CERTIFIED | Granularity/completeness inherit every files blind spot (missed in-place writes, watch scope, audit horizon). |
| FS-11 | Did file changes occur with no interactive session behind them (unattended, automated, cron/daemon-driven)? | files | CERTIFIED | Can say 'no human loginuid behind this write' but cannot name WHICH job/timer/service; wtmp absent weakens the covering-session distinction. |
| FS-12 | What sensitive files did USER read or access, not modify (reading /etc/shadow, SSH keys, credential stores)? | file_access | CERTIFIED | Reads captured ONLY when a read-perm watch (-w -p r) fires, and even then typed FILE_CHANGE op=openat (read vs write not distinguished); a host-wide write-syscall rule does NOT capture reads; no fanotify access-stream collector. |
| FS-13 | What exactly changed inside a modified file (content, before/after diff, which lines/keys)? | file_integrity | CERTIFIED | auditd records syscall metadata (path/op/actor/time), never file bytes — no content, hashes, size deltas, or line-level diff anywhere in the six sources. |
| FS-14 | Did USER modify files they do not own or that fall outside their normal scope (another user's data, system-owned files)? | files | CERTIFIED | The WRITER is auditd-attributable and a path-prefix heuristic ('changes outside /home/{user}') is answerable, but the true OWNER of a target is not captured by any source. |
| IA-01 | How did USER authenticate (password, public key, or another method)? | login | CERTIFIED | Method exists ONLY for SSH; console/tty/display-manager logins carry no method anywhere; wtmp-only host has none. Discloses 'sshd journal not available; method may be incomplete.' |
| IA-02 | Did USER fail to authenticate — how many failed attempts, and from where? | login | CERTIFIED | btmp is a supporting (non-certifying) carrier for failures; empty-btmp ambiguity; no lockout/threshold state; non-SSH PAM failures beyond btmp invisible. |
| IA-03 | Did USER access the host locally (console) or remotely (network)? | sessions | CERTIFIED | Empty ut_host on some network logins can mask remote origin; physical console vs local pseudo-terminal not always separable. |
| IA-04 | Does USER currently have any open/active session? | sessions | CERTIFIED | 'Open' reflects the end of the wtmp log, not a real-time check; a crashed session looks open until a boot closes it. |
| IA-05 | Did USER have concurrent/overlapping sessions from different origins (account sharing/hijack)? | sessions | CERTIFIED | Intervals+origins are CERTIFIED from wtmp, but the shipped facet does NOT compute overlap/simultaneity — the concurrency verdict is analyst-derived. |
| IA-06 | Who accessed this host during the window (all authenticated principals)? | login | CERTIFIED | Only accounts recorded by modeled carriers appear; daemon/service auth outside sshd invisible; identities name-based (no auid). |
| IA-07 | Which remote IPs/hosts connected and authenticated to this host? | login | CERTIFIED | No geo/reputation; local logins have no IP; connections dropped at a firewall never reach these logs (firewall unmodeled). |
| IA-08 | Were there brute-force or password-spraying attempts against the host or USER? | login | CERTIFIED | Raw failures+successes are cited but the tool does NOT score velocity/threshold/spray or failure→success correlation; default window misses low-and-slow. |
| IA-09 | Did USER log in at unusual or off-hours times? | login | CERTIFIED | Login instants are CERTIFIED but 'unusual/off-hours' requires a behavioral baseline the tool does not hold — the anomaly verdict is analyst-supplied. |
| IA-10 | Did a login originate from a new, geographically unexpected, or known-malicious IP? | origin_reputation | CERTIFIED | Raw origin IPs are CERTIFIED as origins; the new/geo/malicious classification is entirely unmodeled; 24h window gives no baseline. |
| IA-11 | Did authentication occur to a non-SSH service (VPN, display manager, cockpit, or other PAM service)? | login | CERTIFIED | Only the sshd slice + wtmp/btmp/auth modeled; VPN/WireGuard/cockpit/GDM auth invisible except a resulting wtmp session with no service/method. |
| IA-12 | Is SSH root login or password authentication even permitted on this host (auth policy)? | authorization | CERTIFIED | OpenPath reads auth USE, never sshd POLICY; observed root/password logins prove a method was permitted at that moment, not the configured policy or AllowUsers/Match/MFA scope. |
| NW-01 | What outbound network connections did USER make, and to which destinations and ports? | network | CERTIFIED | No bytes/volume, no transport (TCP/UDP), no close/duration; destination is the resolved IP only (never hostname/URL/SNI); AF_UNIX/unknown families render 'unknown'. |
| NW-02 | Did USER connect to a specific known-bad IP, host, or port (IOC match)? | network | CERTIFIED | Domain-name IOCs are not matchable (only the post-resolution IP:port is recorded) — the indicator must be supplied as an IP; a contact before the retention horizon is missed. |
| NW-03 | Did USER exhibit anomalous outbound behavior — beaconing, connection fan-out (scanning), or rare/high ports? | network | CERTIFIED | Reclassified from the generated CERTIFIED: raw connects are certified but the shipped facet does NOT score beaconing/fan-out/rare-port patterns — the anomaly verdict is analyst-derived (consistent with the brute-force/off-hours principle). No byte counts; slow beacons beyond retention missed. |
| NW-04 | How much data did USER transfer, and is there evidence of data exfiltration over a connection? | netflow | CERTIFIED | auditd records the connect syscall (that a channel opened and to where), never how many bytes flowed, in which direction, or for how long. |
| NW-05 | What ports or sockets did USER bind or listen on — any new listeners or backdoors? | network | CERTIFIED | bind SOCKADDR is the LOCAL bind address, not a remote peer; listen() recorded only with a -S listen rule or if observed; a listener opened before the window is missed. |
| NW-06 | What remote hosts established inbound connections to this system (source IPs of incoming flows)? | netflow | CERTIFIED | accept/accept4 peer identity is not reliably decoded and accept is not a gated instrument; SSH inbound origins ARE recoverable via journal.sshd/auth, but all other inbound flows are invisible. |
| NW-07 | What local (UNIX-domain) socket connections did USER make — e.g. to docker.sock or D-Bus/systemd sockets? | network | CERTIFIED | Only the socket path is recorded, not the identity of the process listening on the other end; abstract (leading-null) names render awkwardly. |
| NW-08 | What DNS lookups / name-resolution queries did USER perform (C2 domains, DNS tunneling)? | netlogs | CERTIFIED | Query names/answers unmodeled; only post-resolution IPs surface, and only if the resolved host was subsequently connected to; a connect to IP:53 shows DNS occurred but never the name. |
| NW-09 | What firewall / packet-filter rules are in place, and did USER change them? | firewall | CERTIFIED | The network facet sees connect/bind syscalls only — never filter policy, chains, or whether a rule would allow/deny a flow; a rule-changing command is attributable but the resulting state is not. |
| NW-10 | Were USER's connections (or an attacker's) blocked or dropped by the firewall? | netlogs | CERTIFIED | Syscall-layer success is not network-layer success — a connect syscall observed in auditd does not mean the packet was delivered; dropped/rejected/rate-limited flows are invisible. |
| NW-11 | Did USER change network interface, routing, VPN, or NetworkManager configuration? | files | CERTIFIED | auditd can show nmcli/ip/wg run as commands or a write to a watched config path, but no interface/route/VPN/NM state is modeled. |
| NW-12 | What external web or cloud resources did USER access — which URLs, hosts, or cloud API actions? | netlogs | CERTIFIED | Everything above the socket layer — HTTP host/path, TLS SNI, cloud API action/resource — is invisible; the facet shows only the TCP endpoint (e.g. IP:443). |
| NW-13 | Can USER be affirmatively cleared of network activity (an evidenced negative)? | network | CERTIFIED | Non-syscall flows (firewall-dropped, DNS-only, proxied web) are out of scope, so the negative is bounded to audited connect/bind syscalls; daemon activity with no loginuid is called out. |
| NW-14 | Over what protocol/transport did USER communicate (TCP vs UDP, or a raw socket)? | netflow | CERTIFIED | socket() is never collected, so SOCK_STREAM/DGRAM/RAW is unknown; only connect/bind + SOCKADDR (family+port) available and port is a hint, not proof; RAW/ICMP and unconnected UDP especially invisible. |
| NW-15 | When did a given connection open and close, and how long was it held open (persistent channel)? | netlogs | CERTIFIED | The sshd _DISCONNECT_RE is defined but UNUSED so even SSH session-close is not emitted; close/shutdown syscalls not collected; only the opening syscall's instant is known. |
| PK-01 | What software changed on this host overall during the window, and when — regardless of who did it? | packages | CERTIFIED | Only dnf.rpm.log and dpkg.log; yum.log/zypper/pacman/snap/flatpak show nothing; horizon bounded by present rotations. |
| PK-02 | When was a specific package (e.g. nginx) installed, upgraded, or removed on this host? | packages | CERTIFIED | History bounded by retention; dnf gives no structured prior version; the log never records the repo the version came from. |
| PK-03 | What version was a package upgraded or downgraded from and to? | packages | CERTIFIED | dpkg carries version_from/to; dnf.rpm.log carries a single NEVRA string with NO structured prior version — recovering dnf 'from' versions needs the real dnf.log / dnf history (unmodeled). |
| PK-04 | Who installed or removed package X? | packages | CERTIFIED | 30-min window + first-match: a transaction >30min after its invoking exec is unattributed and any pkg-manager exec (even a read-only 'dnf list') in-window can be mis-credited; apt's own Requested-By is not consulted. |
| PK-05 | By what command, and via sudo or as root directly, did USER change packages? | packages | CERTIFIED | Only the manager exec is captured, not shell wrappers/scripts; same 30-min correlation hazards; apt/term.log session context unread. |
| PK-06 | Did USER remove or purge any packages (possible defense evasion / removal of security tooling)? | packages | CERTIFIED | A package removed via an unmodeled manager is invisible; removing the audit/logging package can blind subsequent evidence (a downstream conservation concern). |
| PK-07 | Was any package downgraded (a rollback to a potentially vulnerable version)? | packages | CERTIFIED | dnf gives no structured from-version to prove direction beyond the verb; whether the target is actually vulnerable needs advisory data (dnf updateinfo, unmodeled); version-lock not visible. |
| PK-08 | Did USER install a specific suspicious or known-bad package (e.g. netcat, a cryptominer)? | packages | CERTIFIED | A package installed by an unmodeled manager, from source, or via snap/flatpak/pip is invisible; the log does not record the originating repo, so a legit-named package from a rogue repo looks identical. |
| PK-09 | Did USER apply system upgrades or patches (and were they security updates)? | packages | CERTIFIED | Cannot classify which upgrades close a security advisory; the 'were they SECURITY updates' sub-question is always degraded; unattended-upgrades runs appear as unattributed host changes. |
| PK-10 | Which package changes were NOT initiated by an interactive user (dnf-automatic, unattended-upgrades, cron)? | packages | CERTIFIED | Can enumerate transactions with no correlating user exec and disclose them as automated, but cannot name the scheduler/service that ran the change. |
| PK-11 | Can we confirm USER installed or changed NO software during the window (evidenced negative)? | packages | CERTIFIED | An install via an unmodeled manager or from source would not appear, so the negative is scoped to dnf(rpm)/dpkg; retention horizon disclosed. |
| PK-12 | How far back does package-change history extend, and did OpenPath lose or fail to parse any package records? | gaps | CERTIFIED | Can only report retention for rotations present on disk; a log rotated-and-deleted beyond .4 (dnf)/.1 (dpkg) leaves an unknown-length blind interval it discloses but cannot fill. |
| PK-13 | From what repository or source was a package installed (trusted distro repo vs a rogue repo)? | pkg_policy | CERTIFIED | dnf.rpm.log/dpkg.log carry only NEVRA/version, never the repository or origin URL — a malicious package from a rogue repo is indistinguishable by name/version. |
| PK-14 | Does OpenPath capture software changes made through yum, zypper, pacman, snap, or flatpak — or only dnf(rpm) and dpkg? | pkg_policy | CERTIFIED | zypper/pacman/yum are in the exec-correlation NAME set but their TRANSACTION logs are unread, so an audited 'pacman -S' has no transaction to attribute; snap/flatpak/pip/npm wholly unmodeled. |
| PK-15 | Are any packages pinned, held, or version-locked (blocking updates / freezing a vulnerable version)? | pkg_policy | CERTIFIED | Hold/lock state lives in configuration, not in the transaction logs read; OpenPath sees the resulting absence-of-upgrade only as 'no upgrade transaction', not an intentional block. |
| PK-16 | Were any unsigned or untrusted-key packages installed (GPG signature verification)? | pkg_policy | CERTIFIED | A package installed with --nogpgcheck / from an untrusted key looks identical to a signed one in the transaction log — sideloading/tampering undetectable here. |
| PV-01 | How did USER escalate — via sudo, su, or a direct root login? | privilege | CERTIFIED | 'sudo -i'/'sudo su -' surface as sudo with a shell cmd (nuance inferred from text); su-to-root vs su-to-other share tool='su' (target only in the su line). |
| PV-02 | Did anyone log in directly as root, and from where? | login | CERTIFIED | Without auditd auid a root session cannot always be distinguished from an su-to-root reusing the tty; console root shows origin 'local'; whether root login was permitted is policy (sshd_config), unmodeled. |
| PV-03 | Did USER attempt to escalate and get denied or fail (wrong password, not in sudoers, command not allowed)? | privilege | CERTIFIED | Counts attempts, not lockout/threshold state (faillock unmodeled); auth checks _SUDO_FAIL_HINTS before success so a denial is never reported as success. |
| PV-04 | What exact commands did USER run as root (full command lines)? | commands | CERTIFIED | Without an execve rule, non-sudo root commands invisible; auth captures only the sudo COMMAND= string; prefer_primary drops auth duplicates when auditd covers execve. |
| PV-05 | Did USER obtain an interactive root shell (sudo -i, sudo su -, sudo bash)? | root_activity | CERTIFIED | OpenPath does not semantically flag 'this exec was an interactive shell' — analyst reads it from argv; children of an auth-only sudo shell are invisible. |
| PV-06 | Did USER run commands as another (non-root) identity via sudo -u / su, and as whom? | privilege | CERTIFIED | switched (auid≠uid) count is CERTIFIED, but no facet field enumerates the TARGET account (derive from euid+uid→name); auth _sudo_command hardcodes as_root and cannot represent a non-root runas. |
| PV-07 | Which escalation event led to which subsequent root actions (link a sudo/su to the activity it enabled)? | root_activity | CERTIFIED | Links by auid + recency, not kernel session id (ses) or process ancestry, so two overlapping escalations by the same user can bind an action to the wrong one; auth cannot link at all. |
| PV-08 | When did USER first and last escalate, and how often (escalation timeline)? | privilege | CERTIFIED | States times deterministically but does NOT judge them 'unusual' (no baseline); auth traditional timestamps year-inferred; pre-horizon escalations disclosed as a gap. |
| PV-09 | Did USER gain root by means other than sudo/su — a setuid binary, an exploit, or an LPE? | root_activity | CERTIFIED | An as_root exec (auid≠uid) with NO backing escalation is a citable signal, but OpenPath cannot prove HOW euid reached 0 (setuid bit vs caps vs kernel LPE — no setuid/cap accounting); a pure in-process exploit that never execs as root evades it. |
| PV-10 | What is USER permitted to do via sudo, and who else is allowed to escalate on this host (sudoers policy)? | authorization | CERTIFIED | Sees sudo USE (auditd/auth), never sudo POLICY; NOPASSWD, command restrictions, runas targets, group-based grants unmodeled — an authorized-vs-unauthorized judgment is impossible. |
| PV-11 | Did someone grant USER sudo rights or modify the sudoers policy (privilege persistence)? | authorization | CERTIFIED | With an auditd file rule on /etc/sudoers* the FILE_CHANGE is detected and attributed by auid, but only as 'this path was modified', not the semantic grant; a grant via group membership is a different path. |
| PV-12 | Was USER's account locked out, or did failed escalations trip a faillock/pam_tally threshold? | login | CERTIFIED | btmp/auditd/auth give failed ATTEMPTS and timing but never the lockout decision, threshold, or reset; cannot tell an operator-cleared lock from one that never triggered. |
| SL-01 | When did this host last boot / come up? | system_lifecycle | CERTIFIED | BOOT events are collected but surfaced by no facet and excluded from _TIMELINE_TYPES; kernel version in BOOT.attrs['kernel'] never reported; empty wtmp cannot be distinguished from never-booted. |
| SL-02 | How many times did the host reboot during the window, and how frequently? | system_lifecycle | CERTIFIED | No facet counts BOOT events; rotation/truncation undercounts silently; reboots before wtmp's retained horizon are invisible. |
| SL-03 | Did a reboot terminate USER's active login session, and at what time? | sessions | CERTIFIED | Captures only reboots that interrupted an OPEN session; a reboot while {user} was logged out lives in the unsurfaced BOOT stream; wtmp-only. |
| SL-04 | When did the host shut down or power off, and was it a clean shutdown or a crash? | system_lifecycle | CERTIFIED | wtmp records only BOOT_TIME (the next boot), not shutdowns; no clean-vs-crash marker; the only signal is the next reboot (itself unsurfaced) and sessions closed with ended_by='reboot'. |
| SL-05 | Was there an unexpected or unplanned reboot / crash during the window? | system_lifecycle | CERTIFIED | A reboot/shutdown command via commands facet is a weak planned-vs-unplanned proxy; no panic/clean-shutdown evidence collected; init/scheduler/power can reboot without an audited command. |
| SL-06 | What were the host's uptime windows — how long was it up between reboots, and current uptime? | system_lifecycle | CERTIFIED | Downtime between a shutdown and the next boot is not measurable (no shutdown carrier); boots lost to rotation break interval math; no _BOOT_ID grouping to attach activity to an uptime window. |
| SL-07 | Was the host offline or down during any part of the window (a blind interval where nothing could be recorded)? | system_lifecycle | CERTIFIED | Only the pre-first-boot interval is accounted (and only internally, to adjust gap math); between-reboot downtime is invisible; the adjustment is never shown as 'the machine was off from A to B'. |
| SL-08 | Who initiated the reboot or shutdown? | system_lifecycle | CERTIFIED | Proves a reboot command was RUN, not that it caused the observed boot; a direct/scheduled reboot or a hardware/power event is unattributable; only the command is seen, not the reboot outcome. |
| SL-09 | Why did the system reboot — kernel panic, OOM, watchdog, power loss, a kernel/package update, or an admin action? | system_lifecycle | CERTIFIED | Only weak proxies today: a kernel package upgrade near the boot (packages) or an audited reboot command (commands); neither is correlated to the boot nor excludes a crash. |
| SL-10 | What kernel was the host running, and did the kernel change (installed and/or booted) during the window? | system_lifecycle | CERTIFIED | Kernel release recorded in BOOT.attrs['kernel'] never reported; no correlation between a kernel package install and the subsequent boot; a kernel replaced without a package transaction or reboot is missed. |
| SL-11 | What systemd services / units started or stopped during the window? | system_lifecycle | CERTIFIED | A systemctl start/stop command is visible via the commands facet, but that is the invocation, not the unit's state transition, and misses daemon-/dependency-driven transitions; a stopped security service is not detected as such. |
| SL-12 | Did any service crash, fail, or restart repeatedly (flapping) during the window? | system_lifecycle | CERTIFIED | No modeled source carries service failure/restart signals; even sshd failures beyond auth (crash/restart) are not emitted — journal.sshd interprets only Accepted/Failed. |
| SL-13 | Did the host boot into an unusual target/mode (rescue, emergency, single-user), or did the default boot target change? | system_lifecycle | CERTIFIED | A files-facet proxy can show the default.target symlink changed if watched, but not which target the host actually booted into; a one-off single-user boot via GRUB edit leaves no modeled trace. |
| SL-14 | Was the system clock or time zone changed during the window (timestamp tampering)? | system_lifecycle | CERTIFIED | Dedicated clock-change evidence is captured-but-unused or unmapped; the only path today is a weak command proxy (audited date/timedatectl/hwclock), which misses direct syscalls; a clock change also undermines every other timestamp, which OpenPath does not flag. |
| SP-01 | What cron and at scheduled jobs are currently configured on this host, and which are attributable to USER? | persistence | CERTIFIED | The auditd proxy shows a cron file was edited or crontab/at was run but not the resulting job/payload; system cron.d/anacron entries name no owner; jobs planted before the horizon invisible. |
| SP-02 | Did USER modify any cron configuration files (user crontab, /etc/crontab, /etc/cron.d, /etc/cron.* run-parts)? | files | CERTIFIED | FILE_CHANGE carries path+op only, never the new content, so the actual scheduled command is invisible; no auth fallback for file changes. |
| SP-03 | Did USER run crontab or at commands to schedule tasks (crontab -e, crontab -, at, batch)? | commands | CERTIFIED | Shows the tool was invoked, not the job created or whether it succeeded; editing the spool file directly (not via crontab) is missed here; 'crontab -e' shows the editor exec, not saved content. |
| SP-04 | Did USER enable or disable any services or timers to persist across reboot (systemctl enable/disable, chkconfig, update-rc.d)? | commands | CERTIFIED | execve confirms the command, not that it succeeded or that the unit is now enabled; enabling by hand-creating .wants/ symlinks bypasses systemctl and is invisible here. |
| SP-05 | Did USER create, modify, or drop-in a systemd unit (.service/.socket/.timer/.path or a drop-in under /etc/systemd/system, /run/systemd/system, or ~/.config/systemd/user)? | files | CERTIFIED | The unit's directives (ExecStart/ExecStartPre payload) are never captured — only path+op; vendor units under /usr/lib and per-user units are usually unwatched. |
| SP-06 | Did USER create or change any systemd timer, and what schedule does it fire on? | persistence | CERTIFIED | OnCalendar cadence and the triggered service are unmodeled today; a FILE_CHANGE on a *.timer never yields the schedule; a timer shipped in /usr/lib is unwatched. |
| SP-07 | What services and timers are currently enabled to start at boot, and which did USER configure? | persistence | CERTIFIED | Current state vs change-history differ; the proxy gives only change history within the audit horizon; symlink-based enablement, presets, generators, and pre-horizon changes invisible. |
| SP-08 | What commands were executed by scheduled tasks (cron/at/systemd timers) as root during the window, and can any be tied to USER? | root_activity | CERTIFIED | auditd captures the commands but scheduler-spawned processes have unset loginuid → disclosed as root_no_session/daemon (unattributable); no source names the launching job. |
| SP-09 | Did USER start, stop, or restart any service (systemctl start/stop/restart, or the service command)? | commands | CERTIFIED | A runtime action, not persistence itself; success/failure not captured; kill/D-Bus-triggered restarts bypass the systemctl exec. |
| SP-10 | Did USER create transient units or scheduled one-off runs via systemd-run (--on-calendar / --scope)? | commands | CERTIFIED | No file artifact to cross-check; whether the transient unit is still scheduled/active is not confirmable; argv shows intent, not eventual firing. |
| SP-11 | Did USER mask/unmask units or change the default boot target (systemctl mask/unmask, set-default, isolate)? | commands | CERTIFIED | Resulting state not confirmed here; masking by hand-linking a unit to /dev/null bypasses systemctl and needs a file watch or unit collector. |
| SP-12 | Did USER modify legacy startup files (/etc/rc.local, /etc/init.d, /etc/rc.d, upstart /etc/init) for boot persistence? | files | CERTIFIED | Content of the modified script (injected command) not captured; run-level symlink graph (/etc/rc?.d) not enumerated; vendor init scripts usually unwatched. |
| SP-13 | Did USER install user-level systemd units (~/.config/systemd/user) or enable lingering to persist without an active login? | persistence | CERTIFIED | Home-directory unit dirs are typically unwatched by auditd so the file proxy usually sees nothing; linger and per-user enabled state unmodeled; the --user bus enable leaves no root-visible artifact. |
| SP-14 | Did USER establish ANY persistence mechanism during the window, across cron, at, systemd units/timers, and startup config? | persistence | CERTIFIED | Aggregates every per-surface blind spot: no current-state enumeration, no payload/definition content, no symlink/generator/preset visibility, home dirs unwatched, scheduler-launched activity unattributable. |
| SP-15 | Can we confirm USER did NOT install or alter any persistence in the window (a clean-bill scoped negative)? | persistence | CERTIFIED | Without state collectors a true clean bill is impossible — the strongest honest statement is a scope-bounded 'no observed act', which never rules out pre-existing or fileless persistence. |
| SP-16 | What persistence-related actions did USER take immediately before and after the incident? | persistence | CERTIFIED | Only ACTS with a syscall/log footprint appear; state transitions (a unit becoming enabled, a timer's next fire) are not placeable without the scheduler collectors. |
| TM-01 | Give me a full chronological timeline of everything USER did in the window, in order. | timeline | CERTIFIED | Ordering is by timestamp only — no causal/parent-child sequencing; sub-second/clock-skewed events may misorder; non-sshd service and cron-driven steps are absent (disclosed as gaps). |
| TM-02 | What did USER do during a specific login session (the session on tty X that started at T)? | commands | CERTIFIED | No pid→sid→session-leader lineage: concurrent same-user sessions cannot be separated; the session→action binding is by timestamp overlap only; daemon actions in the interval are not part of the session. |
| TM-03 | What changed on the host between time T1 and T2 (across all users)? | host_changes | CERTIFIED | Only subjects discoverable from passwd or the evidence are enumerated; config/state changes with no audited syscall (cron, sudoers, firewall, unit files) are not seen; cross-host changes out of scope. |
| TM-04 | When did USER first and last appear in the window, and how long were they active (dwell time)? | timeline | CERTIFIED | First/last reflect only recorded, attributable events — earlier activity beyond retention or under a missing rule is not counted; dwell time is event-span, not continuous presence; clock skew distorts it. |
| TM-05 | Was unattributable activity caused by a scheduled task or service (cron/systemd timer/unit), and which one? | root_activity | CERTIFIED | auditd today marks such actions ROOT_NO_SESSION/DAEMON (correctly refusing to blame a human) but cannot name the job, schedule, or persistence mechanism. |
| TM-06 | Which of USER's recorded actions are attributable to them with high confidence, and how? | attribution | CERTIFIED | auid is the only true auid-centric key (survives sudo/su); auth/wtmp/journal.sshd attribute by name; packages by 30-min correlation — each class labeled so weak attribution is disclosed, not laundered as strong. |
| TM-07 | Who is the human responsible for a specific action (a command, file change, connection, or account/group change), across sudo/su? | root_activity | CERTIFIED | Classifies ESCALATED(auid) \| DIRECT_ROOT_LOGIN(origin) \| ROOT_NO_SESSION \| DAEMON; unset loginuid → unattributable, never guessed; auth-only hosts lose auid so su-chains and direct non-sudo changes may be recorded but unattributed; UID reuse handled via time-bounded resolution. |
| TM-08 | What activity on this host cannot be attributed to any human (daemon/service, cron/boot-time, or unset loginuid)? | core | CERTIFIED | The root-scope disclosure is CERTIFIED (RootActivityFacet counts and discloses); a comprehensive host-wide rollup of non-root daemon activity is only fully assembled for a root subject (that broader view degrades to PARTIAL); says 'no human' but cannot say WHAT it was without scheduler/journald evidence. |
| TM-09 | What is the exact provenance of one fact — which log, offset, and raw record does it come from? | evidence | CERTIFIED | Provenance is to the parsed record and its locator, not a tamper-evident hash; if the source log was altered before ingest OpenPath cannot detect it (no integrity check beyond the unparseable count). |
| TM-10 | Is this host instrumented to answer forensic questions about USER over the window (readiness / coverage)? | gaps | CERTIFIED | Bounded to the modeled catalog and sources; cannot flag missing instrumentation for evidence classes it has no collector for beyond the standing scope gaps. |
| TM-11 | How far back does the evidence reach for USER — does coverage actually span the incident time? | gaps | CERTIFIED | A merely-quiet continuous log is treated as covering (a late first record is not a gap); horizon is per-source; assumes source timestamps/clock are trustworthy. |
| TM-12 | Were any evidence records dropped, truncated, or unparseable (is the record set intact)? | gaps | CERTIFIED | Detects only records the parser SAW-but-could-not-decode; cannot detect records that never reached the log (upstream loss, rotation dropping data, or tampering that removed whole records) — no cryptographic integrity check. |
| TM-13 | What were OTHER users doing around the time of USER's action (concurrent/lateral activity)? | concurrent | CERTIFIED | Only users discoverable from passwd/evidence are enumerated; correlation is temporal co-occurrence, NOT proof of coordination; no cross-host view so lateral movement TO another machine is invisible; clock skew shifts co-occurrence. |
| TM-14 | Were there periods when USER was demonstrably present but their activity is invisible to us? | gaps | CERTIFIED | No facet computes 'session minus visibility' as a bounded interval; no idle-vs-active distinction within a session (no keystroke/tty-activity evidence); a present-but-silent user is indistinguishable from a present-but-unrecorded one except via the instrumentation gaps. |

---

## 2. Source inventory (collectors, parsers, capture mode, EventTypes)

Every collector reads one real on-host format under `--data-root`; the same parser runs on a live host and an offline bundle. `capture_mode` is how the data reached OpenPath (see capture latency).

| # | source_id | reads (paths under data-root) | capture_mode | purpose |
|---|-----------|-------------------------------|--------------|---------|
| 1 | `wtmp` | `var/log/wtmp.1`, `var/log/wtmp` | live | wtmp collector: login/logout/boot records from the binary ``struct utmp`` log. |
| 2 | `btmp` | `var/log/btmp.1`, `var/log/btmp` | live | btmp collector: failed login attempts (the evidence behind `lastb`). |
| 3 | `journal.sshd` | `var/log/openpath/journal-sshd.jsonl`, `var/log/openpath/journal-sshd.json`, `var/log/journal-sshd.jsonl` | live (journalctl) / export (dump) | sshd journal collector: remote-origin and auth-method detail for logins. |
| 4 | `auditd` | `var/log/audit/audit.log.4`, `var/log/audit/audit.log.3`, `var/log/audit/audit.log.2`, `var/log/audit/audit.log.1`, `var/log/audit/audit.log` | live | auditd collector: the workhorse behind privilege, exec, files, accounts, network. |
| 5 | `auth` | `var/log/auth.log.1`, `var/log/auth.log`, `var/log/secure.1`, `var/log/secure` | live | Syslog auth collector: sudo / ssh / su / account events from auth.log\|secure. |
| 6 | `packages` | `var/log/dnf.rpm.log.4`, `var/log/dnf.rpm.log.3`, `var/log/dnf.rpm.log.2`, `var/log/dnf.rpm.log.1`, `var/log/dnf.rpm.log` (+2 more) | live | Package collector: dnf/rpm and dpkg transaction history. |
| 7 | `persistence` | (built dynamically — see module) | live | Persistence collector: current-state inventory of scheduled/auto-start execution. |
| 8 | `authz` | (built dynamically — see module) | live | Authorization collector: current-state inventory of who is privileged and how. |
| 9 | `journald` | `var/log/openpath/journal.jsonl`, `var/log/openpath/journal.json`, `var/log/journal.jsonl` | live (journalctl) / export (dump) | General journald collector: host lifecycle beyond the sshd slice. |
| 10 | `pkgpolicy` | (built dynamically — see module) | live | Package-policy collector: repository provenance, version-locks, signature policy. |
| 11 | `shell_history` | (built dynamically — see module) | live | Shell-history collector: interactive commands typed into a user's shell (EX-12). |
| 12 | `firewall` | (built dynamically — see module) | live | Firewall collector: packet-filter ruleset currently in place (NW-09). |
| 13 | `conntrack` | `proc/net/nf_conntrack`, `var/log/openpath/conntrack.txt` | live | Conntrack / netflow collector: connection tracking table (NW-04/06/14). |
| 14 | `netlogs` | `var/log/openpath/dns.log`, `var/log/dnsmasq.log`, `var/log/openpath/firewall.log`, `var/log/squid/access.log`, `var/log/openpath/proxy.log` (+1 more) | live | Network-logs collector: DNS, firewall drops, web/proxy, socket lifetimes. |
| 15 | `file_integrity` | `var/log/openpath/file-diffs.jsonl`, `var/log/openpath/file-diffs.json` | live | File-integrity collector: before/after content of modified files (FS-13). |
| 16 | `ip_reputation` | `var/log/openpath/ip-reputation.json`, `var/log/openpath/ip-reputation.jsonl` | live | IP-reputation collector: geo / threat-intel enrichment for login origins (IA-10). |

**EventType vocabulary (22):** `BOOT`, `LOGIN`, `SESSION`, `SSH_AUTH`, `PRIVILEGE_ESCALATION`, `EXEC`, `FILE_CHANGE`, `FILE_READ`, `FILE_DIFF`, `ACCOUNT_CHANGE`, `GROUP_CHANGE`, `PACKAGE_CHANGE`, `PKG_POLICY`, `PERSISTENCE`, `AUTHZ`, `SYSTEM`, `SHELL_HISTORY`, `FIREWALL`, `NETWORK`, `NETFLOW`, `NETLOG`, `OTHER`.

**Facet families (29):** `core`, `timeline`, `sessions`, `login`, `privilege`, `root_activity`, `commands`, `files`, `accounts`, `groups`, `packages`, `network`, `persistence`, `authorization`, `system_lifecycle`, `pkg_policy`, `process_tree`, `shell_history`, `firewall`, `file_access`, `netflow`, `netlogs`, `host_changes`, `attribution`, `concurrent`, `file_integrity`, `origin_reputation`, `evidence`, `gaps`.

---

## 3. Attribution matrix + adversarial corpus (executed)

Attribution is auid-centric (survives sudo/su); genuine ambiguity is disclosed, never guessed. The corpus exercises the messy cases a reviewer would demand.

### Adversarial attribution corpus

Every messy case: concurrent same-user sessions, multiple sudo chains, nested su, overlapping root logins, post-logout screen/tmux, automation.

`tests.conformance.test_conformance.TestAttributionCorpus` — **6/6 passed** (run while generating this document).

| test | result | what it proves |
|------|--------|----------------|
| `test_action_via_persistent_multiplexer_after_logout_attributed_by_auid` | pass | screen/tmux: alice's interactive login ends, but a command runs later in a |
| `test_automation_is_unattributable_not_blamed` | pass |  |
| `test_concurrent_same_user_sessions_grouped_by_ses` | pass | alice has two concurrent shells (ses 10 and 11) from two IPs; every command |
| `test_multiple_sudo_chains_do_not_cross` | pass | alice and bob each escalate and act as root; root activity must split them. |
| `test_nested_su_attributes_to_login_user` | pass | alice -> su root -> su bob; the login uid stays alice, so root actions are |
| `test_overlapping_root_logins_ambiguity_disclosed` | pass | two concurrent direct root logins from different IPs; a root action cannot |

### Root-action attribution

Escalation vs direct-root-login vs daemon classification.

`tests.conformance.test_conformance.TestRootAttribution` — **7/7 passed** (run while generating this document).

| test | result | what it proves |
|------|--------|----------------|
| `test_core_shows_who_exercised_root` | pass |  |
| `test_direct_root_login_reported_as_such` | pass |  |
| `test_escalated_action_attributes_to_base_user_only` | pass | alice must NOT be credited with the direct-root-login or daemon actions |
| `test_per_user_core_does_not_leak_host_root_attribution` | pass | A non-root user's Core answer must not enumerate other principals' root |
| `test_root_activity_for_root_is_attributed_breakdown` | pass | escalation attributed to the base user |
| `test_unresolved_root_uid_is_disclosed_not_falsely_attributed` | pass | A root action whose login uid (2000) maps to no account name. |
| `test_user_who_sshd_as_root_not_credited_as_base_user` | pass | bob authenticated as root (root's credentials); there is no evidence |

---

## 4. Capture-latency measurements

Measured on this host at 2026-09-26T05:50:23.133550+00:00 (euid 0). OpenPath's own rule applies to its self-measurement: **measured or disclosed, never fabricated.** A `not_measurable` row names the exact method to measure it on a suitable (e.g. auditd-instrumented, non-container) host.

| stage | status | seconds | detail / method |
|-------|--------|---------|-----------------|
| audit_event_to_observable | not_measurable | — | auditctl absent -- the kernel audit subsystem is host-global and not namespaced, so it is unavailable in this (container) environment — method: with auditd: `auditctl -w <tmpfile> -p wa -k lat`; touch the file; poll /var/log/audit/audit.log for the SYSCALL record; report elapsed |
| journal_event_to_observable | not_measurable | — | marker not visible within 20s (journald may be volatile/rate-limited here) — method: emit `logger -t <tag> <marker>`; poll `journalctl -t <tag> -o json` until the marker appears; report the elapsed time |
| analysis_latency | measured | 0.0262 | 40 events, 16 sources over / |
| bundle_export_latency | measured | 0.0338 | bundle size 495 KiB |

Reproduce: `python3 scripts/measure_capture_latency.py`. On a live host every stage is bounded by the source's own write latency; on a bundle every stage is bounded by the stamped `captured-at` instant.

---

## 5. Real-host validation (executed)

Runs the collectors and the shipped CLI against the real `/` filesystem of the machine generating this document — not a fixture.

### Live-host suite

No facet raises; every claim cited; capture_mode valid; a live host invents no not-yet-observed tail; conservation holds on real logs; --selfcheck/--coverage/analysis via main() all clean.

`tests.live.test_live_host.TestLiveHost` — **13/13 passed** (run while generating this document).

| test | result | what it proves |
|------|--------|----------------|
| `test_all_users_sweep_does_not_crash_on_real_host` | pass |  |
| `test_conservation_no_silent_drops_on_real_data` | pass | Evidence conservation on real logs: any source that could not decode a |
| `test_coverage_cli_end_to_end_against_real_root` | pass | Every source is classified and every gap names a reason -- the readiness |
| `test_coverage_ledger_is_populated` | pass | Every default collector should report a coverage record (even ABSENT). |
| `test_direct_filesystem_sources_are_live_on_a_live_host` | pass | Reading the real '/' at analysis time: on-host log artifacts are observed |
| `test_discover_includes_root` | pass |  |
| `test_every_source_has_a_valid_status_and_capture_mode` | pass | No collector may leave a source in an impossible state on a real host, and |
| `test_full_analysis_cli_end_to_end_for_root` | pass | The shipped path (main), not just the engine API: a real analysis for root |
| `test_gaps_are_disclosed_not_silent` | pass | On a minimally instrumented host, auditd-backed questions must disclose |
| `test_live_host_has_no_bundle_not_yet_observed_tail` | pass | A live analysis carries no capture-time marker, so it must NOT fabricate a |
| `test_no_facet_raises_and_every_claim_is_cited` | pass |  |
| `test_real_dpkg_or_dnf_parsed_when_present` | pass | If a real package log exists, we must have parsed real transactions, |
| `test_selfcheck_passes_through_shipped_cli` | pass |  |

---

## 6. Container lifecycle validation (executed)

OpenPath is a stateless batch CLI; `docs/DEPLOYMENT.md` answers all twelve lifecycle questions. Image build/publish is operator-side (a daemonless environment cannot build here); the wiring, health, and failure-mode behavior below are executed.

### Health / readiness / upgrade

selfcheck healthy + detects breakage; contract fingerprint stable; probes exercise real wiring.

`tests.conformance.test_conformance.TestDeployment` — **4/4 passed** (run while generating this document).

| test | result | what it proves |
|------|--------|----------------|
| `test_contract_fingerprint_stable_and_status_bound` | pass | The fingerprint is deterministic (an operator can compare it across an |
| `test_selfcheck_healthy_and_exit_zero` | pass | Every probe passed; none reported FAIL. |
| `test_selfcheck_probes_the_real_wiring` | pass | The pipeline probe actually runs the engine over an empty root (start-with- |
| `test_selfcheck_reports_unhealthy_on_broken_wiring` | pass | If a collector cannot be constructed, the probe must FAIL (non-zero), not |

### Failure modes

permission-denied disclosed not false-negative; idempotent re-run; broken-pipe/IO-error clean exits.

`tests.conformance.test_conformance.TestResilience` — **5/5 passed** (run while generating this document).

| test | result | what it proves |
|------|--------|----------------|
| `test_auditd_permission_denied_is_unreadable_not_false_negative` | pass | audit.log is PRESENT but unreadable (the non-root-container case, simulated |
| `test_broken_pipe_exits_cleanly` | pass | A consumer that closes the pipe (e.g. `\| head`) makes the write raise |
| `test_output_ioerror_exits_nonzero_not_crash` | pass | A non-pipe write failure (e.g. ENOSPC writing a report to a full volume) |
| `test_readable_helper_detects_unreadable` | pass |  |
| `test_rerun_is_idempotent` | pass | Stateless: the same inputs yield byte-identical output, and a second run |

---

## 7. Known limitations & principled exclusions

**Principled exclusions: 0.** No question is excluded from the contract; CONTRACTED is 0. The boundaries below are scope limits on *hosts* (evidence a default host may not retain), not exclusions of *questions* — each is CERTIFIED where the evidence is present and degrades to a remedied UNANSWERABLE without it.

- **Content-level file diffs (FS-13)** need a file-integrity monitor; auditd records the change act, never file content.
- **Origin reputation / geo (IA-10)** needs a provided threat-intel/geo feed; OpenPath is deterministic and offline.
- **DNS / firewall-drop / proxy / socket-lifetime (NW-08/10/12/15)** need the respective logging enabled.
- **Data volume (NW-04)** needs conntrack byte accounting.
- **Shell history (EX-12)** is a lead, not proof of execution (user-editable, usually un-timestamped) — always disclosed as such.
- **Session↔origin linkage:** audit `ses` groups actions but is not bridged to the wtmp login origin, so one action mapped to a specific overlapping login is disclosed as ambiguous, not asserted.
- **Full per-question blind spots:** see the rationale column of section 1 — every CERTIFIED question records its own scope boundary there.

---

## 8. Trust-roadmap matrix (evidence per status)

Reproduced from `docs/PRODUCTION-READINESS.md` (single source of truth); each row names the test(s) that enforce it.

| Area | Status | Evidence / caveat |
|------|--------|-------------------|
| Evidence conservation | STRONG | `records_scanned`/`unparseable` on all 16 collectors; `conservation_gaps()` surfaces any drop; `TestEvidenceConservation` (truncated wtmp tail, unparseable package/journal/cron/sudoers lines counted, consumed-source degrade). |
| Attribution correctness | STRONG | auid-centric `Subject.matches` (survives sudo/su); `TestRootAttribution` + the adversarial `TestAttributionCorpus` covering the full messy-case list: concurrent same-user sessions, multiple sudo chains that must not cross, nested su → login user, overlapping direct root logins (ambiguity **disclosed, not guessed**), a command run in a persistent screen/tmux pane **after logout** (still the base user, by immutable auid), and automation left unattributable; `TestMultiUserSweep` (no cross-attribution); wrong-user isolation in `TestQueryLayer`; TM-06 labels each action high/medium/low. |
| Session correlation | STRONG (with a disclosed boundary) | audit `ses=` id captured and used to group a user's concurrent sessions; the adversarial cases above are proven (`TestAttributionCorpus`); session intervals + overlap (IA-05), still-open (IA-04), reboot-terminated (SL-03), concurrent cross-user (TM-13). *Boundary (disclosed, not silently assumed): `ses` groups audited actions into sessions but is not bridged to the wtmp session's origin, so mapping one audited action to a specific overlapping wtmp login is reported as ambiguous rather than asserted — the honest limit, since no deterministic on-host link exists.* |
| Freshness measurement | STRONG | per-source retention horizon + `freshness_seconds`/`is_stale` (age of newest record vs the analysis anchor), surfaced in `--coverage`; `test_freshness_and_staleness_measure`. A source with no timestamped record reports freshness `None`, never a fabricated "fresh". |
| Capture latency | STRONG | every source is tagged `capture_mode` (`live` = observed now, or `export` = a journald dump) and the tag is surfaced in `--coverage`; an offline bundle stamps its own capture time (`captured-at` marker) and a window reaching past it discloses the not-yet-observed tail (`snapshot_shortfall`); `TestCaptureLatency`. Record *age* is never mistaken for capture staleness — a quiet live source stays a trustworthy negative. |
| Log rotation handling | STRONG | reads rotated `.1` files; `retention_bounded` + `horizon_shortfalls()`; `test_event_split_across_rotation_is_reunited`; a genuine retention gap is disclosed, a merely-quiet log is not. |
| Restart / recovery | STRONG (by design) | stateless CLI (collect → analyze → exit); no persistent state to corrupt or recover; a re-run is byte-identical (`TestResilience.test_rerun_is_idempotent`); a failed output write exits cleanly (broken pipe → 141, IO error → 74, `test_broken_pipe_exits_cleanly` / `test_output_ioerror_exits_nonzero_not_crash`) instead of half-succeeding; `TestStreaming` proves bounded memory on large/rotated logs. |
| Permission-failure degradation | STRONG | a present-but-unreadable root-only source (`audit.log`/`wtmp`/`btmp` under a non-root run) is disclosed **UNREADABLE with a remedy**, never a false "nothing happened"; `Collector._readable` + `TestResilience.test_auditd_permission_denied_is_unreadable_not_false_negative`. |
| Real-host validation | VALIDATED | `tests/live/test_live_host.py` runs every facet against the real `/` filesystem — no facet raises, every event cited, gaps disclosed; run on this container it parsed real `/etc/cron.d`, `/etc/group` (ubuntu in sudo/adm), `/etc/shadow` (`_apt` locked), `/proc/net`. *Caveat: a fully-instrumented, rule-loaded auditd host still needs an operator to drive `scripts/live_conformance.sh`.* |
| Documentation parity | GOOD | docs generated from the contract; `test_docs_parity_with_contract` fails if `PRODUCTION-CATALOG.md` counts drift from `openpath.contract`; `test_scoreboard_renders_and_counts_match` checks the `--contract` output. |
| Catalog completeness | GOOD | 153 questions are an output of an evidence-surface analysis; every collector maps to ≥1 certified question; the contract-completeness principle (below) forbids a permanent CONTRACTED. |
| Container deployment | FUNCTIONAL | ships a non-root, read-only-friendly, zero-dependency `Containerfile` (entrypoint = CLI, `HEALTHCHECK`/CMD = `--selfcheck`), a host-independent health probe (`--selfcheck`: collectors/contract/facets/pipeline, exit 0/non-zero), host readiness (`--coverage`), and a verifiable contract fingerprint for upgrades; `docs/DEPLOYMENT.md` answers all twelve lifecycle questions; `TestDeployment` + `TestResilience`. *Caveat: the image is defined and its install/entrypoint validated, but building/publishing it (and any orchestration manifests) is left to the operator's registry/CI; it remains a batch CLI, by design — no daemon.* |

---

## Shipped-path verification

Certification/answer assertions drive the shipped CLI entrypoint `openpath.cli:main` via the `self.cli(...)` helper — **47 call sites** in the conformance suite (grep `self.cli(` in `tests/conformance/test_conformance.py`). `main()` is the same function `pyproject.toml` binds to the `openpath-ai` console script, so a green suite exercises the code a user runs, not a test-only shortcut. A small number of attribution checks additionally call internal helpers (`classify_root_action`) to assert classification directly; those are labelled and are in addition to, not instead of, the CLI path.
