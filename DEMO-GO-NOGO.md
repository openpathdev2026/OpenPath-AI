# OpenPath-AI — Production Demo GO / NO-GO

**Method:** Adversarial validation against the **real host only** — the shipped
product (`openpath-ai`) run over real auditd / dpkg / wtmp / journal. No new
fixtures, generators, synthetic success cases, or catalog changes. Attribution
proven on real syscalls (test user `op_probe`, since removed). dpkg cross-checked
against an independent raw count (685 installs, exact match).

---

## BOTTOM LINE: **CONDITIONAL GO**

Go with a **defined question set** and **three operational preconditions**. Do
**not** claim "100%" on the login-family questions on this host.

---

## 1. Critical Defect — FOUND and FIXED (commit `a9b16e6`)

**Login false-CERTIFIED contradiction (the kill-shot).**
Before the fix, "When did USER log in?" answered **CERTIFIED — "No logins
(evidenced negative)", GAPS (none)** on a host whose wtmp is empty — while the
*same* wtmp made Sessions say **UNANSWERABLE** and Gaps disclosed the ambiguity.
An audience asking both back-to-back would watch OpenPath contradict itself.

Root cause: an empty-but-present sshd journal satisfied the Login facet's
answerability, licensing a certified negative from a source that was recording
nothing. Fix: a login negative is now an *evidenced* negative only when a login
source is genuinely recording (wtmp instrument present, or an AVAILABLE sshd
journal / auth.log). Otherwise it discloses a Login gap and answers **PARTIAL —
"Cannot confirm whether USER logged in: login accounting is unavailable."**
Now consistent with Sessions and Gaps. **298 tests green**, evidenced-negative on
properly-instrumented hosts preserved.

---

## 2. Preconditions to verify AT DEMO TIME (non-negotiable)

**(a) auditd must be live with rules loaded — auditd *is* the demo.**
On this host auditd has died at session boundaries before. If it is down, every
Q05–Q12 answer collapses to "no data."
```
auditctl -s     # expect: enabled 1, pid non-zero
auditctl -l     # expect: 11 rules incl. -S execve
```
If dead: `service auditd start && augenrules --load`
(Current state: **enabled 1, pid 420, 11 rules loaded, openpath.rules persisted.**)

**(b) Demo users must enter through PAM so their loginuid is set.**
Attribution is by `auid` (immutable login uid). A raw shell with loginuid *unset*
(`4294967295`) attributes activity to "unset", **not** to the user. `pam_loginuid`
is configured for `su` and `login` (verified: `su - nobody` → loginuid 65534).
**Enter each demo user with `su - <demouser>`** (or real SSH/console login) — never
hand the audience a raw shell.

**(c) Use a dedicated demo user, never `root`.**
`root`/system background activity is enormous (root shows **1772 commands**). A
fresh demo user scopes the answer to what the audience actually did.

---

## 3. SAFE questions — sound AND match user intent (lead with these)

Validated on real syscalls; discrete deliberate acts, low noise:

| Q | Question | Real-evidence behavior | Confidence |
|----|----------|------------------------|------------|
| Q05 | Did USER become root? | "Yes — 31 escalations via su/sudo; 24 commands as root" | CERTIFIED |
| Q06 | What did USER do as root? | headline "24 commands as root" | CERTIFIED |
| Q09 | Accounts created/modified? | "1 account change, 7 admin commands" (useradd) | CERTIFIED |
| Q10 | Groups created/modified? | "4 group changes, 6 admin commands" | CERTIFIED |
| Q11 | Packages installed/removed? | install shows up; if none → "no software changes (evidenced negative); N by other actors" | CERTIFIED (cross-checked vs raw dpkg) |
| Q14 | What evidence supports it? | raw records behind the answer | CERTIFIED |
| Q15 | What could NOT be determined? | discloses gaps with reason + remedy | CERTIFIED |

Q11 and Q15 are the strongest crowd-pleasers: Q11 **distinguishes the user's own
installs from other actors'**, and Q15 **shows the tool admitting its own limits**
— the honesty that separates evidence from guessing.

---

## 4. HIGH-RISK questions — SOUND but voluminous (frame, or steer away)

Every event is real and cited, but the **count is larger than the user consciously
did**, because auditd captures every execve / every /etc write / every connect:

| Q | Question | Why it looks "off" | Real measure |
|----|----------|--------------------|--------------|
| Q07 | What commands did USER run? | includes shell-init + every subprocess (`locale-check`, `which node`, `dirname …`) | op_probe: **1253**; root: **1772** |
| Q08 | What files did USER modify? | one `useradd` touches ~dozens of /etc files; broad `-w /etc` watch | **100 files** (fchmod/openat/rename/unlink…) |
| Q12 | What network activity? | includes DNS / localhost | **147 ops**; endpoints (127.0.0.1:22, 93.184.216.34:80) *are* meaningful |

**Not a defect** — this is auditd being honest. But if the audience expects "I ran
3 commands" and sees 1253, the *claim* looks wrong. **Mitigation:** frame as "every
process / file / connection executed under your identity, each with evidence," or
keep these out of the "100%" set. **Never** demo Q07/Q08/Q12 on `root`.

---

## 5. NO-GO for a "100%" claim on THIS host — the login family

| Q | Question | Behavior after fix |
|----|----------|--------------------|
| Q02 | When did USER log in? | "Cannot confirm — login accounting unavailable" (PARTIAL) |
| Q03 | Where did USER log in from? | same |
| Q04 | What sessions did USER have? | "Cannot determine — login accounting unavailable" (UNANSWERABLE) |

**Reason (raw evidence):** this host has **no login accounting at all** — wtmp 0
bytes, btmp 0 bytes, journald **0 entries / no persistent journal**, no
`/var/log/auth.log`, **sshd not even running**. Nothing records a login. The
answers are now *honest*, but honest ≠ "we answer this at 100%."

**Options:** (a) **exclude** Q02/Q03/Q04 from the "100%" set — recommended; or
(b) stand up a real login pipeline before the demo — persistent journald +
running sshd + users actually SSH in — so wtmp/journal carry real login records.

---

## 6. Recommended demo run-of-show

1. **Pre-flight:** `auditctl -s` (enabled 1, pid≠0) and `auditctl -l` (11 rules).
2. **Enter** the demo user: `su - <demouser>` (sets loginuid → attribution works).
3. **Steer the audience pick** to the SAFE set: Q05, Q06, Q09, Q10, Q11 — plus
   Q15/Q14 for the "it admits what it can't prove" moment.
4. If a user insists on Q07/Q08/Q12, **frame the volume** ("captured every action
   with evidence") — do not act surprised by the count.
5. **Do not** put Q02/Q03/Q04 in the "100%" claim on this host.

---

## Verdict

- **GO** (sound, cited, match intent): **Q05, Q06, Q09, Q10, Q11, Q14, Q15**
- **GO WITH FRAMING** (sound but voluminous): **Q07, Q08, Q12**
- **NO-GO for a 100% claim on this host**: **Q02, Q03, Q04** (no login source)

The one thing that turns this GO into a NO-GO in the room is **auditd being down
at demo time** — check it in the last 5 minutes before you start.
