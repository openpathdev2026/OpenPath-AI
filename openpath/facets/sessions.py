"""Sessions (family 3) and Login (family 4)."""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, AnyOf, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding


def _dedup_ssh(events):
    """Collapse the same SSH auth event reported by both the journal and auth.log.

    journald and syslog record the identical sshd line, so an event keyed by
    (result, ip, port) within the same ~2s bucket is one login, not two.
    """
    seen = set()
    out = []
    for e in sorted(events, key=lambda x: x.ts):
        key = (e.attrs.get("result"), e.attrs.get("ip"),
               e.attrs.get("port"), int(e.ts.timestamp()) // 2)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def _merge_failed(events):
    """Merge failed-login attempts across btmp and sshd, deduping the same
    attempt recorded in both (keyed on source IP within a ~2s bucket)."""
    seen = set()
    out = []
    for e in sorted(events, key=lambda x: x.ts):
        origin = e.attrs.get("ip") or e.attrs.get("origin")
        key = (origin, int(e.ts.timestamp()) // 2)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


class SessionsFacet(Facet):
    name = "sessions"
    question_family = "Sessions"
    requirements = (
        Requirement("wtmp", "Sessions", instrument="wtmp accounting present",
                    remedy="enable login accounting so /var/log/wtmp records "
                           "sessions (session intervals are wtmp-only)"),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))
        sessions = ctx.subject_events([EventType.SESSION])
        f.events = sessions

        if not sessions:
            if f.gaps:
                f.summary = (
                    f"Cannot determine {ctx.subject.username}'s sessions: "
                    f"login accounting is unavailable (see gaps)."
                )
            else:
                f.summary = (
                    f"No login sessions for {ctx.subject.username} in {ctx.window.label or 'the window'}. "
                    f"(wtmp was present and readable, so this is an evidenced negative.)"
                )
            return f

        open_n = sum(1 for e in sessions if e.ts_end is None)
        # SL-03: a reboot during a session ends it. A boot whose instant falls after
        # a session's start and at/before its end (or now, if still open) terminated
        # that session -- surfaced with both the session and the boot cited.
        boots = sorted((e for e in ctx.events if e.type is EventType.BOOT),
                       key=lambda e: e.ts)
        reboot_terminated = 0
        for s in sessions:
            end = s.ts_end or ctx.window.end
            for b in boots:
                if s.ts < b.ts <= end:
                    reboot_terminated += 1
                    f.notes.append(
                        f"[reboot-terminated] session on {s.attrs.get('line')} "
                        f"(from {s.attrs.get('origin')}) started {s.ts.isoformat()} "
                        f"was terminated by a reboot at {b.ts.isoformat()}")
                    if b not in f.events:
                        f.events.append(b)
                    break
        f.events.sort(key=lambda e: e.ts)
        f.summary = (
            f"{ctx.subject.username} had {len(sessions)} session(s) in "
            f"{ctx.window.label or 'the window'}"
            + (f", {open_n} still open" if open_n else "")
            + (f", {reboot_terminated} ended by a reboot" if reboot_terminated else "")
            + "."
        )
        for e in sessions:
            origin = e.attrs.get("origin", "local")
            f.notes.append(
                f"{e.ts.isoformat()} on {e.attrs.get('line')} from {origin} "
                f"-> {e.ts_end.isoformat() if e.ts_end else 'still open'} "
                f"({e.attrs.get('ended_by')})"
            )
        return f


class LoginFacet(Facet):
    name = "login"
    question_family = "Login"
    # A *successful* login is witnessed only by wtmp or an sshd auth record; btmp
    # records only FAILURES, so it must NOT satisfy this requirement (otherwise a
    # present btmp would license a false "no logins" for a login it cannot see).
    requirements = (
        AnyOf("Login", [("wtmp", "wtmp accounting present"),
                        ("journal.sshd", None), ("auth", None)],
              remedy="ensure login accounting (wtmp), an sshd journal, or "
                     "/var/log/auth.log is present"),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))
        has_success_source = not any(g.question == "Login" for g in f.gaps)

        sessions = ctx.subject_events([EventType.SESSION])
        ssh = _dedup_ssh(ctx.subject_events([EventType.SSH_AUTH]))
        accepted = [e for e in ssh if e.attrs.get("result") == "accepted"]
        failed_ssh = [e for e in ssh if e.attrs.get("result") == "failed"]
        btmp = ctx.subject_events([EventType.LOGIN])  # failed attempts
        # A failed SSH login is recorded in both btmp and auth.log/journal; merge
        # them so the same attempt is not counted twice.
        failed = _merge_failed(failed_ssh + btmp)
        # IA-11 (non-SSH PAM auth) and PV-12 (account lockout / faillock), from the
        # general journal. Both are authentication facts for this subject.
        sysev = ctx.subject_events([EventType.SYSTEM])
        pam = [e for e in sysev if e.attrs.get("kind") == "pam_auth"]
        locks = [e for e in sysev if e.attrs.get("kind") == "faillock"]
        f.events = sorted(sessions + ssh + btmp + pam + locks, key=lambda e: e.ts)

        journal = ctx.ledger.get("journal.sshd")
        if journal is None or not journal.usable:
            f.notes.append(
                "sshd journal not available; authentication method and some "
                "remote-origin detail may be incomplete.")

        # Successful logins are witnessed by wtmp sessions, else accepted SSH.
        login_events = sessions if sessions else accepted
        first = login_events[0] if login_events else None
        # Origins of *successful* logins only -- never conflate an attacker's
        # failed-attempt source with a legitimate login origin.
        origins = sorted({e.attrs.get("origin") for e in sessions
                          if e.attrs.get("origin")}
                         | {e.attrs.get("ip") for e in accepted if e.attrs.get("ip")}
                         - {None})
        fail_origins = sorted({(e.attrs.get("ip") or e.attrs.get("origin"))
                               for e in failed} - {None})

        if not login_events and not failed and not pam and not locks:
            if has_success_source:
                f.summary = (
                    f"No logins for {ctx.subject.username} in "
                    f"{ctx.window.label or 'the window'} (evidenced negative).")
            else:
                f.summary = (f"Cannot determine when/where "
                             f"{ctx.subject.username} logged in (see gaps).")
            return f

        pam_svcs = sorted({e.attrs.get("service") for e in pam
                           if e.attrs.get("service")})
        # Lead with the successful-login answer (or its absence), then failures.
        if login_events:
            head = (f"{ctx.subject.username} logged in {len(login_events)} time(s)"
                    + (f", first at {first.ts.isoformat()}" if first else "")
                    + (f"; origins: {', '.join(origins)}" if origins else ""))
        elif pam:
            head = (f"{ctx.subject.username} authenticated to non-SSH service(s) "
                    f"{', '.join(pam_svcs)} (no SSH/console login recorded)")
        elif has_success_source:
            head = f"{ctx.subject.username} had no successful logins"
        else:
            head = (f"successful logins for {ctx.subject.username} cannot be "
                    f"confirmed (see gaps)")
        tail = ""
        if pam and login_events:
            tail += f"; also authenticated to non-SSH {', '.join(pam_svcs)}"
        if locks:
            tail += f"; {len(locks)} account-lockout/faillock event(s)"
        if failed:
            tail = (f"; {len(failed)} failed attempt(s)"
                    + (f" from {', '.join(fail_origins)}" if fail_origins else ""))
        # IA-08: brute-force / password-spraying indicator. Deterministic threshold:
        # >=5 failed attempts concentrated on a single source IP (brute-force) is
        # flagged from the evidence itself, no external feed.
        _BRUTE = 5
        by_origin: dict = {}
        for e in failed:
            o = e.attrs.get("ip") or e.attrs.get("origin") or "?"
            by_origin[o] = by_origin.get(o, 0) + 1
        brute = {o: c for o, c in by_origin.items() if c >= _BRUTE}
        if brute:
            tail += ("; BRUTE-FORCE indicator: "
                     + ", ".join(f"{c} failures from {o}"
                                 for o, c in sorted(brute.items())))
            for o, c in sorted(brute.items()):
                f.notes.append(f"[brute-force] {c} failed attempts from {o} "
                               f"(>= {_BRUTE} threshold)")
        # IA-09: off-hours logins. Deterministic policy stated in the note -- a
        # successful login whose UTC hour is outside 07:00-18:59 or on a weekend is
        # flagged (the window is UTC-based and a configurable product policy).
        off = [e for e in login_events
               if e.ts.hour < 7 or e.ts.hour >= 19 or e.ts.weekday() >= 5]
        if off:
            tail += f"; {len(off)} off-hours login(s)"
            for e in off:
                f.notes.append(
                    f"[off-hours] login at {e.ts.isoformat()} (UTC hour "
                    f"{e.ts.hour:02d}, {'weekend' if e.ts.weekday() >= 5 else 'weekday'})"
                    f" -- outside the 07:00-18:59 UTC business-hours policy")
        f.summary = head + tail + "."

        for e in sessions:
            f.notes.append(f"login {e.ts.isoformat()} from "
                           f"{e.attrs.get('origin')} on {e.attrs.get('line')}")
        for e in ssh:
            f.notes.append(f"sshd {e.attrs.get('result')} {e.attrs.get('method')} "
                           f"from {e.attrs.get('ip')}:{e.attrs.get('port')} at "
                           f"{e.ts.isoformat()}")
        for e in btmp:
            f.notes.append(f"failed login as {ctx.subject.username} from "
                           f"{e.attrs.get('origin')} on {e.attrs.get('line')} at "
                           f"{e.ts.isoformat()}")
        return f
