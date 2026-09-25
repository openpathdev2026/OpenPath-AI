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
        Requirement("wtmp", "Sessions", instrument="wtmp accounting present"),
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
        f.summary = (
            f"{ctx.subject.username} had {len(sessions)} session(s) in "
            f"{ctx.window.label or 'the window'}"
            + (f", {open_n} still open" if open_n else "")
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
                        ("journal.sshd", None), ("auth", None)]),
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
        f.events = sorted(sessions + ssh + btmp, key=lambda e: e.ts)

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

        if not login_events and not failed:
            if has_success_source:
                f.summary = (
                    f"No logins for {ctx.subject.username} in "
                    f"{ctx.window.label or 'the window'} (evidenced negative).")
            else:
                f.summary = (f"Cannot determine when/where "
                             f"{ctx.subject.username} logged in (see gaps).")
            return f

        # Lead with the successful-login answer (or its absence), then failures.
        if login_events:
            head = (f"{ctx.subject.username} logged in {len(login_events)} time(s)"
                    + (f", first at {first.ts.isoformat()}" if first else "")
                    + (f"; origins: {', '.join(origins)}" if origins else ""))
        elif has_success_source:
            head = f"{ctx.subject.username} had no successful logins"
        else:
            head = (f"successful logins for {ctx.subject.username} cannot be "
                    f"confirmed (see gaps)")
        tail = ""
        if failed:
            tail = (f"; {len(failed)} failed attempt(s)"
                    + (f" from {', '.join(fail_origins)}" if fail_origins else ""))
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
