"""Sessions (family 3) and Login (family 4)."""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding


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
    requirements = (
        Requirement("wtmp", "Login", instrument="wtmp accounting present"),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        sessions = ctx.subject_events([EventType.SESSION])
        ssh = ctx.subject_events([EventType.SSH_AUTH])
        f.events = sessions + ssh
        f.events.sort(key=lambda e: e.ts)

        # sshd journal enriches origin/method; note (soft gap) when unavailable.
        journal = ctx.ledger.get("journal.sshd")
        if journal is None or not journal.usable:
            f.notes.append(
                "sshd journal not available; authentication method and some "
                "remote-origin detail may be incomplete (wtmp origin still used)."
            )

        if not sessions and not ssh:
            if any(g.question == "Login" for g in f.gaps):
                f.summary = f"Cannot determine when/where {ctx.subject.username} logged in (see gaps)."
            else:
                f.summary = (
                    f"No logins for {ctx.subject.username} in {ctx.window.label or 'the window'} "
                    f"(evidenced negative)."
                )
            return f

        first = sessions[0] if sessions else None
        origins = sorted({
            e.attrs.get("origin") for e in sessions if e.attrs.get("origin")
        } | {
            e.attrs.get("ip") for e in ssh if e.attrs.get("ip")
        } - {None})
        f.summary = (
            f"{ctx.subject.username} logged in {len(sessions)} time(s)"
            + (f", first at {first.ts.isoformat()}" if first else "")
            + (f"; origins: {', '.join(origins)}" if origins else "")
            + "."
        )
        for e in sessions:
            f.notes.append(
                f"login {e.ts.isoformat()} from {e.attrs.get('origin')} on "
                f"{e.attrs.get('line')}"
            )
        for e in ssh:
            f.notes.append(
                f"sshd {e.attrs.get('result')} {e.attrs.get('method')} from "
                f"{e.attrs.get('ip')}:{e.attrs.get('port')} at {e.ts.isoformat()}"
            )
        # Failed SSH attempts are relevant to "where they connected from".
        failed = [e for e in ssh if e.attrs.get("result") == "failed"]
        if failed:
            f.notes.append(f"{len(failed)} failed SSH authentication attempt(s) recorded.")
        return f
