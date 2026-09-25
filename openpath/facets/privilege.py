"""Privilege (family 5), Root activity (family 6), Commands (family 7)."""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding

_EXEC_REMEDY = (
    "add an execve audit rule: "
    "-a always,exit -F arch=b64 -S execve -S execveat -k exec"
)


class PrivilegeFacet(Facet):
    """Did the user become root (or otherwise escalate)?"""

    name = "privilege"
    question_family = "Privilege"
    # sudo/su USER_* records are emitted by PAM whenever auditd runs -- no syscall
    # rule needed -- so the only hard requirement is that auditd is present.
    requirements = (
        Requirement("auditd", "Privilege", instrument="auditd rules loaded"),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        escalations = ctx.subject_events([EventType.PRIVILEGE_ESCALATION])
        root_execs = [
            e for e in ctx.subject_events([EventType.EXEC])
            if e.attrs.get("as_root")
        ]
        f.events = sorted(escalations + root_execs, key=lambda e: e.ts)

        successful = [
            e for e in escalations if (e.attrs.get("res") in (None, "success"))
        ]

        if successful or root_execs:
            tools = sorted({e.attrs.get("tool") for e in successful if e.attrs.get("tool")})
            parts = []
            if successful:
                parts.append(f"{len(successful)} privilege-escalation event(s)"
                             + (f" via {', '.join(tools)}" if tools else ""))
            if root_execs:
                parts.append(f"{len(root_execs)} command(s) executed as root")
            f.summary = (
                f"Yes -- {ctx.subject.username} operated with elevated privilege: "
                + "; ".join(parts) + "."
            )
        else:
            failed = [e for e in escalations if e.attrs.get("res") == "failed"]
            if failed:
                f.summary = (
                    f"{ctx.subject.username} attempted privilege escalation "
                    f"{len(failed)} time(s), all failed."
                )
                f.events = failed
            elif not any(g.question == "Privilege" for g in f.gaps):
                f.summary = (
                    f"No, {ctx.subject.username} did not become root in "
                    f"{ctx.window.label or 'the window'} (no sudo/su and no root "
                    f"execution recorded; auditd was present)."
                )
            else:
                f.summary = f"Cannot determine whether {ctx.subject.username} became root (see gaps)."

        # If we can see sudo but not exec, disclose the partial visibility.
        auditd = ctx.ledger.get("auditd")
        if auditd is not None and not auditd.has_instrument("execve audit rule"):
            f.gaps.append(
                self._gap("Privilege",
                          "sudo/su usage is visible, but commands executed as root "
                          "are not recorded without an execve rule, so the full "
                          "extent of root activity cannot be confirmed.",
                          "auditd", _EXEC_REMEDY)
            )
        return f

    @staticmethod
    def _gap(q, reason, sid, remedy):
        from openpath.model.coverage import Gap
        return Gap(q, reason, sid, remedy)


class RootActivityFacet(Facet):
    """What did the user do as root?"""

    name = "root_activity"
    question_family = "Root activity"
    requirements = (
        Requirement("auditd", "Root activity", instrument="execve audit rule",
                    remedy=_EXEC_REMEDY),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        as_root = [
            e for e in ctx.subject_events(
                [EventType.EXEC, EventType.FILE_CHANGE, EventType.NETWORK]
            )
            if e.uid == 0 or e.attrs.get("euid") == 0 or e.attrs.get("as_root")
        ]
        f.events = as_root

        if not as_root:
            if any(g.question == "Root activity" for g in f.gaps):
                f.summary = f"Cannot determine {ctx.subject.username}'s root activity (see gaps)."
            else:
                f.summary = (
                    f"No activity as root by {ctx.subject.username} recorded in "
                    f"{ctx.window.label or 'the window'} (evidenced negative)."
                )
            return f

        execs = [e for e in as_root if e.type == EventType.EXEC]
        f.summary = (
            f"As root, {ctx.subject.username} ran {len(execs)} command(s) and "
            f"performed {len(as_root) - len(execs)} other privileged operation(s)."
        )
        for e in as_root:
            f.notes.append(f"{e.ts.isoformat()} [{e.type.value}] {e.summary}")
        return f


class CommandsFacet(Facet):
    """What commands did the user execute (at any privilege level)?"""

    name = "commands"
    question_family = "Commands"
    requirements = (
        Requirement("auditd", "Commands", instrument="execve audit rule",
                    remedy=_EXEC_REMEDY),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        execs = ctx.subject_events([EventType.EXEC])
        f.events = execs

        if not execs:
            if any(g.question == "Commands" for g in f.gaps):
                f.summary = f"Cannot determine {ctx.subject.username}'s commands (see gaps)."
            else:
                f.summary = (
                    f"No commands executed by {ctx.subject.username} recorded in "
                    f"{ctx.window.label or 'the window'} (evidenced negative)."
                )
            return f

        as_root = sum(1 for e in execs if e.attrs.get("as_root"))
        switched = sum(1 for e in execs if e.attrs.get("switched"))
        f.summary = (
            f"{ctx.subject.username} executed {len(execs)} command(s) "
            f"({as_root} as root, {switched} after a privilege switch)."
        )
        for e in execs:
            f.notes.append(
                f"{e.ts.isoformat()} {'(root) ' if e.attrs.get('as_root') else ''}"
                f"{e.attrs.get('cmdline') or e.summary}"
            )
        return f
