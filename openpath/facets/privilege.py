"""Privilege (family 5), Root activity (family 6), Commands (family 7)."""

from __future__ import annotations

from openpath.facets.attribution import (
    attribute_root_actions,
    summarize_responsibility,
)
from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.coverage import Gap
from openpath.model.event import EventType
from openpath.model.finding import Finding

_EXEC_REMEDY = (
    "add an execve audit rule: "
    "-a always,exit -F arch=b64 -S execve -S execveat -k exec"
)


def _subject_is_root(ctx: AnalysisContext) -> bool:
    return (
        ctx.subject.username == "root"
        or ctx.subject.current_uid == 0
        or any(iv.uid == 0 for iv in ctx.subject.intervals)
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

        # Direct root logins: a login session whose account is root (e.g. ssh
        # root@host). Only meaningful when the subject IS root -- a normal user
        # cannot log in directly as root.
        if _subject_is_root(ctx):
            direct_logins = ctx.subject_events([EventType.SESSION])
        else:
            direct_logins = []

        escalations = ctx.subject_events([EventType.PRIVILEGE_ESCALATION])
        root_execs = [
            e for e in ctx.subject_events([EventType.EXEC])
            if e.attrs.get("as_root")
        ]
        f.events = sorted(escalations + root_execs + direct_logins,
                          key=lambda e: e.ts)

        successful = [
            e for e in escalations if (e.attrs.get("res") in (None, "success"))
        ]

        if direct_logins:
            origins = sorted({e.attrs.get("origin") for e in direct_logins
                              if e.attrs.get("origin")})
            remote = [o for o in origins if o and o != "local"]
            f.summary = (
                f"{ctx.subject.username} accessed root directly via "
                f"{len(direct_logins)} login session(s)"
                + (f" from {', '.join(remote)}" if remote else " (local console)")
                + ". Actions in these sessions are attributed to the direct root "
                "login, not to any base user."
            )
            f.notes.append(
                "Note: privilege escalations by other users (sudo/su) are "
                "attributed to those base users -- ask their Privilege / Root "
                "activity questions."
            )
            return self._finalize(ctx, f)

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

        return self._finalize(ctx, f)

    def _finalize(self, ctx: AnalysisContext, f: Finding) -> Finding:
        # If we can see sudo but not exec, disclose the partial visibility.
        auditd = ctx.ledger.get("auditd")
        if auditd is not None and not auditd.has_instrument("execve audit rule"):
            f.gaps.append(Gap(
                "Privilege",
                "sudo/su usage is visible, but commands executed as root are not "
                "recorded without an execve rule, so the full extent of root "
                "activity cannot be confirmed.",
                "auditd", _EXEC_REMEDY,
            ))
        return f


class RootActivityFacet(Facet):
    """What did the user do as root -- and, for the root account, who became root?

    For a normal user this is their own escalated activity, each action labelled
    with the escalation path (attributed back to them). For the root account it is
    the host-wide view of everything done with root privilege, each action
    attributed to the base user who escalated, to a direct root login (with its
    origin), or disclosed as an unattributable daemon/cron action.
    """

    name = "root_activity"
    question_family = "Root activity"
    requirements = (
        Requirement("auditd", "Root activity", instrument="execve audit rule",
                    remedy=_EXEC_REMEDY),
    )

    _TYPES = [EventType.EXEC, EventType.FILE_CHANGE, EventType.NETWORK]

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))
        subject_is_root = _subject_is_root(ctx)

        if subject_is_root:
            # Host-wide: every action performed with root privilege, by anyone.
            candidates = [e for e in ctx.events if e.type in self._TYPES]
        else:
            candidates = ctx.subject_events(self._TYPES)
        pairs = attribute_root_actions(ctx, candidates)
        pairs.sort(key=lambda p: p[0].ts)
        if subject_is_root:
            # Attribute each action for the narrative: credit the base user who
            # escalated, the direct root login, or disclose it as a daemon.
            from dataclasses import replace
            display = []
            for e, attr in pairs:
                actor, via = attr.narration()
                display.append(replace(e, actor_name=actor,
                                       attrs={**e.attrs, "via": via}))
            f.events = display
        else:
            f.events = [e for e, _ in pairs]

        if not pairs:
            if any(g.question == "Root activity" for g in f.gaps):
                f.summary = f"Cannot determine {ctx.subject.username}'s root activity (see gaps)."
            else:
                f.summary = (
                    f"No activity as root by {ctx.subject.username} recorded in "
                    f"{ctx.window.label or 'the window'} (evidenced negative)."
                )
            return f

        execs = [e for e, _ in pairs if e.type == EventType.EXEC]
        if subject_is_root:
            who = summarize_responsibility(pairs)
            f.summary = (
                f"{len(pairs)} action(s) were performed with root privilege in "
                f"{ctx.window.label or 'the window'}, attributed as -> "
                + "; ".join(who) + "."
            )
        else:
            f.summary = (
                f"As root (via privilege escalation), {ctx.subject.username} ran "
                f"{len(execs)} command(s) and performed {len(pairs) - len(execs)} "
                f"other privileged operation(s)."
            )
        for e, attr in pairs:
            f.notes.append(
                f"{e.ts.isoformat()} [{e.type.value}] {e.summary}  <- {attr.label()}"
            )

        # Disclose root actions that cannot be tied to a human.
        unattributable = [(e, a) for e, a in pairs if not a.attributable]
        if unattributable:
            f.gaps.append(Gap(
                "Root activity",
                f"{len(unattributable)} root action(s) have no login uid or no "
                f"backing login session (daemon, cron, or boot-time), so they "
                f"cannot be attributed to a specific human.",
                "auditd",
                "record loginuid for service managers, or correlate with "
                "scheduler/unit logs, to attribute automated root activity.",
            ))
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
