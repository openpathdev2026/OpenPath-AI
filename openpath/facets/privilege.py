"""Privilege (family 5), Root activity (family 6), Commands (family 7)."""

from __future__ import annotations

from openpath.facets.attribution import (
    attribute_root_actions,
    summarize_responsibility,
)
from openpath.facets.base import (
    AnalysisContext,
    AnyOf,
    Facet,
    Requirement,
    prefer_primary,
    source_met,
)
from openpath.model.coverage import Gap
from openpath.model.event import EventType
from openpath.model.finding import Finding

_EXEC_REMEDY = (
    "add an execve audit rule: "
    "-a always,exit -F arch=b64 -S execve -S execveat -k exec"
)
_PARTIAL_CMD = (
    "auth.log/secure captures commands run via sudo, but not ordinary (non-sudo) "
    "command execution; add an execve audit rule for complete command visibility."
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
    # Privilege escalation is recorded by auditd (USER_CMD/USER_START) or by syslog
    # (sudo/su lines in auth.log/secure) -- either answers the question.
    requirements = (
        AnyOf("Privilege", [("auditd", "auditd rules loaded"), ("auth", None)],
              remedy="run auditd (load contrib/openpath.rules) or ensure "
                     "/var/log/auth.log (or /var/log/secure) is present"),
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

        escalations = prefer_primary(
            ctx, ctx.subject_events([EventType.PRIVILEGE_ESCALATION]),
            need_execve=False)
        root_execs = prefer_primary(ctx, [
            e for e in ctx.subject_events([EventType.EXEC])
            if e.attrs.get("as_root")
        ], need_execve=True)
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
                src = "auditd" if source_met(ctx, "auditd", "auditd rules loaded") \
                    else "auth.log"
                f.summary = (
                    f"No sudo/su escalation or root execution by "
                    f"{ctx.subject.username} was recorded in "
                    f"{ctx.window.label or 'the window'} ({src} was present) -- an "
                    f"evidenced negative within the covered evidence scope, not a "
                    f"claim that no privilege gain of any kind occurred."
                )
            else:
                f.summary = f"Cannot determine whether {ctx.subject.username} became root (see gaps)."

        return self._finalize(ctx, f)

    def _finalize(self, ctx: AnalysisContext, f: Finding) -> Finding:
        # Sudo/su usage is visible, but if full process execution isn't audited we
        # can't see the full extent of what was done as root. Disclose that whether
        # the gap is a missing execve rule or an auth.log-only (no auditd) host.
        if not source_met(ctx, "auditd", "execve audit rule") and (
            f.events or source_met(ctx, "auth")
        ):
            f.gaps.append(Gap(
                "Privilege",
                "privilege escalation is visible, but commands executed as root "
                "are not fully recorded (only sudo-invoked commands, if any), so "
                "the full extent of root activity cannot be confirmed.",
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
        AnyOf("Root activity",
              [("auditd", "execve audit rule"), ("auth", None)],
              remedy=_EXEC_REMEDY),
    )

    _TYPES = [EventType.EXEC, EventType.FILE_CHANGE, EventType.NETWORK]

    @staticmethod
    def _match_scheduler(event, persist):
        """A persistence artifact whose command/exe matches this action's binary."""
        exe = (event.attrs.get("exe") or event.attrs.get("cmdline")
               or event.attrs.get("path") or "")
        base = exe.rsplit("/", 1)[-1] if exe else ""
        if not base:
            return None
        for p in persist:
            cmd = (p.attrs.get("command") or p.attrs.get("exec_start")
                   or p.attrs.get("artifact") or "")
            if base and (base in cmd or exe and exe in cmd):
                return p
        return None

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        # "What did X do as root" spans commands + files + network done as root.
        # If auditd records commands but not file and/or network changes, root
        # activity of those kinds is unrecorded -- disclose it so the answer is
        # scope-limited (PARTIAL), never a false "full extent as root".
        if source_met(ctx, "auditd", "execve audit rule"):
            missing = []
            if not source_met(ctx, "auditd", "host-wide file-change rule"):
                missing.append("file modifications (no host-wide file-change rule)")
            if not (source_met(ctx, "auditd", "connect audit rule")
                    and source_met(ctx, "auditd", "bind audit rule")):
                missing.append("network activity (connect/bind auditing incomplete)")
            if missing:
                f.gaps.append(Gap(
                    "Root activity",
                    "command execution as root is recorded, but "
                    + " and ".join(missing) + " performed as root are not, so the "
                    "full extent of root activity is scope-limited.",
                    "auditd", _EXEC_REMEDY))

        subject_is_root = _subject_is_root(ctx)

        if subject_is_root:
            # Host-wide: every action performed with root privilege, by anyone.
            candidates = [e for e in ctx.events if e.type in self._TYPES]
        else:
            candidates = ctx.subject_events(self._TYPES)
        # Avoid double-counting a sudo command that auditd also recorded.
        candidates = prefer_primary(ctx, candidates, need_execve=True)
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

        # PV-09: root activity by a non-root subject that is NOT preceded by any
        # observed sudo/su escalation -- a proxy for a setuid binary, an exploit, or
        # an escalation path OpenPath cannot see. Deterministic classification kept
        # as a finding (a note, not a gap) so the answer stays evidence-scoped and
        # certified: either every root action is explained, or the unexplained ones
        # are named.
        if not subject_is_root:
            escs = ctx.subject_events([EventType.PRIVILEGE_ESCALATION])
            has_sudo_su = any(e.attrs.get("tool") in ("sudo", "su")
                              and e.attrs.get("res") in (None, "success") for e in escs)
            if pairs and not has_sudo_su:
                f.notes.append(
                    f"[PV-09] {len(pairs)} root action(s) attributed to "
                    f"{ctx.subject.username} with NO observed sudo/su escalation in "
                    f"the window -- possible setuid binary, exploit/LPE, or an "
                    f"escalation OpenPath does not record (evidence-scoped).")
            elif pairs:
                f.notes.append(
                    f"[PV-09] all of {ctx.subject.username}'s root activity is "
                    f"explained by an observed sudo/su escalation (no evidence of a "
                    f"non-sudo/su root gain within the covered scope).")

        # TM-05: try to explain unattributable root activity by a scheduled task --
        # match a daemon action's binary/command against a persistence artifact's
        # command (cron job / systemd ExecStart). A likely, cited correlation, never
        # asserted as proof (the launching job leaves no loginuid).
        persist = [e for e in ctx.events if e.type is EventType.PERSISTENCE]
        # Disclose root actions that cannot be tied to a human.
        unattributable = [(e, a) for e, a in pairs if not a.attributable]
        for e, _a in unattributable:
            hit = self._match_scheduler(e, persist)
            if hit is not None:
                f.notes.append(
                    f"[TM-05] unattributable root action '{e.summary}' matches "
                    f"persistence artifact '{hit.attrs.get('artifact')}' "
                    f"({hit.attrs.get('kind')}) -- likely launched by it.")
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

        # If we only have auth.log (no execve rule), we see sudo commands but not
        # file/network activity or non-sudo commands done as root -- disclose it.
        if not source_met(ctx, "auditd", "execve audit rule"):
            f.gaps.append(Gap(
                "Root activity",
                "only commands run via sudo are captured (auth.log); file and "
                "network activity performed as root, and non-sudo root commands, "
                "are not recorded without an execve rule.",
                "auditd", _EXEC_REMEDY,
            ))
        return f


class CommandsFacet(Facet):
    """What commands did the user execute (at any privilege level)?"""

    name = "commands"
    question_family = "Commands"
    requirements = (
        AnyOf("Commands",
              [("auditd", "execve audit rule"), ("auth", None)],
              remedy=_EXEC_REMEDY),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        execs = prefer_primary(ctx, ctx.subject_events([EventType.EXEC]),
                               need_execve=True)
        f.events = execs

        # If we can see sudo commands (auth.log) but not general execution, say so.
        if not source_met(ctx, "auditd", "execve audit rule") and source_met(ctx, "auth"):
            f.gaps.append(Gap("Commands", _PARTIAL_CMD, "auditd", _EXEC_REMEDY))

        if not execs:
            if any(g.question == "Commands" and g.reason != _PARTIAL_CMD
                   for g in f.gaps):
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
