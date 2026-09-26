"""Process ancestry (EX-11): the parent process and ancestry of a user's commands.

No new evidence source -- auditd's execve records already carry ``pid`` and
``ppid``. This facet reconstructs, for the subject's executed commands, the parent
process and (as far as the exec records reach) the ancestry chain, by linking a
process's ``ppid`` to another exec whose ``pid`` matches.

Its scope is disclosed honestly: only processes that *exec'd* leave an execve
record, so a fork/clone that never exec'd, and an ancestor whose exec fell outside
the window or was not audited, appear as an unresolved ``ppid`` rather than a
fabricated parent.
"""

from __future__ import annotations

from typing import List

from openpath.facets.base import AnalysisContext, Facet, Requirement, prefer_primary
from openpath.model.event import EventType
from openpath.model.finding import Finding

_EXEC_REMEDY = ("add an execve audit rule: -a always,exit -F arch=b64 -S execve "
                "-S execveat -k exec")


class ProcessTreeFacet(Facet):
    name = "process_tree"
    question_family = "Process ancestry"
    requirements = (
        Requirement("auditd", "Process ancestry", instrument="execve audit rule",
                    remedy=_EXEC_REMEDY),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        execs = prefer_primary(ctx, ctx.subject_events([EventType.EXEC]),
                               need_execve=True)
        f.events = execs
        if not execs:
            if any(g.question == "Process ancestry" for g in f.gaps):
                f.summary = (f"Cannot reconstruct {ctx.subject.username}'s process "
                             f"ancestry (see gaps).")
            else:
                f.summary = (f"No commands by {ctx.subject.username} to build a "
                             f"process tree from in {ctx.window.label or 'the window'} "
                             f"(evidenced negative).")
            return f

        # Index every exec (host-wide) by pid so a parent can be resolved even when
        # the parent ran as a different user (e.g. a shell that spawned the command).
        by_pid = {}
        for e in ctx.events:
            if e.type is EventType.EXEC and e.attrs.get("pid") is not None:
                by_pid[e.attrs["pid"]] = e

        resolved = unresolved = 0
        for e in execs:
            ppid = e.attrs.get("ppid")
            cmd = e.attrs.get("cmdline") or e.attrs.get("comm") or e.summary
            parent = by_pid.get(ppid)
            if parent is not None:
                resolved += 1
                pcmd = parent.attrs.get("cmdline") or parent.attrs.get("comm") or "?"
                f.notes.append(f"{cmd} (pid {e.attrs.get('pid')}) <- parent "
                               f"{pcmd} (pid {ppid})")
            else:
                unresolved += 1
                f.notes.append(f"{cmd} (pid {e.attrs.get('pid')}) <- parent pid "
                               f"{ppid} (exec not in window / not audited)")

        # Ancestry beyond exec'd processes is a scope note, not a coverage gap: the
        # parent-from-ppid answer is complete within the execve evidence. A
        # fork/clone that never exec'd is shown as an unresolved ppid, never invented.
        f.notes.append(
            "[scope] ancestry is reconstructed from execve records; a fork/clone "
            "that never exec'd, or an ancestor whose exec is outside the window or "
            "unaudited, appears as an unresolved ppid. Add fork/clone+exit auditing "
            "for the full non-exec'ing process tree.")

        f.summary = (
            f"{ctx.subject.username} ran {len(execs)} command(s); parent process "
            f"resolved for {resolved}, unresolved (ppid outside the audited exec "
            f"set) for {unresolved}.")
        return f
