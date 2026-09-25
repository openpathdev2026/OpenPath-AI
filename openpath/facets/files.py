"""Files (family 8): what files did the user change?"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement, source_met
from openpath.model.coverage import Gap
from openpath.model.event import EventType
from openpath.model.finding import Finding

_FILE_REMEDY = (
    "add a file watch or write-syscall rule, e.g. "
    "-w /etc -p wa -k etc-change  (or -a always,exit -F arch=b64 -S unlink,rename,"
    "chmod,chown,truncate,creat -k file-change)"
)


class FilesFacet(Facet):
    name = "files"
    question_family = "Files"
    requirements = (
        Requirement("auditd", "Files", instrument="file watch/modify audit rule",
                    remedy=_FILE_REMEDY),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        prereq = self._prereq_gaps(ctx)
        f.gaps.extend(prereq)

        # A path-scoped -w watch answers only for the watched paths; without a
        # host-wide write-syscall rule, changes elsewhere are not recorded, so any
        # negative is scope-limited. Disclose it as a real gap (even with zero
        # events) rather than presenting a false, unqualified "no file changes".
        narrow = (source_met(ctx, "auditd", "file watch/modify audit rule")
                  and not source_met(ctx, "auditd", "host-wide file-change rule"))
        if narrow:
            f.gaps.append(Gap(
                "Files",
                "only path-scoped file watches are loaded; file changes outside the "
                "watched paths are not recorded, so this answer is scope-limited.",
                "auditd", _FILE_REMEDY))

        changes = ctx.subject_events([EventType.FILE_CHANGE])
        f.events = changes

        if not changes:
            if prereq:  # no carrier at all -> genuinely undeterminable
                f.summary = f"Cannot determine {ctx.subject.username}'s file changes (see gaps)."
            elif narrow:
                f.summary = (
                    f"No file changes by {ctx.subject.username} under the watched "
                    f"paths in {ctx.window.label or 'the window'}; changes elsewhere "
                    f"are not recorded (see gaps)."
                )
            else:
                f.summary = (
                    f"No file changes by {ctx.subject.username} recorded in "
                    f"{ctx.window.label or 'the window'} (evidenced negative)."
                )
            return f

        by_op: dict = {}
        paths = []
        for e in changes:
            op = e.attrs.get("op", "modify")
            by_op[op] = by_op.get(op, 0) + 1
            p = e.attrs.get("path")
            if p:
                paths.append(p)
        opsum = ", ".join(f"{v} {k}" for k, v in sorted(by_op.items()))
        f.summary = (
            f"{ctx.subject.username} changed {len(changes)} file(s) ({opsum})."
        )
        for e in changes:
            root = " (as root)" if (e.uid == 0 or e.attrs.get("euid") == 0) else ""
            f.notes.append(
                f"{e.ts.isoformat()} {e.attrs.get('op')} {e.attrs.get('path')}{root}"
            )
        return f
