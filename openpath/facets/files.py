"""Files (family 8): what files did the user change?"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
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
        f.gaps.extend(self._prereq_gaps(ctx))

        changes = ctx.subject_events([EventType.FILE_CHANGE])
        f.events = changes

        if not changes:
            if any(g.question == "Files" for g in f.gaps):
                f.summary = f"Cannot determine {ctx.subject.username}'s file changes (see gaps)."
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
