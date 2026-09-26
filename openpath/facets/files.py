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
        # Disclose the write-syscall content blind spot on every answer: metadata
        # operations (create/delete/rename/chmod/chown/truncate) are captured by the
        # host-wide rule, but an in-place CONTENT edit (open+write to an existing
        # file) is recorded only where a file watch (-p w) covers the path. So a
        # "no changes" negative is scoped to those, never absolute.
        if source_met(ctx, "auditd", "host-wide file-change rule"):
            f.notes.append(
                "Scope: content edits to existing files (open+write) are captured "
                "only under a file watch (-p w); the host-wide rule records metadata "
                "operations. A negative is scoped to the covered evidence.")

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
        # FS-14: changes outside the subject's own scope -- not under their home dir
        # (another user's home, /etc, or a system directory). A path-based heuristic,
        # disclosed as such (true ownership needs a filesystem baseline).
        home = f"/home/{ctx.subject.username}"
        out_of_scope = [
            e for e in changes
            if (p := (e.attrs.get("path") or "")) and not (
                p == home or p.startswith(home + "/")
                or p.startswith("/tmp/") or p.startswith(f"/home/{ctx.subject.username}."))
        ]
        other_home = [e for e in out_of_scope
                      if (e.attrs.get("path") or "").startswith("/home/")]
        f.summary = (
            f"{ctx.subject.username} changed {len(changes)} file(s) ({opsum})"
            + (f"; {len(out_of_scope)} outside their home scope"
               + (f" ({len(other_home)} in another user's home)" if other_home else "")
               if out_of_scope else "")
            + ".")
        for e in out_of_scope:
            f.notes.append(f"[out-of-scope] {ctx.subject.username} modified "
                           f"{e.attrs.get('path')} (outside {home})")
        if out_of_scope:
            f.notes.append("[scope] out-of-scope is a path heuristic (not under the "
                           "user's home); exact ownership needs a filesystem baseline.")
        for e in changes:
            root = " (as root)" if (e.uid == 0 or e.attrs.get("euid") == 0) else ""
            f.notes.append(
                f"{e.ts.isoformat()} {e.attrs.get('op')} {e.attrs.get('path')}{root}"
            )
        return f
