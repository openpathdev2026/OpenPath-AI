"""File integrity / content diff (FS-13): what exactly changed inside a file.

Reads ``EventType.FILE_DIFF`` (before/after content from a file-integrity monitor
or content-snapshot bundle) for the subject. auditd alone cannot answer this -- it
records the modification act, not the content -- so the facet is explicit that a
content answer requires that FIM evidence, and is scoped to the files it covers.
"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding


class FileIntegrityFacet(Facet):
    name = "file_integrity"
    question_family = "File content"
    requirements = (
        Requirement("file_integrity", "File content",
                    remedy="run a file-integrity monitor (AIDE/Tripwire/osquery) or "
                           "include content snapshots so before/after diffs are "
                           "available; auditd records the change act, not content."),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))
        diffs = ctx.subject_events([EventType.FILE_DIFF])
        # host-wide fallback: content diffs may be unattributed; include those too
        if not diffs:
            diffs = [e for e in ctx.events if e.type is EventType.FILE_DIFF]
        f.events = diffs
        f.notes.append("[scope] content diffs come from a file-integrity monitor; "
                       "coverage is limited to the files it snapshots.")
        if not diffs:
            if any(g.question == "File content" for g in f.gaps):
                f.summary = ("Cannot show file content changes: no file-integrity "
                             "(content-diff) evidence present (see gaps).")
            else:
                f.summary = ("No content-level file changes recorded within the "
                             "file-integrity monitor's coverage (evidenced negative).")
            return f

        for e in diffs:
            a = e.attrs
            f.notes.append(
                f"{e.ts.isoformat()} {a.get('path')}: "
                f"+{a.get('lines_added')}/-{a.get('lines_removed')} line(s)"
                + (f"  before={a.get('before')!r} after={a.get('after')!r}"
                   if a.get('before') is not None else ""))
        f.summary = (
            f"{len(diffs)} file(s) have captured content changes (before/after) "
            f"within the file-integrity monitor's coverage.")
        return f
