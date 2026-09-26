"""File access / reads (FS-12): sensitive files a user READ but did not modify.

Distinct from the Files facet (which answers modifications): this reads
``EventType.FILE_READ`` events -- a read of a watched path under a read-permission
audit rule (``-w /etc/shadow -p r``). It flags reads of classically-sensitive
targets (shadow, SSH keys, sudoers). Because read auditing is heavy and often not
configured, the facet discloses that a ``-p r`` watch is required for a complete
answer, so a "no sensitive reads" negative is scoped to the read rules in place.
"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding

_SENSITIVE = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", ".ssh/",
              "id_rsa", "id_ed25519", ".pem", "/etc/ssl/private")
_READ_REMEDY = ("add a read-permission audit watch on sensitive paths, e.g. "
                "-w /etc/shadow -p r -k shadow-read")


def _sensitive(path: str) -> bool:
    return bool(path) and any(s in path for s in _SENSITIVE)


class FileAccessFacet(Facet):
    name = "file_access"
    question_family = "File access"
    requirements = (
        Requirement("auditd", "File access",
                    instrument="file watch/modify audit rule", remedy=_READ_REMEDY),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))
        reads = ctx.subject_events([EventType.FILE_READ])
        f.events = reads

        # Read auditing is not implied by a write watch; disclose the requirement so
        # a negative is scoped to the read rules actually loaded.
        f.notes.append("[scope] file reads are captured only where a read-permission "
                       "watch (-p r) is loaded; a 'no reads' answer is scoped to "
                       "those paths, never absolute.")

        if not reads:
            if any(g.question == "File access" for g in f.gaps):
                f.summary = (f"Cannot determine {ctx.subject.username}'s file reads "
                             f"(see gaps).")
            else:
                f.summary = (f"No audited sensitive-file reads by "
                             f"{ctx.subject.username} within the covered read-watch "
                             f"scope (evidenced negative, not absolute).")
            return f

        sensitive = [e for e in reads if _sensitive(e.attrs.get("path") or "")]
        for e in reads:
            tag = " [SENSITIVE]" if _sensitive(e.attrs.get("path") or "") else ""
            f.notes.append(f"{e.ts.isoformat()} read {e.attrs.get('path')}{tag}")
        f.summary = (
            f"{ctx.subject.username} read {len(reads)} watched file(s)"
            + (f", {len(sensitive)} SENSITIVE (shadow / SSH key / sudoers / TLS key)"
               if sensitive else "")
            + ".")
        return f
