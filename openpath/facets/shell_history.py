"""Shell history (EX-12): the commands a user typed into their interactive shell.

A deliberately weak, heavily-disclosed source. It answers "what did {user} type?"
from their shell-history file, but the file is user-editable, usually carries no
timestamp, and records intent to type -- not proof of execution (for which the
Commands facet's audited execve evidence is authoritative). The facet always
discloses this so the answer is never mistaken for audited execution.
"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding


class ShellHistoryFacet(Facet):
    name = "shell_history"
    question_family = "Shell history"
    requirements = (
        Requirement("shell_history", "Shell history",
                    remedy="collect ~/.bash_history / ~/.zsh_history (or enable "
                           "audited execve for authoritative command evidence)."),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))
        hist = ctx.subject_events([EventType.SHELL_HISTORY])
        f.events = hist
        if not hist:
            if any(g.question == "Shell history" for g in f.gaps):
                f.summary = (f"No shell history available for "
                             f"{ctx.subject.username} (see gaps).")
            else:
                f.summary = (f"{ctx.subject.username} has no shell-history entries "
                             f"(evidenced negative within the covered scope).")
            return f

        timed = sum(1 for e in hist if e.attrs.get("timed"))
        f.summary = (
            f"{ctx.subject.username}'s shell history holds {len(hist)} command(s) "
            f"({timed} with a recorded timestamp). NOTE: shell history is "
            f"user-editable and not proof of execution -- corroborate with audited "
            f"commands.")
        for e in hist:
            f.notes.append(f"{e.attrs.get('cmdline')}"
                           + ("" if e.attrs.get("timed") else "  (time unknown)"))
        # Standing scope caveat (a note, not a gap: the history IS the answer, and
        # its weakness is disclosed rather than treated as missing coverage).
        f.notes.append("[scope] history files carry no login uid, are editable, and "
                       "(without HISTTIMEFORMAT) are un-timestamped; treat as a lead, "
                       "not authoritative execution evidence.")
        return f
