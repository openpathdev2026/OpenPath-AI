"""Accounts / groups (family 9): what accounts or groups did the user change?

Note the attribution direction: for an ADD_USER/DEL_USER/GRP_MGMT record, the
subject is the *actor* (identified by ``auid``), while ``attrs['acct']`` /
``attrs['grp']`` is the *target* account/group being changed. ``Subject.matches``
keys on ``auid`` for these records, so we correctly find the administrator, not
the account they touched.
"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding


class AccountsFacet(Facet):
    name = "accounts"
    question_family = "Accounts/groups"
    # ADD_USER/DEL_USER/GRP_MGMT are PAM/shadow user-space audit messages emitted
    # whenever auditd runs; no syscall rule is required.
    requirements = (
        Requirement("auditd", "Accounts/groups", instrument="auditd rules loaded"),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        changes = ctx.subject_events([EventType.ACCOUNT_CHANGE, EventType.GROUP_CHANGE])
        f.events = changes

        if not changes:
            if any(g.question == "Accounts/groups" for g in f.gaps):
                f.summary = (
                    f"Cannot determine account/group changes by {ctx.subject.username} (see gaps)."
                )
            else:
                f.summary = (
                    f"{ctx.subject.username} made no account or group changes in "
                    f"{ctx.window.label or 'the window'} (evidenced negative)."
                )
            return f

        acct = [e for e in changes if e.type == EventType.ACCOUNT_CHANGE]
        grp = [e for e in changes if e.type == EventType.GROUP_CHANGE]
        f.summary = (
            f"{ctx.subject.username} made {len(acct)} account change(s) and "
            f"{len(grp)} group change(s)."
        )
        for e in changes:
            target = e.attrs.get("acct") or e.attrs.get("grp") or f"id={e.attrs.get('id')}"
            f.notes.append(
                f"{e.ts.isoformat()} {e.attrs.get('action')} {target} "
                f"({e.attrs.get('res', 'n/a')})"
            )
        return f
