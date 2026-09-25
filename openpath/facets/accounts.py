"""Accounts / groups (family 9): what accounts or groups did the user change?

Note the attribution direction: for an ADD_USER/DEL_USER/GRP_MGMT record, the
subject is the *actor* (identified by ``auid``), while ``attrs['acct']`` /
``attrs['grp']`` is the *target* account/group being changed. ``Subject.matches``
keys on ``auid`` for these records, so we correctly find the administrator, not
the account they touched.
"""

import os

from openpath.facets.base import AnalysisContext, AnyOf, Facet, prefer_primary
from openpath.model.event import EventType
from openpath.model.finding import Finding

# Command basenames that administer accounts/groups. When a subject runs one of
# these (via sudo, captured in auth.log, or via an audited execve), it attributes
# the account change to them -- important on hosts where the account-change record
# itself carries no actor (syslog useradd lines).
_ADMIN_TOOLS = {
    "useradd", "userdel", "usermod", "adduser", "deluser",
    "groupadd", "groupdel", "groupmod", "addgroup", "delgroup",
    "gpasswd", "passwd", "chage", "chpasswd", "newusers", "vipw", "vigr",
}


class AccountsFacet(Facet):
    name = "accounts"
    question_family = "Accounts/groups"
    # Account/group changes are recorded by auditd (ADD_USER/DEL_USER/GRP_MGMT,
    # emitted whenever auditd runs) or by syslog (useradd/groupadd lines).
    requirements = (
        AnyOf("Accounts/groups",
              [("auditd", "auditd rules loaded"), ("auth", None)],
              remedy="run auditd (load contrib/openpath.rules) or ensure "
                     "/var/log/auth.log (or /var/log/secure) is present"),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        changes = ctx.subject_events([EventType.ACCOUNT_CHANGE, EventType.GROUP_CHANGE])
        # Syslog account-change lines carry no actor, so also attribute via the
        # subject's own execution of an account-admin tool (e.g. sudo useradd).
        admin_execs = [
            e for e in ctx.subject_events([EventType.EXEC])
            if os.path.basename(e.attrs.get("exe") or "") in _ADMIN_TOOLS
            or (e.attrs.get("comm") in _ADMIN_TOOLS)
            or (e.attrs.get("argv") and os.path.basename(e.attrs["argv"][0]) in _ADMIN_TOOLS)
        ]
        # Drop the auth.log copy of an admin command auditd also recorded.
        admin_execs = prefer_primary(ctx, admin_execs, need_execve=True)
        changes = sorted(changes + admin_execs, key=lambda e: e.ts)
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
        admin = [e for e in changes if e.type == EventType.EXEC]
        parts = [f"{len(acct)} account change(s)", f"{len(grp)} group change(s)"]
        if admin:
            parts.append(f"{len(admin)} account-admin command(s)")
        f.summary = f"{ctx.subject.username} made " + ", ".join(parts) + "."
        for e in changes:
            if e.type == EventType.EXEC:
                f.notes.append(f"{e.ts.isoformat()} ran {e.attrs.get('cmdline')}")
            else:
                target = (e.attrs.get("acct") or e.attrs.get("grp")
                          or f"id={e.attrs.get('id')}")
                f.notes.append(
                    f"{e.ts.isoformat()} {e.attrs.get('action')} {target} "
                    f"({e.attrs.get('res', 'n/a')})")
        return f
