"""Accounts (family 9) and Groups (family 10): what accounts/groups did the user
create or modify?

Attribution direction: for an ADD_USER/DEL_USER/GRP_MGMT record the subject is the
*actor* (identified by ``auid``), while the acct/grp is the *target*. On hosts
where the change record carries no actor (syslog useradd lines), attribution also
comes from the subject's own execution of an account/group admin tool (e.g. sudo
useradd), captured via auth.log or an audited execve.
"""

from __future__ import annotations

import os

from openpath.facets.base import AnalysisContext, AnyOf, Facet, prefer_primary
from openpath.model.event import EventType
from openpath.model.finding import Finding

_ACCOUNT_TOOLS = {
    "useradd", "userdel", "usermod", "adduser", "deluser",
    "passwd", "chage", "chpasswd", "newusers", "vipw",
}
_GROUP_TOOLS = {
    "groupadd", "groupdel", "groupmod", "addgroup", "delgroup", "gpasswd", "vigr",
}
_ANYOF = AnyOf(
    "identity",
    [("auditd", "auditd rules loaded"), ("auth", None)],
    remedy="run auditd (load contrib/openpath.rules) or ensure /var/log/auth.log "
           "(or /var/log/secure) is present",
)


def _admin_execs(ctx: AnalysisContext, tools):
    execs = [
        e for e in ctx.subject_events([EventType.EXEC])
        if os.path.basename(e.attrs.get("exe") or "") in tools
        or (e.attrs.get("comm") in tools)
        or (e.attrs.get("argv") and os.path.basename(e.attrs["argv"][0]) in tools)
    ]
    return prefer_primary(ctx, execs, need_execve=True)


class AccountsFacet(Facet):
    name = "accounts"
    question_family = "Accounts"
    requirements = (AnyOf("Accounts", _ANYOF.options, remedy=_ANYOF.remedy),)

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        changes = ctx.subject_events([EventType.ACCOUNT_CHANGE])
        admin = _admin_execs(ctx, _ACCOUNT_TOOLS)
        events = sorted(changes + admin, key=lambda e: e.ts)
        f.events = events

        if not events:
            if any(g.question == "Accounts" for g in f.gaps):
                f.summary = f"Cannot determine account changes by {ctx.subject.username} (see gaps)."
            else:
                f.summary = (f"{ctx.subject.username} made no account changes in "
                             f"{ctx.window.label or 'the window'} (evidenced negative).")
            return f

        n_change = sum(1 for e in events if e.type == EventType.ACCOUNT_CHANGE)
        parts = [f"{n_change} account change(s)"]
        n_admin = len(events) - n_change
        if n_admin:
            parts.append(f"{n_admin} account-admin command(s)")
        f.summary = f"{ctx.subject.username} made " + ", ".join(parts) + "."
        for e in events:
            if e.type == EventType.EXEC:
                f.notes.append(f"{e.ts.isoformat()} ran {e.attrs.get('cmdline')}")
            else:
                target = e.attrs.get("acct") or f"id={e.attrs.get('id')}"
                f.notes.append(f"{e.ts.isoformat()} {e.attrs.get('action')} {target} "
                               f"({e.attrs.get('res', 'n/a')})")
        return f


class GroupsFacet(Facet):
    name = "groups"
    question_family = "Groups"
    requirements = (AnyOf("Groups", _ANYOF.options, remedy=_ANYOF.remedy),)

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        changes = ctx.subject_events([EventType.GROUP_CHANGE])
        admin = _admin_execs(ctx, _GROUP_TOOLS)
        events = sorted(changes + admin, key=lambda e: e.ts)
        f.events = events

        if not events:
            if any(g.question == "Groups" for g in f.gaps):
                f.summary = f"Cannot determine group changes by {ctx.subject.username} (see gaps)."
            else:
                f.summary = (f"{ctx.subject.username} made no group changes in "
                             f"{ctx.window.label or 'the window'} (evidenced negative).")
            return f

        n_change = sum(1 for e in events if e.type == EventType.GROUP_CHANGE)
        parts = [f"{n_change} group change(s)"]
        n_admin = len(events) - n_change
        if n_admin:
            parts.append(f"{n_admin} group-admin command(s)")
        f.summary = f"{ctx.subject.username} made " + ", ".join(parts) + "."
        for e in events:
            if e.type == EventType.EXEC:
                f.notes.append(f"{e.ts.isoformat()} ran {e.attrs.get('cmdline')}")
            else:
                target = e.attrs.get("grp") or f"id={e.attrs.get('id')}"
                f.notes.append(f"{e.ts.isoformat()} {e.attrs.get('action')} {target} "
                               f"({e.attrs.get('res', 'n/a')})")
        return f
