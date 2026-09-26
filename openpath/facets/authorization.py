"""Authorization (family 16): who holds elevated privilege, and did the subject
grant or change any of it?

Like the persistence facet, this federates two dimensions it never conflates:

  * **State** -- the current authorization inventory (privileged group membership,
    sudoers grants, locked/passwordless accounts, SSH authorized_keys, SSH auth
    policy), read by the authz collector. An artifact is attributed to the account
    a rule *names* (a group member, a sudo spec's user, the shadow account, the
    key's home owner); host-wide policy (sshd directives) is unattributed.

  * **Acts** -- what the subject did in the window that changes authorization: a
    ``FILE_CHANGE`` to an authorization config (``/etc/sudoers*``, ``/etc/group``,
    ``/etc/shadow``, ``~/.ssh/authorized_keys``, ``/etc/pam.d``, ``sshd_config``) or
    an audited execve of a privilege-management tool (``usermod``, ``gpasswd``,
    ``visudo``, ...), attributed by auid.

The subject's *authorization footprint* is the union of the grants they hold and
the authorization-changing acts they took. Host-wide inventory answers "who is
privileged / what is the policy" (``--actor any``). A negative ("did NOT change
authorization") is an evidenced negative only when both the state inventory and
in-window act auditing are present, else it degrades to PARTIAL.
"""

from __future__ import annotations

from typing import List

from openpath.facets.base import AnalysisContext, Facet, Requirement, source_met
from openpath.model.coverage import Gap
from openpath.model.event import Event, EventType
from openpath.model.finding import Finding

# Config whose modification changes authorization. Boundary-correct matching.
_AUTHZ_DIRS = ("/etc/sudoers.d", "/etc/pam.d", "/etc/ssh")
_AUTHZ_FILES = ("/etc/sudoers", "/etc/group", "/etc/gshadow", "/etc/shadow",
                "/etc/passwd", "/etc/nsswitch.conf", "/etc/security/access.conf")
_SSH_KEY_MARKER = "/.ssh/authorized_keys"

_AUTHZ_TOOLS = {
    "usermod", "gpasswd", "visudo", "groupmod", "useradd", "adduser",
    "passwd", "chage", "pam-auth-update", "ssh-keygen",
}


def _is_authz_path(path: str) -> bool:
    if not path:
        return False
    if _SSH_KEY_MARKER in path:
        return True
    if path in _AUTHZ_FILES:
        return True
    return any(path == d or path.startswith(d + "/") for d in _AUTHZ_DIRS)


def _tool_basename(e: Event) -> str:
    exe = e.attrs.get("exe") or ""
    base = exe.rsplit("/", 1)[-1] if exe else ""
    return base or (e.attrs.get("comm") or "")


class AuthorizationFacet(Facet):
    name = "authorization"
    question_family = "Authorization"
    requirements = (
        Requirement(
            "authz", "Authorization",
            remedy="ingest authorization state (/etc/group, /etc/sudoers[.d], "
                   "/etc/shadow, ~/.ssh/authorized_keys, /etc/ssh/sshd_config) so "
                   "current privilege configuration can be enumerated."),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        artifacts = [e for e in ctx.events if e.type is EventType.AUTHZ]
        artifacts.sort(key=lambda e: (e.attrs.get("kind", ""), e.summary))

        own = [a for a in artifacts if ctx.subject.matches(a)]
        file_acts = [
            e for e in ctx.subject_events([EventType.FILE_CHANGE])
            if _is_authz_path(e.attrs.get("path") or "")
        ]
        tool_execs = [
            e for e in ctx.subject_events([EventType.EXEC])
            if _tool_basename(e) in _AUTHZ_TOOLS
        ]
        footprint: List[Event] = own + file_acts + tool_execs
        footprint.sort(key=lambda e: e.ts)
        f.events = footprint

        has_state = source_met(ctx, "authz")
        has_file_audit = (source_met(ctx, "auditd", "host-wide file-change rule")
                          or source_met(ctx, "auditd", "file watch/modify audit rule"))

        if has_state and not has_file_audit:
            f.gaps.append(Gap(
                "Authorization",
                "current authorization state is enumerated, but in-window CHANGES "
                "to it (an edit to sudoers/group/authorized_keys, a usermod/gpasswd) "
                "are only fully captured with host-wide file-change auditing, which "
                "is not loaded; a grant added in the window may not be tied to who "
                "made it, and pre-horizon changes are invisible.",
                "auditd",
                "load a host-wide file-change audit rule covering /etc/sudoers*, "
                "/etc/group, /etc/shadow and ~/.ssh/authorized_keys."))

        for a in artifacts:
            who = a.actor_name or "host-wide"
            f.notes.append(f"[authz:{a.attrs.get('kind')}] {a.summary} (subject: {who})")

        if not has_state and not footprint:
            f.summary = (
                f"Cannot enumerate authorization for {ctx.subject.username}: no "
                f"privilege-configuration state source is present (see gaps).")
            return f

        if not footprint:
            f.summary = (
                f"{ctx.subject.username} holds no enumerated elevated privilege and "
                f"made no authorization change attributable to them, within the "
                f"covered evidence scope -- an evidenced negative, not an absolute "
                f"claim. The host has {len(artifacts)} authorization artifact(s) "
                f"total (see inventory).")
            return f

        n_own, n_file, n_exec = len(own), len(file_acts), len(tool_execs)
        bits = []
        if n_own:
            bits.append(f"{n_own} grant(s)/privilege(s) they hold")
        if n_file:
            bits.append(f"{n_file} authorization-config edit(s)")
        if n_exec:
            bits.append(f"{n_exec} privilege-management command(s)")
        f.summary = (
            f"{ctx.subject.username} has an authorization footprint of "
            f"{', '.join(bits)} (host has {len(artifacts)} artifact(s) total).")
        return f
