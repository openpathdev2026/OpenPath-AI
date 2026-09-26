"""Persistence (family 15): what auto-start / scheduled execution is configured,
and did the subject establish any of it?

This facet federates two evidence dimensions and never conflates them:

  * **State** -- the current inventory of cron/at jobs, systemd units and timers,
    linger, and legacy startup, read by the persistence collector. This is timeless
    (a snapshot), so it is reported regardless of the activity window. An artifact
    is attributed to the subject only when it *names* them (a per-user crontab, a
    linger flag, a ``~/.config/systemd/user`` unit) -- never guessed.

  * **Acts** -- what the subject actually *did* in the window that establishes
    persistence: writing a unit/cron/startup file (a ``FILE_CHANGE`` under a
    persistence path, attributed by auid) or running a persistence-management tool
    (``crontab``/``at``/``systemctl``/``systemd-run``/... via audited execve). These
    tie a human to persistence with the same auid-centric attribution used
    everywhere else.

The subject's *footprint* is the union of the artifacts they own and the
persistence acts they took. The full host inventory is always available host-wide
(``--actor any``) for the "what is configured on this host" questions. A clean bill
("did NOT establish persistence") is an *evidenced negative*: it requires both the
state inventory (a persistence source) and in-window act auditing to be present, or
the facet says so instead of falsely clearing the user.
"""

from __future__ import annotations

from typing import List

from openpath.facets.base import AnalysisContext, Facet, Requirement, source_met
from openpath.model.coverage import Gap
from openpath.model.event import Event, EventType
from openpath.model.finding import Finding

# Filesystem locations whose modification establishes persistence. A FILE_CHANGE
# to one of these (a file exactly, or anything under one of the directories),
# attributed to the subject, is a persistence *act*. Matching is boundary-correct:
# a directory matches only at a path separator, so /etc/init never swallows
# /etc/initramfs-tools.
_PERSIST_DIRS = (
    "/var/spool/cron", "/var/spool/at",
    "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system",
    "/etc/systemd/user", "/var/lib/systemd/linger",
    "/etc/rc.d", "/etc/init.d", "/etc/init",
)
_PERSIST_FILES = ("/etc/crontab", "/etc/anacrontab", "/etc/rc.local")
# ``~/.config/systemd/user`` lives under a home dir; matched separately.
_USER_UNIT_MARKER = "/.config/systemd/user"

# Command basenames that manage persistence. An audited execve of one of these,
# attributed to the subject, is a persistence *act*.
_PERSIST_TOOLS = {
    "crontab", "at", "batch", "atq", "atrm",
    "systemctl", "systemd-run", "chkconfig", "update-rc.d",
    "rc-update", "loginctl",
}


def _is_persist_path(path: str) -> bool:
    if not path:
        return False
    if _USER_UNIT_MARKER in path:
        return True
    if path in _PERSIST_FILES:
        return True
    return any(path == d or path.startswith(d + "/") for d in _PERSIST_DIRS)


def _tool_basename(e: Event) -> str:
    exe = e.attrs.get("exe") or ""
    base = exe.rsplit("/", 1)[-1] if exe else ""
    return base or (e.attrs.get("comm") or "")


class PersistenceFacet(Facet):
    name = "persistence"
    question_family = "Persistence"
    requirements = (
        Requirement(
            "persistence", "Persistence",
            remedy="ingest scheduled-task / unit state (cron spools, /etc/cron*, "
                   "/etc/systemd/system, ~/.config/systemd/user, linger, rc.local) "
                   "so current persistence configuration can be enumerated."),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        artifacts = [e for e in ctx.events if e.type is EventType.PERSISTENCE]
        artifacts.sort(key=lambda e: (e.attrs.get("kind", ""), e.summary))

        # State: artifacts that name the subject (per-user crontab, linger, user unit).
        own_artifacts = [a for a in artifacts if ctx.subject.matches(a)]

        # Acts: in-window persistence file writes + persistence-tool execs by subject.
        file_acts = [
            e for e in ctx.subject_events([EventType.FILE_CHANGE])
            if _is_persist_path(e.attrs.get("path") or "")
        ]
        tool_execs = [
            e for e in ctx.subject_events([EventType.EXEC])
            if _tool_basename(e) in _PERSIST_TOOLS
        ]

        footprint: List[Event] = own_artifacts + file_acts + tool_execs
        footprint.sort(key=lambda e: e.ts)
        f.events = footprint

        # Coverage of the two dimensions.
        has_state = source_met(ctx, "persistence")
        has_file_audit = (source_met(ctx, "auditd", "host-wide file-change rule")
                          or source_met(ctx, "auditd", "file watch/modify audit rule"))
        has_exec_audit = source_met(ctx, "auditd", "execve audit rule")

        # The establishment (act) dimension is only fully visible with host-wide
        # file-change auditing: writing a unit/cron file *in place* leaves a
        # FILE_CHANGE only if that path class is watched. Disclose the shortfall so a
        # "did they establish persistence" answer is scoped, never a false clean bill.
        if has_state and not has_file_audit:
            f.gaps.append(Gap(
                "Persistence",
                "current persistence state is enumerated, but in-window "
                "establishment ACTS (an in-place write to a unit/cron/startup file) "
                "are only fully captured with host-wide file-change auditing, which "
                "is not loaded; a newly-planted artifact may not be tied to who wrote "
                "it, and pre-horizon changes are invisible.",
                "auditd",
                "load a host-wide file-change audit rule covering /etc/cron*, "
                "/etc/systemd/system, and legacy startup paths."))

        # Host-wide inventory for context (the 'what is configured on this host'
        # questions read this; each line stays cited via the artifact's citations).
        for a in artifacts:
            who = a.actor_name or "unattributed"
            f.notes.append(f"[inventory:{a.attrs.get('kind')}] {a.summary} "
                           f"(owner: {who})")

        # Summaries -------------------------------------------------------------- #
        if not has_state and not footprint:
            f.summary = (
                f"Cannot enumerate persistence for {ctx.subject.username}: no "
                f"scheduled-task / unit state source is present (see gaps).")
            return f

        if not footprint:
            scope = ("state inventory and in-window act auditing"
                     if has_file_audit or has_exec_audit else "state inventory")
            f.summary = (
                f"{ctx.subject.username} established no persistence attributable to "
                f"them, and owns none currently configured, within the covered "
                f"evidence scope ({scope}) -- an evidenced negative, not an absolute "
                f"claim. The host has {len(artifacts)} persistence artifact(s) total "
                f"(see inventory).")
            return f

        n_own = len(own_artifacts)
        n_file = len(file_acts)
        n_exec = len(tool_execs)
        bits = []
        if n_own:
            bits.append(f"{n_own} configured artifact(s) they own")
        if n_file:
            bits.append(f"{n_file} persistence file write(s)")
        if n_exec:
            bits.append(f"{n_exec} persistence-tool invocation(s)")
        f.summary = (
            f"{ctx.subject.username} has a persistence footprint of "
            f"{', '.join(bits)} (host has {len(artifacts)} artifact(s) total).")
        return f
