"""Packages (family 10): what software did the user install/remove/change?

Package logs record *what* changed, never *who*. So attribution is a correlation:
a package transaction is attributed to the subject only when the subject is seen
(via audited execve) running a package manager in the interval leading up to the
transaction. When command auditing is unavailable we do not guess -- we report the
host-level changes and disclose that per-user attribution is not possible.
"""

from __future__ import annotations

import os
from datetime import timedelta
from typing import List, Tuple

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.citation import Citation
from openpath.model.coverage import Gap
from openpath.model.event import Event, EventType
from openpath.model.finding import Finding

_PKG_MANAGERS = {
    "dnf", "dnf5", "microdnf", "yum", "rpm",
    "apt", "apt-get", "aptitude", "dpkg", "dpkg-deb",
    "pacman", "zypper",
}
# How long after a package-manager invocation a resulting transaction may land.
_CORRELATION_WINDOW = timedelta(minutes=30)


def _basename(path) -> str:
    return os.path.basename(path) if path else ""


def attribute_packages(
    ctx: AnalysisContext,
) -> Tuple[List[Event], List[Event], bool]:
    """Correlate package transactions with the subject's package-manager execs.

    Returns ``(attributed, host_changes, can_attribute)`` where:
        * ``attributed`` are package-change events (copied, with the attributing
          exec added as an extra citation and ``actor_name`` set) that we can tie
          to the subject;
        * ``host_changes`` are all package transactions in the window (context);
        * ``can_attribute`` is False when command auditing is unavailable, meaning
          no per-user attribution is possible and the caller must disclose that.
    """
    host_changes = [e for e in ctx.events if e.type == EventType.PACKAGE_CHANGE]
    host_changes.sort(key=lambda e: e.ts)

    # Attribution needs to see the subject run a package manager. That comes from
    # an audited execve, or from a sudo package-manager command in auth.log.
    auditd = ctx.ledger.get("auditd")
    auth = ctx.ledger.get("auth")
    can_attribute = bool(
        (auditd and auditd.has_instrument("execve audit rule"))
        or (auth and auth.status.value in ("available", "empty"))
    )

    if not can_attribute:
        return [], host_changes, False

    pm_execs = [
        e for e in ctx.subject_events([EventType.EXEC])
        if _basename(e.attrs.get("exe")) in _PKG_MANAGERS
        or (e.attrs.get("comm") in _PKG_MANAGERS)
    ]

    attributed: List[Event] = []
    for pkg in host_changes:
        match = None
        for ex in pm_execs:
            if ex.ts <= pkg.ts <= ex.ts + _CORRELATION_WINDOW:
                match = ex
                break
        if match is not None:
            cites = list(pkg.citations) + [
                Citation(
                    "correlation",
                    match.citations[0].locator if match.citations else "auditd",
                    f"attributed to {ctx.subject.username} via audited exec "
                    f"'{match.attrs.get('cmdline')}' at {match.ts.isoformat()}",
                )
            ]
            attributed.append(
                Event(
                    ts=pkg.ts, type=EventType.PACKAGE_CHANGE, source_id=pkg.source_id,
                    summary=pkg.summary, actor_name=ctx.subject.username,
                    auid=match.auid, uid=match.uid,
                    attrs={**pkg.attrs, "attributed_via": match.attrs.get("cmdline")},
                    citations=cites,
                )
            )
    return attributed, host_changes, True


class PackagesFacet(Facet):
    name = "packages"
    question_family = "Packages"
    requirements = (
        Requirement("packages", "Packages",
                    instrument="package transaction log present"),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        attributed, host_changes, can_attribute = attribute_packages(ctx)
        f.events = attributed

        if not host_changes:
            if any(g.question == "Packages" for g in f.gaps):
                f.summary = f"Cannot determine software changes by {ctx.subject.username} (see gaps)."
            else:
                f.summary = (
                    f"No package transactions occurred on the host in "
                    f"{ctx.window.label or 'the window'}, so {ctx.subject.username} "
                    f"changed no software (evidenced negative)."
                )
            return f

        if not can_attribute:
            f.gaps.append(Gap(
                "Packages",
                f"{len(host_changes)} package transaction(s) occurred on the host, "
                f"but package logs do not record the user and command auditing "
                f"(execve rule) is unavailable, so they cannot be attributed to "
                f"{ctx.subject.username} specifically.",
                "packages",
                "add an execve audit rule so package-manager invocations are "
                "recorded with the invoking user (auid).",
            ))
            f.summary = (
                f"{len(host_changes)} software change(s) occurred on the host but "
                f"cannot be attributed to {ctx.subject.username} without command "
                f"auditing (see gaps)."
            )
            for e in host_changes:
                f.notes.append(f"[host] {e.ts.isoformat()} {e.summary}")
            return f

        if not attributed:
            f.summary = (
                f"{ctx.subject.username} made no software changes in "
                f"{ctx.window.label or 'the window'} (evidenced negative); the host "
                f"had {len(host_changes)} package transaction(s) attributable to "
                f"other actors."
            )
            for e in host_changes:
                f.notes.append(f"[other actor] {e.ts.isoformat()} {e.summary}")
            return f

        acts: dict = {}
        for e in attributed:
            a = e.attrs.get("action", "change")
            acts[a] = acts.get(a, 0) + 1
        summ = ", ".join(f"{v} {k}" for k, v in sorted(acts.items()))
        f.summary = (
            f"{ctx.subject.username} changed {len(attributed)} package(s) ({summ})."
        )
        for e in attributed:
            f.notes.append(
                f"{e.ts.isoformat()} {e.summary} (via {e.attrs.get('attributed_via')})"
            )
        return f
