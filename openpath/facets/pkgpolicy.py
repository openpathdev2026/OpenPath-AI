"""Package policy / provenance (host-level facet): PK-13/14/15/16.

Host-level, like system lifecycle -- the answers are about the machine's software
supply-chain configuration, not one user, so it does not filter by subject and is
not folded into the per-user Core overview. It reads the ``PKG_POLICY`` state the
package-policy collector produces: configured repositories (and any untrusted
origin), version-locks/holds, GPG-signature policy, and which package managers
OpenPath captures.
"""

from __future__ import annotations

from typing import List

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import Event, EventType
from openpath.model.finding import Finding


class PackagePolicyFacet(Facet):
    name = "pkg_policy"
    question_family = "Package policy"
    requirements = (
        Requirement("pkgpolicy", "Package policy",
                    remedy="ingest package configuration (/etc/yum.repos.d, "
                           "/etc/apt/sources.list[.d], versionlock lists, dnf.conf) "
                           "so repository provenance and signature policy can be "
                           "assessed."),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))
        arts = [e for e in ctx.events if e.type is EventType.PKG_POLICY]
        arts.sort(key=lambda e: (e.attrs.get("kind", ""), e.summary))
        f.events = arts
        if not arts:
            f.summary = ("Cannot assess package policy/provenance: no package "
                         "configuration state is present (see gaps).")
            return f

        repos = [e for e in arts if e.attrs.get("kind") == "repo"]
        untrusted = [e for e in repos if e.attrs.get("trusted") is False]
        locks = [e for e in arts if e.attrs.get("kind") == "versionlock"]
        gpg = [e for e in arts if e.attrs.get("kind") == "gpg_policy"]
        gpg_off = [e for e in gpg if e.attrs.get("gpgcheck") is False]
        for e in arts:
            f.notes.append(f"[{e.attrs.get('kind')}] {e.summary}")

        bits = [f"{len(repos)} configured repo(s)"]
        if untrusted:
            bits.append(f"{len(untrusted)} from an UNTRUSTED origin")
        if locks:
            bits.append(f"{len(locks)} version-lock(s)/hold(s)")
        if gpg_off:
            bits.append("gpgcheck DISABLED (unsigned packages accepted)")
        f.summary = "Package supply chain: " + ", ".join(bits) + "."
        return f
