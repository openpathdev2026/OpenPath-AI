"""Firewall (NW-09, host-level): what packet-filter rules are in place.

Host-level (not per-user). Reads the ``FIREWALL`` state the firewall collector
produces -- chain default policies and rules -- and flags a permissive default
(ACCEPT on an input/forward chain). Whether a specific connection was dropped
(NW-10) needs firewall LOGGING, disclosed here as a separate evidence source.
"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding


class FirewallFacet(Facet):
    name = "firewall"
    question_family = "Firewall"
    requirements = (
        Requirement("firewall", "Firewall",
                    remedy="save the packet-filter ruleset (nft list ruleset, or "
                           "iptables-save) so firewall posture can be assessed."),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))
        rules = [e for e in ctx.events if e.type is EventType.FIREWALL]
        rules.sort(key=lambda e: (e.attrs.get("kind", ""), e.summary))
        f.events = rules
        if not rules:
            if any(g.question == "Firewall" for g in f.gaps):
                f.summary = "Cannot assess firewall rules: no ruleset present (see gaps)."
            else:
                f.summary = "No firewall ruleset found (evidenced negative)."
            return f

        policies = [e for e in rules if e.attrs.get("kind") == "policy"]
        rule_lines = [e for e in rules if e.attrs.get("kind") == "rule"]
        permissive = [e for e in policies if e.attrs.get("permissive")]
        for e in rules:
            f.notes.append(f"[{e.attrs.get('kind')}] {e.summary}")
        f.summary = (
            f"Firewall: {len(rule_lines)} rule(s) across {len(policies)} chain "
            f"policy(ies)"
            + (f"; {len(permissive)} chain(s) default-ACCEPT (permissive)"
               if permissive else "")
            + ". Whether traffic was actually dropped (NW-10) requires firewall "
            "logging, a separate evidence source.")
        return f
