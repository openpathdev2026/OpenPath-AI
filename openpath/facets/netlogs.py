"""Network logs (host-level): DNS (NW-08), firewall drops (NW-10), web/proxy
(NW-12), and socket lifetimes (NW-15).

Host-level. Reads the ``NETLOG`` events the net-logs collector produces and reports
each kind, flagging security-relevant signals (a DROP/REJECT, a proxy request to an
external host). Each sub-answer is scoped to whether its log is present -- a "no
DNS queries" answer without a DNS log is disclosed via the coverage instrumentation,
never asserted as absolute.
"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding


class NetLogsFacet(Facet):
    name = "netlogs"
    question_family = "Network logs"
    requirements = (
        Requirement("netlogs", "Network logs",
                    remedy="provide DNS / firewall / proxy / socket-lifetime logs "
                           "(resolver logging, firewall LOG rules, proxy access log, "
                           "a socket tracer) for full network-telemetry answers."),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))
        logs = [e for e in ctx.events if e.type is EventType.NETLOG]
        logs.sort(key=lambda e: (e.attrs.get("kind", ""), e.summary))
        f.events = logs
        if not logs:
            if any(g.question == "Network logs" for g in f.gaps):
                f.summary = "No network-telemetry logs present (see gaps)."
            else:
                f.summary = "No network-log events recorded (evidenced negative)."
            return f

        by_kind: dict = {}
        for e in logs:
            by_kind.setdefault(e.attrs.get("kind"), []).append(e)
        dns = by_kind.get("dns", [])
        drops = by_kind.get("fw_drop", [])
        web = by_kind.get("webproxy", [])
        socks = by_kind.get("socket", [])
        for e in logs:
            f.notes.append(f"[{e.attrs.get('kind')}] {e.summary}")
        parts = []
        if dns:
            parts.append(f"{len(dns)} DNS query(ies) (NW-08)")
        if drops:
            parts.append(f"{len(drops)} firewall DROP/REJECT(s) (NW-10)")
        if web:
            parts.append(f"{len(web)} web/proxy request(s) (NW-12)")
        if socks:
            held = [e.attrs.get("held_s") for e in socks if e.attrs.get("held_s")]
            longest = f", longest held {max(held)}s" if held else ""
            parts.append(f"{len(socks)} tracked socket lifetime(s) (NW-15{longest})")
        f.summary = "Network telemetry: " + "; ".join(parts) + "."
        return f
