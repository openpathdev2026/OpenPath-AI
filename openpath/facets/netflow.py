"""Network flows (host-level): inbound peers (NW-06), transport (NW-14), and data
volume (NW-04), from the conntrack tracking table.

Host-level: conntrack records host connections, not per-user activity (mapping a
flow to a user needs socket-owner correlation, disclosed as out of scope). Byte
volume (NW-04) is reported only when connection byte accounting is enabled, else
disclosed as unavailable rather than guessed.
"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding


class NetflowFacet(Facet):
    name = "netflow"
    question_family = "Network flows"
    requirements = (
        Requirement("conntrack", "Network flows",
                    remedy="provide the conntrack table (/proc/net/nf_conntrack or a "
                           "saved conntrack -L dump); enable nf_conntrack_acct for "
                           "byte volume."),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))
        flows = [e for e in ctx.events if e.type is EventType.NETFLOW]
        flows.sort(key=lambda e: e.summary)
        f.events = flows
        if not flows:
            if any(g.question == "Network flows" for g in f.gaps):
                f.summary = "Cannot assess network flows: no conntrack table (see gaps)."
            else:
                f.summary = "No tracked network flows found (evidenced negative)."
            return f

        inbound = [e for e in flows if e.attrs.get("direction") == "inbound"]
        protos = sorted({e.attrs.get("proto") for e in flows if e.attrs.get("proto")})
        peers = sorted({e.attrs.get("peer") for e in inbound if e.attrs.get("peer")})
        byte_vals = [e.attrs.get("bytes") for e in flows if e.attrs.get("bytes")]
        total = sum(v for v in byte_vals if v)
        for e in flows:
            f.notes.append(f"[{e.attrs.get('direction')}] {e.summary}")
        vol = (f"; {total} bytes transferred across {len(byte_vals)} accounted flow(s)"
               if byte_vals else
               "; byte volume unavailable (nf_conntrack_acct off) -- NW-04 scoped")
        f.summary = (
            f"{len(flows)} tracked flow(s) over {'/'.join(protos) or '?'} "
            f"(NW-14); {len(inbound)} inbound from {', '.join(peers) or 'n/a'} "
            f"(NW-06){vol}.")
        return f
