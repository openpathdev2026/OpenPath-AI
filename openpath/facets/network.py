"""Network (family 11): what network activity did the user perform?"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding

_NET_REMEDY = (
    "add a network audit rule: "
    "-a always,exit -F arch=b64 -S connect -S bind -k net"
)


class NetworkFacet(Facet):
    name = "network"
    question_family = "Network"
    requirements = (
        Requirement("auditd", "Network",
                    instrument="network (connect/bind) audit rule", remedy=_NET_REMEDY),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        net = ctx.subject_events([EventType.NETWORK])
        f.events = net

        if not net:
            if any(g.question == "Network" for g in f.gaps):
                f.summary = f"Cannot determine {ctx.subject.username}'s network activity (see gaps)."
            else:
                f.summary = (
                    f"No network activity by {ctx.subject.username} recorded in "
                    f"{ctx.window.label or 'the window'} (evidenced negative)."
                )
            return f

        outbound = [e for e in net if e.attrs.get("direction") == "outbound"]
        inbound = [e for e in net if e.attrs.get("direction") == "inbound"]
        targets = sorted({
            f"{e.attrs['addr_info']['addr']}:{e.attrs['addr_info'].get('port')}"
            for e in net
            if isinstance(e.attrs.get("addr_info"), dict)
            and e.attrs["addr_info"].get("family") in ("inet", "inet6")
        })
        f.summary = (
            f"{ctx.subject.username} performed {len(net)} network operation(s): "
            f"{len(outbound)} outbound, {len(inbound)} bind/listen."
            + (f" Endpoints: {', '.join(targets[:10])}"
               + ("..." if len(targets) > 10 else "") if targets else "")
        )
        for e in net:
            f.notes.append(f"{e.ts.isoformat()} {e.summary}")
        return f
