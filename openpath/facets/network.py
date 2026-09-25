"""Network (family 11): what network activity did the user perform?"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement, source_met
from openpath.model.coverage import Gap
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
        prereq = self._prereq_gaps(ctx)
        f.gaps.extend(prereq)

        # A connect-only or bind-only rule records just one direction; disclose the
        # uninstrumented direction as a real gap (even with zero events) so a
        # negative is scope-limited, not a false "no network activity".
        has_connect = source_met(ctx, "auditd", "connect audit rule")
        has_bind = source_met(ctx, "auditd", "bind audit rule")
        one_direction = (not prereq) and (has_connect != has_bind)
        if one_direction:
            missing = "inbound bind/listen" if has_connect else "outbound connect"
            f.gaps.append(Gap(
                "Network",
                f"only {'connect' if has_connect else 'bind'} auditing is loaded; "
                f"{missing} is not recorded, so this answer is scope-limited.",
                "auditd", _NET_REMEDY))

        net = ctx.subject_events([EventType.NETWORK])
        f.events = net

        if not net:
            if prereq:  # no carrier at all -> genuinely undeterminable
                f.summary = f"Cannot determine {ctx.subject.username}'s network activity (see gaps)."
            elif one_direction:
                shown = "outbound" if has_connect else "inbound bind/listen"
                f.summary = (
                    f"No {shown} network activity by {ctx.subject.username} in "
                    f"{ctx.window.label or 'the window'}; the other direction is "
                    f"not recorded (see gaps)."
                )
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
