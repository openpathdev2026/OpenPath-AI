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
        # NW-03: beaconing / fan-out. Deterministic signals from the connect set:
        #  - beaconing: >=4 outbound connects to the SAME endpoint at near-regular
        #    intervals (low jitter -- max gap within 25% of the mean);
        #  - fan-out: outbound connects to >=20 distinct endpoints (scan/spray).
        beacons = self._beaconing(outbound)
        fanout = len({t for t in targets}) if outbound else 0
        anomaly = ""
        for endpoint, n, mean_s in beacons:
            f.notes.append(f"[beaconing] {n} regular outbound connects to {endpoint} "
                           f"(~every {int(mean_s)}s) -- possible C2 beacon")
        if beacons:
            anomaly += f" BEACONING to {len(beacons)} endpoint(s)."
        if fanout >= 20:
            f.notes.append(f"[fan-out] outbound connects to {fanout} distinct "
                           f"endpoints -- possible scanning/spraying")
            anomaly += f" FAN-OUT to {fanout} endpoints."

        f.summary = (
            f"{ctx.subject.username} performed {len(net)} network operation(s): "
            f"{len(outbound)} outbound, {len(inbound)} bind/listen."
            + (f" Endpoints: {', '.join(targets[:10])}"
               + ("..." if len(targets) > 10 else "") if targets else "")
            + anomaly
        )
        for e in net:
            f.notes.append(f"{e.ts.isoformat()} {e.summary}")
        return f

    @staticmethod
    def _beaconing(outbound):
        """Return [(endpoint, count, mean_interval_s)] for near-regular repeats."""
        by_ep: dict = {}
        for e in outbound:
            ai = e.attrs.get("addr_info")
            if isinstance(ai, dict) and ai.get("family") in ("inet", "inet6"):
                ep = f"{ai.get('addr')}:{ai.get('port')}"
                by_ep.setdefault(ep, []).append(e.ts)
        out = []
        for ep, times in by_ep.items():
            if len(times) < 4:
                continue
            times = sorted(times)
            gaps = [(times[i + 1] - times[i]).total_seconds()
                    for i in range(len(times) - 1)]
            mean = sum(gaps) / len(gaps)
            if mean <= 0:
                continue
            # low jitter: every gap within 25% of the mean -> regular cadence
            if all(abs(g - mean) <= 0.25 * mean for g in gaps):
                out.append((ep, len(times), mean))
        return out
