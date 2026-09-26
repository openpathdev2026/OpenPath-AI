"""Origin reputation / geo (IA-10): did a login come from a new, geographically
unexpected, or known-malicious IP?

Correlates the subject's login origins (wtmp sessions, sshd auth) with a
reputation/geo feed loaded by the ip_reputation collector. OpenPath does not itself
geolocate -- it reports what the provided feed says, cited -- so the answer is
scoped to the feed's coverage, and an origin absent from the feed is reported as
"unrated", never silently cleared.
"""

from __future__ import annotations

from openpath.facets.base import AnalysisContext, Facet, Requirement
from openpath.model.event import EventType
from openpath.model.finding import Finding

_FLAGGED = {"malicious", "suspicious", "new"}


class OriginReputationFacet(Facet):
    name = "origin_reputation"
    question_family = "Origin reputation"
    requirements = (
        Requirement("ip_reputation", "Origin reputation",
                    remedy="provide an IP reputation / geo feed "
                           "(var/log/openpath/ip-reputation.json) to rate login "
                           "origins."),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        rep = {}
        for e in ctx.events:
            if e.type is EventType.OTHER and e.attrs.get("kind") == "ip_reputation":
                rep[e.attrs.get("ip")] = e

        # the subject's login origins
        origins = []
        for e in ctx.subject_events([EventType.SESSION]):
            o = e.attrs.get("origin")
            if o and o != "local":
                origins.append((o, e))
        for e in ctx.subject_events([EventType.SSH_AUTH]):
            ip = e.attrs.get("ip")
            if ip:
                origins.append((ip, e))

        flagged = []
        unrated = []
        f.events = [e for _o, e in origins]
        for ip, ev in origins:
            r = rep.get(ip)
            if r is None:
                unrated.append(ip)
                f.notes.append(f"login origin {ip}: unrated (not in the feed)")
                continue
            verdict = (r.attrs.get("reputation") or "unknown").lower()
            country = r.attrs.get("country")
            tag = "FLAGGED" if verdict in _FLAGGED else "ok"
            f.notes.append(f"login origin {ip}: {verdict}"
                           + (f" ({country})" if country else "") + f" -> {tag}")
            if verdict in _FLAGGED:
                flagged.append((ip, verdict))

        if not origins:
            f.summary = (f"{ctx.subject.username} had no remote login origins to rate "
                         f"in {ctx.window.label or 'the window'} (evidenced negative).")
            return f
        if flagged:
            f.summary = (
                f"{len(flagged)} of {ctx.subject.username}'s login origin(s) are "
                f"FLAGGED by the reputation feed: "
                + ", ".join(f"{ip} ({v})" for ip, v in flagged)
                + (f"; {len(unrated)} unrated" if unrated else "") + ".")
        else:
            f.summary = (
                f"None of {ctx.subject.username}'s {len(origins)} login origin(s) "
                f"are flagged by the feed"
                + (f"; {len(unrated)} unrated (not in the feed -- scoped negative)"
                   if unrated else "") + ".")
        return f
