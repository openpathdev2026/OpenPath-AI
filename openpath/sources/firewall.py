"""Firewall collector: packet-filter ruleset currently in place (NW-09).

Reads the on-host firewall configuration -- nftables (``/etc/nftables.conf`` or a
saved ``nft list ruleset`` dump) and iptables (``iptables-save`` output in
``/etc/sysconfig/iptables``, ``/etc/iptables/rules.v4``, or a saved dump) -- and
emits ``EventType.FIREWALL`` events: one per chain default policy and one per rule,
each cited. It flags a permissive default (``policy accept`` / ``ACCEPT``) on an
input chain. (Whether specific connections were *dropped* -- NW-10 -- needs firewall
LOGGING, a separate evidence source, and is disclosed as out of scope here.)
"""

from __future__ import annotations

import re
from typing import List, Optional

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import InstrumentationCheck, SourceCoverage, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

_IPT_FILES = ["etc/sysconfig/iptables", "etc/iptables/rules.v4",
              "var/log/openpath/iptables-save.txt"]
_NFT_FILES = ["etc/nftables.conf", "var/log/openpath/nft-ruleset.txt"]

_IPT_POLICY = re.compile(r"^:(\S+)\s+(\S+)")           # :INPUT ACCEPT [0:0]
_IPT_RULE = re.compile(r"^(-A\s+\S+.*)$")
_NFT_POLICY = re.compile(r"policy\s+(\w+)")
_NFT_HOOK = re.compile(r"hook\s+(\w+)")


class FirewallCollector(Collector):
    source_id = "firewall"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        ts = env.now
        events: List[Event] = []
        locations: List[str] = []

        def mk(kind, artifact, summary, rel, raw, *, extra=None):
            attrs = {"kind": kind, "artifact": artifact}
            if extra:
                attrs.update(extra)
            events.append(Event(
                ts=ts, type=EventType.FIREWALL, source_id=self.source_id,
                summary=summary, attrs=attrs,
                citations=[Citation(self.source_id, rel, raw)]))

        for rel in _IPT_FILES:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p))
            for i, line in self._lines(p):
                s = line.strip()
                mp = _IPT_POLICY.match(s)
                if mp:
                    chain, pol = mp.group(1), mp.group(2)
                    permissive = pol.upper() == "ACCEPT" and chain.upper() in (
                        "INPUT", "FORWARD")
                    mk("policy", chain,
                       f"iptables chain {chain} default policy {pol}"
                       + (" [PERMISSIVE default]" if permissive else ""),
                       f"{rel}:{i}", s,
                       extra={"chain": chain, "policy": pol, "permissive": permissive})
                    continue
                mr = _IPT_RULE.match(s)
                if mr:
                    mk("rule", s, f"iptables rule: {s}", f"{rel}:{i}", s,
                       extra={"rule": s})

        for rel in _NFT_FILES:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p))
            text = self._read(p) or ""
            for block in re.finditer(r"chain\s+(\w+)\s*\{([^}]*)\}", text, re.S):
                name, body = block.group(1), block.group(2)
                hook = _NFT_HOOK.search(body)
                pol = _NFT_POLICY.search(body)
                if pol:
                    policy = pol.group(1)
                    permissive = (policy.lower() == "accept"
                                  and hook and hook.group(1) in ("input", "forward"))
                    mk("policy", name,
                       f"nft chain {name} (hook {hook.group(1) if hook else '?'}) "
                       f"policy {policy}"
                       + (" [PERMISSIVE default]" if permissive else ""),
                       f"{rel}", f"chain {name} policy {policy}",
                       extra={"chain": name, "policy": policy,
                              "permissive": bool(permissive)})
                for rline in body.splitlines():
                    r = rline.strip()
                    if r and ("accept" in r or "drop" in r or "reject" in r) \
                            and "policy" not in r:
                        mk("rule", r, f"nft rule ({name}): {r}", f"{rel}", r,
                           extra={"rule": r, "chain": name})

        events.sort(key=lambda e: (e.attrs.get("kind", ""), e.summary))
        status = SourceStatus.AVAILABLE if locations else SourceStatus.ABSENT
        cov = SourceCoverage(
            source_id=self.source_id, status=status,
            detail=(f"{len(events)} firewall rule/policy artifact(s)"
                    if locations else "no firewall ruleset found"),
            record_count=len(events), records_scanned=len(events),
            locations=locations,
            instrumentation=[InstrumentationCheck(
                "firewall ruleset present", bool(locations),
                "" if locations else
                "no nftables/iptables ruleset found (save one to "
                "/etc/nftables.conf, /etc/iptables/rules.v4, or an exported dump)")],
        )
        return CollectResult(events=events, coverage=cov)

    def _lines(self, p):
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    yield i, line
        except OSError:
            return

    def _read(self, p) -> Optional[str]:
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
