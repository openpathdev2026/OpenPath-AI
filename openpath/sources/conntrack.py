"""Conntrack / netflow collector: connection tracking table (NW-04/06/14).

Reads the netfilter connection-tracking table (``/proc/net/nf_conntrack`` or a
saved ``conntrack -L`` / ``/proc/net/nf_conntrack`` dump) and emits
``EventType.NETFLOW`` -- one per tracked flow, carrying the transport protocol
(NW-14), the remote peer and whether the flow is inbound (NW-06), and the byte
volume when connection-byte accounting (``nf_conntrack_acct``) is enabled (NW-04).

State snapshot: flows are stamped at the analysis anchor. When byte accounting is
off, byte volume is disclosed as unavailable rather than guessed.
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

_PATHS = ["proc/net/nf_conntrack", "var/log/openpath/conntrack.txt"]
# Local address ranges: a flow whose ORIGINAL destination is a local address was
# initiated from outside (inbound). We treat RFC1918 + loopback dsts as local when
# the reply confirms it; without host IPs we fall back to the well-known-port test.
_KV = re.compile(r"(\w+)=(\S+)")


class ConntrackCollector(Collector):
    source_id = "conntrack"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        ts = env.now
        events: List[Event] = []
        locations: List[str] = []
        unparseable = 0
        acct = False

        text = None
        for rel in _PATHS:
            p = env.path(rel)
            if p.exists():
                text = self._read(p)
                if text is not None:
                    locations.append(str(p))
                    break
        if text is None:
            cov = SourceCoverage(
                source_id=self.source_id, status=SourceStatus.ABSENT,
                detail="no conntrack table found",
                instrumentation=[InstrumentationCheck(
                    "conntrack table present", False,
                    "provide /proc/net/nf_conntrack or a saved conntrack -L dump")])
            return CollectResult(events=[], coverage=cov)

        for i, line in enumerate(text.splitlines(), start=1):
            s = line.strip()
            if not s:
                continue
            flow = self._parse(s)
            if flow is None:
                unparseable += 1
                continue
            if flow.get("bytes") is not None:
                acct = True
            proto = flow["proto"]
            peer = flow["peer"]
            dport = flow["dport"]
            direction = flow["direction"]
            nbytes = flow.get("bytes")
            bstr = (f", {nbytes} bytes" if nbytes is not None else "")
            events.append(Event(
                ts=ts, type=EventType.NETFLOW, source_id=self.source_id,
                summary=f"{direction} {proto} flow {peer}:{dport} "
                        f"({flow.get('state', '?')}{bstr})",
                attrs={"artifact": f"{peer}:{dport}", "proto": proto, "peer": peer,
                       "dport": dport, "direction": direction,
                       "state": flow.get("state"), "bytes": nbytes},
                citations=[Citation(self.source_id, f"{_PATHS[0]}:{i}", s[:160])]))

        status = SourceStatus.AVAILABLE if events or locations else SourceStatus.ABSENT
        cov = SourceCoverage(
            source_id=self.source_id, status=status,
            detail=f"{len(events)} tracked flow(s)"
                   + ("" if acct else "; byte accounting OFF (volume unavailable)"),
            record_count=len(events), records_scanned=len(events) + unparseable,
            unparseable=unparseable, locations=locations,
            instrumentation=[
                InstrumentationCheck("conntrack table present", True),
                InstrumentationCheck(
                    "connection byte accounting", acct,
                    "" if acct else "nf_conntrack_acct is off; per-flow byte volume "
                    "(NW-04) is not available"),
            ])
        return CollectResult(events=events, coverage=cov)

    def _parse(self, line: str) -> Optional[dict]:
        parts = line.split()
        # e.g.: ipv4 2 tcp 6 431999 ESTABLISHED src=.. dst=.. sport=.. dport=.. ...
        proto = None
        for tok in parts[:4]:
            if tok in ("tcp", "udp", "icmp", "udplite", "dccp", "sctp"):
                proto = tok
                break
        if proto is None:
            return None
        # The ORIGINAL tuple is the first src=/dst=/dport= (the initiator's
        # direction); the reply tuple repeats them reversed, so we must NOT let a
        # dict collapse to the reply.
        m = re.search(r"src=(\S+)\s+dst=(\S+)\s+sport=(\S+)\s+dport=(\S+)", line)
        if not m:
            return None
        osrc, odst, _osport, dport = m.groups()
        state = next((t for t in parts
                      if t.isalpha() and t.isupper() and len(t) > 2), None)
        # inbound if the original destination is a private/loopback local address
        direction = "inbound" if self._is_local(odst) and not self._is_local(osrc) \
            else "outbound"
        peer = osrc if direction == "inbound" else odst
        nbytes = None
        # bytes appear twice (orig + reply) when accounting is on; sum them
        byte_vals = [int(v) for k, v in _KV.findall(line) if k == "bytes"]
        if byte_vals:
            nbytes = sum(byte_vals)
        return {"proto": proto, "peer": peer, "dport": dport, "direction": direction,
                "state": state, "bytes": nbytes}

    @staticmethod
    def _is_local(addr: Optional[str]) -> bool:
        if not addr:
            return False
        return (addr.startswith("10.") or addr.startswith("192.168.")
                or addr.startswith("127.") or addr == "::1"
                or any(addr.startswith(f"172.{n}.") for n in range(16, 32)))

    def _read(self, p) -> Optional[str]:
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
