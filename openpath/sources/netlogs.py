"""Network-logs collector: DNS, firewall drops, web/proxy, socket lifetimes.

These answers need network telemetry that a standard host does not always retain,
so -- like auditd rules -- OpenPath reads them WHEN an evidence bundle carries them
and discloses their absence otherwise. Emits ``EventType.NETLOG`` with a ``kind``:

  * ``dns``      (NW-08) -- DNS query log (dnsmasq ``query[TYPE] <domain> from <ip>``,
    or an OpenPath ``dns.log`` of ``<iso> <type> <domain> <client>``).
  * ``fw_drop``  (NW-10) -- kernel firewall DROP/REJECT lines (``... SRC=.. DPT=..``).
  * ``webproxy`` (NW-12) -- a proxy access log (``<iso> <client> <verb> <url> ...``).
  * ``socket``   (NW-15) -- socket open/close lifetimes (JSONL from a socket tracer),
    giving how long a connection was held open.

Everything is cited to its source line; nothing is synthesized when a log is absent.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import List, Optional

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import InstrumentationCheck, SourceCoverage, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

_DNS_PATHS = ["var/log/openpath/dns.log", "var/log/dnsmasq.log"]
_FW_PATHS = ["var/log/openpath/firewall.log"]
_PROXY_PATHS = ["var/log/squid/access.log", "var/log/openpath/proxy.log"]
_SOCK_PATHS = ["var/log/openpath/socket-lifetimes.jsonl"]

_DNSMASQ = re.compile(r"query\[(?P<type>\w+)\]\s+(?P<domain>\S+)\s+from\s+(?P<ip>\S+)")
_OPENPATH_DNS = re.compile(r"^(?P<ts>\S+)\s+(?P<type>\w+)\s+(?P<domain>\S+)\s+(?P<ip>\S+)$")
_FW = re.compile(r"SRC=(?P<src>\S+).*?DST=(?P<dst>\S+).*?(?:DPT=(?P<dpt>\d+))?.*?"
                 r"(?P<verdict>DROP|REJECT)", re.I)
_PROXY = re.compile(r"^(?P<ts>\S+)\s+(?P<client>\S+)\s+(?P<verb>\w+)\s+(?P<url>\S+)")


class NetLogsCollector(Collector):
    source_id = "netlogs"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        ts_anchor = env.now
        events: List[Event] = []
        locations: List[str] = []
        unparseable = 0
        kinds_present = set()

        def mk(kind, artifact, summary, rel, lineno, raw, *, ts=None, extra=None):
            attrs = {"kind": kind, "artifact": artifact}
            if extra:
                attrs.update(extra)
            events.append(Event(
                ts=ts or ts_anchor, type=EventType.NETLOG, source_id=self.source_id,
                summary=summary, attrs=attrs,
                citations=[Citation(self.source_id, f"{rel}:{lineno}", raw[:160])]))

        # -- DNS (NW-08) -- #
        for rel in _DNS_PATHS:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p)); kinds_present.add("dns")
            for i, line in self._lines(p):
                s = line.strip()
                m = _DNSMASQ.search(s) or _OPENPATH_DNS.match(s)
                if not m:
                    if s:
                        unparseable += 1
                    continue
                g = m.groupdict()
                mk("dns", g["domain"], f"DNS {g['type']} query for {g['domain']} "
                   f"from {g['ip']}", rel, i, s,
                   extra={"domain": g["domain"], "qtype": g["type"], "client": g["ip"]})
            break

        # -- firewall drops (NW-10) -- #
        for rel in _FW_PATHS:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p)); kinds_present.add("fw_drop")
            for i, line in self._lines(p):
                m = _FW.search(line)
                if not m:
                    if line.strip():
                        unparseable += 1
                    continue
                g = m.groupdict()
                mk("fw_drop", g.get("src"),
                   f"firewall {g['verdict'].upper()} of {g.get('src')} -> "
                   f"{g.get('dst')}:{g.get('dpt') or '?'}", rel, i, line.strip(),
                   extra={"src": g.get("src"), "dst": g.get("dst"),
                          "dport": g.get("dpt"), "verdict": g["verdict"].upper()})

        # -- web / proxy (NW-12) -- #
        for rel in _PROXY_PATHS:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p)); kinds_present.add("webproxy")
            for i, line in self._lines(p):
                m = _PROXY.match(line.strip())
                if not m:
                    if line.strip():
                        unparseable += 1
                    continue
                g = m.groupdict()
                mk("webproxy", g["url"], f"web {g['verb']} {g['url']} by {g['client']}",
                   rel, i, line.strip(),
                   extra={"url": g["url"], "verb": g["verb"], "client": g["client"]})
            break

        # -- socket lifetimes (NW-15) -- #
        for rel in _SOCK_PATHS:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p)); kinds_present.add("socket")
            for i, line in self._lines(p):
                s = line.strip()
                if not s:
                    continue
                try:
                    d = json.loads(s)
                except json.JSONDecodeError:
                    unparseable += 1
                    continue
                held = d.get("held_s")
                peer = f"{d.get('peer')}:{d.get('port')}"
                mk("socket", peer,
                   f"{d.get('proto', 'tcp')} connection to {peer} open "
                   f"{d.get('open')} .. {d.get('close')} (held {held}s)", rel, i, s,
                   extra={"peer": d.get("peer"), "port": d.get("port"),
                          "open": d.get("open"), "close": d.get("close"),
                          "held_s": held, "proto": d.get("proto")})

        status = SourceStatus.AVAILABLE if locations else SourceStatus.ABSENT
        cov = SourceCoverage(
            source_id=self.source_id, status=status,
            detail=(f"{len(events)} network-log event(s): "
                    + ", ".join(sorted(kinds_present)) if locations else
                    "no DNS / firewall / proxy / socket-lifetime logs found"),
            record_count=len(events), records_scanned=len(events) + unparseable,
            unparseable=unparseable, locations=locations,
            instrumentation=[
                InstrumentationCheck("DNS query log", "dns" in kinds_present,
                                     "" if "dns" in kinds_present else
                                     "no DNS query log (NW-08 needs resolver logging)"),
                InstrumentationCheck("firewall drop log", "fw_drop" in kinds_present,
                                     "" if "fw_drop" in kinds_present else
                                     "no firewall drop log (NW-10 needs FW logging)"),
                InstrumentationCheck("web/proxy log", "webproxy" in kinds_present,
                                     "" if "webproxy" in kinds_present else
                                     "no proxy access log (NW-12 needs a proxy)"),
                InstrumentationCheck("socket lifetime log", "socket" in kinds_present,
                                     "" if "socket" in kinds_present else
                                     "no socket-lifetime log (NW-15 needs a tracer)"),
            ])
        return CollectResult(events=events, coverage=cov)

    def _lines(self, p):
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    yield i, line
        except OSError:
            return
