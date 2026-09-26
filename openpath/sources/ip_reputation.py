"""IP-reputation collector: geo / threat-intel enrichment for login origins (IA-10).

OpenPath is deterministic and offline, so it does not itself geolocate or score IPs
-- but when an evidence bundle carries a reputation/geo feed, it reads it and
correlates against login origins. Reads ``var/log/openpath/ip-reputation.json``, a
map ``{ip: {country, asn, reputation, first_seen}}`` where ``reputation`` is one of
``malicious`` / ``suspicious`` / ``new`` / ``expected``. Emits one
``EventType.OTHER`` reference event (``kind=ip_reputation``) per entry, cited to the
feed; the origin-reputation facet does the correlation.
"""

from __future__ import annotations

import json
from typing import List, Optional

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import InstrumentationCheck, SourceCoverage, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

_PATHS = ["var/log/openpath/ip-reputation.json", "var/log/openpath/ip-reputation.jsonl"]


class IpReputationCollector(Collector):
    source_id = "ip_reputation"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        events: List[Event] = []
        locations: List[str] = []
        rel_used = None
        entries: dict = {}
        for rel in _PATHS:
            p = env.path(rel)
            if not p.exists():
                continue
            rel_used = rel
            locations.append(str(p))
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            entries = self._load(text)
            break

        if not locations:
            cov = SourceCoverage(
                source_id=self.source_id, status=SourceStatus.ABSENT,
                detail="no IP-reputation / geo feed present",
                instrumentation=[InstrumentationCheck(
                    "ip reputation feed present", False,
                    "origin reputation / geo (IA-10) needs a threat-intel or geo feed "
                    "at var/log/openpath/ip-reputation.json")])
            return CollectResult(events=[], coverage=cov)

        for ip, meta in entries.items():
            rep = (meta or {}).get("reputation", "unknown")
            country = (meta or {}).get("country")
            events.append(Event(
                ts=env.now, type=EventType.OTHER, source_id=self.source_id,
                summary=f"reputation for {ip}: {rep}"
                        + (f" ({country})" if country else ""),
                attrs={"kind": "ip_reputation", "ip": ip, "reputation": rep,
                       "country": country, "asn": (meta or {}).get("asn"),
                       "first_seen": (meta or {}).get("first_seen")},
                citations=[Citation(self.source_id, rel_used, f"{ip}: {rep}")]))

        cov = SourceCoverage(
            source_id=self.source_id, status=SourceStatus.AVAILABLE,
            detail=f"{len(events)} IP-reputation entr(y/ies)",
            record_count=len(events), records_scanned=len(events), locations=locations,
            instrumentation=[InstrumentationCheck("ip reputation feed present", True)])
        return CollectResult(events=events, coverage=cov)

    @staticmethod
    def _load(text: str) -> dict:
        text = text.strip()
        if not text:
            return {}
        # Whole-file JSON map {ip: {meta}} -- only when values are objects (so a
        # single JSONL entry, which is also a valid dict, is not mistaken for a map).
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and obj and all(
                    isinstance(v, dict) for v in obj.values()):
                return obj
        except json.JSONDecodeError:
            pass
        # JSONL: one entry per line, each carrying its own "ip".
        out = {}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(d, dict) and "ip" in d:
                out[d["ip"]] = {k: v for k, v in d.items() if k != "ip"}
        return out
