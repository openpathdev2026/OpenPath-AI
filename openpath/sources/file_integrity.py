"""File-integrity collector: before/after content of modified files (FS-13).

auditd records that a file changed and who, never its content. Content-level
before/after evidence comes from a file-integrity monitor (AIDE / Tripwire /
osquery file hashing) or a content-snapshot bundle. Like every other source,
OpenPath reads it WHEN a bundle provides it and discloses its absence otherwise --
it never fabricates content.

Reads ``var/log/openpath/file-diffs.jsonl``: one JSON object per changed file with
``{path, ts, actor, lines_added, lines_removed, summary}`` (and optional
``before``/``after`` snippets), emitted as ``EventType.FILE_DIFF``, each cited.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import InstrumentationCheck, SourceCoverage, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

_PATHS = ["var/log/openpath/file-diffs.jsonl", "var/log/openpath/file-diffs.json"]


class FileIntegrityCollector(Collector):
    source_id = "file_integrity"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        events: List[Event] = []
        locations: List[str] = []
        unparseable = 0
        rel_used = None
        for rel in _PATHS:
            p = env.path(rel)
            if p.exists():
                rel_used = rel
                locations.append(str(p))
                for i, line in enumerate(self._read_lines(p), start=1):
                    s = line.strip()
                    if not s:
                        continue
                    try:
                        d = json.loads(s)
                    except json.JSONDecodeError:
                        unparseable += 1
                        continue
                    ev = self._event(d, rel, i, s, env.now)
                    if ev is not None:
                        events.append(ev)
                break

        if not locations:
            cov = SourceCoverage(
                source_id=self.source_id, status=SourceStatus.ABSENT,
                detail="no file-integrity (content-diff) evidence found",
                instrumentation=[InstrumentationCheck(
                    "file-content diffs present", False,
                    "content before/after (FS-13) needs a file-integrity monitor "
                    "(AIDE/Tripwire/osquery) or content-snapshot bundle at "
                    "var/log/openpath/file-diffs.jsonl")])
            return CollectResult(events=[], coverage=cov)

        events.sort(key=lambda e: e.ts)
        cov = SourceCoverage(
            source_id=self.source_id, status=SourceStatus.AVAILABLE,
            detail=f"{len(events)} file content-diff record(s)",
            record_count=len(events), records_scanned=len(events) + unparseable,
            unparseable=unparseable, locations=locations,
            instrumentation=[InstrumentationCheck("file-content diffs present", True)])
        return CollectResult(events=events, coverage=cov)

    def _event(self, d, rel, i, raw, anchor) -> Optional[Event]:
        path = d.get("path")
        if not path:
            return None
        ts = anchor
        if d.get("ts"):
            try:
                ts = datetime.fromisoformat(d["ts"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                ts = anchor
        added = d.get("lines_added")
        removed = d.get("lines_removed")
        summary = d.get("summary") or (
            f"content change to {path}"
            + (f": +{added}/-{removed} line(s)" if added is not None else ""))
        return Event(
            ts=ts, type=EventType.FILE_DIFF, source_id=self.source_id,
            summary=summary, actor_name=d.get("actor"),
            attrs={"path": path, "lines_added": added, "lines_removed": removed,
                   "before": d.get("before"), "after": d.get("after")},
            citations=[Citation(self.source_id, f"{rel}:{i}", raw[:200])])

    def _read_lines(self, p):
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    yield line
        except OSError:
            return
