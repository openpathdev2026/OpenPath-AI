"""sshd journal collector: remote-origin and auth-method detail for logins.

wtmp says *that* a login happened and (often) from where; the sshd journal says
*how* -- which authentication method succeeded or failed, the source address and
port, and failed attempts that never became a session. That enriches the Login
question (family 4).

journald's own store is binary, but it is universally exportable as JSON with
``journalctl -o json``. To stay dependency-free, deterministic, and able to run on
an offline evidence bundle, this collector reads a JSON-lines export placed under
the data root. On a live host with no export present it will, best-effort, invoke
``journalctl`` to produce one. Either way, ``__REALTIME_TIMESTAMP`` is microseconds
since the epoch (UTC), so timestamps are unambiguous.
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import (
    InstrumentationCheck,
    SourceCoverage,
    SourceStatus,
)
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

# Preferred JSON-lines export locations (checked in order).
_EXPORT_PATHS = [
    "var/log/openpath/journal-sshd.jsonl",
    "var/log/openpath/journal-sshd.json",
    "var/log/journal-sshd.jsonl",
]

_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_FAILED_RE = re.compile(
    r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_DISCONNECT_RE = re.compile(
    r"(?:Disconnected from|Connection closed by) (?:authenticating |invalid user )?"
    r"(?:user )?(?P<user>\S+)?\s*(?P<ip>\d[\d.:a-fA-F]+)?"
)


class SshdJournalCollector(Collector):
    source_id = "journal.sshd"

    def _load_entries(
        self, env: Env, window: TimeRange
    ) -> Tuple[List[dict], List[str], bool, str, int]:
        """Return (entries, locations, exported_live, locator_base, unparseable)."""
        for rel in _EXPORT_PATHS:
            p = env.path(rel)
            if p.exists():
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                # Some exports are a single JSON array; most are one object per
                # line (JSONL). Try the array form first, then fall back to JSONL,
                # counting any line that fails to decode rather than dropping it.
                entries: List[dict] = []
                unparseable = 0
                try:
                    arr = json.loads(text)
                except json.JSONDecodeError:
                    arr = None
                if isinstance(arr, list):
                    entries = arr
                else:
                    for line in text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            unparseable += 1
                # Return a relative locator base so evidence never leaks the
                # analyst's local bundle path.
                return entries, [str(p)], False, rel, unparseable

        # Live fallback: only when analyzing the real host.
        if str(env.data_root) == "/":
            live = self._journalctl_live(window)
            if live is not None:
                entries, unparseable = live
                return entries, ["journalctl -u sshd -o json"], True, \
                    "journalctl:_COMM=sshd", unparseable
        return [], [], False, "", 0

    def _journalctl_live(self, window: TimeRange) -> Optional[Tuple[List[dict], int]]:
        try:
            since = window.start.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            until = window.end.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            proc = subprocess.run(
                ["journalctl", "_COMM=sshd", "-o", "json",
                 "--since", since, "--until", until, "--utc"],
                capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        entries = []
        unparseable = 0
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                unparseable += 1
        return entries, unparseable

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        entries, locations, live, locbase, unparseable = self._load_entries(env, window)

        if not locations:
            cov = SourceCoverage(
                source_id=self.source_id,
                status=SourceStatus.ABSENT,
                detail="no sshd journal export found and no live journal available",
                instrumentation=[
                    InstrumentationCheck(
                        "sshd journal available", False,
                        "export sshd journal to "
                        "var/log/openpath/journal-sshd.jsonl "
                        "(journalctl _COMM=sshd -o json) for remote-origin detail",
                    )
                ],
            )
            return CollectResult(events=[], coverage=cov)

        events: List[Event] = []
        all_ts: List[datetime] = []
        for i, entry in enumerate(entries):
            ts = self._entry_ts(entry)
            if ts is None:
                continue
            all_ts.append(ts)
            msg = entry.get("MESSAGE", "")
            if isinstance(msg, list):  # journald can encode as byte array
                try:
                    msg = bytes(msg).decode("utf-8", "replace")
                except (ValueError, TypeError):
                    msg = str(msg)
            ev = self._interpret(entry, msg, ts, locbase, i, window)
            if ev is not None and window.contains(ev.ts):
                events.append(ev)

        events.sort(key=lambda e: e.ts)
        hstart, hend = self._span(all_ts)
        status = SourceStatus.AVAILABLE if entries else SourceStatus.EMPTY
        cov = SourceCoverage(
            source_id=self.source_id,
            status=status,
            detail=f"{len(entries)} sshd journal entries"
                   + (" (captured live)" if live else ""),
            horizon_start=hstart,
            horizon_end=hend,
            record_count=len(entries),
            records_scanned=len(entries) + unparseable,
            unparseable=unparseable,
            unparseable_detail=("journal line(s) that were not valid JSON"
                                if unparseable else ""),
            locations=locations,
            instrumentation=[InstrumentationCheck("sshd journal available", True)],
        )
        return CollectResult(events=events, coverage=cov)

    def _entry_ts(self, entry: dict) -> Optional[datetime]:
        v = entry.get("__REALTIME_TIMESTAMP")
        if v is None:
            return None
        try:
            usec = int(v)
        except (ValueError, TypeError):
            return None
        return datetime.fromtimestamp(usec / 1_000_000, tz=timezone.utc)

    def _interpret(self, entry, msg, ts, loc, idx, window) -> Optional[Event]:
        locator = f"{loc}#{idx}"
        raw = f"{ts.isoformat()} sshd: {msg}"
        cit = [Citation(self.source_id, locator, raw)]
        m = _ACCEPTED_RE.search(msg)
        if m:
            return Event(
                ts=ts, type=EventType.SSH_AUTH, source_id=self.source_id,
                summary=f"sshd accepted {m.group('method')} for {m.group('user')} "
                        f"from {m.group('ip')}",
                actor_name=m.group("user"),
                attrs={"result": "accepted", "method": m.group("method"),
                       "ip": m.group("ip"), "port": int(m.group("port"))},
                citations=cit,
            )
        m = _FAILED_RE.search(msg)
        if m:
            return Event(
                ts=ts, type=EventType.SSH_AUTH, source_id=self.source_id,
                summary=f"sshd failed {m.group('method')} for {m.group('user')} "
                        f"from {m.group('ip')}",
                actor_name=m.group("user"),
                attrs={"result": "failed", "method": m.group("method"),
                       "ip": m.group("ip"), "port": int(m.group("port"))},
                citations=cit,
            )
        return None
