"""General journald collector: host lifecycle beyond the sshd slice.

The sshd journal collector reads only the sshd unit. This one reads the general
journal export and interprets the *system lifecycle* messages that answer the
SL-* questions: clean shutdown / power-off, systemd unit start / stop / failure
(and flapping), kernel panic / OOM / watchdog, an unusual boot target
(rescue / emergency), and a system-clock change. It emits ``EventType.SYSTEM``
events, each cited to the journal entry.

Like the sshd collector it reads a ``journalctl -o json`` JSON-lines export placed
under the data root (staying dependency-free and able to run on an offline evidence
bundle); on a live host with none present it best-effort invokes ``journalctl``.
``__REALTIME_TIMESTAMP`` is microseconds since the epoch (UTC).
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import InstrumentationCheck, SourceCoverage, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

_EXPORT_PATHS = [
    "var/log/openpath/journal.jsonl",
    "var/log/openpath/journal.json",
    "var/log/journal.jsonl",
]

# Ordered (kind, compiled-regex, group-for-detail). First match wins per entry.
_PATTERNS: List[Tuple[str, "re.Pattern", Optional[str]]] = [
    ("kernel_panic", re.compile(r"Kernel panic(?: - not syncing)?:?\s*(?P<d>.*)"), "d"),
    ("oom", re.compile(r"Out of memory: Kill(?:ed)? process \d+ \((?P<d>[^)]+)\)"), "d"),
    ("oom", re.compile(r"oom-kill:.*task=(?P<d>\S+)"), "d"),
    ("watchdog", re.compile(r"watchdog: (?P<d>BUG:.*|.*hard LOCKUP.*)"), "d"),
    ("clock_change", re.compile(r"(?:Time has been changed|System clock .*adjust|"
                                r"RTC configured .*|Timezone has been changed)"
                                r"(?P<d>.*)"), "d"),
    ("boot_target", re.compile(r"Reached target (?P<d>Rescue Mode|Emergency Mode|"
                               r"rescue\.target|emergency\.target)"), "d"),
    ("shutdown", re.compile(r"(?:Reached target (?:Shutdown|Power-?Off|Reboot)|"
                            r"Powering off|System is powering down|"
                            r"Shutting down)(?P<d>.*)"), "d"),
    ("service_failed", re.compile(r"(?P<d>.+): (?:Failed with result|Main process "
                                  r"exited.*status=[^0].*)|Failed to start (?P<d2>.+)\."
                                  r"|start request repeated too quickly"), None),
    ("service_start", re.compile(r"Started (?P<d>.+?)\.?$"), "d"),
    ("service_stop", re.compile(r"Stopped (?P<d>.+?)\.?$"), "d"),
]

# Non-SSH authentication (IA-11) and account lockout (PV-12) from the journal.
_PAM_SESSION = re.compile(
    r"pam_unix\((?P<svc>[\w-]+):session\): session opened for user (?P<user>[\w.-]+)")
_PAM_AUTH = re.compile(
    r"pam_unix\((?P<svc>[\w-]+):auth\): authentication (?P<res>success|failure).*?"
    r"user=(?P<user>[\w.-]+)")
_FAILLOCK = re.compile(
    r"pam_faillock.*?user[= ](?P<user>[\w.-]+)|Consecutive login failures for user "
    r"(?P<user2>[\w.-]+)", re.I)
_SSH_SERVICES = {"sshd", "ssh"}   # covered by the dedicated sshd collector


class GeneralJournaldCollector(Collector):
    source_id = "journald"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        entries, locations, live, locbase, unparseable = self._load(env, window)
        if not locations:
            cov = SourceCoverage(
                source_id=self.source_id, status=SourceStatus.ABSENT,
                detail="no general journal export found and no live journal available",
                instrumentation=[InstrumentationCheck(
                    "general journal available", False,
                    "export the journal to var/log/openpath/journal.jsonl "
                    "(journalctl -o json) for shutdown / service / crash lifecycle "
                    "evidence")],
            )
            return CollectResult(events=[], coverage=cov)

        events: List[Event] = []
        all_ts: List[datetime] = []
        for i, entry in enumerate(entries):
            ts = self._entry_ts(entry)
            if ts is None:
                continue
            all_ts.append(ts)
            msg = self._message(entry)
            ev = self._interpret(entry, msg, ts, locbase, i)
            if ev is not None and window.contains(ev.ts):
                events.append(ev)

        events.sort(key=lambda e: e.ts)
        hstart, hend = self._span(all_ts)
        status = SourceStatus.AVAILABLE if entries else SourceStatus.EMPTY
        cov = SourceCoverage(
            source_id=self.source_id, status=status,
            detail=f"{len(entries)} journal entries; {len(events)} lifecycle event(s)"
                   + (" (captured live)" if live else ""),
            horizon_start=hstart, horizon_end=hend,
            record_count=len(events), records_scanned=len(entries) + unparseable,
            unparseable=unparseable,
            unparseable_detail=("journal line(s) that were not valid JSON"
                                if unparseable else ""),
            locations=locations,
            instrumentation=[InstrumentationCheck("general journal available", True)],
        )
        return CollectResult(events=events, coverage=cov)

    # -- interpretation ------------------------------------------------------ #
    def _interpret(self, entry, msg, ts, loc, idx) -> Optional[Event]:
        unit = entry.get("_SYSTEMD_UNIT") or entry.get("UNIT") or ""
        ident = entry.get("SYSLOG_IDENTIFIER") or ""
        locator = f"{loc}#{idx}"
        raw0 = f"{ts.isoformat()} {ident or unit or 'systemd'}: {msg}"[:200]

        # -- authentication / lockout (IA-11 / PV-12) -- #
        mf = _FAILLOCK.search(msg)
        if mf:
            user = mf.group("user") or mf.group("user2")
            return Event(
                ts=ts, type=EventType.SYSTEM, source_id=self.source_id,
                summary=f"account lockout / faillock event"
                        + (f" for {user}" if user else ""),
                actor_name=user,
                attrs={"kind": "faillock", "artifact": user or "faillock",
                       "user": user},
                citations=[Citation(self.source_id, locator, raw0)])
        for rx in (_PAM_SESSION, _PAM_AUTH):
            m = rx.search(msg)
            if m and m.group("svc") not in _SSH_SERVICES:
                svc = m.group("svc")
                user = m.group("user")
                res = m.groupdict().get("res") or "opened"
                return Event(
                    ts=ts, type=EventType.SYSTEM, source_id=self.source_id,
                    summary=f"non-SSH authentication to '{svc}' for {user} ({res})",
                    actor_name=user,
                    attrs={"kind": "pam_auth", "artifact": svc, "service": svc,
                           "user": user, "result": res},
                    citations=[Citation(self.source_id, locator, raw0)])

        for kind, rx, grp in _PATTERNS:
            m = rx.search(msg)
            if not m:
                continue
            detail = ""
            if grp:
                try:
                    detail = (m.group(grp) or "").strip(" .:\t")
                except Exception:
                    detail = ""
            if kind == "service_failed" and not detail:
                gd = m.groupdict()
                detail = ((gd.get("d") or gd.get("d2") or "")).strip()
            art = unit or ident or detail or kind
            locator = f"{loc}#{idx}"
            raw = f"{ts.isoformat()} {ident or unit or 'systemd'}: {msg}"[:200]
            return Event(
                ts=ts, type=EventType.SYSTEM, source_id=self.source_id,
                summary=self._summary(kind, detail, unit or ident),
                attrs={"kind": kind, "unit": unit, "identifier": ident,
                       "artifact": art, "detail": detail},
                citations=[Citation(self.source_id, locator, raw)],
            )
        return None

    @staticmethod
    def _summary(kind, detail, who) -> str:
        label = {
            "kernel_panic": "KERNEL PANIC", "oom": "out-of-memory kill",
            "watchdog": "watchdog lockup", "clock_change": "system clock changed",
            "boot_target": "booted into", "shutdown": "system shutdown/power-off",
            "service_failed": "service failed", "service_start": "service started",
            "service_stop": "service stopped",
        }.get(kind, kind)
        bits = [label]
        if detail:
            bits.append(detail)
        elif who:
            bits.append(who)
        return ": ".join(bits)

    # -- loading (mirrors the sshd collector) -------------------------------- #
    def _load(self, env, window):
        for rel in _EXPORT_PATHS:
            p = env.path(rel)
            if p.exists():
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
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
                return entries, [str(p)], False, rel, unparseable
        if str(env.data_root) == "/":
            live = self._live(window)
            if live is not None:
                entries, unparseable = live
                return entries, ["journalctl -o json"], True, "journalctl", unparseable
        return [], [], False, "", 0

    def _live(self, window):
        try:
            since = window.start.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            until = window.end.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            proc = subprocess.run(
                ["journalctl", "-o", "json", "--since", since, "--until", until,
                 "--utc"], capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        entries, unparseable = [], 0
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                unparseable += 1
        return entries, unparseable

    @staticmethod
    def _message(entry) -> str:
        msg = entry.get("MESSAGE", "")
        if isinstance(msg, list):
            try:
                msg = bytes(msg).decode("utf-8", "replace")
            except (ValueError, TypeError):
                msg = str(msg)
        return msg

    def _entry_ts(self, entry) -> Optional[datetime]:
        v = entry.get("__REALTIME_TIMESTAMP")
        if v is None:
            return None
        try:
            usec = int(v)
        except (ValueError, TypeError):
            return None
        return datetime.fromtimestamp(usec / 1_000_000, tz=timezone.utc)

    @staticmethod
    def _span(all_ts):
        if not all_ts:
            return None, None
        return min(all_ts), max(all_ts)
