"""wtmp collector: login/logout/boot records from the binary ``struct utmp`` log.

wtmp is the authority for the Sessions (family 3) and Login (family 4) questions.
It is a fixed-size binary format (384 bytes per record on Linux, for both 32- and
64-bit glibc, which keeps the time/address fields at fixed 32-bit widths for
compatibility). We parse it directly rather than shelling out to ``last`` so the
same code works on an offline evidence bundle and so every field is citable.

Session reconstruction (pairing a ``USER_PROCESS`` login with the ``DEAD_PROCESS``
that closes its tty line) is wtmp-specific, so it lives here. Each emitted SESSION
event cites *both* the login and the logout raw record.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

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

# struct utmp (Linux). See bits/utmp.h. Little-endian, fixed widths.
#   short ut_type; (+2 pad) int ut_pid; char ut_line[32]; char ut_id[4];
#   char ut_user[32]; char ut_host[256]; short e_termination; short e_exit;
#   int ut_session; int tv_sec; int tv_usec; int ut_addr_v6[4]; char unused[20];
_UTMP_STRUCT = struct.Struct("<h2xi32s4s32s256shhiii4i20s")
_UTMP_SIZE = _UTMP_STRUCT.size  # 384

# ut_type values.
EMPTY = 0
RUN_LVL = 1
BOOT_TIME = 2
NEW_TIME = 3
OLD_TIME = 4
INIT_PROCESS = 5
LOGIN_PROCESS = 6
USER_PROCESS = 7
DEAD_PROCESS = 8

# wtmp and its common rotations, oldest first so combined records stay ordered.
_WTMP_PATHS = ["var/log/wtmp.1", "var/log/wtmp"]


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


class _Record:
    __slots__ = ("type", "pid", "line", "id", "user", "host", "ts", "locator", "raw")

    def __init__(self, type_, pid, line, id_, user, host, ts, locator, raw):
        self.type = type_
        self.pid = pid
        self.line = line
        self.id = id_
        self.user = user
        self.host = host
        self.ts = ts
        self.locator = locator
        self.raw = raw


class WtmpCollector(Collector):
    source_id = "wtmp"

    def _read_records(self, env: Env) -> Tuple[List[_Record], List[str]]:
        records: List[_Record] = []
        locations: List[str] = []
        for rel in _WTMP_PATHS:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p))
            try:
                data = p.read_bytes()
            except OSError:
                continue
            n = len(data) // _UTMP_SIZE
            for i in range(n):
                chunk = data[i * _UTMP_SIZE : (i + 1) * _UTMP_SIZE]
                (
                    ut_type, ut_pid, ut_line, ut_id, ut_user, ut_host,
                    _term, _exit, _session, tv_sec, tv_usec,
                    a0, a1, a2, a3, _unused,
                ) = _UTMP_STRUCT.unpack(chunk)
                if ut_type == EMPTY:
                    continue
                ts = None
                if tv_sec:
                    ts = datetime.fromtimestamp(
                        tv_sec + tv_usec / 1_000_000, tz=timezone.utc
                    )
                user = _cstr(ut_user)
                host = _cstr(ut_host)
                line = _cstr(ut_line)
                locator = f"{rel}#{i}"
                raw = (
                    f"type={ut_type} pid={ut_pid} line={line!r} "
                    f"user={user!r} host={host!r} "
                    f"time={ts.isoformat() if ts else 'none'}"
                )
                records.append(
                    _Record(ut_type, ut_pid, line, _cstr(ut_id), user, host,
                            ts, locator, raw)
                )
        return records, locations

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        records, locations = self._read_records(env)

        if not locations:
            cov = SourceCoverage(
                source_id=self.source_id,
                status=SourceStatus.ABSENT,
                detail="no wtmp file found under data root",
                instrumentation=[
                    InstrumentationCheck(
                        "wtmp accounting present", False,
                        "var/log/wtmp not found; login/session history unavailable",
                    )
                ],
            )
            return CollectResult(events=[], coverage=cov)

        timed = [r for r in records if r.ts is not None]
        hstart, hend = self._span([r.ts for r in timed])

        if not records:
            cov = SourceCoverage(
                source_id=self.source_id, status=SourceStatus.EMPTY,
                detail="wtmp present but contains no records",
                locations=locations,
                instrumentation=[InstrumentationCheck(
                    "wtmp accounting present", False,
                    "wtmp exists but is empty (0 records) -- login accounting may be "
                    "disabled or the file was truncated (common in containers); "
                    "cannot distinguish this from 'no logins occurred'.",
                )],
            )
            return CollectResult(events=[], coverage=cov)

        events = self._build_sessions(records, window)
        events += self._build_boots(records, window)
        events.sort(key=lambda e: e.ts)

        status = SourceStatus.AVAILABLE
        # If the earliest retained record is after the window start, later logic
        # (CoverageLedger.horizon_shortfalls) will flag the blind spot; mark the
        # extreme case where the whole window predates our data.
        if hstart is not None and hstart > window.end:
            status = SourceStatus.OUT_OF_HORIZON

        cov = SourceCoverage(
            source_id=self.source_id,
            status=status,
            detail=f"{len(records)} wtmp records parsed",
            horizon_start=hstart,
            horizon_end=hend,
            record_count=len(records),
            locations=locations,
            retention_bounded=any("wtmp." in loc for loc in locations),
            instrumentation=[
                InstrumentationCheck("wtmp accounting present", True)
            ],
        )
        return CollectResult(events=events, coverage=cov)

    def _build_sessions(self, records: List[_Record], window: TimeRange) -> List[Event]:
        """Pair USER_PROCESS logins with the DEAD_PROCESS that ends the tty line."""
        events: List[Event] = []
        open_by_line: Dict[str, _Record] = {}
        for r in records:
            if r.type == USER_PROCESS and r.ts is not None and r.user:
                # A new login on this line implicitly ends any prior open one.
                open_by_line[r.line] = r
            elif r.type == DEAD_PROCESS and r.ts is not None:
                login = open_by_line.pop(r.line, None)
                if login is not None:
                    events.append(self._session_event(login, r, window))
            elif r.type == BOOT_TIME and r.ts is not None:
                # A reboot closes all still-open sessions (system went down).
                for login in open_by_line.values():
                    events.append(self._session_event(login, None, window,
                                                       ended_by="reboot",
                                                       reboot_ts=r.ts))
                open_by_line.clear()
        # Sessions still open at end of log = currently logged in.
        for login in open_by_line.values():
            events.append(self._session_event(login, None, window,
                                              ended_by="still logged in"))
        return [e for e in events if e is not None]

    def _session_event(
        self,
        login: _Record,
        logout: Optional[_Record],
        window: TimeRange,
        ended_by: str = "logout",
        reboot_ts: Optional[datetime] = None,
    ) -> Optional[Event]:
        end_ts = logout.ts if logout is not None else reboot_ts
        if not window.overlaps(login.ts, end_ts):
            return None
        citations = [Citation(self.source_id, login.locator, login.raw)]
        if logout is not None:
            citations.append(Citation(self.source_id, logout.locator, logout.raw))
        origin = login.host or "local"
        summary = (
            f"session on {login.line} from {origin} "
            f"({'open' if end_ts is None else 'closed'})"
        )
        return Event(
            ts=login.ts,
            ts_end=end_ts,
            type=EventType.SESSION,
            source_id=self.source_id,
            summary=summary,
            actor_name=login.user,
            attrs={
                "line": login.line,
                "host": login.host,
                "pid": login.pid,
                "ended_by": ended_by,
                "origin": origin,
            },
            citations=citations,
        )

    def _build_boots(self, records: List[_Record], window: TimeRange) -> List[Event]:
        events: List[Event] = []
        for r in records:
            if r.type == BOOT_TIME and r.ts is not None and window.contains(r.ts):
                events.append(
                    Event(
                        ts=r.ts,
                        type=EventType.BOOT,
                        source_id=self.source_id,
                        summary="system boot",
                        attrs={"kernel": r.host} if r.host else {},
                        citations=[Citation(self.source_id, r.locator, r.raw)],
                    )
                )
        return events
