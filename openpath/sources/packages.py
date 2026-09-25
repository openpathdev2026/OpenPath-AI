"""Package collector: dnf/rpm and dpkg transaction history.

Important attribution note: neither ``dnf.rpm.log`` nor ``dpkg.log`` records *who*
ran the transaction. They record *what* changed and *when*. So this collector
emits :class:`Event` objects of type PACKAGE_CHANGE that are deliberately
**unattributed** (no ``actor_name``/``auid``). The Packages facet (family 10) is
responsible for attributing them to a subject by correlating with that subject's
audited execution of a package manager (``dnf``/``rpm``/``apt``/``dpkg``) in the
same interval -- and, when exec auditing is not available, for disclosing that the
change is real but cannot be pinned to a specific user.

This separation is the honest one: we never guess who installed a package.
"""

from __future__ import annotations

import re
from typing import List

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import (
    InstrumentationCheck,
    SourceCoverage,
    SourceStatus,
)
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange, parse_instant
from openpath.sources.base import CollectResult, Collector

_DNF_RPM_PATHS = [
    "var/log/dnf.rpm.log.4", "var/log/dnf.rpm.log.3", "var/log/dnf.rpm.log.2",
    "var/log/dnf.rpm.log.1", "var/log/dnf.rpm.log",
]
_DPKG_PATHS = ["var/log/dpkg.log.1", "var/log/dpkg.log"]

# e.g. "2026-09-25T08:30:13+0000 INFO Installed: nginx-1.24.0-1.fc40.x86_64"
_DNF_RE = re.compile(
    r"^(?P<ts>\S+)\s+\S+\s+"
    r"(?P<verb>Installed|Erased|Upgraded|Upgrade|Downgraded|Reinstalled|Obsoleted|Removed):\s+"
    r"(?P<pkg>.+?)\s*$"
)
# e.g. "2026-09-25 08:30:12 install nginx:amd64 <none> 1.24.0-1"
_DPKG_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>install|remove|purge|upgrade|downgrade)\s+(?P<pkg>\S+)\s+"
    r"(?P<from>\S+)\s+(?P<to>\S+)\s*$"
)

_DNF_VERB_ACTION = {
    "Installed": "install", "Reinstalled": "reinstall",
    "Erased": "remove", "Removed": "remove",
    "Upgraded": "upgrade", "Upgrade": "upgrade",
    "Downgraded": "downgrade", "Obsoleted": "obsolete",
}


class PackageCollector(Collector):
    source_id = "packages"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        events: List[Event] = []
        locations: List[str] = []
        managers_seen = set()
        # Horizon/count tracked incrementally so memory is bounded by the
        # in-window result set, not by the total number of transactions.
        hmin = hmax = None
        count = 0
        unparseable = 0

        def _seen(ts):
            nonlocal hmin, hmax, count
            count += 1
            if hmin is None or ts < hmin:
                hmin = ts
            if hmax is None or ts > hmax:
                hmax = ts

        for rel in _DNF_RPM_PATHS:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p))
            managers_seen.add("dnf")
            try:
                fh = p.open("r", encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:  # stream line-by-line to bound memory on large logs
                for lineno, line in enumerate(fh, start=1):
                    m = _DNF_RE.match(line.strip())
                    if not m:
                        continue
                    try:
                        ts = parse_instant(m.group("ts"), env.local_tz)
                    except ValueError:
                        # A real transaction line whose timestamp we cannot parse:
                        # count it, do not drop it silently.
                        unparseable += 1
                        continue
                    _seen(ts)
                    action = _DNF_VERB_ACTION.get(
                        m.group("verb"), m.group("verb").lower())
                    ev = Event(
                        ts=ts, type=EventType.PACKAGE_CHANGE, source_id="dnf.rpm",
                        summary=f"{action} {m.group('pkg')}",
                        attrs={"action": action, "package": m.group("pkg"),
                               "manager": "dnf"},
                        citations=[Citation("dnf.rpm", f"{rel}:{lineno}",
                                            line.strip())],
                    )
                    if window.contains(ts):
                        events.append(ev)

        for rel in _DPKG_PATHS:
            p = env.path(rel)
            if not p.exists():
                continue
            locations.append(str(p))
            managers_seen.add("dpkg")
            try:
                fh = p.open("r", encoding="utf-8", errors="replace")
            except OSError:
                continue
            with fh:  # stream line-by-line to bound memory on large logs
                for lineno, line in enumerate(fh, start=1):
                    m = _DPKG_RE.match(line.strip())
                    if not m:
                        continue
                    try:
                        ts = parse_instant(f"{m.group('date')} {m.group('time')}",
                                           env.local_tz)
                    except ValueError:
                        unparseable += 1
                        continue
                    _seen(ts)
                    ev = Event(
                        ts=ts, type=EventType.PACKAGE_CHANGE, source_id="dpkg",
                        summary=f"{m.group('action')} {m.group('pkg')} "
                                f"{m.group('from')}->{m.group('to')}",
                        attrs={"action": m.group("action"), "package": m.group("pkg"),
                               "version_from": m.group("from"),
                               "version_to": m.group("to"), "manager": "dpkg"},
                        citations=[Citation("dpkg", f"{rel}:{lineno}", line.strip())],
                    )
                    if window.contains(ts):
                        events.append(ev)

        events.sort(key=lambda e: e.ts)
        hstart, hend = hmin, hmax

        if not locations:
            cov = SourceCoverage(
                source_id=self.source_id,
                status=SourceStatus.ABSENT,
                detail="no package manager logs (dnf.rpm.log / dpkg.log) found",
                instrumentation=[
                    InstrumentationCheck(
                        "package transaction log present", False,
                        "no dnf.rpm.log or dpkg.log; software changes unavailable",
                    )
                ],
            )
            return CollectResult(events=[], coverage=cov)

        status = SourceStatus.AVAILABLE if count else SourceStatus.EMPTY
        cov = SourceCoverage(
            source_id=self.source_id,
            status=status,
            detail=f"{count} package transactions from {sorted(managers_seen)}",
            horizon_start=hstart, horizon_end=hend,
            record_count=count,
            records_scanned=count + unparseable, unparseable=unparseable,
            unparseable_detail=("transaction line(s) with an unparseable timestamp"
                                if unparseable else ""),
            locations=locations,
            retention_bounded=any(".log." in loc for loc in locations),
            instrumentation=[
                InstrumentationCheck("package transaction log present", True),
                InstrumentationCheck(
                    "package change actor attribution", False,
                    "package logs do not record the invoking user; attribution "
                    "requires correlating with audited package-manager execution "
                    "(execve rule).",
                ),
            ],
        )
        return CollectResult(events=events, coverage=cov)
