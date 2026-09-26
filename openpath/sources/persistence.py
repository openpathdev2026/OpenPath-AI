"""Persistence collector: current-state inventory of scheduled/auto-start execution.

Persistence questions ("what cron jobs / systemd timers exist", "what is enabled at
boot", "did the user install a user unit / enable linger") are about the host's
*current state*, not a timestamped act. This collector reads that state directly
from the filesystem under ``data_root`` and emits :class:`Event` objects of type
``PERSISTENCE``, each cited to the file it came from.

These artifacts are deliberately **unattributed** by default -- a unit file does not
record who wrote it. Two honest attribution paths exist: a per-user crontab or a
linger file names the user (carried as ``actor_name``); otherwise a facet may
correlate the artifact's path with a ``FILE_CHANGE`` audit event to tie a human to
its creation. The collector never guesses.

Because this is current state (not a windowed act), each event is stamped at the
analysis anchor (``env.now``) so it reads as "present now", and the facet inventories
it regardless of the requested activity window.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import InstrumentationCheck, SourceCoverage, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

# System crontabs (a USER field between schedule and command).
_SYSTEM_CRONTABS = ["etc/crontab"]
_CRON_D = "etc/cron.d"
_RUNPARTS = ["etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly"]
# Per-user crontabs (the file name is the user); the command has no USER field.
_USER_CRON_DIRS = ["var/spool/cron", "var/spool/cron/crontabs"]
_AT_DIRS = ["var/spool/at", "var/spool/cron/atjobs"]
_SYSTEMD_SYSTEM_DIRS = ["etc/systemd/system", "run/systemd/system"]
_LINGER_DIR = "var/lib/systemd/linger"
_LEGACY_FILES = ["etc/rc.local"]

_CRON_SCHEDULE = re.compile(
    r"^\s*(@\w+|(?:\S+\s+){4}\S+)\s+(.*\S)\s*$")  # 5 fields or @macro, then rest
_ONCALENDAR = re.compile(r"^\s*OnCalendar\s*=\s*(.+?)\s*$", re.M)
_ONBOOT = re.compile(r"^\s*(OnBootSec|OnUnitActiveSec|OnStartupSec)\s*=\s*(.+?)\s*$", re.M)
_EXECSTART = re.compile(r"^\s*ExecStart\s*=\s*(.+?)\s*$", re.M)


class PersistenceCollector(Collector):
    source_id = "persistence"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        ts = env.now
        events: List[Event] = []
        locations: List[str] = []
        unparseable = 0
        detail_bits: List[str] = []

        def mk(kind, artifact, summary, rel, raw, *, user=None, extra=None):
            attrs = {"kind": kind, "artifact": artifact}
            if extra:
                attrs.update(extra)
            events.append(Event(
                ts=ts, type=EventType.PERSISTENCE, source_id=self.source_id,
                summary=summary, actor_name=user, attrs=attrs,
                citations=[Citation(self.source_id, rel, raw)]))

        # -- cron: system crontab + cron.d (schedule USER command) ------------ #
        for rel in _SYSTEM_CRONTABS + [f"{_CRON_D}/*"]:
            for p, r in self._glob(env, rel):
                locations.append(str(p))
                for lineno, line in self._lines(p):
                    s = line.strip()
                    if not s or s.startswith("#") or self._is_env(s):
                        continue
                    parsed = self._parse_system_cron(s)
                    if parsed is None:
                        unparseable += 1
                        continue
                    sched, cuser, cmd = parsed
                    mk("cron", cmd, f"cron ({sched}) as {cuser}: {cmd}",
                       f"{r}:{lineno}", s, user=(cuser if cuser != "root" else None),
                       extra={"schedule": sched, "cron_user": cuser, "command": cmd})

        # -- per-user crontabs (file name = user; no USER field) -------------- #
        for d in _USER_CRON_DIRS:
            for p, r in self._glob(env, f"{d}/*"):
                if p.is_dir():
                    continue
                locations.append(str(p))
                cuser = p.name
                for lineno, line in self._lines(p):
                    s = line.strip()
                    if not s or s.startswith("#") or self._is_env(s):
                        continue
                    m = _CRON_SCHEDULE.match(s)
                    if not m:
                        unparseable += 1
                        continue
                    sched, cmd = m.group(1), m.group(2)
                    mk("cron", cmd, f"cron ({sched}) for {cuser}: {cmd}",
                       f"{r}:{lineno}", s, user=cuser,
                       extra={"schedule": sched, "cron_user": cuser, "command": cmd})

        # -- run-parts dirs: each file is a scheduled script ------------------ #
        for d in _RUNPARTS:
            period = d.rsplit(".", 1)[-1]
            for p, r in self._glob(env, f"{d}/*"):
                if p.is_dir():
                    continue
                locations.append(str(p))
                mk("cron", p.name, f"cron run-parts ({period}): {p.name}", r, r,
                   extra={"schedule": f"@{period}", "command": p.name})

        # -- at jobs: presence + owner (file name) ---------------------------- #
        for d in _AT_DIRS:
            for p, r in self._glob(env, f"{d}/*"):
                if p.is_dir():
                    continue
                locations.append(str(p))
                mk("at", p.name, f"at job {p.name}", r, r, extra={"command": p.name})

        # -- systemd units + timers + enabled state --------------------------- #
        enabled = self._enabled_units(env)
        for d in _SYSTEMD_SYSTEM_DIRS:
            for p, r in self._glob(env, f"{d}/*"):
                if p.is_dir() or p.is_symlink():
                    continue
                if p.suffix not in (".service", ".timer", ".socket", ".path"):
                    continue
                locations.append(str(p))
                text = self._read(p)
                if text is None:
                    unparseable += 1
                    continue
                unit = p.name
                is_enabled = unit in enabled
                if p.suffix == ".timer":
                    when = (_ONCALENDAR.search(text) or _ONBOOT.search(text))
                    sched = when.group(when.re.groups).strip() if when else "?"
                    mk("systemd_timer", unit,
                       f"systemd timer {unit} (schedule {sched}"
                       + (", enabled" if is_enabled else "") + ")",
                       r, sched, extra={"schedule": sched, "enabled": is_enabled})
                else:
                    ex = _EXECSTART.search(text)
                    exec_start = ex.group(1) if ex else "?"
                    mk("systemd_unit", unit,
                       f"systemd {p.suffix[1:]} {unit} (ExecStart {exec_start}"
                       + (", enabled" if is_enabled else "") + ")",
                       r, exec_start,
                       extra={"exec_start": exec_start, "enabled": is_enabled})

        # -- user-level systemd units (~/.config/systemd/user) ---------------- #
        for p, r in self._glob(env, "home/*/.config/systemd/user/*"):
            if p.is_dir() or p.suffix not in (".service", ".timer"):
                continue
            locations.append(str(p))
            # home/<user>/.config/systemd/user/<unit>
            parts = r.split("/")
            cuser = parts[1] if len(parts) > 1 else None
            mk("systemd_user_unit", p.name,
               f"user systemd unit {p.name} for {cuser}", r, r, user=cuser)

        # -- linger (persist without an active login) ------------------------- #
        for p, r in self._glob(env, f"{_LINGER_DIR}/*"):
            if p.is_dir():
                continue
            locations.append(str(p))
            mk("linger", p.name, f"linger enabled for {p.name}", r, r, user=p.name)

        # -- legacy startup --------------------------------------------------- #
        for rel in _LEGACY_FILES:
            p = env.path(rel)
            if p.exists() and p.is_file():
                locations.append(str(p))
                text = self._read(p) or ""
                body = [ln for ln in text.splitlines()
                        if ln.strip() and not ln.strip().startswith("#")
                        and ln.strip() != "exit 0"]
                if body:
                    mk("legacy_startup", rel, f"legacy startup {rel} ({len(body)} line(s))",
                       rel, body[0], extra={"lines": len(body)})

        events.sort(key=lambda e: (e.attrs.get("kind", ""), e.summary))
        status = SourceStatus.AVAILABLE if events or locations else SourceStatus.ABSENT
        detail = (f"{len(events)} persistence artifact(s) across {len(locations)} file(s)"
                  if locations else "no cron/systemd/startup persistence sources found")
        cov = SourceCoverage(
            source_id=self.source_id, status=status, detail=detail,
            record_count=len(events), records_scanned=len(events) + unparseable,
            unparseable=unparseable,
            unparseable_detail=("; ".join(detail_bits) or
                                ("unrecognized cron line(s)" if unparseable else "")),
            locations=locations,
            instrumentation=[InstrumentationCheck(
                "persistence sources present", bool(locations),
                "" if locations else
                "no cron/systemd/startup files found under data root")],
        )
        return CollectResult(events=events, coverage=cov)

    # -- helpers ------------------------------------------------------------- #
    def _glob(self, env: Env, rel: str):
        """Yield ``(path, data-root-relative str)`` for a rel path or glob pattern.

        Globs may span segments (``home/*/.config/systemd/user/*``); pathlib's glob
        resolves those, and the relative string is what citations point to.
        """
        if "*" in rel:
            root = env.data_root
            for p in sorted(root.glob(rel)):
                try:
                    yield p, str(p.relative_to(root))
                except ValueError:
                    yield p, rel
        else:
            p = env.path(rel)
            if p.exists():
                yield p, rel

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

    @staticmethod
    def _is_env(s: str) -> bool:
        return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s))

    @staticmethod
    def _parse_system_cron(s: str) -> Optional[Tuple[str, str, str]]:
        """system crontab / cron.d: 'sched(5) USER command' or '@macro USER command'."""
        if s.startswith("@"):
            parts = s.split(None, 2)
            if len(parts) < 3:
                return None
            return parts[0], parts[1], parts[2]
        parts = s.split(None, 6)
        if len(parts) < 7:
            return None
        sched = " ".join(parts[:5])
        return sched, parts[5], parts[6]

    def _enabled_units(self, env: Env) -> set:
        """Units symlinked into a *.wants/ or *.requires/ dir are enabled."""
        enabled = set()
        for d in _SYSTEMD_SYSTEM_DIRS:
            base = env.path(d)
            if not base.is_dir():
                continue
            for wants in list(base.glob("*.wants")) + list(base.glob("*.requires")):
                if not wants.is_dir():
                    continue
                for link in wants.iterdir():
                    enabled.add(link.name)
        return enabled
