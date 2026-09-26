"""Shell-history collector: interactive commands typed into a user's shell (EX-12).

Reads ``~/.bash_history`` / ``~/.zsh_history`` / ``~/.sh_history`` (and root's) and
emits ``EventType.SHELL_HISTORY``, attributed to the home-directory owner. This is a
deliberately *weak* source and is kept distinct from audited execution: the file is
user-editable, usually carries no timestamp (so events are stamped at the analysis
anchor and disclosed as time-unknown), and records intent to type, not proof of
execution. zsh's ``: <epoch>:<dur>;<cmd>`` extended format is parsed for a real time
when present.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import InstrumentationCheck, SourceCoverage, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

_HISTORY_FILES = (".bash_history", ".zsh_history", ".sh_history", ".history")
_ZSH_EXT = re.compile(r"^:\s*(\d+):\d+;(.*)$")


class ShellHistoryCollector(Collector):
    source_id = "shell_history"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        events: List[Event] = []
        locations: List[str] = []
        anchor = env.now

        for p, rel, owner in self._history_paths(env):
            locations.append(str(p))
            for i, line in self._lines(p):
                s = line.rstrip("\n")
                if not s.strip():
                    continue
                ts, cmd, timed = self._parse(s, anchor)
                if not cmd.strip():
                    continue
                events.append(Event(
                    ts=ts, type=EventType.SHELL_HISTORY, source_id=self.source_id,
                    summary=f"{owner} shell history: {cmd}", actor_name=owner,
                    attrs={"cmdline": cmd, "timed": timed, "owner": owner},
                    citations=[Citation(self.source_id, f"{rel}:{i}", s[:120])]))

        status = SourceStatus.AVAILABLE if locations else SourceStatus.ABSENT
        cov = SourceCoverage(
            source_id=self.source_id, status=status,
            detail=(f"{len(events)} shell-history line(s) across {len(locations)} "
                    f"file(s)" if locations else "no shell history files found"),
            record_count=len(events), records_scanned=len(events),
            locations=locations,
            instrumentation=[InstrumentationCheck(
                "shell history present", bool(locations),
                "" if locations else "no ~/.bash_history / ~/.zsh_history found")],
        )
        return CollectResult(events=events, coverage=cov)

    def _history_paths(self, env: Env):
        root = env.data_root
        for hf in _HISTORY_FILES:
            for p in sorted(root.glob(f"home/*/{hf}")):
                if p.is_file():
                    parts = p.relative_to(root).parts
                    owner = parts[1] if len(parts) > 1 else None
                    yield p, str(p.relative_to(root)), owner
            rp = env.path(f"root/{hf}")
            if rp.exists() and rp.is_file():
                yield rp, f"root/{hf}", "root"

    def _parse(self, line: str, anchor) -> Tuple[datetime, str, bool]:
        m = _ZSH_EXT.match(line)
        if m:
            try:
                return (datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc),
                        m.group(2), True)
            except (ValueError, OSError):
                return anchor, m.group(2), False
        return anchor, line, False

    def _lines(self, p):
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    yield i, line
        except OSError:
            return
