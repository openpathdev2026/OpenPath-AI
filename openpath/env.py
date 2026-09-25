"""Host environment abstraction: where collectors read from, and how time is anchored.

The single most important design choice for testability (and for offline forensic
work on collected evidence bundles) is that collectors never hardcode ``/var/log``.
They resolve every path under a configurable ``data_root``. Pointing ``data_root``
at ``/`` analyzes the live host; pointing it at a fixture directory analyzes a
captured bundle. The same parsing code runs in both cases, so the conformance
suite exercises exactly the production path.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import List, Optional, Tuple


def _system_local_tz() -> tzinfo:
    """Best-effort host local timezone, always returning a concrete tzinfo."""
    tz = datetime.now().astimezone().tzinfo
    return tz if tz is not None else timezone.utc


@dataclass
class Env:
    """Resolves source locations and anchors time interpretation.

    Attributes:
        data_root: Filesystem root that all source paths are resolved under.
        now: The "current" instant for relative windows (timezone-aware UTC).
        local_tz: Timezone used to interpret source records that carry a naive
            local timestamp (rare -- most sources are epoch/UTC). Anchored
            explicitly so tests are deterministic regardless of the runner's TZ.
    """

    data_root: Path = field(default_factory=lambda: Path("/"))
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    local_tz: tzinfo = field(default_factory=_system_local_tz)

    def __post_init__(self) -> None:
        self.data_root = Path(self.data_root)
        if self.now.tzinfo is None:
            raise ValueError("Env.now must be timezone-aware")
        self.now = self.now.astimezone(timezone.utc)

    # -- path helpers ------------------------------------------------------- #

    def path(self, *relparts: str) -> Path:
        """Resolve a path under the data root (leading slashes are stripped)."""
        rel = Path(*[p.lstrip("/") for p in relparts])
        return self.data_root / rel

    def exists(self, *relparts: str) -> bool:
        return self.path(*relparts).exists()

    # -- passwd snapshot ---------------------------------------------------- #

    def read_passwd(self) -> List[Tuple[str, int]]:
        """Parse the current passwd snapshot into ``(name, uid)`` pairs.

        Returns an empty list if the file is absent/unreadable. Only local users
        are visible here; directory-backed users (LDAP/SSSD) are not, which the
        identity layer discloses when a name cannot be resolved.
        """
        p = self.path("etc/passwd")
        out: List[Tuple[str, int]] = []
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return out
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) < 3:
                continue
            name = fields[0]
            try:
                uid = int(fields[2])
            except ValueError:
                continue
            out.append((name, uid))
        return out

    def read_group(self) -> List[Tuple[str, int, List[str]]]:
        """Parse the group snapshot into ``(name, gid, [members])`` tuples."""
        p = self.path("etc/group")
        out: List[Tuple[str, int, List[str]]] = []
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return out
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) < 4:
                continue
            try:
                gid = int(fields[2])
            except ValueError:
                continue
            members = [m for m in fields[3].split(",") if m]
            out.append((fields[0], gid, members))
        return out
