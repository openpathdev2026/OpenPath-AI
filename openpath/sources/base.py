"""Collector base class and the shape of what a collector returns.

A collector is responsible for exactly one raw source. It:

    * reads the source's file(s) under ``env.data_root`` (including rotated files
      where relevant), so it can report the true retention *horizon*;
    * emits normalized :class:`Event` objects (each already cited) whose primary
      timestamp falls within the requested window;
    * reports a :class:`SourceCoverage` describing status, horizon, record count,
      and instrumentation checks -- the raw material for honest gap disclosure.

Collectors do no identity filtering and no interpretation beyond the record. That
keeps them simple and keeps attribution logic in one place (the identity layer).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from openpath.env import Env
from openpath.model.coverage import SourceCoverage
from openpath.model.event import Event
from openpath.model.timerange import TimeRange


@dataclass
class CollectResult:
    events: List[Event] = field(default_factory=list)
    coverage: Optional[SourceCoverage] = None


class Collector(ABC):
    #: Stable identifier, also used as the ``source_id`` on emitted events.
    source_id: str = "base"

    @abstractmethod
    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        """Read the source and return in-window events plus coverage."""
        raise NotImplementedError

    # -- helpers shared by concrete collectors ------------------------------ #

    @staticmethod
    def _span(timestamps: List[datetime]):
        """Return (min, max) of a list of datetimes, or (None, None) if empty."""
        if not timestamps:
            return None, None
        return min(timestamps), max(timestamps)
