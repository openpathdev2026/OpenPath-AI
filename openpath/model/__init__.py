"""Core data model for OpenPath-AI.

Nothing in this package touches the filesystem or shells out; it is pure data and
logic so it can be unit-tested in isolation and reused across collectors, facets,
and the conformance harness.
"""

from openpath.model.citation import Citation
from openpath.model.coverage import (
    CoverageLedger,
    Gap,
    InstrumentationCheck,
    SourceCoverage,
    SourceStatus,
)
from openpath.model.event import Event, EventType
from openpath.model.finding import Finding
from openpath.model.identity import (
    IdentityInterval,
    Subject,
    resolve_identity,
)
from openpath.model.timerange import (
    TimeParseError,
    TimeRange,
    build_range,
    parse_instant,
    parse_range,
)

__all__ = [
    "Citation",
    "CoverageLedger",
    "Gap",
    "InstrumentationCheck",
    "SourceCoverage",
    "SourceStatus",
    "Event",
    "EventType",
    "Finding",
    "IdentityInterval",
    "Subject",
    "resolve_identity",
    "TimeParseError",
    "TimeRange",
    "build_range",
    "parse_instant",
    "parse_range",
]
