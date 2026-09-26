#!/usr/bin/env python3
"""Generate docs/ARCHITECTURE-TRACE.md -- walk any answer back to its raw evidence.

The traceability document: for every question family it shows the full chain

    Question → Facet → Event Types → Collectors → Raw Sources

so a trust question ("why does OpenPath say alice did X?") can be walked from the
user-visible answer all the way down to the file on disk it rests on. Every link is
derived from the shipped code -- the facet↔EventType map (`cli._facet_event_types`),
the EventTypes each collector emits (scanned from collector source), and the paths
each collector reads -- so the trace cannot drift from the implementation.

Usage:  python3 scripts/gen_architecture_trace.py [--out docs/ARCHITECTURE-TRACE.md]
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from openpath.cli import _facet_event_types                        # noqa: E402
from openpath.contract import PRODUCTION_CONTRACT                  # noqa: E402
from openpath.facets import FAMILIES                               # noqa: E402
from openpath.sources import default_collectors                   # noqa: E402
from scripts.gen_evidence_surface import collector_paths, parsed_eventtypes  # noqa: E402

_AGGREGATE = {"core", "timeline", "evidence", "gaps", "host_changes",
              "attribution", "concurrent"}
_DATA_FACETS = ("sessions", "login", "privilege", "root_activity", "commands",
                "files", "accounts", "groups", "packages", "network",
                "persistence", "authorization")


def eventtype_to_collectors():
    """Inverse map: EventType name -> [source_id] that emits it (from code scan)."""
    inv = defaultdict(list)
    for c in default_collectors():
        for et in parsed_eventtypes(c):
            inv[et].append(c.source_id)
    return inv


import re as _re


def _primary_path(paths: list) -> str:
    """The current (non-rotated) file among a collector's paths, for display.

    Path constants list rotated files (`.1`/`.2`/`.4`) alongside the live file; the
    live one is the representative source, so prefer a path whose basename has no
    trailing numeric rotation suffix.
    """
    if not paths:
        return "(dynamic)"
    for p in paths:
        if not _re.search(r"\.\d+$", p):
            return p
    return paths[-1]


def collector_first_paths():
    return {c.source_id: _primary_path(collector_paths(c))
            for c in default_collectors()}


def facet_event_type_names(facet: str) -> list:
    return [e.name for e in _facet_event_types(facet)]


def build() -> str:
    inv = eventtype_to_collectors()
    firstpath = collector_first_paths()
    q_by_facet = defaultdict(list)
    for q in PRODUCTION_CONTRACT:
        q_by_facet[q.facet].append(q.id)

    def collectors_for(ets: list) -> list:
        out = []
        for et in ets:
            for sid in inv.get(et, []):
                if sid not in out:
                    out.append(sid)
        return out

    lines = [
        "# OpenPath-AI — Architecture Trace", "",
        f"_Generated {datetime.now(timezone.utc).isoformat()} by "
        f"`scripts/gen_architecture_trace.py` — regenerate to re-verify._", "",
        "Walk any user-visible answer back to the raw evidence it rests on:", "",
        "```",
        "Question → Facet → Event Types → Collectors → Raw Sources",
        "```", "",
        "Every link is derived from the shipped code (the facet↔EventType map, the "
        "EventTypes each collector emits, the files each collector reads), so this "
        "trace is verifiable against the implementation, not asserted.", "",
        "## Per-facet trace", "",
        "| facet | kind | event types | collectors | raw sources | # questions |",
        "|-------|------|-------------|------------|-------------|-------------|",
    ]
    for spec in FAMILIES:
        f = spec.name
        n = len(q_by_facet.get(f, []))
        if f in _AGGREGATE:
            kind = "aggregate"
            ets_disp = "_federates the 12 data facets_"
            data_ets = []
            for df in _DATA_FACETS:
                data_ets.extend(facet_event_type_names(df))
            cols = collectors_for(sorted(set(data_ets)))
            col_disp = "_(union of data-facet collectors)_"
            src_disp = "_(union of data-facet sources)_"
        else:
            kind = "data"
            ets = facet_event_type_names(f)
            ets_disp = ", ".join(f"`{e}`" for e in ets) or "—"
            cols = collectors_for(ets)
            col_disp = ", ".join(f"`{c}`" for c in cols) or "—"
            srcs = []
            for c in cols:
                p = firstpath.get(c, "?")
                if p not in srcs:
                    srcs.append(p)
            src_disp = ", ".join(f"`{p}`" for p in srcs) or "—"
        lines.append(f"| `{f}` | {kind} | {ets_disp} | {col_disp} | {src_disp} | {n} |")

    lines += [
        "",
        "## Worked examples", "",
        "```",
        "\"What did USER do as root?\"",
        "  → RootActivityFacet (facet: root_activity)",
        "  → EXEC + FILE_CHANGE + NETWORK events, attributed by auid (survives sudo/su)",
        "  → auditd collector",
        "  → /var/log/audit/audit.log*",
        "```", "",
        "```",
        "\"Who logged into this host, and from where?\"",
        "  → Login / Sessions facets (facets: login, sessions)",
        "  → SESSION + SSH_AUTH + LOGIN events",
        "  → wtmp collector + journal.sshd collector + btmp collector",
        "  → /var/log/wtmp*  +  journalctl _COMM=sshd export  +  /var/log/btmp*",
        "```", "",
        "## Question → facet index", "",
        "Every one of the frozen questions, and the facet whose trace (above) answers "
        "it. Combine with the per-facet trace to reach the raw source for any question.",
        "",
        "| facet | questions |",
        "|-------|-----------|",
    ]
    for spec in FAMILIES:
        ids = q_by_facet.get(spec.name, [])
        if ids:
            lines.append(f"| `{spec.name}` | {', '.join(ids)} |")
    # Any facet a question names that isn't a FAMILIES entry (defensive).
    known = {s.name for s in FAMILIES}
    extra = {q.facet for q in PRODUCTION_CONTRACT} - known
    for f in sorted(extra):
        lines.append(f"| `{f}` (non-family) | {', '.join(q_by_facet[f])} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(ROOT / "docs" / "ARCHITECTURE-TRACE.md"))
    args = ap.parse_args(argv)
    doc = build()
    Path(args.out).write_text(doc)
    print(f"wrote {args.out} ({len(doc.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
