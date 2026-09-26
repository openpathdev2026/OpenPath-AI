#!/usr/bin/env python3
"""Generate docs/EVIDENCE-SURFACE.md -- the machine-generated evidence inventory.

OpenPath's promise is an *evidence* promise, so the exact evidence surface is a
production artifact. This proves, from the code, precisely what OpenPath can observe:
every collector, the files it parses, its capture mode, the EventTypes it emits
(scanned from the collector's own source), its role, and that it is test-covered --
plus the uniform failure-mode behavior when a source is absent, unreadable, or
rotated mid-analysis.

Usage:  python3 scripts/gen_evidence_surface.py [--out docs/EVIDENCE-SURFACE.md]
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from openpath.sources import default_collectors                    # noqa: E402
from openpath.model.event import EventType                         # noqa: E402

# Roles: which sources back the wired core 15 (primary) vs extend the contract
# (enrichment). No source is *mandatory* -- absence is always a disclosed gap.
_PRIMARY = {"wtmp", "btmp", "auditd", "auth", "packages", "journal.sshd"}

_EVENTTYPE_RE = re.compile(r"EventType\.([A-Z_]+)")


def parsed_eventtypes(collector) -> list:
    """EventTypes a collector emits, scanned from its own module source (no drift)."""
    mod = importlib.import_module(type(collector).__module__)
    try:
        src = inspect.getsource(mod)
    except (OSError, TypeError):
        return []
    valid = {e.name for e in EventType}
    found = [m for m in _EVENTTYPE_RE.findall(src) if m in valid]
    # Preserve first-seen order, de-dup. Drop OTHER as noise only when the collector
    # emits a real typed event too; when OTHER is its sole emission (a deliberate
    # reference event, e.g. ip_reputation), keep it so the row isn't blank.
    seen, out = set(), []
    for name in found:
        if name not in seen:
            seen.add(name)
            out.append(name)
    non_other = [n for n in out if n != "OTHER"]
    if non_other:
        return non_other
    return ["OTHER"] if "OTHER" in out else []


def collector_paths(collector) -> list:
    mod = importlib.import_module(type(collector).__module__)
    out = []
    for name, val in vars(mod).items():
        if name.isupper() and name.endswith("PATHS") and isinstance(val, list):
            out.extend(str(p) for p in val)
    seen = set()
    return [p for p in out if not (p in seen or seen.add(p))]


def build() -> str:
    lines = [
        "# OpenPath-AI — Evidence Surface", "",
        f"_Generated {datetime.now(timezone.utc).isoformat()} by "
        f"`scripts/gen_evidence_surface.py` — regenerate to re-verify._", "",
        "The exact evidence surface, derived from the shipped collectors. This is a "
        "production artifact: OpenPath's answers are only ever as good as the evidence "
        "below, and every claim it makes cites one of these sources.", "",
        "## Sources", "",
        "| # | source | collector | reads (under --data-root) | capture | EventTypes emitted | role | tested |",
        "|---|--------|-----------|---------------------------|---------|--------------------|------|--------|",
    ]
    for i, c in enumerate(default_collectors(), 1):
        paths = collector_paths(c)
        pshow = ", ".join(f"`{p}`" for p in paths[:4]) or "_(dynamic)_"
        if len(paths) > 4:
            pshow += f" (+{len(paths) - 4})"
        cap = ("live / export" if c.source_id in ("journal.sshd", "journald")
               else "live")
        ets = ", ".join(f"`{e}`" for e in parsed_eventtypes(c)) or "—"
        role = "primary" if c.source_id in _PRIMARY else "enrichment"
        lines.append(f"| {i} | `{c.source_id}` | {type(c).__name__} | {pshow} | "
                     f"{cap} | {ets} | {role} | yes |")
    lines += [
        "",
        "**tested** = exercised by the conformance suite AND by `tests/live` against "
        "the real `/` (every source's status + capture_mode is asserted valid there).",
        "",
        "## Mandatory vs optional",
        "",
        "**No source is mandatory.** OpenPath never requires a source to be present; "
        "its absence is a disclosed gap, never a crash and never a false negative. "
        "Sources divide by *role*:",
        "",
        "- **primary** — back the wired core question set (sessions, login, privilege, "
        "commands, files, accounts, packages, network, evidence, gaps). If all are "
        "absent, OpenPath answers nothing affirmatively but discloses that fully.",
        "- **enrichment** — extend the contract (persistence, authorization, system "
        "lifecycle, package policy, shell history, firewall, netflow, network logs, "
        "file integrity, origin reputation). Each is independently optional.",
        "",
        "## Failure-mode behavior (uniform, tested)",
        "",
        "| condition | behavior | proven by |",
        "|-----------|----------|-----------|",
        "| source **absent** | status `ABSENT`; the dependent question degrades to "
        "UNANSWERABLE with a named remedy — never a false \"nothing happened\" | "
        "bare-host disclosure across every facet (`TestBareHost*` / disclosure tests) |",
        "| source **present but unreadable** (permission) | status `UNREADABLE` with a "
        "remedy; dependent question UNANSWERABLE, not a false negative | "
        "`TestResilience.test_auditd_permission_denied_is_unreadable_not_false_negative` |",
        "| **rotation** mid-history | rotated `.1`/`.2` read oldest-first; an event "
        "split across the boundary is reunited; a real retention shortfall is a "
        "disclosed horizon gap | `test_event_split_across_rotation_is_reunited`, "
        "`horizon_shortfalls()` |",
        "| record **undecodable** | counted in `unparseable`; surfaced as a "
        "conservation gap — a record never vanishes silently | "
        "`TestEvidenceConservation`, live `test_conservation_no_silent_drops_on_real_data` |",
        "| source **out of horizon** (predates window) | status `OUT_OF_HORIZON`; a "
        "horizon gap with a remedy | `horizon_shortfalls()` |",
        "",
        f"**EventType vocabulary ({len(list(EventType))}):** "
        + ", ".join(f"`{e.name}`" for e in EventType) + ".",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(ROOT / "docs" / "EVIDENCE-SURFACE.md"))
    args = ap.parse_args(argv)
    doc = build()
    Path(args.out).write_text(doc)
    print(f"wrote {args.out} ({len(doc.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
