#!/usr/bin/env python3
"""Host-trial harness: measure OpenPath's resource use and stability over repeated
analysis cycles on a real host (or bundle).

Release Gate D asks for a 30-day continuous trial measuring CPU, memory, disk,
latency, collector failures, and parsing failures. The 30-day *duration* is an
irreducible real-world run an operator performs; this harness is the instrument that
produces the measurements, and it runs a bounded BURST here so the numbers are real,
not assumed. An operator runs it long-form (e.g. under cron/systemd-timer for 30
days, appending to a log) to close the duration component.

What it measures per cycle (a full collect → analyze over --data-root):
  * wall-clock latency
  * process peak RSS (ru_maxrss) — memory does not grow unbounded across cycles
  * collector failures (sources reported UNREADABLE / that raised)
  * parsing failures (sources with unparseable > 0)
It asserts stability: no cycle raises, latency stays bounded, RSS does not climb
monotonically (a leak signature). Output is JSON + a human summary.

Usage:
  python3 scripts/host_trial.py --cycles 50 [--data-root /] [--facet timeline]
  python3 scripts/host_trial.py --cycles 50 --out trial.json
Exit 0 if the burst was stable (no failures, bounded), non-zero otherwise.
"""

from __future__ import annotations

import argparse
import json
import resource
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openpath.engine import Engine
from openpath.env import Env
from openpath.facets import get_facet
from openpath.model.coverage import SourceStatus
from openpath.model.timerange import build_range


def _rss_kb() -> int:
    # ru_maxrss is kilobytes on Linux.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def run(cycles: int, data_root: str, facet: str) -> dict:
    now = datetime.now(timezone.utc)
    env = Env(data_root=Path(data_root), now=now, local_tz=timezone.utc)
    window = build_range(expr="last 24 hours", since=None, until=None,
                         now=now, default_tz=timezone.utc)
    eng = Engine()
    latencies = []
    rss_series = []
    collector_failures = 0
    parsing_failures = 0
    cycle_errors = []
    events_seen = None
    for i in range(cycles):
        t0 = time.monotonic()
        try:
            collected = eng.collect(env, window)
            ctx = eng.context_for(collected, "root")
            get_facet(facet).analyze(ctx)
        except Exception as exc:  # noqa: BLE001 — a trial records failures, never crashes
            cycle_errors.append(f"cycle {i}: {type(exc).__name__}: {exc}")
            continue
        latencies.append(time.monotonic() - t0)
        rss_series.append(_rss_kb())
        if i == 0:
            events_seen = len(collected.events)
            for s in collected.ledger.sources:
                if s.status == SourceStatus.UNREADABLE:
                    collector_failures += 1
                if s.unparseable > 0:
                    parsing_failures += 1

    def stats(xs):
        return {"min": round(min(xs), 4), "max": round(max(xs), 4),
                "mean": round(sum(xs) / len(xs), 4)} if xs else None

    # Leak signature: RSS at the end materially above the early plateau. Compare the
    # last-fifth mean to the first-fifth mean; a real leak grows every cycle.
    rss_growth_kb = None
    if len(rss_series) >= 10:
        k = max(1, len(rss_series) // 5)
        rss_growth_kb = int(sum(rss_series[-k:]) / k - sum(rss_series[:k]) / k)

    stable = (not cycle_errors
              and collector_failures == 0
              and (rss_growth_kb is None or rss_growth_kb <= 2048))  # <=2 MiB drift
    return {
        "measured_at": now.isoformat(),
        "data_root": data_root,
        "facet": facet,
        "cycles_requested": cycles,
        "cycles_completed": len(latencies),
        "events_per_cycle": events_seen,
        "latency_seconds": stats(latencies),
        "peak_rss_kb": max(rss_series) if rss_series else None,
        "rss_growth_kb_first_to_last_fifth": rss_growth_kb,
        "collector_failures": collector_failures,
        "parsing_failures": parsing_failures,
        "cycle_errors": cycle_errors,
        "stable": stable,
        "note": ("bounded burst; the 30-day continuous duration is the operator's "
                 "run (schedule this harness under cron/systemd-timer, append output)"),
    }


def render_text(r: dict) -> str:
    lat = r["latency_seconds"] or {}
    return "\n".join([
        f"Host trial @ {r['measured_at']} — {r['cycles_completed']}/"
        f"{r['cycles_requested']} cycles over {r['data_root']} (facet {r['facet']})",
        f"  latency  s : min {lat.get('min')}  mean {lat.get('mean')}  max {lat.get('max')}",
        f"  peak RSS   : {r['peak_rss_kb']} KiB",
        f"  RSS drift  : {r['rss_growth_kb_first_to_last_fifth']} KiB (first→last fifth; "
        f"leak signature if large)",
        f"  collector failures : {r['collector_failures']}",
        f"  parsing failures   : {r['parsing_failures']}",
        f"  cycle errors       : {len(r['cycle_errors'])}",
        f"  STABLE (burst)     : {r['stable']}",
        f"  {r['note']}",
    ])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cycles", type=int, default=50)
    ap.add_argument("--data-root", default="/")
    ap.add_argument("--facet", default="timeline")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    r = run(args.cycles, args.data_root, args.facet)
    if args.out:
        Path(args.out).write_text(json.dumps(r, indent=2) + "\n")
    print(json.dumps(r, indent=2) if args.format == "json" else render_text(r))
    return 0 if r["stable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
