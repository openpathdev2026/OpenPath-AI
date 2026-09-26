#!/usr/bin/env python3
"""Measure OpenPath's capture latency -- with real numbers, or an honest "not
measurable here" plus the method that would measure it on a suitable host.

The trust question this answers is "what is the lifecycle from activity to answer":
for each stage, how long from an event happening to OpenPath being able to report
it. OpenPath's own rule applies to its self-measurement: **measure it or disclose
it, never fabricate it.** So every row below is one of:

    * measured   -- a real elapsed time on THIS host, reproducible; or
    * not_measurable -- the capability is absent here (e.g. no auditd in a
                     container), with the exact method to measure it on a real host.

Stages measured:
    * journal_event_to_observable -- emit a `logger` marker, then time until it is
      visible via a `journalctl -o json` export (the sshd/general journald path).
    * audit_event_to_observable   -- (needs auditd) load a temp watch, touch a file,
      time until the SYSCALL record is in audit.log. Disclosed if auditctl absent.
    * analysis_latency            -- wall time of a full collect+analyze over the
      real `/` (how long "queryable" takes once evidence exists).
    * bundle_export_latency       -- wall time of scripts/collect_bundle.sh (the
      offline-bundle capture step).

Usage:
    sudo python3 scripts/measure_capture_latency.py                # text table
    python3 scripts/measure_capture_latency.py --format json       # machine form
    python3 scripts/measure_capture_latency.py --out lat.json      # write JSON too

Exit code is 0 whenever the harness ran (measured + disclosed rows are both a
success); it is non-zero only if the harness itself failed to run.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make the package importable when run from a checkout without installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_TIMEOUT = 20.0        # cap any single wait so the harness never hangs
_POLL = 0.05           # 50 ms polling granularity for "time until observable"


def _measured(stage, seconds, method, note=""):
    return {"stage": stage, "status": "measured",
            "seconds": round(seconds, 4), "method": method, "note": note}


def _not_measurable(stage, reason, method):
    return {"stage": stage, "status": "not_measurable",
            "seconds": None, "reason": reason, "method": method}


def measure_journal_latency():
    stage = "journal_event_to_observable"
    method = ("emit `logger -t <tag> <marker>`; poll `journalctl -t <tag> -o json` "
              "until the marker appears; report the elapsed time")
    if not shutil.which("logger") or not shutil.which("journalctl"):
        return _not_measurable(stage, "logger/journalctl not available", method)
    # Confirm journalctl actually works (containers often ship it non-functional).
    probe = subprocess.run(["journalctl", "-n", "1", "-o", "json", "--no-pager"],
                           capture_output=True, text=True)
    if probe.returncode != 0:
        return _not_measurable(
            stage, f"journalctl present but non-functional (rc={probe.returncode})",
            method)
    tag = "openpath_lat"
    marker = uuid.uuid4().hex
    t0 = time.monotonic()
    emit = subprocess.run(["logger", "-t", tag, marker], capture_output=True)
    if emit.returncode != 0:
        return _not_measurable(stage, "logger failed to emit", method)
    deadline = t0 + _TIMEOUT
    while time.monotonic() < deadline:
        q = subprocess.run(
            ["journalctl", "-t", tag, "-o", "cat", "--no-pager", "--since",
             "-1min"], capture_output=True, text=True)
        if marker in (q.stdout or ""):
            return _measured(stage, time.monotonic() - t0, method,
                             note="syslog->journald visibility on this host")
        time.sleep(_POLL)
    return _not_measurable(
        stage, f"marker not visible within {_TIMEOUT:.0f}s (journald may be "
        f"volatile/rate-limited here)", method)


def measure_audit_latency():
    stage = "audit_event_to_observable"
    method = ("with auditd: `auditctl -w <tmpfile> -p wa -k lat`; touch the file; "
              "poll /var/log/audit/audit.log for the SYSCALL record; report elapsed")
    if os.geteuid() != 0:
        return _not_measurable(stage, "not root (cannot load an audit rule)", method)
    if not shutil.which("auditctl"):
        return _not_measurable(
            stage, "auditctl absent -- the kernel audit subsystem is host-global and "
            "not namespaced, so it is unavailable in this (container) environment",
            method)
    logp = Path("/var/log/audit/audit.log")
    if not logp.exists():
        return _not_measurable(stage, "no /var/log/audit/audit.log present", method)
    tmpf = Path(tempfile.mktemp(prefix="openpath_lat_", dir="/tmp"))
    key = "openpath_lat"
    add = subprocess.run(["auditctl", "-w", str(tmpf), "-p", "wa", "-k", key],
                         capture_output=True, text=True)
    if add.returncode != 0:
        return _not_measurable(stage, f"auditctl rule load failed: {add.stderr.strip()}",
                               method)
    try:
        t0 = time.monotonic()
        tmpf.write_text("x")   # the audited event
        deadline = t0 + _TIMEOUT
        while time.monotonic() < deadline:
            try:
                txt = logp.read_text(errors="replace")
            except OSError:
                txt = ""
            if key in txt and tmpf.name in txt:
                return _measured(stage, time.monotonic() - t0, method,
                                 note="kernel->auditd->audit.log on this host")
            time.sleep(_POLL)
        return _not_measurable(stage, f"record not visible within {_TIMEOUT:.0f}s", method)
    finally:
        subprocess.run(["auditctl", "-W", str(tmpf), "-p", "wa", "-k", key],
                       capture_output=True)
        try:
            tmpf.unlink()
        except OSError:
            pass


def measure_analysis_latency():
    stage = "analysis_latency"
    method = ("time a full Engine collect()+analyze() over --data-root / for one "
              "subject and facet (how long 'queryable' takes once evidence exists)")
    try:
        from openpath.engine import Engine
        from openpath.env import Env
        from openpath.model.timerange import build_range
        now = datetime.now(timezone.utc)
        env = Env(data_root=Path("/"), now=now, local_tz=timezone.utc)
        window = build_range(expr="last 24 hours", since=None, until=None,
                             now=now, default_tz=timezone.utc)
        eng = Engine()
        t0 = time.monotonic()
        collected = eng.collect(env, window)
        ctx = eng.context_for(collected, "root")
        from openpath.facets import get_facet
        get_facet("timeline").analyze(ctx)
        return _measured(stage, time.monotonic() - t0, method,
                         note=f"{len(collected.events)} events, "
                              f"{len(collected.ledger.sources)} sources over /")
    except Exception as exc:  # noqa: BLE001
        return _not_measurable(stage, f"{type(exc).__name__}: {exc}", method)


def measure_bundle_export_latency():
    stage = "bundle_export_latency"
    script = Path(__file__).resolve().parent / "collect_bundle.sh"
    method = f"time {script.name} into a temp dir (the offline-bundle capture step)"
    if not script.exists():
        return _not_measurable(stage, "collect_bundle.sh not found", method)
    dest = tempfile.mkdtemp(prefix="openpath_lat_bundle_")
    try:
        t0 = time.monotonic()
        proc = subprocess.run(["bash", str(script), dest],
                              capture_output=True, text=True, timeout=120)
        elapsed = time.monotonic() - t0
        if proc.returncode != 0:
            return _not_measurable(stage, f"bundle script rc={proc.returncode}", method)
        size = sum(f.stat().st_size for f in Path(dest).rglob("*") if f.is_file())
        return _measured(stage, elapsed, method,
                         note=f"bundle size {size/1024:.0f} KiB")
    except subprocess.TimeoutExpired:
        return _not_measurable(stage, "bundle export exceeded 120s", method)
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def run() -> dict:
    rows = [
        measure_audit_latency(),
        measure_journal_latency(),
        measure_analysis_latency(),
        measure_bundle_export_latency(),
    ]
    return {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "host_data_root": "/",
        "euid": os.geteuid(),
        "rows": rows,
    }


def render_text(report: dict) -> str:
    out = [f"Capture-latency measurement @ {report['measured_at']} (euid "
           f"{report['euid']})", ""]
    out.append(f"{'stage':30s} {'status':15s} {'seconds':>9s}  detail")
    out.append("-" * 78)
    for r in report["rows"]:
        secs = f"{r['seconds']:.4f}" if r["seconds"] is not None else "-"
        detail = r.get("note") or r.get("reason") or ""
        out.append(f"{r['stage']:30s} {r['status']:15s} {secs:>9s}  {detail}")
    out.append("")
    out.append("Rows marked 'not_measurable' name the exact method to measure them on "
               "a suitable host;")
    out.append("no latency is ever fabricated. Re-run on a fully-instrumented auditd "
               "host for the audit row.")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--out", help="also write the JSON report to this path")
    args = ap.parse_args(argv)
    report = run()
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n")
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
