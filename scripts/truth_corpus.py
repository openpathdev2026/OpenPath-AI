#!/usr/bin/env python3
"""Host Truth Corpus framework: compare OpenPath's answers to human-established truth.

This is where production *trust* is actually earned. Fixtures prove the code does
what the author expected; a truth corpus proves OpenPath's answers match what really
happened on a real host, as determined *independently* by a human investigator.

Workflow (the operator's job to populate; this script is the harness):

    real host / bundle              ground_truth.json (authored by an investigator
        │                            who inspected the host BEFORE seeing OpenPath's
        │                            answer -- that independence is the whole point)
        └──────────────┬────────────┘
                       ▼
              truth_corpus.py  ── runs OpenPath (the shipped CLI) per case,
                       │           compares its answer to the declared truth
                       ▼
              report: per-case PASS / MISMATCH + aggregate precision & recall

A MISMATCH is not a corpus bug; it is either a real OpenPath defect (fix it) or an
error in the human's ground truth (fix that). Either way the disagreement is the
signal. A corpus that only ever passes proves nothing -- so the framework is itself
tested against a deliberately-false claim to show it detects disagreement.

ground_truth.json schema -- a JSON list of cases:

    {
      "id": "TC-01",
      "description": "what the investigator established, in words",
      "user": "alice",                 // subject (or omit for --actor any)
      "facet": "commands",             // the question family
      "window": "last 24 hours",       // or "since"/"until" ISO instants
      "actor_mode": "subject",         // subject|any|unattributable (default subject)
      "expect": {
         "confidence":      "certified",       // optional exact match
         "min_events":      1,                  // optional lower bound
         "max_events":      10,                 // optional upper bound
         "events_contain":  ["ls", "curl"],     // each MUST appear (recall / false-neg)
         "events_absent":   ["rm -rf /"],       // none may appear (precision / false-pos)
         "actor":           "alice",            // every event attributed to this actor
         "must_disclose_gap": false             // whether a gap must be disclosed
      }
    }

Usage:
    python3 scripts/truth_corpus.py --data-root <host|bundle> \
        --truth ground_truth.json [--now <ISO>] [--format text|json] [--out r.json]

Exit code: 0 if every case matched, 1 if any case mismatched (so it can gate CI).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _run_cli(argv: List[str]) -> Dict[str, Any]:
    from openpath.cli import main
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    out = buf.getvalue()
    if rc != 0:
        return {"_cli_error": f"rc={rc}", "_raw": out}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"_cli_error": "non-JSON output", "_raw": out[:500]}


def _event_text(ev: Dict[str, Any]) -> str:
    """Flatten an event to searchable text (summary + attr values + actor)."""
    bits = [str(ev.get("summary", "")), str(ev.get("actor_name", ""))]
    attrs = ev.get("attrs") or {}
    bits.extend(str(v) for v in attrs.values())
    return " ".join(bits).lower()


def check_case(case: Dict[str, Any], data_root: str, now: str) -> Dict[str, Any]:
    exp = case.get("expect", {})
    argv = ["--data-root", data_root, "--facet", case["facet"],
            "--format", "json"]
    if case.get("user"):
        argv += ["--user", case["user"]]
    argv += ["--actor", case.get("actor_mode", "subject")]
    if case.get("window"):
        argv += ["--window", case["window"]]
    if case.get("since"):
        argv += ["--since", case["since"]]
    if case.get("until"):
        argv += ["--until", case["until"]]
    if now:
        argv += ["--now", now]

    d = _run_cli(argv)
    failures: List[str] = []
    if "_cli_error" in d:
        return {"id": case.get("id"), "ok": False,
                "failures": [f"CLI error: {d['_cli_error']}"], "kind": "error"}

    finding = d.get("finding", {})
    events = finding.get("events", [])
    texts = [_event_text(e) for e in events]

    kinds = set()

    if "confidence" in exp and finding.get("confidence") != exp["confidence"]:
        failures.append(
            f"confidence {finding.get('confidence')!r} != expected {exp['confidence']!r}")
        kinds.add("confidence")

    if "min_events" in exp and len(events) < exp["min_events"]:
        failures.append(f"only {len(events)} events, expected >= {exp['min_events']}")
        kinds.add("false_negative")

    if "max_events" in exp and len(events) > exp["max_events"]:
        failures.append(f"{len(events)} events, expected <= {exp['max_events']}")
        kinds.add("false_positive")

    for needle in exp.get("events_contain", []):
        if not any(needle.lower() in t for t in texts):
            failures.append(f"expected an event containing {needle!r}, none found")
            kinds.add("false_negative")

    for needle in exp.get("events_absent", []):
        if any(needle.lower() in t for t in texts):
            failures.append(f"an event contains {needle!r} but truth says it must not")
            kinds.add("false_positive")

    if "actor" in exp:
        wrong = [e.get("actor_name") for e in events
                 if e.get("actor_name") and e.get("actor_name") != exp["actor"]]
        if wrong:
            failures.append(f"events attributed to {sorted(set(wrong))}, "
                            f"expected only {exp['actor']!r}")
            kinds.add("misattribution")

    if "must_disclose_gap" in exp:
        has_gap = bool(finding.get("gaps"))
        if exp["must_disclose_gap"] and not has_gap:
            failures.append("expected a disclosed gap, none present")
            kinds.add("undisclosed_gap")
        if not exp["must_disclose_gap"] and has_gap:
            # A disclosed gap when truth expects a clean answer is not a failure per se
            # (disclosure is safe), but we record it for review.
            kinds.add("extra_gap_disclosed")

    return {"id": case.get("id"), "ok": not failures, "failures": failures,
            "kind": sorted(kinds), "n_events": len(events),
            "confidence": finding.get("confidence")}


def run_corpus(data_root: str, truth: List[Dict[str, Any]], now: str) -> Dict[str, Any]:
    results = [check_case(c, data_root, now) for c in truth]
    passed = [r for r in results if r["ok"]]
    failed = [r for r in results if not r["ok"]]
    # Aggregate the disagreement kinds so a reviewer sees precision vs recall issues.
    false_neg = sum(1 for r in failed if "false_negative" in r["kind"])
    false_pos = sum(1 for r in failed if "false_positive" in r["kind"])
    misattr = sum(1 for r in failed if "misattribution" in r["kind"])
    total = len(results)
    return {
        "total": total,
        "passed": len(passed),
        "failed": len(failed),
        "match_rate": round(len(passed) / total, 4) if total else None,
        "false_negatives": false_neg,   # OpenPath missed something that happened
        "false_positives": false_pos,   # OpenPath reported something that did not
        "misattributions": misattr,     # attributed to the wrong principal
        "results": results,
    }


def render_text(report: Dict[str, Any]) -> str:
    out = [f"Host Truth Corpus: {report['passed']}/{report['total']} matched "
           f"(rate {report['match_rate']})",
           f"  false negatives: {report['false_negatives']}  "
           f"false positives: {report['false_positives']}  "
           f"misattributions: {report['misattributions']}", ""]
    for r in report["results"]:
        mark = "PASS" if r["ok"] else "MISMATCH"
        out.append(f"[{mark}] {r['id']} ({r.get('n_events')} events, "
                   f"conf={r.get('confidence')})")
        for f in r["failures"]:
            out.append(f"        - {f}")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-root", required=True)
    ap.add_argument("--truth", required=True, help="ground_truth.json path")
    ap.add_argument("--now", help="anchor 'now' (ISO) for relative windows")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--out", help="also write the JSON report here")
    args = ap.parse_args(argv)

    truth = json.loads(Path(args.truth).read_text())
    report = run_corpus(args.data_root, truth, args.now)
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2) if args.format == "json"
          else render_text(report))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
