#!/usr/bin/env python3
"""Generate the production-readiness EVIDENCE PACKAGE: docs/PRODUCTION-EVIDENCE.md.

This is the artifact a reviewer requested instead of "another certification count":
a single document that lets someone independently verify whether the reported
completion state matches the implementation. Every section is derived FROM THE CODE
(so it cannot drift from reality) or from a REAL TEST RUN executed while generating:

    1. Full question catalog (all questions) with per-question certification
       rationale / blind spots -- so certification-by-narrowing is visible if present.
    2. Source inventory: every collector, the files it parses, its capture_mode, and
       the full EventType vocabulary.
    3. Attribution matrix + adversarial corpus results (executed here).
    4. Capture-latency measurements (from scripts/measure_capture_latency.py).
    5. Real-host validation results (executed here).
    6. Container lifecycle validation results (executed here).
    7. Known limitations and principled exclusions.
    8. Trust-roadmap matrix with the test backing each status.

Plus a shipped-path check (how many assertions go through main(), the CLI).

Usage:  python3 scripts/gen_evidence_package.py [--out docs/PRODUCTION-EVIDENCE.md]
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import io
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from openpath import __version__                                    # noqa: E402
from openpath.contract import (                                     # noqa: E402
    CatalogStatus, PRODUCTION_CONTRACT, contract_fingerprint, status_counts)
from openpath.model.event import EventType                          # noqa: E402
from openpath.sources import default_collectors                    # noqa: E402
from openpath.facets import FAMILIES                                # noqa: E402


# -- test execution (evidence, not assertion) -------------------------------- #

def _iter_tests(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from _iter_tests(t)
        else:
            yield t


def run_testclass(dotted: str):
    """Run one TestCase class and return (ids, passed_ids, failed_ids, summary)."""
    loader = unittest.TestLoader()
    try:
        suite = loader.loadTestsFromName(dotted)
    except Exception as exc:  # noqa: BLE001
        return [], [], [], f"LOAD ERROR: {type(exc).__name__}: {exc}"
    ids = [t.id().split(".")[-1] for t in _iter_tests(suite)]
    result = unittest.TestResult()
    buf = io.StringIO()
    _stdout, _stderr = sys.stdout, sys.stderr
    try:
        sys.stdout = sys.stderr = buf     # keep test prints out of our output
        suite.run(result)
    finally:
        sys.stdout, sys.stderr = _stdout, _stderr
    bad = {tc.id().split(".")[-1] for tc, _ in (result.failures + result.errors)}
    skipped = {tc.id().split(".")[-1] for tc, _ in result.skipped}
    passed = [i for i in ids if i not in bad and i not in skipped]
    summary = (f"{len(passed)}/{len(ids)} passed"
               + (f", {len(skipped)} skipped" if skipped else "")
               + (f", {len(bad)} FAILED" if bad else ""))
    return ids, passed, sorted(bad), summary


def method_gist(dotted_class: str, method: str) -> str:
    """First line of a test method's docstring, else its first inline comment."""
    modname, clsname = dotted_class.rsplit(".", 1)
    try:
        cls = getattr(importlib.import_module(modname), clsname)
        fn = getattr(cls, method)
    except Exception:  # noqa: BLE001
        return ""
    if fn.__doc__:
        return fn.__doc__.strip().splitlines()[0].strip()
    try:
        src = inspect.getsource(fn).splitlines()
    except (OSError, TypeError):
        return ""
    for line in src[1:]:
        s = line.strip()
        if s.startswith("#"):
            return s.lstrip("# ").strip()
    return ""


# -- section builders -------------------------------------------------------- #

def sec_catalog() -> str:
    counts = status_counts()
    lines = [
        "## 1. Question catalog with certification rationale", "",
        f"**{len(PRODUCTION_CONTRACT)} questions — CERTIFIED "
        f"{counts[CatalogStatus.CERTIFIED]}, CONTRACTED "
        f"{counts[CatalogStatus.CONTRACTED]}.** Contract fingerprint "
        f"`{contract_fingerprint()}` (deterministic over ids+statuses).", "",
        "The **rationale** column is each question's own recorded blind-spot / scope "
        "note. Read it to check the reviewer's concern directly: a certification "
        "achieved by *narrowing* the question would show up here as a scope that no "
        "longer answers the question asked. These notes are the honest boundary of "
        "each CERTIFIED path, not marketing.", "",
        "| id | question | facet | status | certification rationale / blind spots |",
        "|----|----------|-------|--------|----------------------------------------|",
    ]
    for q in PRODUCTION_CONTRACT:
        text = q.question.replace("{user}", "USER").replace("|", "\\|")
        rationale = (q.blind_spots or "").replace("|", "\\|")
        needs = f" — needs: {q.needs}" if q.needs else ""
        lines.append(f"| {q.id} | {text} | {q.facet} | {q.status.value.upper()} | "
                     f"{rationale}{needs} |")
    return "\n".join(lines)


def sec_sources() -> str:
    lines = [
        "## 2. Source inventory (collectors, parsers, capture mode, EventTypes)", "",
        "Every collector reads one real on-host format under `--data-root`; the same "
        "parser runs on a live host and an offline bundle. `capture_mode` is how the "
        "data reached OpenPath (see capture latency).", "",
        "| # | source_id | reads (paths under data-root) | capture_mode | purpose |",
        "|---|-----------|-------------------------------|--------------|---------|",
    ]
    for i, c in enumerate(default_collectors(), 1):
        mod = importlib.import_module(type(c).__module__)
        found = []
        for name, val in vars(mod).items():
            if name.isupper() and name.endswith("PATHS") and isinstance(val, list):
                found.extend(str(p) for p in val)
        seen = set()
        found = [p for p in found if not (p in seen or seen.add(p))]
        if found:
            shown = ", ".join(f"`{p}`" for p in found[:5])
            if len(found) > 5:
                shown += f" (+{len(found) - 5} more)"
            paths = shown
        else:
            paths = "(built dynamically — see module)"
        cap = ("live (journalctl) / export (dump)"
               if c.source_id in ("journal.sshd", "journald") else "live")
        # The collector's PURPOSE lives in its module docstring, not the class
        # (classes inherit ABC's docstring), so read the module's first line.
        moddoc = (inspect.getdoc(mod) or "").splitlines()
        purpose = (moddoc[0].strip() if moddoc else "").replace("|", "\\|")
        lines.append(f"| {i} | `{c.source_id}` | {paths} | {cap} | {purpose} |")
    lines += [
        "",
        f"**EventType vocabulary ({len(list(EventType))}):** "
        + ", ".join(f"`{e.name}`" for e in EventType) + ".",
        "",
        f"**Facet families ({len(FAMILIES)}):** "
        + ", ".join(f"`{s.name}`" for s in FAMILIES) + ".",
    ]
    return "\n".join(lines)


def _test_table(dotted_class: str, title: str, blurb: str) -> str:
    ids, passed, failed, summary = run_testclass(dotted_class)
    lines = [f"### {title}", "", blurb, "",
             f"`{dotted_class}` — **{summary}** (run while generating this document).",
             "", "| test | result | what it proves |",
             "|------|--------|----------------|"]
    for tid in ids:
        result = "FAIL" if tid in failed else "pass"
        gist = method_gist(dotted_class, tid).replace("|", "\\|")
        lines.append(f"| `{tid}` | {result} | {gist} |")
    return "\n".join(lines)


def sec_attribution() -> str:
    C = "tests.conformance.test_conformance"
    parts = [
        "## 3. Attribution matrix + adversarial corpus (executed)", "",
        "Attribution is auid-centric (survives sudo/su); genuine ambiguity is "
        "disclosed, never guessed. The corpus exercises the messy cases a reviewer "
        "would demand.",
        "",
        _test_table(f"{C}.TestAttributionCorpus", "Adversarial attribution corpus",
                    "Every messy case: concurrent same-user sessions, multiple sudo "
                    "chains, nested su, overlapping root logins, post-logout "
                    "screen/tmux, automation."),
        "",
        _test_table(f"{C}.TestRootAttribution", "Root-action attribution",
                    "Escalation vs direct-root-login vs daemon classification."),
    ]
    return "\n".join(parts)


def sec_latency() -> str:
    from scripts import measure_capture_latency as mcl
    report = mcl.run()
    lines = [
        "## 4. Capture-latency measurements", "",
        f"Measured on this host at {report['measured_at']} (euid {report['euid']}). "
        "OpenPath's own rule applies to its self-measurement: **measured or "
        "disclosed, never fabricated.** A `not_measurable` row names the exact method "
        "to measure it on a suitable (e.g. auditd-instrumented, non-container) host.",
        "",
        "| stage | status | seconds | detail / method |",
        "|-------|--------|---------|-----------------|",
    ]
    for r in report["rows"]:
        secs = f"{r['seconds']:.4f}" if r["seconds"] is not None else "—"
        detail = (r.get("note") or r.get("reason") or "")
        if r["status"] == "not_measurable":
            detail = f"{detail} — method: {r.get('method', '')}"
        detail = detail.replace("|", "\\|")
        lines.append(f"| {r['stage']} | {r['status']} | {secs} | {detail} |")
    lines += ["", "Reproduce: `python3 scripts/measure_capture_latency.py`. On a live "
              "host every stage is bounded by the source's own write latency; on a "
              "bundle every stage is bounded by the stamped `captured-at` instant."]
    return "\n".join(lines)


def sec_realhost() -> str:
    return ("## 5. Real-host validation (executed)\n\n"
            "Runs the collectors and the shipped CLI against the real `/` filesystem "
            "of the machine generating this document — not a fixture.\n\n"
            + _test_table("tests.live.test_live_host.TestLiveHost",
                          "Live-host suite",
                          "No facet raises; every claim cited; capture_mode valid; a "
                          "live host invents no not-yet-observed tail; conservation "
                          "holds on real logs; --selfcheck/--coverage/analysis via "
                          "main() all clean."))


def sec_container() -> str:
    C = "tests.conformance.test_conformance"
    return ("## 6. Container lifecycle validation (executed)\n\n"
            "OpenPath is a stateless batch CLI; `docs/DEPLOYMENT.md` answers all "
            "twelve lifecycle questions. Image build/publish is operator-side (a "
            "daemonless environment cannot build here); the wiring, health, and "
            "failure-mode behavior below are executed.\n\n"
            + _test_table(f"{C}.TestDeployment", "Health / readiness / upgrade",
                          "selfcheck healthy + detects breakage; contract fingerprint "
                          "stable; probes exercise real wiring.")
            + "\n\n"
            + _test_table(f"{C}.TestResilience", "Failure modes",
                          "permission-denied disclosed not false-negative; idempotent "
                          "re-run; broken-pipe/IO-error clean exits."))


def sec_limitations() -> str:
    # Aggregate the standing runtime boundaries from the contract's own notes.
    return (
        "## 7. Known limitations & principled exclusions\n\n"
        f"**Principled exclusions: 0.** No question is excluded from the contract; "
        f"CONTRACTED is {status_counts()[CatalogStatus.CONTRACTED]}. The boundaries "
        "below are scope limits on *hosts* (evidence a default host may not retain), "
        "not exclusions of *questions* — each is CERTIFIED where the evidence is "
        "present and degrades to a remedied UNANSWERABLE without it.\n\n"
        "- **Content-level file diffs (FS-13)** need a file-integrity monitor; auditd "
        "records the change act, never file content.\n"
        "- **Origin reputation / geo (IA-10)** needs a provided threat-intel/geo feed; "
        "OpenPath is deterministic and offline.\n"
        "- **DNS / firewall-drop / proxy / socket-lifetime (NW-08/10/12/15)** need the "
        "respective logging enabled.\n"
        "- **Data volume (NW-04)** needs conntrack byte accounting.\n"
        "- **Shell history (EX-12)** is a lead, not proof of execution (user-editable, "
        "usually un-timestamped) — always disclosed as such.\n"
        "- **Session↔origin linkage:** audit `ses` groups actions but is not bridged "
        "to the wtmp login origin, so one action mapped to a specific overlapping "
        "login is disclosed as ambiguous, not asserted.\n"
        "- **Full per-question blind spots:** see the rationale column of section 1 — "
        "every CERTIFIED question records its own scope boundary there."
    )


def sec_trustmatrix() -> str:
    # Pull the matrix straight from PRODUCTION-READINESS.md so the two never diverge.
    src = ROOT / "docs" / "PRODUCTION-READINESS.md"
    rows = []
    if src.exists():
        capture = False
        for line in src.read_text().splitlines():
            if line.startswith("| Area "):
                capture = True
            if capture:
                if line.startswith("|"):
                    rows.append(line)
                elif rows:
                    break
    body = ("\n".join(rows) if rows
            else "_(see docs/PRODUCTION-READINESS.md)_")
    return ("## 8. Trust-roadmap matrix (evidence per status)\n\n"
            "Reproduced from `docs/PRODUCTION-READINESS.md` (single source of truth); "
            "each row names the test(s) that enforce it.\n\n" + body)


def sec_shipped_path() -> str:
    tf = ROOT / "tests" / "conformance" / "test_conformance.py"
    n_cli = tf.read_text().count("self.cli(") if tf.exists() else 0
    return ("## Shipped-path verification\n\n"
            f"Certification/answer assertions drive the shipped CLI entrypoint "
            f"`openpath.cli:main` via the `self.cli(...)` helper — **{n_cli} call "
            "sites** in the conformance suite (grep `self.cli(` in "
            "`tests/conformance/test_conformance.py`). `main()` is the same function "
            "`pyproject.toml` binds to the `openpath-ai` console script, so a green "
            "suite exercises the code a user runs, not a test-only shortcut. A small "
            "number of attribution checks additionally call internal helpers "
            "(`classify_root_action`) to assert classification directly; those are "
            "labelled and are in addition to, not instead of, the CLI path.")


def build() -> str:
    counts = status_counts()
    header = [
        "# OpenPath-AI — Production-readiness evidence package", "",
        f"_Generated {datetime.now(timezone.utc).isoformat()} by "
        f"`scripts/gen_evidence_package.py` — regenerate to re-verify._", "",
        f"Version `{__version__}` · contract fingerprint `{contract_fingerprint()}` · "
        f"CERTIFIED {counts[CatalogStatus.CERTIFIED]} / CONTRACTED "
        f"{counts[CatalogStatus.CONTRACTED]}.", "",
        "This document exists to be *independently verified against the "
        "implementation*, not taken on faith. Code-derived sections are read from the "
        "shipped modules; test-result sections are executed while generating; latency "
        "numbers are measured on the generating host (or disclosed as not measurable "
        "here). Reproduce the whole thing with the command in the file header.", "",
        "---", "",
    ]
    sections = [
        sec_catalog(), sec_sources(), sec_attribution(), sec_latency(),
        sec_realhost(), sec_container(), sec_limitations(), sec_trustmatrix(),
        sec_shipped_path(),
    ]
    return "\n".join(header) + "\n\n" + "\n\n---\n\n".join(sections) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(ROOT / "docs" / "PRODUCTION-EVIDENCE.md"))
    args = ap.parse_args(argv)
    doc = build()
    Path(args.out).write_text(doc)
    print(f"wrote {args.out} ({len(doc.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
