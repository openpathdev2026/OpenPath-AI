"""Live end-to-end test against the REAL host filesystem (``--data-root /``).

Unlike the conformance suite (which uses synthetic bundles), this exercises the
collectors against whatever real logs exist on the machine running the test. It
is written to be meaningful on ANY host:

    * it always asserts the soundness invariant -- every event OpenPath returns on
      the real host carries a citation -- and that no facet raises;
    * source-specific assertions are guarded, so the suite passes on a minimally
      instrumented box and gets stronger on a fully instrumented one.

For a fully-instrumented, rule-loaded auditd host, drive real activity first with
``scripts/live_conformance.sh`` (needs root), then run this to confirm the
activity is attributed with evidence.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from openpath.engine import Engine
from openpath.env import Env
from openpath.facets import FAMILIES, get_facet
from openpath.model.coverage import SourceStatus
from openpath.model.timerange import TimeRange

_RUN_LIVE = os.environ.get("OPENPATH_LIVE", "1") != "0"


def _cli(*argv):
    """Run the shipped CLI in-process against the real host; return (rc, stdout)."""
    from openpath.cli import main
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(list(argv))
    return rc, buf.getvalue()


@unittest.skipUnless(_RUN_LIVE, "set OPENPATH_LIVE=0 to skip live-host tests")
class TestLiveHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        now = datetime.now(timezone.utc)
        # A very wide window so whatever real history the host retains is in range.
        cls.window = TimeRange(start=now - timedelta(days=3650), end=now)
        cls.env = Env(data_root=Path("/"), now=now)
        cls.collected = Engine().collect(cls.env, cls.window)

    def test_no_facet_raises_and_every_claim_is_cited(self):
        eng = Engine()
        for spec in FAMILIES:
            ctx = eng.context_for(self.collected, "root")
            finding = get_facet(spec.name).analyze(ctx)  # must not raise
            for e in finding.events:
                self.assertTrue(
                    e.citations,
                    f"{spec.name}: real-host event without a citation: {e.summary}",
                )

    def test_coverage_ledger_is_populated(self):
        # Every default collector should report a coverage record (even ABSENT).
        source_ids = {c.source_id for c in self.collected.ledger.sources}
        for expected in ("wtmp", "auditd", "packages", "journal.sshd"):
            self.assertIn(expected, source_ids)

    def test_discover_includes_root(self):
        subjects = Engine().discover_subjects(self.collected)
        self.assertIn("root", subjects)

    def test_real_dpkg_counts_match_independent_ground_truth(self):
        # REAL-HOST TRUTH CORPUS (self-grounding): independently count the package
        # transactions in the actual /var/log/dpkg.log(.1) with our OWN parse, then
        # run OpenPath over a covering window and assert its per-action event counts
        # EQUAL the independent counts. Ground truth is derived from the raw file, not
        # from OpenPath — so this is a real cross-check, not producer-checks-producer.
        import re as _re
        logs = [Path("/var/log/dpkg.log"), Path("/var/log/dpkg.log.1")]
        present = [p for p in logs if p.exists() and p.stat().st_size > 0]
        if not present:
            self.skipTest("no /var/log/dpkg.log on this host")
        line_re = _re.compile(
            r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d) "
            r"(install|remove|purge|upgrade|downgrade) \S+ \S+ \S+\s*$")
        truth = {}
        dates = []
        for p in present:
            for ln in p.read_text(errors="replace").splitlines():
                m = line_re.match(ln.strip())
                if m:
                    truth[m.group(3)] = truth.get(m.group(3), 0) + 1
                    dates.append(m.group(1))
        if not truth:
            self.skipTest("no parseable dpkg transaction lines on this host")
        # A window covering the full retained history (min date .. max date + 1d).
        rc, out = _cli("--data-root", "/", "--facet", "packages", "--actor", "any",
                       "--since", f"{min(dates)}T00:00:00",
                       "--until", f"{max(dates)}T23:59:59",
                       "--format", "json")
        self.assertEqual(rc, 0, out)
        events = json.loads(out)["finding"]["events"]
        got = {}
        for e in events:
            a = (e.get("attrs") or {}).get("action")
            got[a] = got.get(a, 0) + 1
        for action, n in truth.items():
            self.assertEqual(got.get(action, 0), n,
                             f"dpkg {action}: OpenPath {got.get(action, 0)} != "
                             f"independent ground truth {n}")

    def test_real_dpkg_or_dnf_parsed_when_present(self):
        cov = self.collected.ledger.get("packages")
        self.assertIsNotNone(cov)
        has_log = any(
            Path(p).exists() and Path(p).stat().st_size > 0 for p in cov.locations
        )
        if not has_log:
            self.skipTest("no non-empty package log on this host")
        # If a real package log exists, we must have parsed real transactions,
        # and each must be cited back to a real file line.
        self.assertGreater(cov.record_count, 0)
        pkg_events = [
            e for e in self.collected.events if e.source_id in ("dnf.rpm", "dpkg")
        ]
        for e in pkg_events[:50]:
            self.assertTrue(e.citations)
            loc = e.citations[0].locator
            self.assertRegex(loc, r".+:\d+$")  # file:lineno

    def test_gaps_are_disclosed_not_silent(self):
        # On a minimally instrumented host, auditd-backed questions must disclose
        # gaps rather than silently claim "nothing happened".
        ctx = Engine().context_for(self.collected, "root")
        auditd = self.collected.ledger.get("auditd")
        if auditd is not None and not auditd.has_instrument("execve audit rule"):
            finding = get_facet("commands").analyze(ctx)
            self.assertTrue(
                finding.gaps,
                "commands returned no gap on a host without an execve rule",
            )

    # -- trust properties, validated against the real filesystem ------------- #

    def test_every_source_has_a_valid_status_and_capture_mode(self):
        # No collector may leave a source in an impossible state on a real host, and
        # every source must declare its capture_mode so a quiet answer is
        # interpretable (live vs snapshot).
        valid = set(SourceStatus)
        self.assertTrue(self.collected.ledger.sources, "no sources probed")
        for s in self.collected.ledger.sources:
            self.assertIn(s.status, valid, f"{s.source_id}: bad status {s.status}")
            self.assertIn(s.capture_mode, ("live", "export"),
                          f"{s.source_id}: bad capture_mode {s.capture_mode!r}")

    def test_direct_filesystem_sources_are_live_on_a_live_host(self):
        # Reading the real '/' at analysis time: on-host log artifacts are observed
        # up to now (capture_mode 'live'), so a quiet answer means quiet -- not a
        # stale snapshot. (Journal collectors may be 'export' if they read a dump.)
        for sid in ("wtmp", "btmp", "auditd", "auth", "packages"):
            cov = self.collected.ledger.get(sid)
            if cov is not None:
                self.assertEqual(cov.capture_mode, "live",
                                 f"{sid}: on-host artifact should be 'live'")

    def test_live_host_has_no_bundle_not_yet_observed_tail(self):
        # A live analysis carries no capture-time marker, so it must NOT fabricate a
        # bundle-level 'not yet observed' tail -- the whole point of the distinction.
        self.assertIsNone(self.collected.ledger.captured_at)
        recency = [g for g in self.collected.ledger.all_gaps()
                   if g.question == "recency" and g.source_id is None]
        self.assertEqual(recency, [], "live host invented a bundle recency tail")

    def test_conservation_no_silent_drops_on_real_data(self):
        # Evidence conservation on real logs: any source that could not decode a
        # record MUST surface a conservation gap -- a record can never vanish
        # silently, even on messy real-world input.
        gaps = self.collected.ledger.all_gaps()
        for s in self.collected.ledger.sources:
            if s.unparseable > 0:
                matched = [g for g in gaps if g.question == "conservation"
                           and g.source_id == s.source_id]
                self.assertTrue(
                    matched,
                    f"{s.source_id}: {s.unparseable} undecoded record(s) not disclosed")

    def test_selfcheck_passes_through_shipped_cli(self):
        rc, out = _cli("--selfcheck")
        self.assertEqual(rc, 0, out)
        self.assertIn("SELFCHECK: HEALTHY", out)

    def test_coverage_cli_end_to_end_against_real_root(self):
        rc, out = _cli("--coverage", "--format", "json", "--data-root", "/")
        self.assertEqual(rc, 0, out)
        cov = json.loads(out)["coverage"]
        self.assertTrue(cov["sources"])
        # Every source is classified and every gap names a reason -- the readiness
        # report is complete and honest on a real host.
        for s in cov["sources"]:
            self.assertIn("status", s)
            self.assertIn("capture_mode", s)
        for g in cov["gaps"]:
            self.assertTrue(g.get("reason"), "a gap without a reason")

    def test_full_analysis_cli_end_to_end_for_root(self):
        # The shipped path (main), not just the engine API: a real analysis for root
        # over multiple facets must exit 0, parse, and keep every claim cited.
        for facet in ("core", "timeline", "sessions", "commands"):
            rc, out = _cli("--user", "root", "--facet", facet, "--format", "json",
                           "--data-root", "/")
            self.assertEqual(rc, 0, f"{facet}: rc={rc}\n{out}")
            d = json.loads(out)
            for e in d.get("evidence", []):
                self.assertTrue(e.get("records"),
                                f"{facet}: evidence object without a raw record")

    def test_all_users_sweep_does_not_crash_on_real_host(self):
        rc, out = _cli("--all-users", "--facet", "core", "--format", "json",
                       "--data-root", "/", "--window", "last 7 days")
        self.assertEqual(rc, 0, out)
        json.loads(out)  # must be well-formed


if __name__ == "__main__":
    unittest.main(verbosity=2)
