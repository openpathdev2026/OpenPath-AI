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

import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from openpath.engine import Engine
from openpath.env import Env
from openpath.facets import FAMILIES, get_facet
from openpath.model.timerange import TimeRange

_RUN_LIVE = os.environ.get("OPENPATH_LIVE", "1") != "0"


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
