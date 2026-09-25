"""Product-readiness conformance suite.

This is the baseline the product must never regress below: for *any* user and
*any* time range, all 13 question families must answer soundly (every claim
cited) and disclose every gap (never a false "nothing happened"). The scenarios
below deliberately include the cases that break naive implementations:

    * a brand-new user created *inside* the window,
    * UID reuse across a deleted and a recreated user,
    * attribution after ``sudo`` (auid vs uid),
    * a user that never existed,
    * hosts missing the audit rules that a question depends on,
    * a retention-bounded log that does not reach the window start,
    * the same question asked with different time expressions.

Every source is a real on-disk format parsed by the production collectors.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from openpath import router
from openpath.engine import Engine
from openpath.env import Env
from openpath.model.timerange import TimeRange, build_range
from openpath.render import render_json, render_text
from tests.conformance.fixtures import HostBuilder

# The canonical 13 questions, as {user} templates -> expected facet.
CANONICAL = [
    ("What did {u} do during the last 24 hours?", "core"),
    ("Show me everything {u} did chronologically during the last 24 hours.", "timeline"),
    ("What sessions did {u} have during the last 24 hours?", "sessions"),
    ("When did {u} log in and where did they connect from?", "login"),
    ("Did {u} become root during the last 24 hours?", "privilege"),
    ("What did {u} do as root during the last 24 hours?", "root_activity"),
    ("What commands did {u} execute during the last 24 hours?", "commands"),
    ("What files did {u} change during the last 24 hours?", "files"),
    ("What accounts or groups did {u} change during the last 24 hours?", "accounts"),
    ("What software did {u} install, remove, or change during the last 24 hours?", "packages"),
    ("What network activity did {u} perform during the last 24 hours?", "network"),
    ("What evidence supports what {u} did during the last 24 hours?", "evidence"),
    ("What could OpenPath not determine about {u} during the last 24 hours?", "gaps"),
]

NOW = datetime(2026, 9, 25, 12, 0, 0, tzinfo=timezone.utc)


def ago(**kw):
    return NOW - timedelta(**kw)


class Base(unittest.TestCase):
    def make_root(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="openpath-conf-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return root

    def env(self, root: Path) -> Env:
        return Env(data_root=root, now=NOW, local_tz=timezone.utc)

    def win(self, expr="last 24 hours", since=None, until=None) -> TimeRange:
        return build_range(expr=expr, since=since, until=until,
                           now=NOW, default_tz=timezone.utc)

    def finding(self, root, user, facet, window=None):
        window = window or self.win()
        return Engine().analyze(self.env(root), user, window, facet).finding

    def result(self, root, user, facet, window=None):
        window = window or self.win()
        return Engine().analyze(self.env(root), user, window, facet)

    # -- shared scenario: a fully instrumented host with alice active --------- #

    def fully_instrumented(self) -> Path:
        root = self.make_root()
        h = HostBuilder(root)
        (h.passwd("root", 0).passwd("alice", 1001).passwd("bob", 1002)
         .passwd("deploybot", 1500))
        h.group("wheel", 10, ["alice"])
        h.enable_execve().enable_network().enable_file_syscalls().watch("/etc", "wa", "etc")
        h.boot(ago(hours=20))
        h.ssh_accept("alice", "203.0.113.7", ago(hours=3, minutes=1))
        h.login("alice", ago(hours=3), line="pts/0", host="203.0.113.7",
                until=ago(hours=1))
        h.sudo(1001, 1001, "/usr/bin/dnf install -y nginx", ago(hours=2, minutes=40))
        h.exec(1001, 0, ["dnf", "install", "-y", "nginx"], "/usr/bin/dnf",
               ago(hours=2, minutes=40), euid=0, comm="dnf")
        h.pkg("Installed", "nginx-1.24.0-1.fc40.x86_64", ago(hours=2, minutes=39))
        h.exec(1001, 1001, ["ls", "-la"], "/usr/bin/ls", ago(hours=2, minutes=35))
        h.connect(1001, 0, "93.184.216.34", 443, ago(hours=2, minutes=30))
        h.file_change(1001, 0, "openat", "/etc/hosts", ago(hours=2, minutes=20),
                      euid=0, key="etc")
        h.add_user(1001, "deploybot", 1500, ago(hours=2, minutes=10))
        h.add_group(1001, "deploygrp", 3000, ago(hours=2, minutes=5))
        h.write()
        return root


class TestActiveUserAllFamilies(Base):
    """Every family answers correctly for an active user on an instrumented host."""

    def setUp(self):
        self.root = self.fully_instrumented()

    def test_sessions(self):
        f = self.finding(self.root, "alice", "sessions")
        self.assertEqual(len(f.events), 1)
        self.assertEqual(f.gaps, [])

    def test_login_origin(self):
        f = self.finding(self.root, "alice", "login")
        self.assertIn("203.0.113.7", f.summary)

    def test_privilege_yes(self):
        f = self.finding(self.root, "alice", "privilege")
        self.assertTrue(f.summary.startswith("Yes"))
        self.assertEqual(f.gaps, [])  # fully instrumented -> no partial-visibility gap

    def test_root_activity(self):
        f = self.finding(self.root, "alice", "root_activity")
        # dnf exec + connect + /etc/hosts change, all as root
        self.assertGreaterEqual(len(f.events), 3)

    def test_commands_count(self):
        f = self.finding(self.root, "alice", "commands")
        self.assertEqual(len(f.events), 2)
        self.assertEqual(f.gaps, [])

    def test_files(self):
        f = self.finding(self.root, "alice", "files")
        self.assertEqual(len(f.events), 1)
        self.assertEqual(f.events[0].attrs.get("path"), "/etc/hosts")

    def test_accounts_and_groups(self):
        f = self.finding(self.root, "alice", "accounts")
        targets = {e.attrs.get("acct") or e.attrs.get("grp") for e in f.events}
        self.assertIn("deploybot", targets)
        self.assertIn("deploygrp", targets)

    def test_packages_attributed(self):
        f = self.finding(self.root, "alice", "packages")
        self.assertEqual(len(f.events), 1)
        self.assertIn("nginx", f.events[0].summary)
        self.assertEqual(f.gaps, [])

    def test_network_endpoint(self):
        f = self.finding(self.root, "alice", "network")
        self.assertIn("93.184.216.34:443", f.summary)

    def test_evidence_every_claim_cited(self):
        # Soundness invariant: every event behind every family carries a citation.
        for facet in ["timeline", "commands", "files", "network", "accounts",
                      "privilege", "root_activity", "packages", "login", "sessions"]:
            f = self.finding(self.root, "alice", facet)
            for e in f.events:
                self.assertTrue(e.citations, f"{facet}: event without citation: {e.summary}")

    def test_gaps_none_when_fully_instrumented(self):
        f = self.finding(self.root, "alice", "gaps")
        self.assertEqual(f.gaps, [], f"unexpected gaps: {[g.reason for g in f.gaps]}")

    def test_core_overview(self):
        f = self.finding(self.root, "alice", "core")
        self.assertEqual(f.gaps, [])
        self.assertTrue(any("nginx" in n or "package" in n.lower() for n in f.notes))


class TestTimeFormatEquivalence(Base):
    """The same question over the same real interval yields the same answer,
    regardless of how the time range was expressed."""

    def test_relative_vs_explicit(self):
        root = self.fully_instrumented()
        f_rel = self.finding(root, "alice", "commands", self.win("last 24 hours"))
        f_abs = self.finding(
            root, "alice", "commands",
            self.win(since="2026-09-24T12:00:00Z", until="2026-09-25T12:00:00Z"),
        )
        f_iso = self.finding(
            root, "alice", "commands",
            self.win("2026-09-24T12:00:00Z..2026-09-25T12:00:00Z"),
        )
        self.assertEqual(len(f_rel.events), len(f_abs.events))
        self.assertEqual(len(f_rel.events), len(f_iso.events))

    def test_narrow_window_excludes_earlier_events(self):
        root = self.fully_instrumented()
        # Only the last hour: alice's activity was >2h ago, so zero commands.
        f = self.finding(root, "alice", "commands", self.win("last 1 hour"))
        self.assertEqual(len(f.events), 0)
        self.assertEqual(f.gaps, [])  # instrumented -> evidenced negative, not a gap


class TestNewAndReusedIdentities(Base):
    """Any user, including newly-created ones and reused UIDs."""

    def test_user_created_in_window_is_attributed(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("admin", 1001).passwd("deploybot", 1500)
        h.enable_execve()
        h.boot(ago(hours=20))
        # admin creates deploybot mid-window; deploybot then acts.
        h.add_user(1001, "deploybot", 1500, ago(hours=5))
        h.login("deploybot", ago(hours=4), line="pts/2", host="10.0.0.3")
        h.exec(1500, 1500, ["systemctl", "restart", "web"], "/usr/bin/systemctl",
               ago(hours=3, minutes=30), comm="systemctl")
        h.write()

        r = self.result(root, "deploybot", "commands")
        self.assertTrue(r.subject.exists_now)
        self.assertEqual(len(r.finding.events), 1)
        self.assertIn("systemctl", r.finding.events[0].attrs.get("cmdline", ""))
        # deploybot's identity interval must open at creation, not at -inf.
        self.assertTrue(any(iv.start is not None for iv in r.subject.intervals))

    def test_uid_reuse_no_cross_attribution(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("admin", 1001).passwd("deploybot", 1500)
        h.enable_execve()
        h.boot(ago(hours=40))
        # olduser held uid 1500, created -30h, deleted -20h.
        h.add_user(1001, "olduser", 1500, ago(hours=30))
        h.exec(1500, 1500, ["olduser-cmd"], "/usr/bin/olduser-cmd", ago(hours=25))
        h.del_user(1001, "olduser", 1500, ago(hours=20))
        # deploybot reuses uid 1500, created -2h.
        h.add_user(1001, "deploybot", 1500, ago(hours=2))
        h.exec(1500, 1500, ["deploybot-cmd"], "/usr/bin/deploybot-cmd", ago(hours=1))
        h.write()

        win = self.win("last 48 hours")
        f_old = self.finding(root, "olduser", "commands", win)
        f_new = self.finding(root, "deploybot", "commands", win)
        old_cmds = [e.attrs.get("cmdline") for e in f_old.events]
        new_cmds = [e.attrs.get("cmdline") for e in f_new.events]
        self.assertIn("olduser-cmd", old_cmds)
        self.assertNotIn("deploybot-cmd", old_cmds)
        self.assertIn("deploybot-cmd", new_cmds)
        self.assertNotIn("olduser-cmd", new_cmds)

    def test_auid_after_sudo_attributes_to_real_user(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001).passwd("bob", 1002)
        h.enable_execve()
        h.boot(ago(hours=10))
        # alice sudo->root runs one command; bob sudo->root runs another.
        h.exec(1001, 0, ["alice-root-cmd"], "/usr/bin/a", ago(hours=3), euid=0)
        h.exec(1002, 0, ["bob-root-cmd"], "/usr/bin/b", ago(hours=2), euid=0)
        h.write()

        f_alice = self.finding(root, "alice", "root_activity")
        f_bob = self.finding(root, "bob", "root_activity")
        a_cmds = [e.attrs.get("cmdline") for e in f_alice.events]
        b_cmds = [e.attrs.get("cmdline") for e in f_bob.events]
        self.assertIn("alice-root-cmd", a_cmds)
        self.assertNotIn("bob-root-cmd", a_cmds)
        self.assertIn("bob-root-cmd", b_cmds)
        self.assertNotIn("alice-root-cmd", b_cmds)

    def test_never_existed_user_is_evidenced_negative(self):
        root = self.fully_instrumented()
        r = self.result(root, "ghost", "core")
        self.assertFalse(r.subject.exists_now)
        # No crash, no fabricated activity.
        self.assertTrue(r.subject.resolution_notes)
        f_cmd = self.finding(root, "ghost", "commands")
        self.assertEqual(len(f_cmd.events), 0)


class TestGapDisclosure(Base):
    """Missing instrumentation must become a disclosed gap, never a false negative."""

    def _host_no_execve(self) -> Path:
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        # auditd running, but only account/sudo user-space messages; NO execve rule.
        h.boot(ago(hours=10))
        h.login("alice", ago(hours=3), until=ago(hours=1), host="10.0.0.5")
        h.sudo(1001, 1001, "/usr/bin/vi /etc/hosts", ago(hours=2))
        h.add_user(1001, "svc", 1600, ago(hours=2, minutes=30))
        h.pkg("Installed", "htop-3.2.1-1.fc40.x86_64", ago(hours=2, minutes=10))
        h.write()
        return root

    def test_commands_gap_without_execve_rule(self):
        f = self.finding(self._host_no_execve(), "alice", "commands")
        self.assertEqual(len(f.events), 0)
        self.assertTrue(f.gaps, "commands must disclose a gap when execve is off")
        self.assertIn("Commands", [g.question for g in f.gaps])
        self.assertTrue(any(g.remedy for g in f.gaps))

    def test_privilege_still_detects_sudo_but_discloses_partial(self):
        f = self.finding(self._host_no_execve(), "alice", "privilege")
        # sudo usage is visible even without an execve rule.
        self.assertTrue(f.summary.startswith("Yes"))
        # ...but the tool must disclose that root *commands* aren't fully visible.
        self.assertTrue(any(g.question == "Privilege" for g in f.gaps))

    def test_accounts_work_without_syscall_rules(self):
        f = self.finding(self._host_no_execve(), "alice", "accounts")
        self.assertTrue(any(e.attrs.get("acct") == "svc" for e in f.events))
        self.assertEqual([g for g in f.gaps if g.question == "Accounts/groups"], [])

    def test_packages_unattributable_without_execve(self):
        f = self.finding(self._host_no_execve(), "alice", "packages")
        # A package changed on the host, but with no command auditing it cannot be
        # pinned to alice -> disclosed gap, not a false claim either way.
        self.assertTrue(any(g.question == "Packages" for g in f.gaps))

    def test_auditd_absent_discloses_gaps_but_sessions_work(self):
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001)
        h.boot(ago(hours=10))
        h.login("alice", ago(hours=3), until=ago(hours=1), host="10.0.0.5")
        h.write()

        # wtmp-backed questions still answer.
        self.assertEqual(len(self.finding(root, "alice", "sessions").events), 1)
        # auditd-backed questions must all disclose gaps.
        for facet in ["commands", "files", "network", "privilege", "root_activity",
                      "accounts"]:
            f = self.finding(root, "alice", facet)
            self.assertTrue(f.gaps, f"{facet} must disclose a gap when auditd absent")
            self.assertEqual(len(f.events), 0)

    def test_retention_horizon_shortfall_disclosed(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve()
        # All records are AFTER the window start, and the log is rotated (bounded).
        h.login("alice", ago(hours=6), until=ago(hours=5), host="10.0.0.5")
        h.rotate_logs()  # push existing records into wtmp.1 / audit.log.1
        h.login("alice", ago(hours=2), until=ago(hours=1), host="10.0.0.5")
        h.write()
        f = self.finding(root, "alice", "gaps")
        self.assertTrue(any(g.question == "horizon" for g in f.gaps),
                        "a retention-bounded log starting mid-window must disclose "
                        "a horizon gap")


class TestNaturalLanguageRouting(Base):
    """The 13 canonical questions route to the right facet and extract the right
    subject -- for arbitrary usernames, not a hardcoded set."""

    USERNAMES = ["alice", "deploybot", "svc-01", "j.doe", "root", "u12345"]

    def test_all_canonical_questions_route(self):
        for tmpl, expected_facet in CANONICAL:
            for user in self.USERNAMES:
                q = tmpl.format(u=user)
                self.assertEqual(
                    router.route(q), expected_facet,
                    f"routing wrong for {q!r}: expected {expected_facet}")
                self.assertEqual(
                    router.extract_user(q), user,
                    f"user extraction wrong for {q!r}: expected {user}")

    def test_time_extraction_variants(self):
        self.assertEqual(router.extract_time("... during the last 24 hours?"),
                         "last 24 hours")
        self.assertEqual(router.extract_time("... over the past 7 days"),
                         "past 7 days")
        self.assertIsNotNone(router.extract_time("between 2026-09-01 and later")
                             or router.extract_time("2026-09-01..2026-09-02"))


class TestSerialization(Base):
    def test_json_and_text_render(self):
        root = self.fully_instrumented()
        r = self.result(root, "alice", "core")
        text = render_text(r)
        self.assertIn("ANSWER", text)
        self.assertIn("EVIDENCE", text)
        self.assertIn("GAPS", text)
        payload = json.loads(render_json(r))
        self.assertEqual(payload["question_family"], "Core")
        self.assertIn("coverage", payload)
        self.assertIn("subject", payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
