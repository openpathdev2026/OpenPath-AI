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
import tracemalloc
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from openpath import router
from openpath.engine import Engine
from openpath.env import Env
from openpath.model.timerange import TimeRange, build_range
from openpath.render import render_json, render_text
from openpath.sources.auditd import AuditdCollector
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


class TestRootAttribution(Base):
    """Root activity must be attributed to *who became root* -- the base user who
    escalated -- except when someone logged in directly as root, and daemon/no-uid
    root activity must be disclosed as unattributable rather than blamed."""

    def _host(self) -> Path:
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001).passwd("bob", 1002)
        h.enable_execve().enable_network()
        h.boot(ago(hours=10))
        # alice escalates via sudo, runs a command as root
        h.sudo(1001, 1001, "/usr/bin/systemctl restart nginx", ago(hours=3, minutes=1))
        h.exec(1001, 0, ["systemctl", "restart", "nginx"], "/usr/bin/systemctl",
               ago(hours=3), euid=0, comm="systemctl")
        # someone logs in DIRECTLY as root over ssh (no base user to attribute to)
        h.ssh_accept("root", "203.0.113.9", ago(hours=2, minutes=1))
        h.login("root", ago(hours=2), line="pts/5", host="203.0.113.9",
                until=ago(hours=1))
        h.exec(0, 0, ["cat", "/etc/shadow"], "/usr/bin/cat",
               ago(hours=1, minutes=50), euid=0, comm="cat")
        # a daemon runs as root with NO login uid (unset auid)
        h.exec(4294967295, 0, ["logrotate"], "/usr/sbin/logrotate",
               ago(hours=1, minutes=30), euid=0, comm="logrotate")
        h.write()
        return root

    def _labels(self, finding):
        return "\n".join(finding.notes)

    def test_root_activity_for_root_is_attributed_breakdown(self):
        f = self.finding(self._host(), "root", "root_activity")
        labels = self._labels(f)
        # escalation attributed to the base user
        self.assertIn("alice (via sudo/su)", labels)
        # ssh-as-root attributed to the direct login + origin, not a base user
        self.assertIn("direct login from 203.0.113.9", labels)
        # daemon disclosed
        self.assertTrue(any(g.question == "Root activity" for g in f.gaps))

    def test_escalated_action_attributes_to_base_user_only(self):
        f = self.finding(self._host(), "alice", "root_activity")
        cmds = [e.attrs.get("cmdline") for e in f.events]
        self.assertIn("systemctl restart nginx", cmds)
        # alice must NOT be credited with the direct-root-login or daemon actions
        self.assertNotIn("cat /etc/shadow", cmds)
        self.assertNotIn("logrotate", cmds)

    def test_direct_root_login_reported_as_such(self):
        f = self.finding(self._host(), "root", "privilege")
        self.assertIn("directly", f.summary)
        self.assertIn("203.0.113.9", f.summary)

    def test_user_who_sshd_as_root_not_credited_as_base_user(self):
        # bob authenticated as root (root's credentials); there is no evidence
        # tying the human 'bob' to the root session -> honest negative for bob.
        f = self.finding(self._host(), "bob", "privilege")
        self.assertTrue(f.summary.startswith("No"))
        f_root = self.finding(self._host(), "bob", "root_activity")
        self.assertEqual(len(f_root.events), 0)

    def test_core_shows_who_exercised_root(self):
        f = self.finding(self._host(), "root", "core")
        note = "\n".join(f.notes)
        self.assertIn("Root attribution", note)
        self.assertIn("alice (via sudo/su)", note)

    def test_per_user_core_does_not_leak_host_root_attribution(self):
        # A non-root user's Core answer must not enumerate other principals' root
        # activity.
        f = self.finding(self._host(), "alice", "core")
        note = "\n".join(f.notes)
        self.assertNotIn("[Root attribution]", note)

    def test_unresolved_root_uid_is_disclosed_not_falsely_attributed(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve()
        h.boot(ago(hours=10))
        # A root action whose login uid (2000) maps to no account name.
        h.exec(2000, 0, ["mystery-root"], "/usr/bin/x", ago(hours=2), euid=0)
        h.write()
        f = self.finding(root, "root", "root_activity")
        # It must be disclosed as not attributable to a specific human...
        self.assertTrue(any(g.question == "Root activity" for g in f.gaps))
        # ...and never claimed as a confident named escalation.
        self.assertNotIn("via sudo/su", "\n".join(f.notes))


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


class TestMultiUserSweep(Base):
    """'For every user, track all that activity' -- the whole-host sweep."""

    def _host(self) -> Path:
        root = self.make_root()
        h = HostBuilder(root)
        (h.passwd("root", 0).passwd("alice", 1001).passwd("bob", 1002)
         .passwd("svc", 1600).passwd("nobody", 65534))
        h.enable_execve()
        h.boot(ago(hours=20))
        h.login("alice", ago(hours=3), host="203.0.113.7", until=ago(hours=1))
        h.exec(1001, 1001, ["vim"], "/usr/bin/vim", ago(hours=2))
        h.exec(1002, 1002, ["ls"], "/usr/bin/ls", ago(hours=4))
        h.write()
        return root

    def test_sweep_covers_every_local_user(self):
        collected = Engine().collect(self.env(self._host()), self.win())
        subjects = Engine().discover_subjects(collected)
        for u in ["root", "alice", "bob", "svc", "nobody"]:
            self.assertIn(u, subjects)

    def test_sweep_runs_facet_per_user_and_separates_active(self):
        results = Engine().analyze_all(self.env(self._host()), self.win(), "commands")
        by_user = {r.subject.username: r for r in results}
        # active users have their commands
        self.assertTrue(by_user["alice"].finding.events)
        self.assertTrue(by_user["bob"].finding.events)
        # an inactive account is an evidenced negative (no events), not a crash
        self.assertIn("nobody", by_user)
        self.assertEqual(len(by_user["nobody"].finding.events), 0)

    def test_evidence_only_login_uid_is_tracked(self):
        # A login uid with no account name (deleted user, no account records) must
        # still be discovered and its activity attributed -- the sweep is complete.
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve()
        h.boot(ago(hours=10))
        h.exec(2000, 2000, ["mystery"], "/usr/bin/mystery", ago(hours=2))
        h.write()
        collected = Engine().collect(self.env(root), self.win())
        subjects = Engine().discover_subjects(collected)
        self.assertIn("uid:2000", subjects)
        results = {r.subject.username: r
                   for r in Engine().analyze_all(self.env(root), self.win(), "commands")}
        self.assertIn("uid:2000", results)
        cmds = [e.attrs.get("cmdline") for e in results["uid:2000"].finding.events]
        self.assertIn("mystery", cmds)

    def test_sweep_does_not_cross_attribute(self):
        results = Engine().analyze_all(self.env(self._host()), self.win(), "commands")
        by_user = {r.subject.username: r for r in results}
        alice_cmds = {e.attrs.get("cmdline") for e in by_user["alice"].finding.events}
        bob_cmds = {e.attrs.get("cmdline") for e in by_user["bob"].finding.events}
        self.assertIn("vim", alice_cmds)
        self.assertNotIn("ls", alice_cmds)
        self.assertIn("ls", bob_cmds)
        self.assertNotIn("vim", bob_cmds)


class TestMultiArch(Base):
    """Syscalls must be decoded per the record's arch, so exec/network/file
    questions work on ARM64 hosts, not just x86-64."""

    def test_aarch64_exec_is_decoded(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve()
        h.boot(ago(hours=10))
        # execve on aarch64 is syscall 221, arch c00000b7 -- would be misread as a
        # different call under an x86-64-only table.
        h.exec(1001, 1001, ["deploy.sh"], "/usr/local/bin/deploy.sh",
               ago(hours=2), arch="aarch64")
        h.write()
        f = self.finding(root, "alice", "commands")
        self.assertEqual(len(f.events), 1)
        self.assertEqual(f.events[0].attrs.get("syscall"), "execve")
        self.assertIn("deploy.sh", f.events[0].attrs.get("cmdline", ""))


class TestStreaming(Base):
    """Large audit logs are streamed: memory stays bounded by the in-window result
    set, not by log size, and correctness is unaffected."""

    def test_large_audit_log_bounded_memory_and_correct(self):
        import os
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve()
        h.boot(ago(hours=40))
        # 8000 noise events well OUTSIDE the 24h window
        for i in range(8000):
            h.exec(1001, 1001, ["noise", str(i)], "/usr/bin/noise",
                   ago(hours=35, seconds=-(i % 3000)))
        # a couple INSIDE the window
        h.exec(1001, 1001, ["real-cmd-1"], "/usr/bin/a", ago(hours=2))
        h.exec(1001, 0, ["real-cmd-2"], "/usr/bin/b", ago(hours=1), euid=0)
        h.write()

        env = self.env(root)
        win = self.win()
        log_size = os.path.getsize(root / "var/log/audit/audit.log")
        tracemalloc.start()
        res = AuditdCollector().collect(env, win)
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # correctness: only the in-window events are returned
        cmds = sorted(e.attrs.get("cmdline") for e in res.events)
        self.assertEqual(cmds, ["real-cmd-1", "real-cmd-2"])
        self.assertGreaterEqual(res.coverage.record_count, 8000)
        # bounded memory, expressed relative to input size (robust across
        # interpreters/allocators): a materialize-everything parser holds Python
        # objects several times the file size; streaming keeps peak a fraction of
        # it. The multi-MB log must parse in well under one file's worth of memory.
        self.assertLess(peak, log_size,
                        f"peak {peak} >= log size {log_size}: not streaming")
        self.assertLess(peak, 2_000_000)  # absolute sanity ceiling

    def test_event_split_across_rotation_is_reunited(self):
        # An event whose records straddle a rotation boundary (SYSCALL in
        # audit.log.1, EXECVE/CWD at the head of audit.log) must still be
        # reconstructed -- the streaming grouper carries the group across files.
        from tests.conformance.fixtures import _epoch_msec
        root = self.make_root()
        (root / "var/log/audit").mkdir(parents=True)
        (root / "etc/audit").mkdir(parents=True)
        (root / "etc").joinpath("passwd").write_text(
            "root:x:0:0::/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n")
        (root / "etc/audit/audit.rules").write_text(
            "-a always,exit -F arch=b64 -S execve -k exec\n")
        aid = f"{_epoch_msec(ago(hours=2))}:9001"
        # older file ends with the SYSCALL record...
        (root / "var/log/audit/audit.log.1").write_text(
            f'type=SYSCALL msg=audit({aid}): arch=c000003e syscall=59 success=yes '
            f'auid=1001 uid=0 euid=0 tty=pts0 comm="dnf" exe="/usr/bin/dnf" key="exec"\n')
        # ...the current file begins with the rest of the SAME event.
        (root / "var/log/audit/audit.log").write_text(
            f'type=EXECVE msg=audit({aid}): argc=2 a0="dnf" a1="update"\n'
            f'type=CWD msg=audit({aid}): cwd="/root"\n')
        f = self.finding(root, "alice", "commands")
        self.assertEqual(len(f.events), 1)
        self.assertEqual(f.events[0].attrs.get("cmdline"), "dnf update")
        self.assertEqual(f.events[0].attrs.get("as_root"), True)


class TestFailedLogins(Base):
    """btmp failed-login attempts answer 'who tried and failed to log in as X,
    and from where' -- part of Login (family 4)."""

    def test_failed_attempts_surface_with_origin(self):
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001)
        h.login("alice", ago(hours=3), host="203.0.113.7", until=ago(hours=1))
        h.failed_login("alice", ago(hours=2, minutes=30), host="45.9.9.9")
        h.failed_login("alice", ago(hours=2, minutes=29), host="45.9.9.9")
        h.write()
        f = self.finding(root, "alice", "login")
        self.assertIn("2 failed attempt(s)", f.summary)
        self.assertIn("45.9.9.9", f.summary)

    def test_failed_attempts_for_never_existed_user(self):
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0)
        h.failed_login("admin", ago(hours=2), host="185.1.1.1")
        h.failed_login("admin", ago(hours=1), host="185.1.1.1")
        h.write()
        r = self.result(root, "admin", "login")
        self.assertFalse(r.subject.exists_now)
        self.assertIn("2 failed attempt(s)", r.finding.summary)

    def test_btmp_only_host_reports_failures_but_discloses_success_gap(self):
        # No wtmp, no auditd, no auth.log -- only btmp exists. btmp evidences
        # FAILURES only, so successful logins cannot be confirmed (a gap), yet the
        # failed attempts are still reported.
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("bob", 1002)
        h.failed_login("bob", ago(hours=2), host="10.0.0.5")
        h.write()
        f = self.finding(root, "bob", "login")
        self.assertTrue(any(g.question == "Login" for g in f.gaps))  # can't confirm success
        self.assertIn("failed attempt", f.summary)
        self.assertIn("10.0.0.5", f.summary)

    def test_failed_ssh_not_double_counted_across_btmp_and_authlog(self):
        # The same failed SSH login is in btmp AND auth.log; count it once.
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001)
        h.login("alice", ago(hours=3), host="10.0.0.2", until=ago(hours=1))  # wtmp
        h.auth_ssh_fail("alice", "45.9.9.9", ago(hours=2))       # auth.log failure
        h.failed_login("alice", ago(hours=2), host="45.9.9.9")   # same, in btmp
        h.write()
        f = self.finding(root, "alice", "login")
        self.assertIn("1 failed attempt(s)", f.summary)
        # the successful-login origin is not polluted by the failed source
        self.assertNotIn("45.9.9.9;", f.summary.split("failed")[0])


class TestSyslogAuth(Base):
    """Debian/Ubuntu hosts without auditd: sudo/ssh/su/account events from
    /var/log/auth.log make Privilege, Login, Accounts, and sudo-Commands
    answerable -- with honest disclosure of what syslog does not capture."""

    def _debian_host(self) -> Path:
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001).passwd("bob", 1002)
        h.boot(ago(hours=20))
        h.login("alice", ago(hours=3), host="203.0.113.7", until=ago(hours=1))
        h.auth_ssh_accept("alice", "203.0.113.7", ago(hours=3, minutes=1))
        h.auth_sudo("alice", "/usr/bin/apt install -y nginx", ago(hours=2, minutes=40))
        h.dpkg("install", "nginx:amd64", "<none>", "1.24.0-1", ago(hours=2, minutes=39))
        h.auth_sudo("alice", "/usr/sbin/useradd deploybot", ago(hours=2, minutes=10))
        h.auth_useradd("deploybot", 1500, ago(hours=2, minutes=9))
        h.auth_su("bob", ago(hours=1, minutes=30))
        h.write()
        return root

    def test_privilege_from_sudo_and_su(self):
        root = self._debian_host()
        pa = self.finding(root, "alice", "privilege")
        self.assertTrue(pa.summary.startswith("Yes"))
        # discloses that full (non-sudo) command visibility needs auditd
        self.assertTrue(any(g.question == "Privilege" for g in pa.gaps))
        pb = self.finding(root, "bob", "privilege")
        self.assertTrue(pb.summary.startswith("Yes"))  # via su

    def test_commands_partial_and_disclosed(self):
        root = self._debian_host()
        f = self.finding(root, "alice", "commands")
        cmds = [e.attrs.get("cmdline") for e in f.events]
        self.assertIn("/usr/bin/apt install -y nginx", cmds)
        self.assertTrue(any("sudo" in g.reason for g in f.gaps))  # partial disclosed

    def test_login_from_wtmp_and_auth(self):
        root = self._debian_host()
        f = self.finding(root, "alice", "login")
        self.assertIn("203.0.113.7", f.summary)
        self.assertEqual([g for g in f.gaps if g.question == "Login"], [])

    def test_accounts_attributed_via_sudo_admin_command(self):
        root = self._debian_host()
        f = self.finding(root, "alice", "accounts")
        joined = f.summary + " " + " ".join(f.notes)
        self.assertIn("useradd deploybot", joined)

    def test_packages_attributed_via_auth_sudo(self):
        root = self._debian_host()
        f = self.finding(root, "alice", "packages")
        self.assertEqual(len(f.events), 1)
        self.assertIn("nginx", f.events[0].summary)

    def test_files_and_network_still_disclosed_absent(self):
        root = self._debian_host()
        for facet in ("files", "network"):
            f = self.finding(root, "alice", facet)
            self.assertEqual(len(f.events), 0)
            self.assertTrue(f.gaps)  # auditd genuinely required for these

    def test_login_from_auth_only_without_wtmp(self):
        # A host with no wtmp but an sshd auth record still answers Login.
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001)
        h.auth_ssh_accept("alice", "198.51.100.7", ago(hours=2))
        h.write()
        f = self.finding(root, "alice", "login")
        self.assertIn("198.51.100.7", f.summary)
        self.assertGreaterEqual(len(f.events), 1)

    def test_denied_sudo_is_not_a_successful_escalation(self):
        # A denied sudo line carries COMMAND= but must never read as success.
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("mallory", 1005)
        h.auth_sudo_fail("mallory", ago(hours=2))
        h.write()
        pr = self.finding(root, "mallory", "privilege")
        self.assertFalse(pr.summary.startswith("Yes"))
        # and no root command is attributed to a denied attempt
        self.assertEqual(len(self.finding(root, "mallory", "commands").events), 0)

    def test_pam_auth_failure_line_does_not_create_garbage_actor(self):
        root = self.make_root()
        (root / "var/log").mkdir(parents=True)
        stamp = ago(hours=2).strftime("%b ") + f"{ago(hours=2).day:2d}" \
            + ago(hours=2).strftime(" %H:%M:%S")
        (root / "var/log/auth.log").write_text(
            f"{stamp} host sudo: pam_unix(sudo:auth): authentication failure; "
            f"logname=alice uid=1001 euid=0 tty=/dev/pts/0 ruser=alice user=alice\n")
        (root / "etc").mkdir(parents=True)
        (root / "etc/passwd").write_text("alice:x:1001:1001::/home/alice:/bin/bash\n")
        collected = Engine().collect(Env(data_root=root, now=NOW, local_tz=timezone.utc),
                                     self.win())
        for e in collected.events:
            self.assertNotIn("(", e.actor_name or "")

    def test_legacy_su_plus_form_is_captured(self):
        root = self.make_root()
        (root / "var/log").mkdir(parents=True)
        t = ago(hours=2)
        stamp = t.strftime("%b ") + f"{t.day:2d}" + t.strftime(" %H:%M:%S")
        (root / "var/log/auth.log").write_text(
            f"{stamp} host su: + pts/1 alice:root\n")
        (root / "etc").mkdir(parents=True)
        (root / "etc/passwd").write_text("alice:x:1001:1001::/home/alice:/bin/bash\n")
        f = self.finding(root, "alice", "privilege")
        self.assertTrue(f.summary.startswith("Yes"))

    def test_login_deduped_across_journal_and_auth(self):
        # No wtmp; the same login is in both the journal export and auth.log.
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001)
        h.ssh_accept("alice", "203.0.113.7", ago(hours=2))           # journal
        h.auth_ssh_accept("alice", "203.0.113.7", ago(hours=2))       # auth.log
        h.write()
        f = self.finding(root, "alice", "login")
        self.assertIn("logged in 1 time(s)", f.summary)

    def test_no_double_count_when_auditd_and_auth_both_present(self):
        root = self.make_root()
        h = HostBuilder(root)  # auditd present
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve()
        h.boot(ago(hours=10))
        h.sudo(1001, 1001, "/usr/bin/dnf install nginx", ago(hours=2))
        h.exec(1001, 0, ["dnf", "install", "nginx"], "/usr/bin/dnf",
               ago(hours=2), euid=0, comm="dnf")
        h.auth_sudo("alice", "/usr/bin/dnf install nginx", ago(hours=2))
        h.write()
        f = self.finding(root, "alice", "commands")
        # auditd is authoritative; the auth-log duplicate is dropped.
        self.assertEqual(len(f.events), 1)
        self.assertEqual(f.events[0].source_id, "auditd")


class TestSerialization(Base):
    def test_json_and_text_render(self):
        root = self.fully_instrumented()
        # Core is an overview: ANSWER + DETAIL + GAPS.
        core = render_text(self.result(root, "alice", "core"))
        self.assertIn("ANSWER", core)
        self.assertIn("GAPS", core)
        # An activity facet narrates and cites by object.
        tl = render_text(self.result(root, "alice", "timeline"))
        self.assertIn("WHAT HAPPENED", tl)
        self.assertIn("EVIDENCE", tl)
        payload = json.loads(render_json(self.result(root, "alice", "core")))
        self.assertEqual(payload["question_family"], "Core")
        self.assertIn("coverage", payload)
        self.assertIn("subject", payload)
        self.assertIn("narrative", payload)


class TestNarration(Base):
    """Activity is narrated in flowing sentences that name the object acted
    against, with each claim tied to its evidence."""

    def test_timeline_narrative_names_objects(self):
        root = self.fully_instrumented()
        text = render_text(self.result(root, "alice", "timeline"))
        self.assertIn("WHAT HAPPENED", text)
        # objects appear in the prose
        self.assertIn("the file `/etc/hosts`", text)
        self.assertIn("the account `deploybot`", text)
        self.assertIn("93.184.216.34:443", text)
        # evidence is keyed by the object acted against
        self.assertIn("file: /etc/hosts", text)
        self.assertIn("account: deploybot", text)

    def test_event_target_is_the_acted_on_object(self):
        root = self.fully_instrumented()
        f = self.finding(root, "alice", "files")
        kind, obj = f.events[0].target()
        self.assertEqual(kind, "file")
        self.assertEqual(obj, "/etc/hosts")
        # ...and it is surfaced in JSON for a client to track
        d = f.events[0].to_dict()
        self.assertEqual(d["target_kind"], "file")
        self.assertEqual(d["target"], "/etc/hosts")

    def test_root_activity_narrative_attributes_each_action(self):
        root = TestRootAttribution._host(self)
        text = render_text(self.result(root, "root", "root_activity"))
        self.assertIn("via sudo/su", text)                 # escalation → base user
        self.assertIn("via a direct root login from 203.0.113.9", text)
        self.assertIn("evidence".upper(), text)  # EVIDENCE section present

    def test_json_evidence_carries_object(self):
        root = self.fully_instrumented()
        payload = json.loads(render_json(self.result(root, "alice", "timeline")))
        self.assertTrue(payload["evidence"])
        objs = {(e["object_kind"], e["object"]) for e in payload["evidence"]}
        self.assertIn(("file", "/etc/hosts"), objs)
        for e in payload["evidence"]:
            self.assertTrue(e["records"])  # every evidence item has raw records

    def test_evidence_facet_text_lists_object_keyed_evidence(self):
        # The Evidence question (family 12) must render its evidence in text, keyed
        # by object -- not be dropped by the overview gate.
        root = self.fully_instrumented()
        text = render_text(self.result(root, "alice", "evidence"))
        self.assertIn("EVIDENCE", text)
        self.assertIn("file: /etc/hosts", text)
        self.assertNotIn("WHAT HAPPENED", text)  # evidence is the answer, not prose

    def test_overview_facets_have_no_per_event_narrative_in_json(self):
        # Core/Gaps keep a structured overview; JSON must match the text contract.
        root = self.fully_instrumented()
        for facet in ("core", "gaps"):
            payload = json.loads(render_json(self.result(root, "alice", facet)))
            self.assertEqual(payload["narrative"], [])
            self.assertEqual(payload["evidence"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
