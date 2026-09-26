"""Product-readiness conformance suite.

This is the baseline the product must never regress below: for *any* user and
*any* time range, every question in the frozen catalog (`openpath/catalog.py`)
must answer soundly (every claim cited) and disclose every gap (never a false
"nothing happened"). The scenarios below deliberately include the cases that
break naive implementations:

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
from openpath.catalog import CATALOG
from openpath.engine import Engine
from openpath.env import Env
from openpath.model.timerange import TimeRange, build_range
from openpath.render import render_json, render_text
from openpath.sources.auditd import AuditdCollector
from tests.conformance.fixtures import HostBuilder

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

    def cli(self, *argv):
        """Run the product exactly as a user would: through ``main`` (the shipped
        path), with ``now`` pinned. Returns (exit_code, stdout)."""
        import contextlib
        import io
        from openpath.cli import main
        args = list(argv) + ["--now", NOW.isoformat()]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(args)
        return rc, buf.getvalue()

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
        accts = {e.attrs.get("acct") for e in self.finding(self.root, "alice", "accounts").events}
        self.assertIn("deploybot", accts)
        grps = {e.attrs.get("grp") for e in self.finding(self.root, "alice", "groups").events}
        self.assertIn("deploygrp", grps)

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
        # No *coverage* gaps on a fully instrumented host...
        coverage_gaps = [g for g in f.gaps if g.question != "scope"]
        self.assertEqual(coverage_gaps, [],
                         f"unexpected coverage gaps: {[g.reason for g in coverage_gaps]}")
        # ...but the standing unmodeled-source disclosures are always present, so
        # Gaps never implies the six modeled sources are the whole picture.
        self.assertTrue(any(g.question == "scope" for g in f.gaps))

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
        self.assertEqual([g for g in f.gaps if g.question == "Accounts"], [])

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


class TestRootSessionChain(Base):
    """Flagship correctness guarantee: when a human SSHes in and `sudo su`s to
    root, everything they do as root (kernel auid=<human>, uid=0) is attributed
    to the human -- "What did aclaye do?" includes their root actions."""

    def _host(self) -> Path:
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("aclaye", 1001)
        h.enable_execve().enable_file_syscalls().watch("/etc", "wa", "etc")
        h.boot(ago(hours=6))
        h.auth_ssh_accept("aclaye", "1.2.3.4", ago(hours=3))
        h.login("aclaye", ago(hours=3), line="pts/0", host="1.2.3.4",
                until=ago(hours=2, minutes=50))
        h.sudo(1001, 1001, "/bin/su -", ago(hours=2, minutes=59))
        # As root, auid stays 1001 -- the kernel still knows it is aclaye.
        h.exec(1001, 0, ["useradd", "bob"], "/usr/sbin/useradd",
               ago(hours=2, minutes=58), euid=0, comm="useradd")
        h.add_user(1001, "bob", 1600, ago(hours=2, minutes=58))
        h.exec(1001, 0, ["chmod", "600", "/etc/shadow"], "/usr/bin/chmod",
               ago(hours=2, minutes=57), euid=0, comm="chmod")
        h.file_change(1001, 0, "chmod", "/etc/shadow", ago(hours=2, minutes=57),
                      euid=0, key="etc")
        h.exec(1001, 0, ["vim", "/etc/hosts"], "/usr/bin/vim",
               ago(hours=2, minutes=56), euid=0, comm="vim")
        h.file_change(1001, 0, "openat", "/etc/hosts", ago(hours=2, minutes=56),
                      euid=0, key="etc")
        h.write()
        return root

    def test_root_actions_attributed_to_the_human(self):
        root = self._host()
        cmds = [e.attrs.get("cmdline") for e in self.finding(root, "aclaye", "commands").events]
        self.assertIn("useradd bob", cmds)
        self.assertIn("chmod 600 /etc/shadow", cmds)
        self.assertIn("vim /etc/hosts", cmds)
        accts = {e.attrs.get("acct") for e in self.finding(root, "aclaye", "accounts").events}
        self.assertIn("bob", accts)
        paths = {e.attrs.get("path") for e in self.finding(root, "aclaye", "files").events}
        self.assertEqual({"/etc/shadow", "/etc/hosts"}, paths)
        self.assertTrue(self.finding(root, "aclaye", "privilege").summary.startswith("Yes"))

    def test_narrative_states_the_human_did_it_as_root(self):
        root = self._host()
        text = render_text(self.result(root, "aclaye", "timeline"))
        self.assertIn("aclaye created the account `bob` (uid 1600) as root", text)
        self.assertIn("aclaye changed permissions on the file `/etc/shadow` as root", text)
        # mechanical narration -- no speculation
        for weasel in ("appears", "likely", "probably", "seems", "may have"):
            self.assertNotIn(weasel, text.lower())


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
        # The frozen catalog is the contract: every question routes to its facet
        # and its subject is extracted, for arbitrary usernames.
        for cq in CATALOG:
            for user in self.USERNAMES:
                q = cq.text.format(user=user)
                self.assertEqual(
                    router.route(q), cq.facet,
                    f"routing wrong for {cq.id} {q!r}: expected {cq.facet}")
                self.assertEqual(
                    router.extract_user(q), user,
                    f"user extraction wrong for {cq.id} {q!r}: expected {user}")

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


class TestReadiness(Base):
    """The host readiness self-check reports which questions are answerable."""

    def _rd(self, root):
        return Engine().readiness(self.env(root), self.win())

    def _by_label(self, report):
        return {fr.label: fr.answerable for fr in report.families}

    def test_fully_instrumented_answers_all(self):
        report = self._rd(self.fully_instrumented())
        # all substantive data questions answerable (aggregates not counted)
        self.assertEqual(report.answerable, report.data_total)
        self.assertEqual(report.data_total, 10)

    def test_debian_host_blind_on_files_and_network_only(self):
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001)
        h.boot(ago(hours=10))
        h.login("alice", ago(hours=3), host="10.0.0.5", until=ago(hours=1))
        h.auth_sudo("alice", "/usr/bin/apt update", ago(hours=2))
        h.write()
        by = self._by_label(self._rd(root))
        self.assertFalse(by["Files"])
        self.assertFalse(by["Network"])
        self.assertTrue(by["Privilege"])
        self.assertTrue(by["Login"])
        self.assertTrue(by["Accounts"])
        self.assertTrue(by["Groups"])

    def test_bare_host_only_aggregates_answerable(self):
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0)
        h.write()
        by = self._by_label(self._rd(root))
        self.assertTrue(by["Core"])       # aggregates -- always runs
        self.assertTrue(by["Gaps"])
        self.assertFalse(by["Files"])
        self.assertFalse(by["Commands"])

    def test_report_has_remedies_for_blind_families(self):
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0)
        h.write()
        report = self._rd(root)
        blind = [fr for fr in report.families if not fr.answerable]
        self.assertTrue(blind)
        # at least one blind family carries an actionable remedy
        self.assertTrue(any(g.remedy for fr in blind for g in fr.gaps))


class TestEvidenceConservation(Base):
    """Gate 1: no parser may drop a record it read without disclosing it.

    Every assertion runs through the shipped CLI (`main`), not an internal
    function, so the guarantee is proven on the product path. The pass condition
    is literally "0 silent loss": records_in == events_out + unparseable, and any
    non-zero ``unparseable`` is surfaced as a conservation gap.
    """

    def test_clean_host_reports_zero_silent_loss(self):
        root = self.fully_instrumented()
        rc, out = self.cli("--coverage", "--data-root", str(root))
        self.assertEqual(rc, 0)
        self.assertIn("EVIDENCE CONSERVATION", out)
        self.assertIn("0 silent loss", out)
        self.assertNotIn("CONSERVATION:", out)  # no per-source '!' warning line

    def test_clean_host_json_has_no_conservation_gap(self):
        root = self.fully_instrumented()
        rc, out = self.cli("--coverage", "--format", "json", "--data-root", str(root))
        data = json.loads(out)
        for s in data["coverage"]["sources"]:
            self.assertEqual(s["unparseable"], 0,
                             f"{s['source_id']} dropped {s['unparseable']} record(s)")
        cons = [g for g in data["coverage"]["gaps"] if g["question"] == "conservation"]
        self.assertEqual(cons, [])

    def test_truncated_wtmp_tail_is_disclosed(self):
        root = self.fully_instrumented()
        # Append a partial (< 384-byte) record: exactly what a truncated/corrupt
        # binary log looks like, and what integer-division parsing would drop.
        with open(root / "var/log/wtmp", "ab") as fh:
            fh.write(b"\x07\x00\x00\x00partial-truncated-record")
        rc, out = self.cli("--coverage", "--data-root", str(root))
        self.assertIn("FAIL", out)
        self.assertIn("wtmp", out)
        self.assertIn("truncated tail", out)
        # And it must be a real disclosed gap in the structured output.
        _rc, jout = self.cli("--coverage", "--format", "json", "--data-root", str(root))
        gaps = [g for g in json.loads(jout)["coverage"]["gaps"]
                if g["question"] == "conservation"]
        self.assertTrue(gaps and any("wtmp" in g["reason"] for g in gaps))

    def test_unparseable_package_line_is_counted_not_dropped(self):
        root = self.fully_instrumented()
        # A genuine transaction line (matches the Installed: shape) whose timestamp
        # cannot be parsed -- previously dropped silently by `except ValueError`.
        with open(root / "var/log/dnf.rpm.log", "a") as fh:
            fh.write("NOT-A-TIMESTAMP INFO Installed: ghostpkg-1.0-1.fc40.x86_64\n")
        rc, out = self.cli("--coverage", "--format", "json", "--data-root", str(root))
        pkg = [s for s in json.loads(out)["coverage"]["sources"]
               if s["source_id"] == "packages"][0]
        self.assertEqual(pkg["unparseable"], 1)

    def test_malformed_journal_line_is_counted(self):
        root = self.fully_instrumented()
        with open(root / "var/log/openpath/journal-sshd.jsonl", "a") as fh:
            fh.write("{ this is not valid json\n")
        rc, out = self.cli("--coverage", "--format", "json", "--data-root", str(root))
        j = [s for s in json.loads(out)["coverage"]["sources"]
             if s["source_id"] == "journal.sshd"][0]
        self.assertEqual(j["unparseable"], 1)

    def test_large_result_is_capped_in_text_but_complete_in_json(self):
        """The narration cap must not be silent loss: text discloses the overflow
        and JSON carries every event, so the 'full detail in --format json' promise
        is true."""
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve()
        h.boot(ago(hours=20))
        n = 75  # more than the 60-event narration cap
        for i in range(n):
            h.exec(1001, 1001, ["do-thing", str(i)], "/usr/bin/do-thing",
                   ago(hours=5, minutes=i), comm="do-thing")
        h.write()

        _rc, text = self.cli("--user", "alice", "--facet", "commands",
                             "--data-root", str(root))
        self.assertIn("further event(s) not narrated", text)  # overflow disclosed

        _rc, jout = self.cli("--user", "alice", "--facet", "commands",
                             "--format", "json", "--data-root", str(root))
        data = json.loads(jout)
        # JSON is complete: every command is both an event and a cited evidence entry.
        self.assertEqual(len(data["finding"]["events"]), n)
        self.assertEqual(len(data["evidence"]), n)
        self.assertIsNone(data["narrative_overflow"])


class TestFederatedEvidence(Base):
    """The resilience property: still answer (and say what was lost) when a source
    disappears; and the confidence label never contradicts the finding."""

    from openpath.model.evidence_matrix import Confidence as _C

    # -- fixtures -- #
    def _full(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve().enable_network().enable_file_syscalls().watch("/etc", "wa", "etc")
        h.boot(ago(hours=20))
        h.ssh_accept("alice", "203.0.113.7", ago(hours=3, minutes=1))
        h.login("alice", ago(hours=3), host="203.0.113.7", until=ago(hours=1))
        h.sudo(1001, 1001, "/usr/bin/dnf install -y nginx", ago(hours=2))
        h.exec(1001, 0, ["dnf", "install", "nginx"], "/usr/bin/dnf", ago(hours=2), euid=0)
        h.connect(1001, 0, "10.0.0.9", 443, ago(hours=2))
        h.bind(1001, 0, "0.0.0.0", 80, ago(hours=2))
        h.file_change(1001, 0, "chmod", "/etc/shadow", ago(hours=2), key="etc")
        h.pkg("Installed", "nginx-1.24.0-1.fc40.x86_64", ago(hours=2))
        h.add_user(1001, "bob", 1600, ago(hours=2))
        h.write()
        return root

    def _conf(self, root, user, facet):
        return self.finding(root, user, facet).confidence

    def test_full_host_all_certified(self):
        root = self._full()
        for facet in ["login", "sessions", "privilege", "commands", "files",
                      "network", "accounts", "groups", "packages", "core"]:
            self.assertIs(self._conf(root, "alice", facet), self._C.CERTIFIED, facet)

    def test_dropping_wtmp_keeps_login_certified_and_core_certified(self):
        """The motivating case: wtmp is supporting, not primary, for login/core."""
        root = self._full()
        (root / "var/log/wtmp").unlink()
        self.assertIs(self._conf(root, "alice", "login"), self._C.CERTIFIED)
        # Sessions is genuinely wtmp-only (interval durations) -> unanswerable.
        self.assertIs(self._conf(root, "alice", "sessions"), self._C.UNANSWERABLE)
        # ...but the overview still stands, and names the blind slice.
        core = self.finding(root, "alice", "core")
        self.assertIs(core.confidence, self._C.CERTIFIED)
        self.assertIn("Sessions", core.confidence_note)

    def test_auth_only_host_degrades_but_still_answers(self):
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001)
        h.boot(ago(hours=20))
        h.login("alice", ago(hours=3), host="10.0.0.5", until=ago(hours=1))
        h.auth_ssh_accept("alice", "10.0.0.5", ago(hours=3))
        h.auth_sudo("alice", "/usr/bin/systemctl restart nginx", ago(hours=2))
        h.auth_useradd("bob", 1600, ago(hours=2))
        h.write()
        self.assertIs(self._conf(root, "alice", "login"), self._C.CERTIFIED)
        # Privilege: the sudo/su escalation is a certified fact, but without auditd
        # the full extent of root activity (and non-PAM privilege gains) can't be
        # confirmed -- the facet discloses that, so the honest label is PARTIAL.
        self.assertIs(self._conf(root, "alice", "privilege"), self._C.PARTIAL)
        self.assertIs(self._conf(root, "alice", "commands"), self._C.PARTIAL)
        self.assertIs(self._conf(root, "alice", "root_activity"), self._C.PARTIAL)
        self.assertIs(self._conf(root, "alice", "accounts"), self._C.PARTIAL)
        self.assertIs(self._conf(root, "alice", "files"), self._C.UNANSWERABLE)
        self.assertIs(self._conf(root, "alice", "network"), self._C.UNANSWERABLE)
        self.assertIs(self._conf(root, "alice", "core"), self._C.CERTIFIED)

    def test_narrow_watch_downgrades_files_to_partial(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve().watch("/etc", "wa", "etc")  # NO write-syscall rule
        h.file_change(1001, 0, "chmod", "/etc/shadow", ago(hours=2), key="etc")
        h.write()
        self.assertIs(self._conf(root, "alice", "files"), self._C.PARTIAL)

    def test_connect_only_downgrades_network_to_partial(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h._rules.append("-a always,exit -F arch=b64 -S connect -k net")  # no bind
        h.connect(1001, 0, "10.0.0.9", 443, ago(hours=2))
        h.write()
        self.assertIs(self._conf(root, "alice", "network"), self._C.PARTIAL)

    def test_narrow_watch_zero_events_partial_with_real_gap(self):
        """Review finding #1: a narrow watch + zero file changes must not be a
        bare 'no file changes' certified negative -- it is PARTIAL, backed by a real
        Files gap, and the render never claims completeness."""
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve().watch("/etc", "wa", "etc")  # narrow, no write-syscall rule
        h.write()  # alice makes NO file changes
        f = self.finding(root, "alice", "files")
        self.assertEqual(f.events, [])
        self.assertIs(f.confidence, self._C.PARTIAL)
        self.assertTrue(any(g.question == "Files" for g in f.gaps),
                        "narrow-watch negative must disclose a real Files gap")
        text = render_text(self.result(root, "alice", "files"))
        self.assertNotIn("fully substantiated and complete", text)

    def test_connect_only_zero_events_partial_with_real_gap(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h._rules.append("-a always,exit -F arch=b64 -S connect -k net")  # no bind
        h.write()  # no network events
        f = self.finding(root, "alice", "network")
        self.assertEqual(f.events, [])
        self.assertIs(f.confidence, self._C.PARTIAL)
        self.assertTrue(any(g.question == "Network" for g in f.gaps))

    def test_conservation_loss_on_consumed_source_degrades(self):
        """Review finding #2: a source that FEEDS the finding's events but dropped
        undecodable records degrades confidence, even if it isn't the winner."""
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0)
        h.enable_execve()  # auditd is the clean winning source for privilege
        h.boot(ago(hours=20))
        h.login("root", ago(hours=3), host="198.51.100.5", until=ago(hours=1))
        h.write()
        with open(root / "var/log/wtmp", "ab") as fh:  # corrupt wtmp tail
            fh.write(b"\x07\x00truncated-tail")
        f = self.finding(root, "root", "privilege")
        self.assertTrue(f.events)  # direct root login came from wtmp
        self.assertIsNot(f.confidence, self._C.CERTIFIED,
                         "a consumed source that dropped records must degrade")

    def test_packages_auth_only_is_partial_with_gap(self):
        """Review finding #3: auth only witnesses sudo-invoked package managers, so
        packages+auth is PARTIAL (not CERTIFIED), backed by a disclosed gap."""
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001)
        h.auth_sudo("alice", "/usr/bin/dnf install -y nginx", ago(hours=2))
        h.pkg("Installed", "nginx-1.24.0-1.fc40.x86_64", ago(hours=2))
        h.write()
        f = self.finding(root, "alice", "packages")
        self.assertIs(f.confidence, self._C.PARTIAL)
        self.assertTrue(any(g.question == "Packages" for g in f.gaps))

    def test_root_activity_execve_only_is_partial(self):
        """Catalog-build review (Q06): 'what did {user} do as root' must not be
        CERTIFIED when only command auditing is on -- root file/network actions
        would be silently unseen. Requires execve + file + network to certify."""
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve()  # execve only; no file/network rules
        h.sudo(1001, 1001, "/usr/bin/vi /etc/hosts", ago(hours=2))
        h.exec(1001, 0, ["vi", "/etc/hosts"], "/usr/bin/vi", ago(hours=2), euid=0)
        h.write()
        f = self.finding(root, "alice", "root_activity")
        self.assertIs(f.confidence, self._C.PARTIAL)
        self.assertTrue(any(g.question == "Root activity" for g in f.gaps))

    def test_wtmp_only_direct_root_login_is_not_unanswerable(self):
        """The invariant: a determined, cited finding is never UNANSWERABLE, even
        though Q05's certified sources (auditd/auth) are both absent."""
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0)
        h.boot(ago(hours=20))
        h.login("root", ago(hours=3), host="198.51.100.5", until=ago(hours=1))
        h.write()
        f = self.finding(root, "root", "privilege")
        self.assertTrue(f.events)  # the direct root login is visible in wtmp
        self.assertIsNot(f.confidence, self._C.UNANSWERABLE)


class TestConfidenceInvariants(Base):
    """Cross-checks that the confidence label agrees with the finding it labels."""

    from openpath.model.evidence_matrix import Confidence as _C

    def _hosts(self):
        # A spread of instrumentation states.
        full = TestFederatedEvidence._full(self)
        auth = self.make_root()
        h = HostBuilder(auth).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001).boot(ago(hours=20))
        h.login("alice", ago(hours=3), host="10.0.0.5", until=ago(hours=1))
        h.auth_sudo("alice", "/bin/systemctl restart x", ago(hours=2))
        h.write()
        bare = self.make_root()
        HostBuilder(bare).passwd("root", 0).passwd("alice", 1001).write()
        return [full, auth, bare]

    def test_label_never_contradicts_finding(self):
        facets = ["login", "sessions", "privilege", "commands", "files", "network",
                  "accounts", "groups", "packages", "core", "timeline",
                  "evidence", "gaps"]
        for root in self._hosts():
            for user in ("alice", "root"):
                for facet in facets:
                    f = self.finding(root, user, facet)
                    self.assertIsNotNone(f.confidence, f"{facet}: no confidence set")
                    # (a) determined, cited events => never UNANSWERABLE.
                    if f.events and f.citations():
                        self.assertIsNot(
                            f.confidence, self._C.UNANSWERABLE,
                            f"{facet}/{user}: cited events but UNANSWERABLE")
                    # (b) UNANSWERABLE must carry a blocking gap and assert nothing.
                    if f.confidence is self._C.UNANSWERABLE:
                        self.assertTrue(f.gaps, f"{facet}/{user}: UNANSWERABLE w/o gap")
                        self.assertEqual(f.events, [],
                                         f"{facet}/{user}: UNANSWERABLE with events")


class TestSpecConsistency(Base):
    """The catalog EvidenceSpec and the facet requirements cannot drift."""

    def _req_sources(self, reqs):
        from openpath.facets.base import AnyOf
        out = set()
        for r in reqs:
            if isinstance(r, AnyOf):
                out |= {sid for (sid, _i) in r.options}
            else:
                out.add(r.source_id)
        return out

    def test_answerability_matches_facet_requirements(self):
        from openpath.catalog import spec_for_facet
        from openpath.facets import FAMILIES
        from openpath.engine import _AGGREGATE_FACETS
        for spec in FAMILIES:
            if spec.name in _AGGREGATE_FACETS:
                continue
            espec = spec_for_facet(spec.name)
            self.assertIsNotNone(espec, spec.name)
            facet = spec.cls()
            self.assertEqual(
                set(espec.answerability_sources()),
                self._req_sources(getattr(facet, "requirements", ())),
                f"{spec.name}: spec answerability set != facet requirement sources")

    def test_aggregate_derived_from_matches_data_facets(self):
        """Review finding #4: derived_from must name exactly the data facets the
        aggregates federate, so the declared contract can't drift from behavior."""
        from openpath.catalog import spec_for_facet, _DATA_FACETS
        from openpath.facets.meta import _base_facets
        base_names = tuple(f.name for f in _base_facets())
        self.assertEqual(base_names, _DATA_FACETS)
        for agg in ("core", "timeline", "evidence"):
            self.assertEqual(spec_for_facet(agg).derived_from, _DATA_FACETS, agg)


class TestQueryLayer(Base):
    """The deterministic query/filter/pivot layer, exercised through the CLI.

    These are the certification tests for the projection questions: they prove
    provenance (every returned fact is cited), correct auid-centric attribution
    (no wrong-user / no cross-session contamination), honest scoped negatives
    (never an absolute claim, never a false negative on an un-instrumented host),
    inherited confidence/gaps, and the host-wide + unattributable pivots.
    """

    def _q(self, root, *argv):
        rc, out = self.cli("--data-root", str(root), "--format", "json", *argv)
        self.assertEqual(rc, 0, out)
        return json.loads(out)

    def _busy_host(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001).passwd("bob", 1002)
        h.enable_execve().enable_network().enable_file_syscalls().watch("/etc", "wa", "etc")
        # alice: delete an account, chmod /etc/shadow, run curl (non-sudo), connect out
        h.del_user(1001, "olduser", 1500, ago(hours=3))
        h.file_change(1001, 0, "chmod", "/etc/shadow", ago(hours=3), key="etc")
        h.exec(1001, 1001, ["curl", "http://x"], "/usr/bin/curl", ago(hours=3), comm="curl")
        h.connect(1001, 1001, "10.0.0.9", 443, ago(hours=3))
        # bob: run a different command, change a file under /home
        h.exec(1002, 1002, ["python", "app.py"], "/usr/bin/python", ago(hours=2), comm="python")
        h.file_change(1002, 1002, "creat", "/home/bob/app.py", ago(hours=2))
        # a daemon (unset loginuid) file change -> unattributable
        h.file_change(4294967295, 0, "creat", "/var/run/x.pid", ago(hours=1))
        h.write()
        return root

    def test_action_filter_positive_is_cited(self):
        d = self._q(self._busy_host(), "--facet", "accounts", "--user", "alice",
                    "--action", "del_user")
        self.assertEqual(d["finding"]["confidence"], "certified")
        self.assertTrue(d["evidence"], "a positive result must carry evidence")
        self.assertTrue(all(e["records"] for e in d["evidence"]), "provenance lost")
        self.assertTrue(any("olduser" in e["object"] for e in d["evidence"]))

    def test_scoped_negative_is_not_absolute(self):
        d = self._q(self._busy_host(), "--facet", "accounts", "--user", "bob",
                    "--action", "del_user")
        self.assertEqual(d["finding"]["events"], [])
        # An evidenced negative -- scoped, never absolute.
        self.assertIn("within the covered evidence scope", d["finding"]["summary"])
        self.assertNotIn("did not", d["finding"]["summary"].lower())

    def test_wrong_user_isolation(self):
        root = self._busy_host()
        # bob did not run curl; alice did. bob's filtered query must be empty.
        db = self._q(root, "--facet", "commands", "--user", "bob", "--contains", "curl")
        self.assertEqual(db["finding"]["events"], [])
        # and alice's command query must not contain bob's python.
        da = self._q(root, "--facet", "commands", "--user", "alice")
        cmds = " ".join(e["object"] for e in da["evidence"])
        self.assertIn("curl", cmds)
        self.assertNotIn("python", cmds)

    def test_path_filter(self):
        d = self._q(self._busy_host(), "--facet", "files", "--user", "alice",
                    "--path", "/etc/*")
        objs = [e["object"] for e in d["evidence"]]
        self.assertIn("/etc/shadow", objs)

    def test_command_and_non_sudo_filter(self):
        root = self._busy_host()
        d = self._q(root, "--facet", "commands", "--user", "alice", "--contains", "curl")
        self.assertTrue(any("curl" in e["object"] for e in d["evidence"]))
        # alice's curl was NOT via sudo -> --no-sudo keeps it.
        d2 = self._q(root, "--facet", "commands", "--user", "alice", "--no-sudo")
        self.assertTrue(d2["finding"]["events"])

    def test_network_direction_filter(self):
        d = self._q(self._busy_host(), "--facet", "network", "--user", "alice",
                    "--direction", "outbound")
        self.assertTrue(d["finding"]["events"])
        self.assertTrue(all(e.get("target_kind") == "endpoint"
                            for e in d["finding"]["events"]))

    def test_host_wide_who_pivot(self):
        # actor=any, no --user: who changed files under /etc across the host?
        d = self._q(self._busy_host(), "--facet", "files", "--actor", "any",
                    "--path", "/etc/*")
        objs = [e["object"] for e in d["evidence"]]
        self.assertIn("/etc/shadow", objs)

    def test_unattributable_pivot(self):
        d = self._q(self._busy_host(), "--facet", "files", "--actor", "unattributable")
        objs = [e["object"] for e in d["evidence"]]
        self.assertIn("/var/run/x.pid", objs)          # the daemon file change
        self.assertNotIn("/etc/shadow", objs)          # alice's is attributable, excluded

    def test_partial_confidence_inherited_from_narrow_watch(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve().watch("/etc", "wa", "etc")   # narrow watch, no host-wide rule
        h.file_change(1001, 1001, "creat", "/etc/cron.d/x", ago(hours=2), key="etc")
        h.write()
        d = self._q(root, "--facet", "files", "--user", "alice", "--path", "/etc/*")
        self.assertEqual(d["finding"]["confidence"], "partial")
        self.assertTrue(any(g["question"] == "Files" for g in d["finding"]["gaps"]))

    def test_unanswerable_not_false_negative(self):
        # No auditd and no auth -> a command filter cannot be answered; it must be
        # UNANSWERABLE, never a false "no matching commands".
        root = self.make_root()
        h = HostBuilder(root).no_auditd()
        h.passwd("root", 0).passwd("alice", 1001)
        h.boot(ago(hours=10))
        h.login("alice", ago(hours=3), until=ago(hours=1), host="10.0.0.5")
        h.write()
        d = self._q(root, "--facet", "commands", "--user", "alice", "--contains", "curl")
        self.assertEqual(d["finding"]["confidence"], "unanswerable")

    def _ops_host(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001).passwd("bob", 1002)
        h.enable_execve().enable_network().enable_file_syscalls().watch("/etc", "wa", "etc")
        h.file_change(1001, 0, "unlink", "/var/log/audit/audit.log", ago(hours=3))  # wipe
        h.file_change(1001, 0, "chmod", "/etc/shadow", ago(hours=3), key="etc")       # perms
        h.chauthtok(1001, "bob", 1002, ago(hours=3))                                  # passwd change
        h.bind(1001, 0, "0.0.0.0", 4444, ago(hours=3))                                 # listener
        h.write()
        return root

    def test_certify_fs03_delete_truncate(self):
        d = self._q(self._ops_host(), "--facet", "files", "--user", "alice",
                    "--action", "unlink")
        self.assertTrue(any("audit.log" in e["object"] for e in d["evidence"]))
        # bob did not delete anything -> scoped negative
        db = self._q(self._ops_host(), "--facet", "files", "--user", "bob",
                     "--action", "unlink")
        self.assertEqual(db["finding"]["events"], [])
        self.assertIn("within the covered evidence scope", db["finding"]["summary"])

    def test_certify_fs05_chmod_chown(self):
        d = self._q(self._ops_host(), "--facet", "files", "--user", "alice",
                    "--action", "chmod")
        self.assertTrue(any("/etc/shadow" in e["object"] for e in d["evidence"]))

    def test_certify_ac03_password_change(self):
        d = self._q(self._ops_host(), "--facet", "accounts", "--user", "alice",
                    "--action", "passwd_change")
        self.assertTrue(d["finding"]["events"])
        self.assertTrue(all(e["records"] for e in d["evidence"]))  # provenance

    def test_certify_nw05_inbound_listener(self):
        d = self._q(self._ops_host(), "--facet", "network", "--user", "alice",
                    "--direction", "inbound")
        self.assertTrue(d["finding"]["events"])

    def test_path_filter_no_boundary_overmatch(self):
        """Review: `--path /etc` must not match /etcpasswd or /etc-backup."""
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_file_syscalls()
        h.file_change(1001, 0, "creat", "/etcpasswd", ago(hours=2))   # sibling, NOT under /etc
        h.file_change(1001, 0, "creat", "/etc/real", ago(hours=2))
        h.write()
        d = self._q(root, "--facet", "files", "--user", "alice", "--path", "/etc")
        objs = [e["object"] for e in d["evidence"]]
        self.assertIn("/etc/real", objs)
        self.assertNotIn("/etcpasswd", objs)

    def test_aggregate_facet_query_rejected(self):
        """Review: a query over an aggregate facet would mislabel confidence, so it
        must be refused rather than answered with a wrong status."""
        root = self.make_root()
        HostBuilder(root).passwd("root", 0).passwd("alice", 1001).write()
        rc, out = self.cli("--data-root", str(root), "--facet", "core",
                           "--user", "alice", "--path", "/etc/*")
        self.assertEqual(rc, 2)  # refused (message on stderr, not captured here)

    def test_contradictory_flags_rejected(self):
        root = self.make_root()
        HostBuilder(root).passwd("root", 0).passwd("alice", 1001).write()
        rc, _ = self.cli("--data-root", str(root), "--facet", "commands",
                         "--user", "alice", "--as-root", "--not-root")
        self.assertEqual(rc, 2)

    def test_root_attribution_survives_in_query(self):
        # alice sudo -> root, deletes an account as root; the query attributes the
        # root action to alice (auid), and bob's identical query is empty.
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001).passwd("bob", 1002)
        h.enable_execve()
        h.su(1001, 0, ago(hours=2))
        h.exec(1001, 0, ["userdel", "victim"], "/usr/sbin/userdel", ago(hours=2),
               euid=0, comm="userdel")
        h.write()
        d_alice = self._q(root, "--facet", "commands", "--user", "alice",
                          "--as-root", "--contains", "userdel")
        self.assertTrue(d_alice["finding"]["events"], "root action not attributed to alice")
        d_bob = self._q(root, "--facet", "commands", "--user", "bob",
                        "--as-root", "--contains", "userdel")
        self.assertEqual(d_bob["finding"]["events"], [], "root action wrongly attributed to bob")


class TestQueryCertification(Base):
    """Data-driven certification of query-layer questions through the shipped CLI.

    One rich, fully-instrumented host; each entry maps a contract question to its
    canonical deterministic filter and the object it must surface. The loop proves,
    per question: a cited positive (provenance) via the CLI JSON path. A companion
    test proves the scoped-negative behavior. This is a parameterized harness over
    reusable primitives -- NOT a special-case handler per question.
    """

    # (qid, facet, query-flags, expected-substring-in-an-evidence-object)
    _CERT = [
        ("EX-07", "commands", ["--contains", "/tmp"], "/tmp/evil"),
        ("EX-10", "commands", ["--contains", "python"], "python"),
        ("PV-04", "commands", ["--as-root"], "userdel"),
        ("SP-03", "commands", ["--contains", "crontab"], "crontab"),
        ("SP-09", "commands", ["--contains", "systemctl"], "systemctl"),
        ("FS-02", "files", ["--path", "/tmp/*"], "/tmp/x"),
        ("FS-06", "files", ["--action", "rename"], "/home/alice/a"),
        ("FS-07", "files", ["--action", "symlink"], "/home/alice/link"),
        ("FS-08", "files", ["--as-root"], "/etc/shadow"),
        ("FS-09", "files", ["--actor", "any", "--path", "/etc/shadow"], "/etc/shadow"),
        ("NW-02", "network", ["--object", "10.0.0.9"], "10.0.0.9"),
        ("PK-01", "packages", ["--actor", "any"], "nginx"),          # host-wide software
        ("PK-02", "packages", ["--actor", "any", "--object", "nginx"], "nginx"),
        ("PK-04", "packages", ["--actor", "any", "--object", "nginx"], "nginx"),
        ("PK-06", "packages", ["--action", "remove"], "telnet"),     # alice, correlated
        ("PK-07", "packages", ["--action", "downgrade"], "openssl"),
        ("AC-05", "groups", ["--object", "sudo"], "sudo"),
        ("IA-06", "login", ["--actor", "any"], None),
        ("EX-06", "commands", ["--tty", "pts"], None),
        ("PV-05", "commands", ["--as-root", "--contains", "bash"], "bash"),
        ("PK-08", "packages", ["--object", "nc-"], "nc-"),
        ("AC-02", "accounts", ["--action", "user_mgmt"], "svc"),
        ("AC-04", "accounts", ["--action", "acct_lock"], "svc"),
        ("AC-06", "accounts", ["--result", "failed"], "denied"),
        ("EX-09", "commands", ["--result", "failed"], "badcmd"),
        ("PK-03", "packages", ["--actor", "any", "--object", "curl"], "curl"),
        ("SP-02", "files", ["--path", "/etc/cron.d/*"], "/etc/cron.d/evil"),
        ("SP-05", "files", ["--path", "/etc/systemd/system/*"], "evil.service"),
        ("SP-12", "files", ["--path", "/etc/rc.local"], "/etc/rc.local"),
        ("SP-04", "commands", ["--contains", "enable"], "enable"),
        ("SP-11", "commands", ["--contains", "mask"], "mask"),
        ("SP-10", "commands", ["--contains", "systemd-run"], "systemd-run"),
    ]

    def _rich_host(self):
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001).passwd("bob", 1002)
        h.enable_execve().enable_network().enable_file_syscalls().watch("/etc", "wa", "etc")
        h.boot(ago(hours=6))
        h.login("alice", ago(hours=5), until=ago(hours=1), host="203.0.113.7")
        h.ssh_accept("alice", "203.0.113.7", ago(hours=5))
        h.exec(1001, 1001, ["curl", "http://10.0.0.9"], "/usr/bin/curl", ago(hours=4), comm="curl")
        h.exec(1001, 1001, ["python", "/home/alice/x.py"], "/usr/bin/python", ago(hours=4), comm="python")
        h.exec(1001, 1001, ["/tmp/evil"], "/tmp/evil", ago(hours=4), comm="evil")
        h.exec(1001, 1001, ["crontab", "-e"], "/usr/bin/crontab", ago(hours=4), comm="crontab")
        h.exec(1001, 0, ["systemctl", "restart", "nginx"], "/usr/bin/systemctl", ago(hours=4), euid=0, comm="systemctl")
        h.exec(1001, 0, ["userdel", "victim"], "/usr/sbin/userdel", ago(hours=4), euid=0, comm="userdel")
        h.exec(1001, 0, ["-bash"], "/bin/bash", ago(hours=4), euid=0, comm="bash")  # interactive root shell
        h.file_change(1001, 1001, "creat", "/tmp/x", ago(hours=4))
        h.file_change(1001, 0, "chmod", "/etc/shadow", ago(hours=4), euid=0, key="etc")
        h.file_change(1001, 1001, "rename", "/home/alice/a", ago(hours=4))
        h.file_change(1001, 1001, "symlink", "/home/alice/link", ago(hours=4))
        h.add_group(1001, "sudo", 27, ago(hours=4))
        h.usermod(1001, "svc", 1800, ago(hours=4))                       # modify account
        h.acct_lock(1001, "svc", 1800, ago(hours=4), lock=True)          # lock account
        h.add_user(1001, "denied", 1900, ago(hours=4), res="failed")     # failed account change
        h.exec(1001, 1001, ["badcmd"], "/usr/bin/badcmd", ago(hours=4), comm="badcmd", success="no")  # failed command
        h.dpkg("upgrade", "curl:amd64", "7.68.0", "7.81.0", ago(hours=4))  # version from->to
        # persistence actions (captured as file creates / commands)
        h.file_change(1001, 0, "creat", "/etc/cron.d/evil", ago(hours=4), euid=0)
        h.file_change(1001, 0, "creat", "/etc/systemd/system/evil.service", ago(hours=4), euid=0)
        h.file_change(1001, 0, "creat", "/etc/rc.local", ago(hours=4), euid=0)
        h.exec(1001, 0, ["systemctl", "enable", "evil.service"], "/usr/bin/systemctl", ago(hours=4), euid=0, comm="systemctl")
        h.exec(1001, 0, ["systemctl", "mask", "auditd"], "/usr/bin/systemctl", ago(hours=4), euid=0, comm="systemctl")
        h.exec(1001, 0, ["systemd-run", "--on-calendar", "*:0/5", "/tmp/evil"], "/usr/bin/systemd-run", ago(hours=4), euid=0, comm="systemd-run")
        h.connect(1001, 1001, "10.0.0.9", 443, ago(hours=4))
        h.bind(1001, 0, "0.0.0.0", 4444, ago(hours=4))
        # Package changes + alice's audited dnf execs just before them, so the
        # packages facet correlates them to alice (per-user attribution).
        h.exec(1001, 0, ["dnf", "install", "-y", "nginx"], "/usr/bin/dnf",
               ago(hours=4, minutes=2), euid=0, comm="dnf")
        h.exec(1001, 0, ["dnf", "remove", "-y", "telnet"], "/usr/bin/dnf",
               ago(hours=4, minutes=2), euid=0, comm="dnf")
        h.exec(1001, 0, ["dnf", "downgrade", "-y", "openssl"], "/usr/bin/dnf",
               ago(hours=4, minutes=2), euid=0, comm="dnf")
        h.exec(1001, 0, ["dnf", "install", "-y", "nc"], "/usr/bin/dnf",
               ago(hours=4, minutes=2), euid=0, comm="dnf")
        h.pkg("Installed", "nginx-1.24.0-1.fc40.x86_64", ago(hours=4))
        h.pkg("Erased", "telnet-1.2-1.fc40.x86_64", ago(hours=4))
        h.pkg("Downgraded", "openssl-3.0.0-1.fc40.x86_64", ago(hours=4))
        h.pkg("Installed", "nc-1.0-1.fc40.x86_64", ago(hours=4))
        h.sudo(1001, 1001, "/bin/sh", ago(hours=4), res="failed")   # denied escalation
        h.ssh_fail("alice", "198.51.100.9", ago(hours=4))            # failed auth
        h.write()
        return root

    def _run(self, root, facet, flags, user="alice"):
        argv = ["--data-root", str(root), "--format", "json", "--facet", facet]
        if "--actor" not in flags:
            argv += ["--user", user]
        argv += flags
        rc, out = self.cli(*argv)
        self.assertEqual(rc, 0, out)
        return json.loads(out)

    def test_query_questions_certified(self):
        root = self._rich_host()
        proven = []
        for qid, facet, flags, expect in self._CERT:
            d = self._run(root, facet, flags)
            self.assertTrue(d["finding"]["events"], f"{qid}: no events matched")
            self.assertTrue(all(e["records"] for e in d["evidence"]),
                            f"{qid}: provenance lost (an event without citations)")
            if expect is not None:
                objs = " ".join(e["object"] for e in d["evidence"])
                self.assertIn(expect, objs, f"{qid}: expected {expect!r} in {objs!r}")
            proven.append(qid)
        self.assertEqual(len(proven), len(self._CERT))

    def test_pv03_denied_escalation(self):
        root = self._rich_host()
        # Specifically the DENIED escalation (result=failed), not all sudo attempts.
        d = self._run(root, "privilege", ["--result", "failed"])
        self.assertTrue(d["finding"]["events"], "denied escalation not surfaced")
        self.assertTrue(all(e["records"] for e in d["evidence"]))

    def test_ia02_failed_auth(self):
        root = self._rich_host()
        d = self._run(root, "login", ["--user", "alice"])
        # a failed SSH auth from 198.51.100.9 is in the login evidence
        blob = json.dumps(d)
        self.assertIn("198.51.100.9", blob)

    # -- timeline / projection questions: answered by the ordered facet output -- #
    def test_timeline_projection_questions(self):
        """EX-08, AC-07, FS-10, PV-08, TM-04: 'when / first / last / timeline'
        questions are the facet's chronologically ordered, cited output."""
        root = self._rich_host()
        for facet in ("commands", "accounts", "files", "privilege", "timeline"):
            f = self.finding(root, "alice", facet)
            self.assertTrue(f.events, f"{facet}: no events")
            ts = [e.ts for e in f.events]
            self.assertEqual(ts, sorted(ts), f"{facet}: events not chronological")
            self.assertTrue(all(e.citations for e in f.events), f"{facet}: uncited event")

    def test_tm04_dwell_time(self):
        # first/last/dwell: the session carries start + end (duration).
        f = self.finding(self._rich_host(), "alice", "sessions")
        self.assertTrue(any(e.ts_end is not None for e in f.events))

    # -- coverage / conservation / provenance meta-questions -- #
    def test_tm09_provenance_of_facts(self):
        # The evidence question surfaces, per claim, the source + locator + raw record.
        d = self._run(self._rich_host(), "files", ["--path", "/etc/shadow"])
        rec = d["evidence"][0]["records"][0]
        self.assertTrue(rec["source_id"] and rec["locator"] and rec["raw"])

    def test_tm10_readiness_coverage(self):
        rc, out = self.cli("--coverage", "--data-root", str(self._rich_host()))
        self.assertEqual(rc, 0)
        self.assertIn("QUESTION FAMILIES", out)
        self.assertIn("Certified:", out)

    def test_tm11_tm12_pk12_horizon_and_conservation(self):
        rc, out = self.cli("--coverage", "--format", "json",
                           "--data-root", str(self._rich_host()))
        cov = json.loads(out)["coverage"]
        srcs = {s["source_id"]: s for s in cov["sources"]}
        # TM-11: evidence reach (retention horizon) is reported per source.
        self.assertIn("horizon_end", srcs["auditd"])
        # TM-12 / PK-12: conservation counters exist per source (records unaccounted-for).
        self.assertIn("unparseable", srcs["packages"])
        self.assertIn("records_scanned", srcs["auditd"])

    def test_nw13_evidenced_negative_cleared(self):
        # A fully-instrumented host where alice made no network connections: she can
        # be affirmatively cleared -- an evidenced negative, scoped, not absolute.
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("alice", 1001)
        h.enable_execve().enable_network()
        h.exec(1001, 1001, ["id"], "/usr/bin/id", ago(hours=2))  # active, but no network
        h.write()
        d = self._run(root, "network", ["--direction", "outbound"])
        self.assertEqual(d["finding"]["events"], [])
        self.assertEqual(d["finding"]["confidence"], "certified")
        self.assertIn("within the covered evidence scope", d["finding"]["summary"])


class TestProductionContract(Base):
    """The full production contract is honest: CERTIFIED == the wired core, and
    every CONTRACTED question names what it needs and is never silently answered."""

    # The ONLY questions allowed to be CERTIFIED beyond the wired 15 are query-layer
    # questions that have a dedicated proving test in TestQueryLayer. This allowlist
    # is the guard: flipping any other question to CERTIFIED without a proving test
    # fails here (prevents silent over-certification).
    _QUERY_CERTIFIED = {"AC-01", "AC-02", "AC-03", "AC-04", "AC-05", "AC-06", "AC-07", "EX-01", "EX-02", "EX-06", "EX-07", "EX-08", "EX-09", "EX-10", "FS-01", "FS-02", "FS-03", "FS-05", "FS-06", "FS-07", "FS-08", "FS-09", "FS-10", "IA-02", "IA-06", "NW-01", "NW-02", "NW-05", "NW-13", "PK-01", "PK-02", "PK-03", "PK-04", "PK-06", "PK-07", "PK-08", "PK-12", "PV-03", "PV-04", "PV-05", "PV-08", "SP-02", "SP-03", "SP-04", "SP-05", "SP-09", "SP-10", "SP-11", "SP-12", "TM-01", "TM-04", "TM-08", "TM-09", "TM-10", "TM-11", "TM-12"}

    def test_certified_set_is_exactly_the_proven_set(self):
        from openpath.contract import PRODUCTION_CONTRACT, CatalogStatus
        from openpath.catalog import CATALOG
        certified = {q.id for q in PRODUCTION_CONTRACT
                     if q.status is CatalogStatus.CERTIFIED}
        expected = {q.id for q in CATALOG} | self._QUERY_CERTIFIED
        self.assertEqual(certified, expected,
                         "CERTIFIED must be exactly the wired 15 plus the "
                         "query-layer questions proven in TestQueryLayer")
        from openpath.facets import get_facet
        for q in PRODUCTION_CONTRACT:
            if q.status is CatalogStatus.CERTIFIED:
                get_facet(q.facet)  # every CERTIFIED entry must be a runnable facet

    def test_every_contracted_question_names_what_it_needs(self):
        from openpath.contract import PRODUCTION_CONTRACT, CatalogStatus
        for q in PRODUCTION_CONTRACT:
            if q.status is CatalogStatus.CONTRACTED:
                self.assertTrue(q.needs.strip(),
                                f"{q.id} is CONTRACTED but names no collector/subsystem")

    def test_ids_unique(self):
        from openpath.contract import PRODUCTION_CONTRACT
        ids = [q.id for q in PRODUCTION_CONTRACT]
        self.assertEqual(len(ids), len(set(ids)))

    def test_certified_facets_are_wired(self):
        """A CERTIFIED question must point at a real, runnable facet; a CONTRACTED
        one need not (that is exactly what 'not yet built' means)."""
        from openpath.contract import PRODUCTION_CONTRACT, CatalogStatus
        from openpath.facets import get_facet
        for q in PRODUCTION_CONTRACT:
            if q.status is CatalogStatus.CERTIFIED:
                get_facet(q.facet)  # raises if not wired

    def test_scoreboard_renders_and_counts_match(self):
        rc, out = self.cli("--contract")
        self.assertEqual(rc, 0)
        self.assertIn("Production question contract", out)
        rc, jout = self.cli("--contract", "--format", "json")
        data = json.loads(jout)
        # CERTIFIED = the wired 15 + the query-layer questions proven in TestQueryLayer.
        from openpath.catalog import CATALOG
        self.assertGreaterEqual(data["counts"]["certified"], len(CATALOG))
        self.assertEqual(data["total"], len(data["questions"]))
        self.assertEqual(data["counts"]["certified"] + data["counts"]["contracted"],
                         data["total"])


class TestCatalog(Base):
    """The frozen catalog stays coherent with the code and the docs."""

    def test_every_catalog_facet_exists(self):
        from openpath.facets import get_facet
        for cq in CATALOG:
            get_facet(cq.facet)  # raises KeyError if the facet is unknown

    def test_catalog_doc_lists_every_question(self):
        doc = Path("docs/CLIENT-QUESTION-CATALOG.md").read_text()
        for cq in CATALOG:
            self.assertIn(cq.id, doc, f"{cq.id} missing from the catalog doc")

    def test_ids_are_sequential(self):
        self.assertEqual([cq.id for cq in CATALOG],
                         [f"Q{i:02d}" for i in range(1, len(CATALOG) + 1)])


class TestDemoReadiness(Base):
    """The demo contract: every catalog question, over a golden host, answered
    correctly, backed by cited evidence, disclosing gaps, inventing nothing."""

    def _golden(self) -> Path:
        root = self.make_root()
        h = HostBuilder(root)
        h.passwd("root", 0).passwd("aclaye", 1001)
        h.enable_execve().enable_network().enable_file_syscalls().watch("/etc", "wa", "etc")
        h.boot(ago(hours=6))
        h.auth_ssh_accept("aclaye", "1.2.3.4", ago(hours=3))
        h.login("aclaye", ago(hours=3), line="pts/0", host="1.2.3.4", until=ago(hours=1))
        h.failed_login("aclaye", ago(hours=3, minutes=2), host="9.9.9.9")
        h.sudo(1001, 1001, "/bin/su -", ago(hours=2, minutes=59))
        h.exec(1001, 0, ["useradd", "bob"], "/usr/sbin/useradd", ago(hours=2, minutes=58), euid=0, comm="useradd")
        h.add_user(1001, "bob", 1600, ago(hours=2, minutes=58))
        h.exec(1001, 0, ["groupadd", "devs"], "/usr/sbin/groupadd", ago(hours=2, minutes=57), euid=0, comm="groupadd")
        h.add_group(1001, "devs", 4000, ago(hours=2, minutes=57))
        h.exec(1001, 0, ["chmod", "600", "/etc/shadow"], "/usr/bin/chmod", ago(hours=2, minutes=56), euid=0, comm="chmod")
        h.file_change(1001, 0, "chmod", "/etc/shadow", ago(hours=2, minutes=56), euid=0, key="etc")
        h.exec(1001, 0, ["dnf", "install", "-y", "nginx"], "/usr/bin/dnf", ago(hours=2, minutes=55), euid=0, comm="dnf")
        h.pkg("Installed", "nginx-1.24.0-1.fc40.x86_64", ago(hours=2, minutes=54))
        h.connect(1001, 0, "93.184.216.34", 443, ago(hours=2, minutes=53))
        h.write()
        return root

    def test_every_catalog_question_is_sound_and_disclosed(self):
        root = self._golden()
        for cq in CATALOG:
            f = self.finding(root, "aclaye", cq.facet)
            # soundness: every asserted fact carries a citation
            for e in f.events:
                self.assertTrue(e.citations, f"{cq.id}: uncited event {e.summary}")
            # disclosure: a data facet with no events must say why (gap) or state
            # an evidenced negative -- never a silent blank
            if cq.facet not in ("core", "timeline", "evidence", "gaps") and not f.events:
                disclosed = bool(f.gaps) or any(
                    kw in f.summary.lower()
                    for kw in ("no ", "cannot determine", "evidenced negative"))
                self.assertTrue(disclosed, f"{cq.id}: silent empty answer")

    def test_demo_commands_answer_correctly(self):
        root = self._golden()
        # the six demo commands, checked for correct, evidenced content
        self.assertTrue(self.finding(root, "aclaye", "privilege").summary.startswith("Yes"))
        cmds = [e.attrs.get("cmdline") for e in self.finding(root, "aclaye", "commands").events]
        self.assertTrue({"useradd bob", "chmod 600 /etc/shadow"} <= set(cmds))
        files = {e.attrs.get("path") for e in self.finding(root, "aclaye", "files").events}
        self.assertIn("/etc/shadow", files)
        self.assertIn("bob", {e.attrs.get("acct") for e in self.finding(root, "aclaye", "accounts").events})
        self.assertIn("devs", {e.attrs.get("grp") for e in self.finding(root, "aclaye", "groups").events})
        self.assertTrue(self.finding(root, "aclaye", "evidence").citations())
        # gaps facet is honest: on this fully-instrumented host no COVERAGE gap is
        # outstanding, though the standing unmodeled-source disclosures remain.
        gf = self.finding(root, "aclaye", "gaps")
        self.assertEqual([g for g in gf.gaps if g.question != "scope"], [])

    def test_never_invents_for_a_quiet_user(self):
        # A real account that did nothing must get evidenced negatives, not fiction.
        root = self._golden()
        for facet in ("commands", "files", "network", "accounts", "groups"):
            f = self.finding(root, "root", facet)  # root itself did nothing here
            self.assertEqual(len(f.events), 0)


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
