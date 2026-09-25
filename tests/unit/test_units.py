"""Unit tests for the low-level primitives that everything else relies on."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from openpath.model.timerange import (
    TimeParseError, build_range, parse_instant, parse_range,
)
from openpath.model.event import Event, EventType
from openpath.model.citation import Citation
from openpath.model.identity import resolve_identity
from openpath.model.timerange import TimeRange
from openpath.sources.auditd import _decode_saddr, _parse_fields, _maybe_hex_decode
from openpath.sources.wtmp import _UTMP_STRUCT

UTC = timezone.utc
NOW = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)


class TestTime(unittest.TestCase):
    def test_instant_forms(self):
        z = parse_instant("2026-09-25T08:30:00Z", UTC)
        off = parse_instant("2026-09-25 04:30:00-04:00", UTC)
        self.assertEqual(z, off)
        self.assertEqual(z.tzinfo, UTC)
        # epoch seconds
        ep = parse_instant(str(int(z.timestamp())), UTC)
        self.assertEqual(ep, z)

    def test_naive_uses_default_tz(self):
        import zoneinfo
        ny = zoneinfo.ZoneInfo("America/New_York")
        got = parse_instant("2026-09-25 08:30:00", ny)  # EDT = UTC-4
        self.assertEqual(got, datetime(2026, 9, 25, 12, 30, tzinfo=UTC))

    def test_relative_ranges(self):
        r = parse_range("last 24 hours", now=NOW, default_tz=UTC)
        self.assertEqual(r.start, NOW - timedelta(hours=24))
        self.assertEqual(r.end, NOW)
        r2 = parse_range("past 7 days", now=NOW, default_tz=UTC)
        self.assertEqual(r2.start, NOW - timedelta(days=7))

    def test_build_range_precedence(self):
        # since/until overrides expr
        r = build_range(expr="last 24 hours", since="2026-09-01",
                        until="2026-09-02", now=NOW, default_tz=UTC)
        self.assertEqual(r.start.date().isoformat(), "2026-09-01")
        # default is last 24h
        d = build_range(expr=None, since=None, until=None, now=NOW, default_tz=UTC)
        self.assertEqual(d.start, NOW - timedelta(hours=24))

    def test_bad_range_rejected(self):
        with self.assertRaises(TimeParseError):
            build_range(expr=None, since="2026-09-05", until="2026-09-01",
                        now=NOW, default_tz=UTC)


class TestIdentity(unittest.TestCase):
    def _win(self):
        return TimeRange(start=NOW - timedelta(days=1), end=NOW)

    def _acct_ev(self, ts, action, acct, uid):
        return Event(ts=ts, type=EventType.ACCOUNT_CHANGE, source_id="auditd",
                     summary="", attrs={"action": action, "acct": acct, "id": uid},
                     citations=[Citation("auditd", "x", "x")])

    def test_stable_user(self):
        s = resolve_identity("alice", self._win(),
                             passwd_entries=[("alice", 1001)], account_events=[])
        self.assertTrue(s.exists_now)
        self.assertEqual(s.current_uid, 1001)
        self.assertTrue(s.has_uid_mapping)

    def test_never_existed(self):
        s = resolve_identity("ghost", self._win(),
                             passwd_entries=[("alice", 1001)], account_events=[])
        self.assertFalse(s.exists_now)
        self.assertFalse(s.has_uid_mapping)
        self.assertTrue(s.resolution_notes)

    def test_created_in_window_interval_bounded(self):
        ev = self._acct_ev(NOW - timedelta(hours=5), "add_user", "svc", 1500)
        s = resolve_identity("svc", self._win(),
                             passwd_entries=[("svc", 1500)], account_events=[ev])
        self.assertTrue(any(iv.start is not None for iv in s.intervals))

    def test_matches_auid_not_foreign_uid(self):
        s = resolve_identity("alice", self._win(),
                             passwd_entries=[("alice", 1001)], account_events=[])
        mine = Event(ts=NOW - timedelta(hours=1), type=EventType.EXEC,
                     source_id="auditd", summary="", auid=1001, uid=0,
                     citations=[Citation("a", "b", "c")])
        foreign = Event(ts=NOW - timedelta(hours=1), type=EventType.EXEC,
                        source_id="auditd", summary="", auid=1002, uid=0,
                        citations=[Citation("a", "b", "c")])
        self.assertTrue(s.matches(mine))
        self.assertFalse(s.matches(foreign))


class TestAuditParsing(unittest.TestCase):
    def test_saddr_inet(self):
        # 127.0.0.1:443 -> family LE 0200, port BE 01BB, addr 7F000001
        info = _decode_saddr("02000" + "1BB" + "7F000001" + "0000000000000000")
        # rebuild precisely instead of guessing hex spacing:
        import socket, struct, binascii
        raw = struct.pack("<H", socket.AF_INET) + struct.pack(">H", 443) \
            + socket.inet_aton("127.0.0.1") + b"\x00" * 8
        info = _decode_saddr(binascii.hexlify(raw).decode())
        self.assertEqual(info["family"], "inet")
        self.assertEqual(info["addr"], "127.0.0.1")
        self.assertEqual(info["port"], 443)

    def test_inner_msg_fields_parsed(self):
        line = ("type=USER_CMD msg=audit(1758801600.123:4567): pid=1 uid=1001 "
                "auid=1001 ses=3 msg='cwd=\"/home/a\" cmd=6c73 terminal=pts/0 "
                "res=success' exe=\"/usr/bin/sudo\"")
        fields = _parse_fields(line)
        self.assertEqual(fields.get("res"), "success")
        self.assertEqual(_maybe_hex_decode(fields.get("cmd")), "ls")
        self.assertEqual(fields.get("terminal"), "pts/0")

    def test_unset_auid_is_none(self):
        line = "type=SYSCALL msg=audit(1.0:1): syscall=59 auid=4294967295 uid=0"
        fields = _parse_fields(line)
        from openpath.sources.auditd import _auid
        self.assertIsNone(_auid(fields))


class TestWtmpStruct(unittest.TestCase):
    def test_record_size_is_384(self):
        self.assertEqual(_UTMP_STRUCT.size, 384)


if __name__ == "__main__":
    unittest.main(verbosity=2)
