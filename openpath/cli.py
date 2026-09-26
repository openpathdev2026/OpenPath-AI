"""Command-line entrypoint: ``openpath-ai "<question>"``.

Examples:
    openpath-ai "What did alice do during the last 24 hours?"
    openpath-ai --user alice --facet timeline --window "last 7 days"
    openpath-ai --user deploybot --since 2026-09-24 --until 2026-09-25 \\
        --data-root ./evidence-bundle --format json "did deploybot become root?"

The subject can be named explicitly with ``--user`` (authoritative) or left to
best-effort extraction from the question. Time can be given with ``--window``,
``--since/--until``, or extracted from the question; it defaults to the last 24
hours. ``--data-root`` points the collectors at a live host (``/``, the default)
or an offline evidence bundle.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Optional

from openpath import __version__
from openpath.engine import Engine
from openpath.env import Env
from openpath.facets import FAMILIES, get_spec
from openpath.model.timerange import TimeParseError, build_range, parse_instant
from openpath.render import (
    render_json,
    render_readiness,
    render_readiness_json,
    render_text,
)
from openpath import router


def _resolve_tz(name: Optional[str]) -> tzinfo:
    if not name:
        tz = datetime.now().astimezone().tzinfo
        return tz if tz is not None else timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        raise SystemExit(f"error: unknown timezone {name!r}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="openpath-ai",
        description="Evidence-first forensic Q&A over Linux user activity.",
    )
    p.add_argument("question", nargs="?", help="natural-language question")
    p.add_argument("--user", "-u", help="subject username (authoritative)")
    p.add_argument("--facet", "-f", help="force a facet by name (see --list-families)")
    p.add_argument("--window", "-w", help="time expression, e.g. 'last 24 hours'")
    p.add_argument("--since", help="range start (any timestamp)")
    p.add_argument("--until", help="range end (any timestamp)")
    p.add_argument("--around", help="pivot timestamp for 'what happened "
                                    "before/after EVENT' (Q13); shows +/-1h around it")
    # -- deterministic query/filter/pivot layer (composes with --facet/--user) -- #
    q = p.add_argument_group("query filters (deterministic projections over evidence)")
    q.add_argument("--actor", choices=["subject", "any", "unattributable"],
                   default="subject",
                   help="whose events: the --user subject, ANY actor (host-wide "
                        "'who did X'), or UNATTRIBUTABLE (no login uid / no name)")
    q.add_argument("--object", dest="q_object",
                   help="filter to events whose acted-on object contains this text")
    q.add_argument("--path", dest="q_paths", action="append", default=[],
                   help="filter to file paths/objects matching this prefix or glob "
                        "(repeatable)")
    q.add_argument("--action", dest="q_actions", action="append", default=[],
                   help="filter to events with this action/op/tool, e.g. del_user, "
                        "chmod, sudo (repeatable)")
    q.add_argument("--contains", dest="q_contains",
                   help="filter to commands whose cmdline/exe/comm contains this text")
    q.add_argument("--direction", choices=["outbound", "inbound"],
                   help="filter network events by direction")
    q.add_argument("--as-root", dest="q_as_root", action="store_true", default=None,
                   help="filter to events performed with root privilege")
    q.add_argument("--not-root", dest="q_not_root", action="store_true",
                   help="filter to events NOT performed as root")
    q.add_argument("--via-sudo", dest="q_via_sudo", action="store_true", default=None,
                   help="filter to sudo-invoked events")
    q.add_argument("--no-sudo", dest="q_no_sudo", action="store_true",
                   help="filter to non-sudo events")
    q.add_argument("--result", choices=["success", "failed"],
                   help="filter by outcome (e.g. denied/failed escalations or logins)")
    q.add_argument("--target-user", dest="q_target_user",
                   help="filter to actions switching TO this identity (sudo -u / su)")
    q.add_argument("--tty", dest="q_tty",
                   help="filter to a controlling terminal (substring)")
    q.add_argument("--source", dest="q_sources", action="append", default=[],
                   help="filter to a specific evidence source id (repeatable)")
    p.add_argument("--data-root", default="/",
                   help="filesystem root for sources (default '/'; use an evidence "
                        "bundle dir for offline analysis)")
    p.add_argument("--now", help="anchor 'now' for relative windows (testing)")
    p.add_argument("--tz", help="timezone for naive source timestamps (IANA name)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="show all raw evidence records inline")
    p.add_argument("--list-families", action="store_true",
                   help="list the facet families and exit")
    p.add_argument("--catalog", action="store_true",
                   help="print the frozen, wired client question catalog (the "
                        "CERTIFIED core) and exit")
    p.add_argument("--contract", action="store_true",
                   help="print the full production question contract with each "
                        "question's certification status (CERTIFIED/CONTRACTED) "
                        "and exit")
    p.add_argument("--all-users", action="store_true",
                   help="run the facet (default: core) for EVERY discovered user "
                        "(local accounts + anyone seen in the evidence)")
    p.add_argument("--include-inactive", action="store_true",
                   help="with --all-users, also show users with no recorded activity")
    p.add_argument("--coverage", action="store_true",
                   help="report which catalog questions this host can answer "
                        "(no subject needed) and exit")
    p.add_argument("--version", action="version", version=f"openpath-ai {__version__}")
    return p


def _facet_event_types(facet_name):
    """Default event types a facet reasons over (so a query inherits its scope)."""
    from openpath.model.event import EventType as E
    return {
        "sessions": (E.SESSION,), "login": (E.SESSION, E.SSH_AUTH, E.LOGIN),
        "privilege": (E.PRIVILEGE_ESCALATION, E.SESSION),
        "root_activity": (E.EXEC, E.FILE_CHANGE, E.NETWORK),
        "commands": (E.EXEC,), "files": (E.FILE_CHANGE,),
        "accounts": (E.ACCOUNT_CHANGE,), "groups": (E.GROUP_CHANGE,),
        "packages": (E.PACKAGE_CHANGE,), "network": (E.NETWORK,),
        "persistence": (E.PERSISTENCE,), "authorization": (E.AUTHZ,),
        "system_lifecycle": (E.BOOT, E.SYSTEM), "pkg_policy": (E.PKG_POLICY,),
        "process_tree": (E.EXEC,), "shell_history": (E.SHELL_HISTORY,),
        "firewall": (E.FIREWALL,),
    }.get(facet_name, ())


def _query_flags_present(args) -> bool:
    return bool(args.q_object or args.q_paths or args.q_actions or args.q_contains
                or args.direction or args.q_as_root or args.q_not_root
                or args.q_via_sudo or args.q_no_sudo or args.q_sources
                or args.result or args.q_target_user or args.q_tty
                or args.actor != "subject")


def _build_query_spec(args, facet_name):
    from openpath.query import QuerySpec
    as_root = True if args.q_as_root else (False if args.q_not_root else None)
    via_sudo = True if args.q_via_sudo else (False if args.q_no_sudo else None)
    return QuerySpec(
        types=_facet_event_types(facet_name),
        sources=tuple(args.q_sources),
        actor=args.actor,
        object_contains=args.q_object or "",
        object_paths=tuple(args.q_paths),
        command_contains=args.q_contains or "",
        actions=tuple(args.q_actions),
        direction=args.direction or "",
        as_root=as_root,
        via_sudo=via_sudo,
        result=args.result or "",
        target_user=args.q_target_user or "",
        tty=args.q_tty or "",
    )


def _resolve_window(args, env):
    # Q13: pivot window centered on an event ("before/after EVENT").
    if args.around:
        pivot = parse_instant(args.around, env.local_tz)
        from openpath.model.timerange import TimeRange
        return TimeRange(start=pivot - timedelta(hours=1),
                         end=pivot + timedelta(hours=1),
                         label=f"around {args.around}")
    window_expr = args.window or (
        router.extract_time(args.question) if args.question else None)
    return build_range(
        expr=window_expr, since=args.since, until=args.until,
        now=env.now, default_tz=env.local_tz,
    )


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_families:
        for spec in FAMILIES:
            print(f"{spec.number:2d}  {spec.name:14s} {spec.label}")
        return 0

    if args.catalog:
        from openpath.catalog import CATALOG
        for cq in CATALOG:
            print(f"{cq.id}  [{cq.facet:13s}] {cq.text.replace('{user}', 'USER')}")
        return 0

    if args.contract:
        from openpath.contract import PRODUCTION_CONTRACT
        from openpath.render import render_contract, render_contract_json
        if args.format == "json":
            print(render_contract_json(PRODUCTION_CONTRACT))
        else:
            print(render_contract(PRODUCTION_CONTRACT))
        return 0

    query_mode = _query_flags_present(args)
    if (not args.coverage and not args.all_users and not args.question
            and not (args.facet and args.user) and not (args.around and args.user)
            and not (query_mode and args.facet)):
        print("error: provide a question, or both --facet and --user, "
              "or --all-users, or --coverage, or --facet with query filters",
              file=sys.stderr)
        return 2

    tz = _resolve_tz(args.tz)
    now = (
        parse_instant(args.now, tz) if args.now
        else datetime.now(timezone.utc)
    )
    env = Env(data_root=Path(args.data_root), now=now, local_tz=tz)

    # Host readiness: which catalog questions can this host answer?
    if args.coverage:
        try:
            window = _resolve_window(args, env)
        except (TimeParseError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        report = Engine().readiness(env, window)
        if args.format == "json":
            print(render_readiness_json(report))
        else:
            print(render_readiness(report))
        return 0

    # Multi-user sweep: "track all that activity for every user".
    if args.all_users:
        facet_name = args.facet or (
            router.route(args.question) if args.question else "core")
        try:
            get_spec(facet_name)
        except KeyError:
            print(f"error: unknown facet {facet_name!r}; see --list-families",
                  file=sys.stderr)
            return 2
        try:
            window = _resolve_window(args, env)
        except (TimeParseError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        results = Engine().analyze_all(env, window, facet_name)
        return _render_all_users(results, window, facet_name, args)

    # Deterministic query/filter/pivot layer.
    if query_mode:
        facet_name = args.facet or (router.route(args.question) if args.question else None)
        if not facet_name:
            print("error: query filters require --facet (the evidence family to "
                  "filter); see --list-families", file=sys.stderr)
            return 2
        try:
            get_spec(facet_name)
        except KeyError:
            print(f"error: unknown facet {facet_name!r}; see --list-families",
                  file=sys.stderr)
            return 2
        if args.q_as_root and args.q_not_root:
            print("error: --as-root and --not-root are contradictory.", file=sys.stderr)
            return 2
        if args.q_via_sudo and args.q_no_sudo:
            print("error: --via-sudo and --no-sudo are contradictory.", file=sys.stderr)
            return 2
        username = args.user or (
            router.extract_user(args.question) if args.question else None)
        if args.actor == "subject" and not username:
            print("error: --actor subject (default) needs --user; or pass "
                  "--actor any / --actor unattributable for a host-wide query.",
                  file=sys.stderr)
            return 2
        try:
            window = _resolve_window(args, env)
        except (TimeParseError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        spec = _build_query_spec(args, facet_name)
        try:
            result = Engine().query(env, window, facet_name, spec, username=username)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.format == "json":
            print(render_json(result))
        else:
            print(render_text(result, verbose=args.verbose))
        return 0

    # Subject.
    username = args.user or (router.extract_user(args.question) if args.question else None)
    if not username:
        print("error: could not determine the subject user from the question; "
              "pass --user NAME.", file=sys.stderr)
        return 2

    # Facet.
    facet_name = (
        args.facet
        or ("timeline" if args.around else None)
        or (router.route(args.question) if args.question else "core")
    )
    try:
        get_spec(facet_name)
    except KeyError:
        print(f"error: unknown facet {facet_name!r}; see --list-families",
              file=sys.stderr)
        return 2

    # Window.
    try:
        window = _resolve_window(args, env)
    except (TimeParseError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = Engine().analyze(env, username, window, facet_name)

    if args.format == "json":
        print(render_json(result))
    else:
        print(render_text(result, verbose=args.verbose))
    return 0


def _render_all_users(results, window, facet_name, args) -> int:
    active = [r for r in results if r.finding.events]
    shown = results if args.include_inactive else active

    if args.format == "json":
        payload = {
            "facet": facet_name,
            "window": window.to_dict(),
            "users_checked": [r.subject.username for r in results],
            "results": [
                {"subject": r.subject.username, "finding": r.finding.to_dict()}
                for r in shown
            ],
        }
        print(json.dumps(payload, indent=2))
        return 0

    print("=" * 72)
    print(f"OpenPath | {facet_name} for ALL users | {window.describe()}")
    print(f"checked {len(results)} user(s); {len(active)} had recorded activity")
    print("=" * 72)
    for r in shown:
        marker = "*" if r.finding.events else " "
        print(f"\n[{marker}] {r.subject.username}"
              + ("" if r.subject.exists_now else " (not a current local account)"))
        print(f"    {r.finding.summary}")
        if r.finding.gaps:
            print(f"    ({len(r.finding.gaps)} gap(s) disclosed)")
    if not args.include_inactive:
        inactive = [r.subject.username for r in results if not r.finding.events]
        if inactive:
            print(f"\nno recorded activity (checked): {', '.join(inactive)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
