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
import sys
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Optional

from openpath import __version__
from openpath.engine import Engine
from openpath.env import Env
from openpath.facets import FAMILIES, get_spec
from openpath.model.timerange import TimeParseError, build_range, parse_instant
from openpath.render import render_json, render_text
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
    p.add_argument("--data-root", default="/",
                   help="filesystem root for sources (default '/'; use an evidence "
                        "bundle dir for offline analysis)")
    p.add_argument("--now", help="anchor 'now' for relative windows (testing)")
    p.add_argument("--tz", help="timezone for naive source timestamps (IANA name)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="show all raw evidence records inline")
    p.add_argument("--list-families", action="store_true",
                   help="list the 13 question families and exit")
    p.add_argument("--version", action="version", version=f"openpath-ai {__version__}")
    return p


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_families:
        for spec in FAMILIES:
            print(f"{spec.number:2d}  {spec.name:14s} {spec.label}")
        return 0

    if not args.question and not (args.facet and args.user):
        print("error: provide a question, or both --facet and --user",
              file=sys.stderr)
        return 2

    tz = _resolve_tz(args.tz)
    now = (
        parse_instant(args.now, tz) if args.now
        else datetime.now(timezone.utc)
    )
    env = Env(data_root=Path(args.data_root), now=now, local_tz=tz)

    # Subject.
    username = args.user or (router.extract_user(args.question) if args.question else None)
    if not username:
        print("error: could not determine the subject user from the question; "
              "pass --user NAME.", file=sys.stderr)
        return 2

    # Facet.
    facet_name = args.facet or (router.route(args.question) if args.question else "core")
    try:
        get_spec(facet_name)
    except KeyError:
        print(f"error: unknown facet {facet_name!r}; see --list-families",
              file=sys.stderr)
        return 2

    # Window.
    window_expr = args.window or (router.extract_time(args.question) if args.question else None)
    try:
        window = build_range(
            expr=window_expr, since=args.since, until=args.until,
            now=env.now, default_tz=env.local_tz,
        )
    except (TimeParseError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = Engine().analyze(env, username, window, facet_name)

    if args.format == "json":
        print(render_json(result))
    else:
        print(render_text(result, verbose=args.verbose))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
