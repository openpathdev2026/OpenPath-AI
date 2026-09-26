"""Self-check: an internal health/readiness probe for deployment.

``openpath-ai --selfcheck`` runs a set of *host-independent* integrity checks and
exits 0 (healthy) or non-zero (broken). It is what a container ``HEALTHCHECK`` (or a
Kubernetes liveness probe) should call: it needs no evidence, no privilege, and no
network, so it answers exactly one question -- "is this OpenPath build wired
correctly and able to run the pipeline?" -- without depending on what host it will
later analyze.

It is deliberately distinct from ``--coverage`` (host *readiness*: can THIS host
answer question X). Self-check verifies the *binary*; coverage verifies the *host*.

Each check is a ``(name, ok, detail)`` triple so the output is greppable and the
first failure is obvious. The contract fingerprint is printed so an operator can
verify an upgrade deterministically (same fingerprint == same question contract).
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from openpath import __version__

Check = Tuple[str, bool, str]


def run_checks() -> List[Check]:
    """Run every self-check and return the results (never raises)."""
    checks: List[Check] = []

    # 1. Version is present and non-empty.
    checks.append(("version", bool(__version__), f"openpath-ai {__version__}"))

    # 2. The collector registry constructs, every collector has a unique id and a
    #    collect() method.
    try:
        from openpath.sources import default_collectors
        collectors = default_collectors()
        ids = [getattr(c, "source_id", None) for c in collectors]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        all_callable = all(callable(getattr(c, "collect", None)) for c in collectors)
        ok = bool(collectors) and not dupes and all(ids) and all_callable
        detail = f"{len(collectors)} collectors" + (
            f"; DUPLICATE source_id: {dupes}" if dupes else "")
        checks.append(("collectors", ok, detail))
    except Exception as exc:  # noqa: BLE001 -- a health probe reports, never crashes
        checks.append(("collectors", False, f"{type(exc).__name__}: {exc}"))

    # 3. The production contract loads and is internally consistent.
    try:
        from openpath.contract import (
            CatalogStatus, PRODUCTION_CONTRACT, contract_fingerprint, status_counts)
        counts = status_counts()
        certified = counts.get(CatalogStatus.CERTIFIED, 0)
        contracted = counts.get(CatalogStatus.CONTRACTED, 0)
        ids = [q.id for q in PRODUCTION_CONTRACT]
        unique_ids = len(set(ids)) == len(ids)
        ok = bool(PRODUCTION_CONTRACT) and unique_ids
        detail = (f"{len(PRODUCTION_CONTRACT)} questions "
                  f"(CERTIFIED {certified}, CONTRACTED {contracted}); "
                  f"fingerprint {contract_fingerprint()}"
                  + ("" if unique_ids else "; DUPLICATE ids"))
        checks.append(("contract", ok, detail))
    except Exception as exc:  # noqa: BLE001
        checks.append(("contract", False, f"{type(exc).__name__}: {exc}"))

    # 4. Every declared family resolves to a constructible facet.
    try:
        from openpath.facets import FAMILIES, get_facet
        missing = []
        for spec in FAMILIES:
            try:
                get_facet(spec.name)
            except Exception as exc:  # noqa: BLE001
                missing.append(f"{spec.name}: {type(exc).__name__}")
        ok = not missing
        detail = (f"{len(FAMILIES)} families wired"
                  if ok else f"unresolved facets: {missing}")
        checks.append(("facets", ok, detail))
    except Exception as exc:  # noqa: BLE001
        checks.append(("facets", False, f"{type(exc).__name__}: {exc}"))

    # 5. The full pipeline runs end-to-end against an EMPTY data root without
    #    raising -- the "start with nothing present" resilience case. A bare host /
    #    empty bundle must yield a clean, all-gaps-disclosed report, never a crash.
    try:
        from openpath.engine import Engine
        from openpath.env import Env
        from openpath.model.timerange import build_range
        with tempfile.TemporaryDirectory(prefix="openpath-selfcheck-") as d:
            now = datetime.now(timezone.utc)
            env = Env(data_root=Path(d), now=now, local_tz=timezone.utc)
            window = build_range(expr="last 24 hours", since=None, until=None,
                                 now=now, default_tz=timezone.utc)
            report = Engine().readiness(env, window)
            # A report over an empty root must render and account for every source.
            _ = report.to_dict()
            n_sources = len(report.ledger.sources)
        ok = n_sources > 0
        checks.append(("pipeline", ok,
                       f"readiness over an empty root OK ({n_sources} sources probed, "
                       f"gaps disclosed)"))
    except Exception as exc:  # noqa: BLE001
        checks.append(("pipeline", False, f"{type(exc).__name__}: {exc}"))

    return checks


def render(checks: List[Check]) -> str:
    lines = []
    for name, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        lines.append(f"[{mark}] {name:11s} {detail}")
    healthy = all(ok for _n, ok, _d in checks)
    lines.append("")
    lines.append("SELFCHECK: HEALTHY" if healthy
                 else "SELFCHECK: UNHEALTHY (see FAIL above)")
    return "\n".join(lines)


def run() -> int:
    """Print the self-check report; return 0 if healthy, 1 otherwise."""
    checks = run_checks()
    print(render(checks))
    return 0 if all(ok for _n, ok, _d in checks) else 1
