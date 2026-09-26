"""Facet registry: the question families that implement the catalog.

Each entry ties a stable facet ``name`` to its human family label and the class
that answers it. One facet may serve more than one catalog question (e.g.
``login`` answers both Q02 "when" and Q03 "where"). The CLI router maps a
natural-language question to one of these names; the engine instantiates and
runs it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Type

from openpath.facets.accounts import AccountsFacet, GroupsFacet
from openpath.facets.authorization import AuthorizationFacet
from openpath.facets.base import AnalysisContext, Facet
from openpath.facets.file_access import FileAccessFacet
from openpath.facets.files import FilesFacet
from openpath.facets.firewall import FirewallFacet
from openpath.facets.lifecycle import SystemLifecycleFacet
from openpath.facets.meta import CoreFacet, EvidenceFacet, GapsFacet
from openpath.facets.netflow import NetflowFacet
from openpath.facets.network import NetworkFacet
from openpath.facets.packages import PackagesFacet
from openpath.facets.persistence import PersistenceFacet
from openpath.facets.pkgpolicy import PackagePolicyFacet
from openpath.facets.proctree import ProcessTreeFacet
from openpath.facets.shell_history import ShellHistoryFacet
from openpath.facets.privilege import (
    CommandsFacet,
    PrivilegeFacet,
    RootActivityFacet,
)
from openpath.facets.sessions import LoginFacet, SessionsFacet
from openpath.facets.temporal import (
    AttributionFacet,
    ConcurrentFacet,
    HostChangesFacet,
)
from openpath.facets.timeline import TimelineFacet


@dataclass(frozen=True)
class FamilySpec:
    number: int
    name: str
    label: str
    cls: Type[Facet]


# The canonical 13-question taxonomy, in demo order.
FAMILIES: List[FamilySpec] = [
    FamilySpec(1, "core", "Core", CoreFacet),
    FamilySpec(2, "timeline", "Timeline", TimelineFacet),
    FamilySpec(3, "sessions", "Sessions", SessionsFacet),
    FamilySpec(4, "login", "Login", LoginFacet),
    FamilySpec(5, "privilege", "Privilege", PrivilegeFacet),
    FamilySpec(6, "root_activity", "Root activity", RootActivityFacet),
    FamilySpec(7, "commands", "Commands", CommandsFacet),
    FamilySpec(8, "files", "Files", FilesFacet),
    FamilySpec(9, "accounts", "Accounts", AccountsFacet),
    FamilySpec(10, "groups", "Groups", GroupsFacet),
    FamilySpec(11, "packages", "Packages", PackagesFacet),
    FamilySpec(12, "network", "Network", NetworkFacet),
    FamilySpec(13, "persistence", "Persistence", PersistenceFacet),
    FamilySpec(14, "authorization", "Authorization", AuthorizationFacet),
    FamilySpec(15, "system_lifecycle", "System lifecycle", SystemLifecycleFacet),
    FamilySpec(16, "pkg_policy", "Package policy", PackagePolicyFacet),
    FamilySpec(17, "process_tree", "Process ancestry", ProcessTreeFacet),
    FamilySpec(18, "shell_history", "Shell history", ShellHistoryFacet),
    FamilySpec(19, "firewall", "Firewall", FirewallFacet),
    FamilySpec(20, "file_access", "File access", FileAccessFacet),
    FamilySpec(21, "netflow", "Network flows", NetflowFacet),
    FamilySpec(22, "host_changes", "Host changes", HostChangesFacet),
    FamilySpec(23, "attribution", "Attribution", AttributionFacet),
    FamilySpec(24, "concurrent", "Concurrent activity", ConcurrentFacet),
    FamilySpec(25, "evidence", "Evidence", EvidenceFacet),
    FamilySpec(26, "gaps", "Gaps", GapsFacet),
]

_BY_NAME: Dict[str, FamilySpec] = {spec.name: spec for spec in FAMILIES}
_BY_NUMBER: Dict[int, FamilySpec] = {spec.number: spec for spec in FAMILIES}


def get_facet(name: str) -> Facet:
    spec = _BY_NAME.get(name)
    if spec is None:
        raise KeyError(f"unknown facet: {name}")
    return spec.cls()


def get_spec(name: str) -> FamilySpec:
    return _BY_NAME[name]


def spec_by_number(number: int) -> FamilySpec:
    return _BY_NUMBER[number]


__all__ = [
    "AnalysisContext",
    "Facet",
    "FamilySpec",
    "FAMILIES",
    "get_facet",
    "get_spec",
    "spec_by_number",
]
