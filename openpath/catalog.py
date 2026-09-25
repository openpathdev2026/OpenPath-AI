"""The frozen client question catalog -- OpenPath's contract.

This is the single source of truth for *what OpenPath promises to answer*. The
demo, the routing tests, the evidence-source doc, and the readiness story all
derive from this list. Adding or removing a question is a deliberate change to the
contract, made here.

Each entry ties a client-facing question to the facet that answers it, the
evidence sources it draws on, and whether it is certified (has a passing
conformance test asserting a correct, cited, gap-disclosing answer).

The facet layer is the *implementation*: one facet may serve more than one catalog
question (e.g. the `login` facet answers both "when" and "where"). The catalog is
the contract; facets are how it is met.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from openpath.model.evidence_matrix import EvidenceSpec

_S = EvidenceSpec.make

# The ten data facets a federated overview draws on.
_DATA_FACETS = ("sessions", "login", "privilege", "root_activity", "commands",
                "files", "accounts", "groups", "packages", "network")


@dataclass(frozen=True)
class CatalogQuestion:
    id: str            # "Q01"
    text: str          # client-facing phrasing, with {user}/{event} placeholders
    facet: str         # facet name that answers it
    sources: Tuple[str, ...]
    certified: bool
    # The federated evidence model for this question: which sources are the
    # primary carriers, which merely corroborate, and what confidence the answer
    # earns given what is present. Aggregate questions set only ``derived_from``.
    evidence: EvidenceSpec = field(default_factory=EvidenceSpec)


CATALOG: List[CatalogQuestion] = [
    CatalogQuestion("Q01", "What did {user} do during the last 24 hours?",
                    "core", ("all facets federated",), True,
                    _S(derived_from=_DATA_FACETS)),
    CatalogQuestion("Q02", "When did {user} log in during the last 24 hours?",
                    "login", ("wtmp", "journal.sshd", "auth"), True,
                    _S(certified=[["wtmp(wtmp accounting present)"],
                                  ["journal.sshd"], ["auth"]],
                       supporting=["btmp"],
                       fatal=["wtmp", "journal.sshd", "auth"])),
    CatalogQuestion("Q03", "Where did {user} log in from?",
                    "login", ("wtmp", "journal.sshd", "auth", "btmp"), True,
                    _S(certified=[["wtmp(wtmp accounting present)"],
                                  ["journal.sshd"], ["auth"]],
                       supporting=["btmp"],
                       fatal=["wtmp", "journal.sshd", "auth"])),
    CatalogQuestion("Q04", "What sessions did {user} have during the last 24 hours?",
                    "sessions", ("wtmp",), True,
                    _S(certified=[["wtmp(wtmp accounting present)"]],
                       fatal=["wtmp"])),
    CatalogQuestion("Q05", "Did {user} become root during the last 24 hours?",
                    "privilege", ("auditd", "auth"), True,
                    _S(certified=[["auditd(auditd rules loaded)"], ["auth"]],
                       supporting=["wtmp"], optional=["journal.sshd"],
                       fatal=["auditd", "auth"])),
    CatalogQuestion("Q06", "What did {user} do as root during the last 24 hours?",
                    "root_activity", ("auditd (execve)", "auth (sudo)"), True,
                    _S(certified=[["auditd(execve audit rule)"]],
                       partial=["auth"], supporting=["wtmp"],
                       fatal=["auditd", "auth"])),
    CatalogQuestion("Q07", "What commands did {user} run during the last 24 hours?",
                    "commands", ("auditd (execve)", "auth (sudo)"), True,
                    _S(certified=[["auditd(execve audit rule)"]],
                       partial=["auth"], fatal=["auditd", "auth"])),
    CatalogQuestion("Q08", "What files did {user} modify during the last 24 hours?",
                    "files", ("auditd (PATH+SYSCALL / watch)",), True,
                    _S(certified=[["auditd(host-wide file-change rule)"]],
                       partial=["auditd(file watch/modify audit rule)"],
                       supporting=["wtmp"], fatal=["auditd"])),
    CatalogQuestion("Q09", "What accounts did {user} create or modify during the last 24 hours?",
                    "accounts", ("auditd (ADD/DEL_USER)", "auth"), True,
                    _S(certified=[["auditd(auditd rules loaded)"]],
                       partial=["auth"], supporting=["wtmp"],
                       fatal=["auditd", "auth"])),
    CatalogQuestion("Q10", "What groups did {user} create or modify during the last 24 hours?",
                    "groups", ("auditd (ADD/DEL_GROUP)", "auth"), True,
                    _S(certified=[["auditd(auditd rules loaded)"]],
                       partial=["auth"], supporting=["wtmp"],
                       fatal=["auditd", "auth"])),
    CatalogQuestion("Q11", "What packages did {user} install or remove during the last 24 hours?",
                    "packages", ("dnf.rpm.log / dpkg.log", "exec correlation"), True,
                    _S(certified=[["packages(package transaction log present)",
                                   "auditd(execve audit rule)"],
                                  ["packages(package transaction log present)",
                                   "auth"]],
                       partial=["packages(package transaction log present)"],
                       fatal=["packages"])),
    CatalogQuestion("Q12", "What network activity did {user} perform during the last 24 hours?",
                    "network", ("auditd (connect/bind + SOCKADDR)",), True,
                    _S(certified=[["auditd(connect audit rule)",
                                   "auditd(bind audit rule)"]],
                       partial=["auditd(connect audit rule)",
                                "auditd(bind audit rule)"],
                       fatal=["auditd"])),
    CatalogQuestion("Q13", "What did {user} do before and after the incident?",
                    "timeline", ("all facets federated (pivoted with --around)",), True,
                    _S(derived_from=_DATA_FACETS)),
    CatalogQuestion("Q14", "What evidence supports what {user} did during the last 24 hours?",
                    "evidence", ("every claim's cited source record",), True,
                    _S(derived_from=_DATA_FACETS)),
    CatalogQuestion("Q15", "What could OpenPath not determine about {user} during the last 24 hours?",
                    "gaps", ("coverage ledger + blind spots + horizons",), True,
                    _S()),  # gaps is always answerable: its content IS the disclosure
]

_BY_FACET = {}
for _q in CATALOG:
    _BY_FACET.setdefault(_q.facet, _q)  # login -> Q02 (Q02/Q03 share the login spec)


def by_id(qid: str) -> CatalogQuestion:
    for q in CATALOG:
        if q.id == qid:
            return q
    raise KeyError(qid)


def spec_for_facet(facet_name: str) -> Optional[EvidenceSpec]:
    q = _BY_FACET.get(facet_name)
    return q.evidence if q else None
