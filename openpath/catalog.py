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

from dataclasses import dataclass
from typing import List, Tuple


@dataclass(frozen=True)
class CatalogQuestion:
    id: str            # "Q01"
    text: str          # client-facing phrasing, with {user}/{event} placeholders
    facet: str         # facet name that answers it
    sources: Tuple[str, ...]
    certified: bool


CATALOG: List[CatalogQuestion] = [
    CatalogQuestion("Q01", "What did {user} do during the last 24 hours?",
                    "core", ("all facets federated",), True),
    CatalogQuestion("Q02", "When did {user} log in during the last 24 hours?",
                    "login", ("wtmp", "journal.sshd", "auth"), True),
    CatalogQuestion("Q03", "Where did {user} log in from?",
                    "login", ("wtmp", "journal.sshd", "auth", "btmp"), True),
    CatalogQuestion("Q04", "What sessions did {user} have during the last 24 hours?",
                    "sessions", ("wtmp",), True),
    CatalogQuestion("Q05", "Did {user} become root during the last 24 hours?",
                    "privilege", ("auditd", "auth"), True),
    CatalogQuestion("Q06", "What did {user} do as root during the last 24 hours?",
                    "root_activity", ("auditd (execve)", "auth (sudo)"), True),
    CatalogQuestion("Q07", "What commands did {user} run during the last 24 hours?",
                    "commands", ("auditd (execve)", "auth (sudo)"), True),
    CatalogQuestion("Q08", "What files did {user} modify during the last 24 hours?",
                    "files", ("auditd (PATH+SYSCALL / watch)",), True),
    CatalogQuestion("Q09", "What accounts did {user} create or modify during the last 24 hours?",
                    "accounts", ("auditd (ADD/DEL_USER)", "auth"), True),
    CatalogQuestion("Q10", "What groups did {user} create or modify during the last 24 hours?",
                    "groups", ("auditd (ADD/DEL_GROUP)", "auth"), True),
    CatalogQuestion("Q11", "What packages did {user} install or remove during the last 24 hours?",
                    "packages", ("dnf.rpm.log / dpkg.log", "exec correlation"), True),
    CatalogQuestion("Q12", "What network activity did {user} perform during the last 24 hours?",
                    "network", ("auditd (connect/bind + SOCKADDR)",), True),
    CatalogQuestion("Q13", "What did {user} do before and after the incident?",
                    "timeline", ("all facets federated (pivoted with --around)",), True),
    CatalogQuestion("Q14", "What evidence supports what {user} did during the last 24 hours?",
                    "evidence", ("every claim's cited source record",), True),
    CatalogQuestion("Q15", "What could OpenPath not determine about {user} during the last 24 hours?",
                    "gaps", ("coverage ledger + blind spots + horizons",), True),
]


def by_id(qid: str) -> CatalogQuestion:
    for q in CATALOG:
        if q.id == qid:
            return q
    raise KeyError(qid)
