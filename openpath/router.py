"""Route a natural-language question to a facet, and best-effort extract the
subject and time expression.

Design boundary: the *analysis* is what carries the soundness guarantee, not the
English parsing. Routing to the right facet is highly reliable (distinctive verbs
per family). Extracting the username from free text is only a convenience; the
authoritative way to name the subject is the ``--user`` flag (or the ``<user>``
token in the demo phrasing). When extraction is ambiguous the CLI asks for
``--user`` rather than guessing, so we never analyze the wrong account silently.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

# Ordered (facet_name, keyword-patterns). First matching rule wins, so more
# specific families are listed before more general ones. Ordering resolves the
# genuine overlaps in the canonical phrasings: "software ... change" must route to
# packages before files sees "change"; "connect from" must route to login before
# network sees "connect"; "become root" is privilege while "as root" is activity.
_ROUTES: List[Tuple[str, List[str]]] = [
    ("gaps", [r"could .*not determine", r"couldn'?t determine",
              r"\bgaps?\b", r"blind spots?", r"unable to determine"]),
    ("evidence", [r"\bevidence\b", r"what supports", r"\bproof\b", r"substantiat"]),
    ("timeline", [r"chronolog", r"\btimeline\b", r"in order",
                  r"everything .*\bdid\b", r"time ?line"]),
    ("sessions", [r"\bsessions?\b"]),
    ("login", [r"log ?in", r"logged in", r"connect from", r"where .* connect",
               r"when did .* log", r"authenticat", r"where .* from"]),
    ("root_activity", [r"do as root", r"as root\b", r"activity as root",
                       r"while root"]),
    ("privilege", [r"become root", r"became root", r"gain(ed)? root",
                   r"\bprivilege", r"\bsudo\b", r"\bsu\b", r"escalat", r"elevat"]),
    ("accounts", [r"\baccounts?\b", r"\bgroups?\b",
                  r"\busers?\b.*(add|remov|creat|delet|change|modif)"]),
    ("packages", [r"software", r"packages?", r"install", r"uninstall",
                  r"\brpm\b", r"\bdnf\b", r"\bapt\b", r"\byum\b", r"\bpacman\b"]),
    ("network", [r"network", r"\bconnection", r"\bbind\b", r"\blisten",
                 r"outbound", r"inbound", r"\bsocket", r"remote host"]),
    ("files", [r"\bfiles?\b", r"filesystem", r"\bpaths?\b"]),
    ("commands", [r"\bcommands?\b", r"what .* execute", r"programs? .* r[au]n",
                  r"\bexecuted?\b", r"what .* ran\b"]),
    ("core", [r".*"]),  # fallback: "what did X do ..."
]

_RELATIVE_TIME_RE = re.compile(
    r"\b((?:last|past|previous)\s+(?:\d+\s+)?"
    r"(?:second|minute|hour|day|week|month)s?)\b",
    re.IGNORECASE,
)
_TODAY_RE = re.compile(r"\b(today|yesterday)\b", re.IGNORECASE)
_RANGE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)?"
    r"\s*(?:\.\.|/|to)\s*"
    r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)?)"
)

# Words that can appear in the "did <token>" position but are never a username.
_STOPWORDS = {
    "openpath", "the", "a", "an", "what", "who", "when", "where", "which",
    "everything", "not", "anything", "something", "it", "they",
    "he", "she", "show", "me", "during", "do", "did", "does",
    # family nouns that must never be mistaken for a username by the fallbacks
    "command", "commands", "file", "files", "software", "package", "packages",
    "network", "account", "accounts", "group", "groups", "session", "sessions",
    "evidence", "activity", "user", "users", "gap", "gaps", "login",
    "chronologically", "connect",
}


def route(question: str) -> str:
    """Return the facet name best matching the question."""
    q = question.lower()
    for facet_name, patterns in _ROUTES:
        for pat in patterns:
            if re.search(pat, q):
                return facet_name
    return "core"


def extract_time(question: str) -> Optional[str]:
    """Best-effort extraction of a time expression from the question."""
    m = _RANGE_RE.search(question)
    if m:
        return m.group(1).strip()
    m = _RELATIVE_TIME_RE.search(question)
    if m:
        return m.group(1).strip()
    m = _TODAY_RE.search(question)
    if m:
        return m.group(1).lower()
    return None


# A verb that typically follows the subject in the canonical phrasings. Used to
# anchor the far-more-reliable "did <name> <verb>" pattern.
_SUBJECT_VERBS = (
    r"do|does|did|execute[d]?|change[d]?|install|installed|remove[d]?|perform(?:ed)?|"
    r"become|became|have|has|had|log|logged|connect(?:ed)?|run|ran|modif"
)


def extract_user(question: str) -> Optional[str]:
    """Best-effort extraction of the subject username.

    Uses an ordered list of patterns and returns the first, left-most, non-stopword
    match. The high-precision anchors ("about <name>", "did <name> <verb>",
    "<name> did") are tried before the loose fallback so that phrasings like
    "What commands did alice execute" resolve to *alice*, not to "commands".
    Returns None when nothing confident is found (the CLI then asks for --user).
    """
    patterns = [
        rf"\babout\s+([A-Za-z_][\w.\-]*)",                        # "about alice"
        rf"\bdid\s+([A-Za-z_][\w.\-]*)\s+(?:{_SUBJECT_VERBS})\b",  # "did alice execute"
        rf"\b([A-Za-z_][\w.\-]*)\s+did\b",                        # "alice did"
        rf"\bdid\s+([A-Za-z_][\w.\-]*)\b",                        # fallback "did alice"
        rf"\b([A-Za-z_][\w.\-]*)\s+(?:logged|connected|ran)\b",
    ]
    for pat in patterns:
        for m in re.finditer(pat, question, re.IGNORECASE):
            tok = m.group(1)
            if tok.lower() not in _STOPWORDS:
                return tok
    return None
