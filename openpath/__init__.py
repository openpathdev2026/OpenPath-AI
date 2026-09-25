"""OpenPath-AI: evidence-first forensic Q&A over Linux user activity.

Design principle (the only thing that makes "100% accuracy" an honest claim):

    * Soundness  - every asserted fact carries a citation to a raw source record
                   (question family 12, "Evidence").
    * Disclosure - anything that cannot be determined is reported explicitly with
                   a reason, never returned as a silent empty result
                   (question family 13, "Gaps").

Under those two invariants the product answers all 13 question families for *any*
user (present, newly created, deleted, or never-existed) over *any* time range,
without hardcoding to the users that happen to exist on a given host.
"""

from openpath.version import __version__

__all__ = ["__version__"]
