"""Collectors and the default registry.

Each collector reads one raw source under ``env.data_root`` and returns normalized,
cited events plus a coverage report. The registry is the ordered set the engine
runs for a full analysis.
"""

from typing import List

from openpath.sources.auditd import AuditdCollector
from openpath.sources.auth import SyslogAuthCollector
from openpath.sources.authz import AuthzCollector
from openpath.sources.base import CollectResult, Collector
from openpath.sources.conntrack import ConntrackCollector
from openpath.sources.file_integrity import FileIntegrityCollector
from openpath.sources.firewall import FirewallCollector
from openpath.sources.ip_reputation import IpReputationCollector
from openpath.sources.shell_history import ShellHistoryCollector
from openpath.sources.btmp import BtmpCollector
from openpath.sources.journal_sshd import SshdJournalCollector
from openpath.sources.journald import GeneralJournaldCollector
from openpath.sources.netlogs import NetLogsCollector
from openpath.sources.packages import PackageCollector
from openpath.sources.persistence import PersistenceCollector
from openpath.sources.pkgpolicy import PkgPolicyCollector
from openpath.sources.wtmp import WtmpCollector


def default_collectors() -> List[Collector]:
    return [
        WtmpCollector(),
        BtmpCollector(),
        SshdJournalCollector(),
        AuditdCollector(),
        SyslogAuthCollector(),
        PackageCollector(),
        PersistenceCollector(),
        AuthzCollector(),
        GeneralJournaldCollector(),
        PkgPolicyCollector(),
        ShellHistoryCollector(),
        FirewallCollector(),
        ConntrackCollector(),
        NetLogsCollector(),
        FileIntegrityCollector(),
        IpReputationCollector(),
    ]


__all__ = [
    "Collector",
    "CollectResult",
    "WtmpCollector",
    "BtmpCollector",
    "SshdJournalCollector",
    "GeneralJournaldCollector",
    "AuditdCollector",
    "SyslogAuthCollector",
    "PackageCollector",
    "PersistenceCollector",
    "AuthzCollector",
    "PkgPolicyCollector",
    "ShellHistoryCollector",
    "FirewallCollector",
    "ConntrackCollector",
    "NetLogsCollector",
    "FileIntegrityCollector",
    "IpReputationCollector",
    "default_collectors",
]
