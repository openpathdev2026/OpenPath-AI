"""Package-policy collector: repository provenance, version-locks, signature policy.

Answers the "is my software supply chain trustworthy?" questions from current
on-host configuration (not a timestamped act):

  * **PK-13** configured repositories (`/etc/yum.repos.d/*.repo`, `/etc/apt/
    sources.list[.d]`) and whether any points at an untrusted (non-distro) origin --
    the rogue-repo signal.
  * **PK-15** version-locks / holds (`dnf versionlock list`, apt pins in
    `/etc/apt/preferences.d/*`) that freeze a package (possibly at a vulnerable
    version).
  * **PK-16** GPG-signature policy (`gpgcheck` in `dnf.conf` and per-repo) -- a repo
    with `gpgcheck=0` accepts unsigned packages.
  * **PK-14** which package managers are present on the host and whether OpenPath
    captures them (a coverage self-report).

Emits ``EventType.PKG_POLICY``, each cited to the config file it came from. This is
host-level state; it is unattributed unless a file-change act ties a user to editing
the config.
"""

from __future__ import annotations

import re
from typing import List, Optional

from openpath.env import Env
from openpath.model.citation import Citation
from openpath.model.coverage import InstrumentationCheck, SourceCoverage, SourceStatus
from openpath.model.event import Event, EventType
from openpath.model.timerange import TimeRange
from openpath.sources.base import CollectResult, Collector

# Hostnames considered trusted first-party distro / major mirror origins. A repo
# baseurl outside these is flagged for review (not condemned) as a rogue-repo risk.
_TRUSTED_HOSTS = (
    "fedoraproject.org", "centos.org", "rockylinux.org", "almalinux.org",
    "redhat.com", "debian.org", "ubuntu.com", "canonical.com", "opensuse.org",
    "epel.cloud", "mirror", "mirrors", "download.opensuse.org", "packages.microsoft.com",
)
# Package managers OpenPath's PackageCollector actually parses today.
_CAPTURED_LOGS = {"var/log/dnf.rpm.log": "dnf/rpm", "var/log/dpkg.log": "apt/dpkg"}
# Managers whose presence we detect but do NOT yet parse (disclosed for PK-14).
_UNCAPTURED_LOGS = {
    "var/log/yum.log": "yum", "var/log/pacman.log": "pacman",
    "var/log/zypp/history": "zypper", "var/log/snapd.log": "snap",
    "var/lib/flatpak/history": "flatpak",
}

_KV = re.compile(r"^\s*(\w+)\s*=\s*(.+?)\s*$")


class PkgPolicyCollector(Collector):
    source_id = "pkgpolicy"

    def collect(self, env: Env, window: TimeRange) -> CollectResult:
        ts = env.now
        events: List[Event] = []
        locations: List[str] = []
        unparseable = 0

        def mk(kind, artifact, summary, rel, raw, *, extra=None):
            attrs = {"kind": kind, "artifact": artifact}
            if extra:
                attrs.update(extra)
            events.append(Event(
                ts=ts, type=EventType.PKG_POLICY, source_id=self.source_id,
                summary=summary, attrs=attrs,
                citations=[Citation(self.source_id, rel, raw)]))

        # -- global gpgcheck default (dnf.conf) ------------------------------- #
        default_gpgcheck = True
        conf = env.path("etc/dnf/dnf.conf")
        if conf.exists():
            locations.append(str(conf))
            for i, line in self._lines(conf):
                m = _KV.match(line)
                if m and m.group(1) == "gpgcheck":
                    default_gpgcheck = m.group(2).strip() not in ("0", "false", "no")

        # -- yum/dnf repositories (PK-13, PK-16) ------------------------------ #
        for p, r in self._glob(env, "etc/yum.repos.d/*.repo"):
            if p.is_dir():
                continue
            locations.append(str(p))
            for repo in self._parse_repo_file(p, r, default_gpgcheck):
                trusted = repo["trusted"]
                mk("repo", repo["id"],
                   f"repo '{repo['id']}' -> {repo['baseurl'] or '(no baseurl)'}"
                   + ("" if trusted else " [UNTRUSTED ORIGIN]")
                   + ("" if repo["gpgcheck"] else " [gpgcheck=0: unsigned allowed]"),
                   f"{r}", repo["raw"],
                   extra={"baseurl": repo["baseurl"], "enabled": repo["enabled"],
                          "gpgcheck": repo["gpgcheck"], "trusted": trusted})

        # -- apt sources (PK-13) ---------------------------------------------- #
        for rel in ["etc/apt/sources.list"]:
            p = env.path(rel)
            if p.exists():
                locations.append(str(p))
                for i, line in self._lines(p):
                    s = line.strip()
                    if not s or s.startswith("#") or not s.startswith("deb"):
                        continue
                    url = next((tok for tok in s.split() if "://" in tok), "")
                    trusted = self._trusted(url)
                    mk("repo", url, f"apt source {url}"
                       + ("" if trusted else " [UNTRUSTED ORIGIN]"),
                       f"{rel}:{i}", s, extra={"baseurl": url, "trusted": trusted})
        for p, r in self._glob(env, "etc/apt/sources.list.d/*"):
            if p.is_dir():
                continue
            locations.append(str(p))
            for i, line in self._lines(p):
                s = line.strip()
                if not s or s.startswith("#") or not s.startswith("deb"):
                    continue
                url = next((tok for tok in s.split() if "://" in tok), "")
                trusted = self._trusted(url)
                mk("repo", url, f"apt source {url}"
                   + ("" if trusted else " [UNTRUSTED ORIGIN]"),
                   f"{r}:{i}", s, extra={"baseurl": url, "trusted": trusted})

        # -- version-locks / holds (PK-15) ------------------------------------ #
        for rel in ["etc/dnf/plugins/versionlock.list",
                    "etc/yum/pluginconf.d/versionlock.list"]:
            p = env.path(rel)
            if p.exists():
                locations.append(str(p))
                for i, line in self._lines(p):
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    mk("versionlock", s, f"version-locked (dnf): {s}", f"{rel}:{i}", s,
                       extra={"package": s})
        for p, r in self._glob(env, "etc/apt/preferences.d/*"):
            if p.is_dir():
                continue
            locations.append(str(p))
            txt = self._read(p) or ""
            pkgs = re.findall(r"Package:\s*(.+)", txt)
            if "Pin-Priority: -" in txt or re.search(r"Pin-Priority:\s*-?\d", txt):
                for pk in pkgs:
                    mk("versionlock", pk.strip(), f"apt pin/hold: {pk.strip()}",
                       f"{r}", pk.strip(), extra={"package": pk.strip()})

        # Only report policy/coverage when the host actually has a package system
        # (a repo dir, dnf.conf, apt sources, or a package-manager log). On a host
        # with none, the question is UNANSWERABLE, not a fabricated default.
        captured = [lbl for rel, lbl in _CAPTURED_LOGS.items() if env.path(rel).exists()]
        uncaptured = [lbl for rel, lbl in _UNCAPTURED_LOGS.items()
                      if env.path(rel).exists()]
        has_system = bool(locations) or bool(captured) or bool(uncaptured)
        if not has_system:
            cov = SourceCoverage(
                source_id=self.source_id, status=SourceStatus.ABSENT,
                detail="no package-system configuration or logs found",
                instrumentation=[InstrumentationCheck(
                    "package configuration present", False,
                    "no /etc/yum.repos.d, /etc/apt sources, dnf.conf or package "
                    "logs found")])
            return CollectResult(events=[], coverage=cov)

        # -- gpg policy summary (PK-16) --------------------------------------- #
        gpg_state = "on" if default_gpgcheck else "OFF (unsigned packages accepted)"
        mk("gpg_policy", "gpgcheck-default",
           f"dnf default gpgcheck = {gpg_state}",
           "etc/dnf/dnf.conf" if conf.exists() else "(default)",
           f"gpgcheck={'1' if default_gpgcheck else '0'}",
           extra={"gpgcheck": default_gpgcheck})

        # -- coverage self-report (PK-14) ------------------------------------- #
        for rel, lbl in _UNCAPTURED_LOGS.items():
            if env.path(rel).exists():
                locations.append(str(env.path(rel)))
        mk("coverage", "package-manager-coverage",
           "package-manager coverage: OpenPath parses "
           + (", ".join(captured) or "none")
           + (f"; PRESENT BUT NOT PARSED: {', '.join(uncaptured)}"
              if uncaptured else "; no other package-manager logs detected"),
           "(coverage)", "package coverage self-report",
           extra={"captured": captured, "uncaptured": uncaptured})

        events.sort(key=lambda e: (e.attrs.get("kind", ""), e.summary))
        status = SourceStatus.AVAILABLE if events else SourceStatus.ABSENT
        cov = SourceCoverage(
            source_id=self.source_id, status=status,
            detail=f"{len(events)} package-policy artifact(s)",
            record_count=len(events), records_scanned=len(events) + unparseable,
            unparseable=unparseable, locations=locations,
            instrumentation=[
                InstrumentationCheck("repository config present",
                                     any(e.attrs.get("kind") == "repo" for e in events),
                                     "" if any(e.attrs.get("kind") == "repo"
                                               for e in events) else
                                     "no /etc/yum.repos.d or /etc/apt sources found"),
            ],
        )
        return CollectResult(events=events, coverage=cov)

    # -- helpers ------------------------------------------------------------- #
    def _parse_repo_file(self, p, rel, default_gpgcheck):
        repos = []
        cur = None
        text = self._read(p) or ""
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("[") and s.endswith("]"):
                if cur:
                    repos.append(cur)
                cur = {"id": s[1:-1], "baseurl": "", "enabled": True,
                       "gpgcheck": default_gpgcheck, "raw": s}
            elif cur is not None:
                m = _KV.match(s)
                if not m:
                    continue
                k, v = m.group(1), m.group(2).strip()
                if k in ("baseurl", "metalink", "mirrorlist"):
                    cur["baseurl"] = cur["baseurl"] or v
                elif k == "enabled":
                    cur["enabled"] = v not in ("0", "false", "no")
                elif k == "gpgcheck":
                    cur["gpgcheck"] = v not in ("0", "false", "no")
        if cur:
            repos.append(cur)
        for repo in repos:
            repo["trusted"] = self._trusted(repo["baseurl"])
        return repos

    def _trusted(self, url: str) -> bool:
        if not url:
            return True  # a mirrorlist/metalink with no baseurl -- not a rogue signal
        return any(host in url for host in _TRUSTED_HOSTS)

    def _glob(self, env, rel):
        root = env.data_root
        for p in sorted(root.glob(rel)):
            try:
                yield p, str(p.relative_to(root))
            except ValueError:
                yield p, rel

    def _lines(self, p):
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    yield i, line
        except OSError:
            return

    def _read(self, p) -> Optional[str]:
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
