# OpenPath-AI — Production Readiness

Status at this milestone: **the full production question contract is CERTIFIED —
153 / 153, CONTRACTED 0, PARTIAL 0 (at the catalog level).**

Every user-facing forensic question OpenPath commits to is answered end-to-end
through the shipped CLI with **cited, evidence-scoped, gap-disclosing** findings.
This document is the readiness matrix: what "CERTIFIED" means, how each question is
proven, the invariants that keep answers honest, and the runtime boundaries.

## What CERTIFIED means (and does not)

CERTIFIED is a property of a **question**: its deterministic evidence path exists
and is proven end-to-end (RAW → parse → normalized `Event` → correlation → query →
answer → provenance → negative behavior → shipped CLI). It is **not** a promise
that every host can answer it. Runtime confidence is separate and per-host:

| Confidence (runtime) | Meaning |
|----------------------|---------|
| CERTIFIED | the sources that record this class of activity were present + instrumented; complete *within the covered evidence scope* |
| PARTIAL | substantive and cited, but a named scope/coverage gap is disclosed |
| UNANSWERABLE | no usable carrier present — "cannot determine (see gaps)" **with a named remedy**, never a false negative |

So a CERTIFIED question on a host that lacks its evidence source returns
UNANSWERABLE with the exact remedy (e.g. "load an execve audit rule") — exactly as
the original wired questions (commands, files, network) already behaved. Nothing is
answered from thin air.

## Evidence surface (16 collectors)

Each collector reads a real on-host format under a configurable `--data-root`
(offline evidence bundles work identically to a live host), normalizes to cited
`Event`s, and reports a `SourceCoverage` with conservation counters.

`wtmp` · `btmp` · `journal.sshd` · `auditd` (+ read watches) · `auth` (syslog) ·
`packages` (dnf/dpkg) · `persistence` (cron/at, systemd units/timers, linger,
startup) · `authz` (group/sudoers/shadow, authorized_keys, sshd_config) · `journald`
(general: lifecycle + non-SSH PAM auth + faillock) · `pkgpolicy` (repos, versionlock,
gpg, coverage) · `shell_history` · `firewall` (nft/iptables) · `conntrack` ·
`netlogs` (DNS / firewall-drop / proxy / socket-lifetime) · `file_integrity` (FIM
content diffs) · `ip_reputation` (geo / threat-intel feed).

## Soundness invariants (enforced by the conformance suite)

- **Soundness** — every asserted fact carries a citation. Guarded by
  `test_every_certified_facet_answerable_and_cited` (every certified facet, on a
  fully-instrumented host, is answerable and emits only cited events) and by the
  per-family evidence assertions.
- **Disclosure** — an absent/narrow/uninstrumented source is a disclosed gap with a
  remedy, never a silent blank. Verified on a **bare host** for every facet.
- **Evidenced negatives** — "the user did NOT do X" is only stated when the source
  that would record X was present and instrumented; otherwise it is UNANSWERABLE.
  Negatives are always scoped ("within the covered evidence scope, not an absolute
  claim").
- **Attribution** — auid-centric (survives sudo/su); host-wide data is never
  presented as user-attributed; scheduler/daemon activity is disclosed as
  unattributable rather than blamed on a human.
- **Conservation** — records scanned vs emitted vs unparseable are counted per
  source; an undecodable record degrades confidence rather than vanishing.
- **Spec ↔ requirement consistency** — each data facet's `EvidenceSpec`
  answerability set equals its facet requirement sources; aggregates' `derived_from`
  equals the federated data facets.
- **Shipped path** — every certification runs through `main()` (the CLI), not a
  test-only shortcut.
- **No silent over-certification** — the certified set is pinned; a question cannot
  flip to CERTIFIED without a proving test and a runnable facet.

## Runtime boundaries (honest scope, not gaps in the contract)

Some questions depend on evidence a default host does not retain. These are
CERTIFIED (the path is built and proven with the evidence present) and degrade to a
remedied UNANSWERABLE without it:

- **Content-level file diffs (FS-13)** need a file-integrity monitor / content
  snapshot — auditd records the change act, never file content.
- **Origin reputation / geo (IA-10)** needs a threat-intel / geo feed — OpenPath is
  deterministic and offline; it reports what the provided feed says, cited.
- **DNS / firewall-drop / proxy / socket-lifetime (NW-08/10/12/15)** need resolver
  logging, firewall LOG rules, a proxy log, or a socket tracer respectively.
- **Data volume (NW-04)** needs conntrack byte accounting (`nf_conntrack_acct`).
- **Process ancestry (EX-11)** reconstructs the exec chain from `pid`/`ppid`; a
  fork/clone that never exec'd is shown as an unresolved parent, not invented.
- **Shell history (EX-12)** is a lead, not proof of execution (user-editable,
  usually un-timestamped) — always disclosed as such.

## Quality metrics

- 153 / 153 questions CERTIFIED (CONTRACTED 0).
- 29 facets, 16 collectors, ~11k LOC, zero third-party dependencies (stdlib only).
- 233 conformance tests green, including adversarial cases (wrong-user isolation,
  scoped-negative-not-absolute, provenance, path-boundary, contradictory flags,
  read-not-a-write, reply-tuple direction, bare-host disclosure).

## How to reproduce

```
python3 -m unittest discover -s tests -p 'test_*.py'   # full conformance suite
openpath-ai --contract                                 # 153 CERTIFIED / 0 CONTRACTED
openpath-ai --coverage --data-root <bundle>            # per-host readiness self-check
```
