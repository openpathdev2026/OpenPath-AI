"""System lifecycle (family, host-level): when did the host boot/reboot, how long
was it up, what kernel ran, and who initiated a reboot?

This is a *host-level* facet -- its answers are about the machine, not a single
user, so it does not filter by subject and is deliberately NOT folded into the
per-user Core overview (alice's activity report must not claim the host's reboots
as hers). It reads the boot record wtmp already emits (``EventType.BOOT``, one per
boot with the kernel release and a citation) plus, where present, the audited
reboot/shutdown commands that explain who initiated a restart, and the
``EventType.SYSTEM`` lifecycle events a general-journal collector contributes
(shutdown, service transitions, panics, clock changes).

Everything is evidence-scoped: uptime between two boots is a span that MAY include
downtime, so without a shutdown carrier the facet reports the boot-to-boot span and
discloses that the offline portion is unmeasured rather than asserting exact uptime.
"""

from __future__ import annotations

from datetime import timedelta
from typing import List, Optional

from openpath.facets.base import AnalysisContext, Facet, Requirement, source_met
from openpath.model.coverage import Gap
from openpath.model.event import Event, EventType
from openpath.model.finding import Finding

# Commands that initiate a restart/shutdown (basename or systemctl subcommand).
_REBOOT_TOOLS = {"reboot", "shutdown", "poweroff", "halt", "init", "telinit"}
_SYSTEMCTL_REBOOT = {"reboot", "poweroff", "halt", "kexec", "rescue", "emergency"}
# How long before a BOOT an initiating command may have run.
_INITIATE_WINDOW = timedelta(minutes=5)


def _fmt(td: timedelta) -> str:
    secs = int(td.total_seconds())
    if secs < 0:
        secs = 0
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m, _s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h or d:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)


def _is_reboot_exec(e: Event) -> bool:
    exe = (e.attrs.get("exe") or "")
    base = exe.rsplit("/", 1)[-1] if exe else (e.attrs.get("comm") or "")
    if base in _REBOOT_TOOLS:
        return True
    if base == "systemctl":
        cmd = (e.attrs.get("cmdline") or "").split()
        return any(tok in _SYSTEMCTL_REBOOT for tok in cmd)
    return False


class SystemLifecycleFacet(Facet):
    name = "system_lifecycle"
    question_family = "System lifecycle"
    requirements = (
        Requirement("wtmp", "System lifecycle",
                    instrument="wtmp accounting present",
                    remedy="provide wtmp (boot accounting) so host boot/reboot "
                           "history can be reconstructed."),
    )

    def analyze(self, ctx: AnalysisContext) -> Finding:
        f = self._new_finding(ctx)
        f.gaps.extend(self._prereq_gaps(ctx))

        boots = sorted((e for e in ctx.events if e.type is EventType.BOOT),
                       key=lambda e: e.ts)
        sysev = sorted((e for e in ctx.events if e.type is EventType.SYSTEM),
                       key=lambda e: e.ts)
        reboot_execs = sorted(
            (e for e in ctx.events
             if e.type is EventType.EXEC and _is_reboot_exec(e)),
            key=lambda e: e.ts)
        now = ctx.window.end

        f.events = boots + sysev
        f.events.sort(key=lambda e: e.ts)

        if not boots and not sysev:
            f.summary = (
                "No boot or shutdown was recorded within the window; the host was "
                "up throughout (it booted before the window) -- an evidenced "
                "negative within the covered evidence scope, not an absolute claim.")
            return f

        # -- reboot count + frequency (SL-02) -- #
        n = len(boots)
        # -- kernel per boot + change (SL-10 boot half) -- #
        kernels = [b.attrs.get("kernel") for b in boots if b.attrs.get("kernel")]
        kernel_change = len(set(kernels)) > 1

        # -- who initiated each boot (SL-08): a reboot command just before it -- #
        initiators = []
        initiating_execs: List[Event] = []
        for b in boots:
            actor = None
            for ex in reboot_execs:
                if b.ts - _INITIATE_WINDOW <= ex.ts <= b.ts:
                    actor = ex.actor_name or (f"auid {ex.auid}" if ex.auid is not None
                                              else "?")
                    initiating_execs.append(ex)  # keep the cited command as evidence
            if actor:
                initiators.append((b.ts, actor))
                f.notes.append(f"[initiated] boot at {b.ts.isoformat()} was preceded "
                               f"by a reboot command from {actor}")
        for ex in initiating_execs:
            if ex not in f.events:            # identity dedup (Events are unhashable)
                f.events.append(ex)
        f.events.sort(key=lambda e: e.ts)

        # -- uptime windows (SL-06) + offline/blind intervals (SL-07) -- #
        # A shutdown carrier lets downtime be measured; without one it is disclosed.
        shutdowns = [e for e in sysev
                     if e.attrs.get("kind") in ("shutdown", "poweroff")]
        for i, b in enumerate(boots):
            end = boots[i + 1].ts if i + 1 < len(boots) else now
            f.notes.append(
                f"[uptime] boot {b.ts.isoformat()} -> "
                f"{'next boot ' + boots[i+1].ts.isoformat() if i+1 < len(boots) else 'now'}"
                f" (span {_fmt(end - b.ts)}"
                + (", current" if i + 1 == len(boots) else "") + ")")
        # pre-first-boot blind interval (nothing could be recorded before it)
        if boots and ctx.window.start < boots[0].ts:
            f.notes.append(
                f"[blind] {ctx.window.start.isoformat()} -> {boots[0].ts.isoformat()}: "
                f"host was down/booting before the first in-window boot "
                f"({_fmt(boots[0].ts - ctx.window.start)} with no recordable activity)")

        # -- SYSTEM lifecycle events (SL-04/05/09/11/12/13/14) -- #
        by_kind: dict = {}
        for e in sysev:
            k = e.attrs.get("kind", "system")
            by_kind.setdefault(k, []).append(e)
        for k in sorted(by_kind):
            evs = by_kind[k]
            f.notes.append(f"[{k}] {len(evs)} event(s): "
                           + "; ".join(e.summary for e in evs[:5]))
        crash_kinds = {"kernel_panic", "oom", "watchdog"}
        crashed = [e for e in sysev if e.attrs.get("kind") in crash_kinds]
        clean = bool(shutdowns)

        # Between-reboot downtime is unmeasured without a shutdown carrier.
        if n > 1 and not shutdowns and not source_met(ctx, "journald"):
            f.gaps.append(Gap(
                "System lifecycle",
                "boot times are authoritative, but the time the host spent DOWN "
                "between reboots is not measurable without a shutdown carrier "
                "(general journald / RUN_LVL), so a boot-to-boot span is an upper "
                "bound on uptime, not exact.",
                "journald",
                "add a general journald collector so clean-shutdown / poweroff "
                "events bound the downtime between reboots."))

        current_uptime = _fmt(now - boots[-1].ts) if boots else "unknown"
        kbit = (f"; kernel(s) {', '.join(sorted(set(kernels)))}"
                + (" (CHANGED across boots)" if kernel_change else "")) if kernels else ""
        life = []
        if shutdowns:
            life.append(f"{len(shutdowns)} clean shutdown/power-off")
        if crashed:
            life.append(f"{len(crashed)} crash/panic/OOM event(s)")
        if by_kind.get("service_failed"):
            life.append(f"{len(by_kind['service_failed'])} service failure(s)")
        if by_kind.get("clock_change"):
            life.append("a system-clock change")
        if by_kind.get("boot_target"):
            life.append("an unusual boot target (rescue/emergency)")
        lifebit = (" Lifecycle: " + ", ".join(life) + "." if life else "")
        f.summary = (
            f"The host booted {n} time(s) in {ctx.window.label or 'the window'}"
            f"{' (last ' + boots[-1].ts.isoformat() + ')' if boots else ''}; "
            f"current uptime {current_uptime}{kbit}."
            + (f" {len(initiators)} reboot(s) tied to an initiating command."
               if initiators else "")
            + lifebit)
        return f
