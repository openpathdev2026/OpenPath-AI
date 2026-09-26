# D. 30-Day Host Trial — RED

_Generated 2026-09-26T15:35:27.940255+00:00 by scripts/run_release_gates.py — computed from executed checks._

## Executable checks

| check | result | evidence |
|-------|--------|----------|
| burst completed without cycle errors | PASS | 40/40 cycles, 0 errors |
| no collector failures | PASS | collector_failures=0 |
| memory does not grow unbounded (no leak signature) | PASS | RSS drift 48 KiB, peak 24572 KiB |
| bounded latency | PASS | latency {'min': 0.0186, 'max': 0.0309, 'mean': 0.0239} |

## Unmet blockers (keep this gate RED — not fabricated)

- **30-day CONTINUOUS trial (the irreducible wall-clock duration)**
  - why: a bounded burst was measured here; 30 days of runtime cannot elapse in a session and must not be simulated or assumed
  - closes when: `schedule scripts/host_trial.py under a systemd-timer/cron for 30 days, appending JSON; assert stability across the run`

## Detail

- latency s: {'min': 0.0186, 'max': 0.0309, 'mean': 0.0239}
- peak RSS: 24572 KiB, drift 48 KiB
- bounded burst; the 30-day continuous duration is the operator's run (schedule this harness under cron/systemd-timer, append output)

**Status: RED.** Executable checks above are real evidence; the gate stays RED until the blocker's closing command is run and recorded.
