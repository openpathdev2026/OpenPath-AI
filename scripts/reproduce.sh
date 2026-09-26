#!/usr/bin/env bash
# Independent reproduction: prove the sign-off claims from a clean checkout, using
# the documented install path only. Intended to be run by someone who did NOT write
# the code -- self-verification can miss systemic assumptions; independent
# reproduction finds them.
#
#   git clone <repo> && cd OpenPath-AI
#   ./scripts/reproduce.sh
#
# It (1) installs OpenPath by its documented instructions into a throwaway venv,
# (2) runs the health probe and contract, (3) runs the full conformance + live
# suite, (4) regenerates every evidence/sign-off artifact, and (5) runs the Host
# Truth Corpus against the ten-scenario worked example. Exit 0 only if everything
# passes. No network, no privilege required.
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
PASS=0; FAIL=0
step(){ printf '\n=== %s ===\n' "$*"; }
ok(){   echo "  PASS: $*"; PASS=$((PASS+1)); }
bad(){  echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
check(){ # check "<label>" <exit-status>
  if [[ "$2" -eq 0 ]]; then ok "$1"; else bad "$1 (exit $2)"; fi
}

step "Environment"
python3 --version || { echo "python3 required"; exit 2; }

step "Install the package (throwaway venv) — the same install the Containerfile uses"
# `pip install --no-deps .` is exactly the Containerfile's install line (zero
# third-party deps, so nothing is fetched); it produces the openpath-ai console
# entry point pyproject declares. (README also documents the editable form
# `pip install -e .`; both yield the same entry point.)
VENV="$(mktemp -d)/venv"
python3 -m venv "$VENV"
# shellcheck disable=SC1091
"$VENV/bin/pip" install --no-cache-dir --no-deps -q . && ok "pip install --no-deps ." \
  || bad "pip install"

step "Health probe + contract (installed package)"
"$VENV/bin/openpath-ai" --selfcheck | grep -q "SELFCHECK: HEALTHY"; check "selfcheck HEALTHY" $?
"$VENV/bin/openpath-ai" --contract | grep -qE "CERTIFIED 153 +CONTRACTED 0"; check "contract 153/0" $?

step "Full conformance + live suite (from source)"
python3 -m unittest discover -s tests -p 'test_*.py' >/tmp/repro_tests.log 2>&1
check "unittest discover green" $?
tail -1 /tmp/repro_tests.log

step "Regenerate evidence / sign-off artifacts to a temp dir (working tree untouched)"
# Generate to --out under a temp dir so a clean checkout stays clean, and assert the
# regenerated artifact CONTAINS its load-bearing content -- so a generator that runs
# but emits wrong/empty output fails here, not silently passes on exit 0 alone.
TMPD="$(mktemp -d)"
for g in gen_evidence_surface gen_architecture_trace gen_evidence_package \
         gen_signoff_package; do
  case "$g" in
    gen_evidence_surface)  need="Evidence Surface" ;;
    gen_architecture_trace) need="Architecture Trace" ;;
    gen_evidence_package)  need="153 questions" ;;
    gen_signoff_package)   need="Go / No-Go" ;;
  esac
  out="$TMPD/$g.md"
  python3 "scripts/$g.py" --out "$out" >/dev/null 2>&1
  rc=$?
  if [[ $rc -eq 0 && -s "$out" ]] && grep -qF "$need" "$out"; then
    ok "$g.py regenerates and contains '$need'"
  else
    bad "$g.py regenerate/content (exit $rc)"
  fi
done

step "Host Truth Corpus — ten investigation scenarios"
NOW="2026-09-25T12:00:00Z"
SCEN="$(mktemp -d)/scenhost"
python3 - "$SCEN" <<PY
import sys
from datetime import datetime, timezone
from tests.corpus.build_scenario_host import build
from pathlib import Path
build(Path(sys.argv[1]), datetime(2026,9,25,12,0,0,tzinfo=timezone.utc))
PY
# Redirect (no pipe) so truth_corpus.py's exit code is preserved, then check BOTH
# the exit code (0 == every case matched) AND the printed tally.
python3 scripts/truth_corpus.py --data-root "$SCEN" \
  --truth tests/corpus/scenarios_ground_truth.json --now "$NOW" \
  --format text > /tmp/repro_corpus.log 2>&1
rc=$?
tail -3 /tmp/repro_corpus.log
if [[ $rc -eq 0 ]] && grep -q "10/10 matched" /tmp/repro_corpus.log; then
  ok "truth corpus 10/10 matched (exit 0)"
else
  bad "truth corpus (exit $rc)"
fi

step "RESULT"
echo "  $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] && echo "  REPRODUCTION: OK" || echo "  REPRODUCTION: FAILED"
[[ "$FAIL" -eq 0 ]]
