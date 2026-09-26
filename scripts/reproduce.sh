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

step "Install by documented instructions (throwaway venv, no deps)"
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

step "Regenerate every evidence / sign-off artifact"
for g in gen_evidence_surface gen_architecture_trace gen_evidence_package \
         gen_signoff_package; do
  python3 "scripts/$g.py" >/dev/null 2>&1; check "$g.py regenerates" $?
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
python3 scripts/truth_corpus.py --data-root "$SCEN" \
  --truth tests/corpus/scenarios_ground_truth.json --now "$NOW" \
  --format text | tee /tmp/repro_corpus.log | tail -3
grep -q "10/10 matched" /tmp/repro_corpus.log; check "truth corpus 10/10 matched" $?

step "RESULT"
echo "  $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] && echo "  REPRODUCTION: OK" || echo "  REPRODUCTION: FAILED"
[[ "$FAIL" -eq 0 ]]
