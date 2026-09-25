#!/usr/bin/env bash
# Live conformance on a REAL, fully-instrumented auditd host.
#
# This is the complement to the synthetic conformance suite: it loads the
# recommended audit rules, performs a known sequence of real actions as a test
# user, then runs OpenPath-AI against the live host and checks that the catalog
# questions report the activity with evidence -- and attributes root actions
# to the base user who escalated.
#
# REQUIREMENTS: root, a running auditd, and a real (non-container) host or VM
# where the kernel audit subsystem accepts rules. It WILL NOT work inside an
# unprivileged container (the audit subsystem is host-global and not namespaced).
#
# Usage:  sudo ./scripts/live_conformance.sh
# Env:    OPENPATH="python3 -m openpath"   (override how the CLI is invoked)
#         KEEP=1                            (do not delete the test user at the end)
set -uo pipefail

OPENPATH="${OPENPATH:-python3 -m openpath}"
TESTUSER="${TESTUSER:-openpath_probe}"
PASS=0; FAIL=0
say()  { printf '\n=== %s ===\n' "$*"; }
check(){ # check "<label>" "<needle>" <<<"$output"
  local label="$1" needle="$2" text; text="$(cat)"
  if grep -qiF -- "$needle" <<<"$text"; then
    echo "  PASS: $label"; PASS=$((PASS+1))
  else
    echo "  FAIL: $label (expected to find: $needle)"; FAIL=$((FAIL+1))
  fi
}

[[ "$(id -u)" -eq 0 ]] || { echo "must run as root"; exit 2; }
command -v auditctl >/dev/null || { echo "auditctl not found; install auditd"; exit 2; }

say "Loading recommended audit rules"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
auditctl -R "$HERE/contrib/openpath.rules" || auditctl -l
auditctl -l | sed 's/^/  rule: /' | head -20

say "Generating known activity as $TESTUSER"
id "$TESTUSER" >/dev/null 2>&1 || useradd -m "$TESTUSER"
# a command as the user, a command as root via sudo, a file change, a connection,
# and an account change -- one per auditd-backed question.
sudo -u "$TESTUSER" /bin/ls -la /tmp >/dev/null 2>&1 || true
sudo -u "$TESTUSER" sudo -n /usr/bin/id >/dev/null 2>&1 || true   # may prompt; best-effort
touch /etc/openpath_probe_marker 2>/dev/null || true
sudo -u "$TESTUSER" bash -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>/dev/null || true
groupadd openpath_probe_grp 2>/dev/null || true
sleep 2  # let auditd flush

W='--window "last 1 hour"'
run(){ eval "$OPENPATH --user \"$1\" --facet \"$2\" $W \"x\""; }

say "Q3 Sessions"       ; run "$TESTUSER" sessions      | check "sessions runs" "Sessions"
say "Q5 Privilege"      ; run "$TESTUSER" privilege     | check "privilege runs" "Privilege"
say "Q7 Commands"       ; run "$TESTUSER" commands      | check "ls recorded" "ls"
say "Q8 Files"          ; run root files                | check "files runs" "Files"
say "Q9 Accounts"       ; run root accounts             | check "group change" "openpath_probe_grp"
say "Q11 Network"       ; run "$TESTUSER" network        | check "network runs" "Network"
say "Q6 Root activity"  ; run root root_activity         | check "root attribution" "attributed"
say "Q12 Evidence"      ; run "$TESTUSER" evidence       | check "evidence cited" "record(s)"
say "Q13 Gaps"          ; run "$TESTUSER" gaps           | check "gaps runs" "Gaps"

say "Cleanup"
rm -f /etc/openpath_probe_marker
groupdel openpath_probe_grp 2>/dev/null || true
if [[ "${KEEP:-0}" != "1" ]]; then userdel -r "$TESTUSER" 2>/dev/null || true; fi

say "RESULT: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
