#!/usr/bin/env bash
# Snapshot a host's forensic evidence into a self-contained bundle that
# OpenPath-AI can analyze offline with --data-root <bundle>.
#
# The bundle mirrors the real filesystem layout under a directory, so the same
# collectors run against it unchanged. Run as root to read /var/log/audit and
# /etc/shadow-adjacent files; without root it captures whatever is readable and
# the coverage ledger will disclose what was missed.
#
# Usage:  sudo ./scripts/collect_bundle.sh /path/to/bundle
set -euo pipefail

DEST="${1:?usage: collect_bundle.sh <dest-dir>}"
mkdir -p "$DEST"

copy() {  # copy SRC preserving its path under DEST, if it exists
  local src="$1"
  [[ -e "$src" ]] || return 0
  local rel="${src#/}"
  mkdir -p "$DEST/$(dirname "$rel")"
  cp -a "$src" "$DEST/$rel" 2>/dev/null || true
}

# Sessions / login
copy /var/log/wtmp
copy /var/log/wtmp.1
# auditd log + the loaded rules (so instrumentation coverage is captured too)
for f in /var/log/audit/audit.log /var/log/audit/audit.log.1 \
         /var/log/audit/audit.log.2 /var/log/audit/audit.log.3 \
         /var/log/audit/audit.log.4; do copy "$f"; done
copy /etc/audit/audit.rules
if [[ -d /etc/audit/rules.d ]]; then
  mkdir -p "$DEST/etc/audit/rules.d"; cp -a /etc/audit/rules.d/. "$DEST/etc/audit/rules.d/" 2>/dev/null || true
fi
# Packages
for f in /var/log/dnf.rpm.log /var/log/dnf.rpm.log.1 /var/log/dnf.log \
         /var/log/dpkg.log /var/log/dpkg.log.1; do copy "$f"; done
# Identity snapshots
copy /etc/passwd
copy /etc/group
# sshd journal export (login origin / auth method) + general journal (system
# lifecycle / non-SSH auth / lockout). journald's store is binary, so these are
# exported to JSON -- a genuine capture step, which is why the ledger treats them
# as snapshot ("export") sources whose recent tail may be not-yet-observed.
mkdir -p "$DEST/var/log/openpath"
if command -v journalctl >/dev/null; then
  journalctl _COMM=sshd -o json --no-pager > "$DEST/var/log/openpath/journal-sshd.jsonl" 2>/dev/null || true
  journalctl -o json --no-pager      > "$DEST/var/log/openpath/journal.jsonl"      2>/dev/null || true
fi

# Capture-time marker: the edge of observation for this snapshot. OpenPath reads it
# to disclose when an analysis window reaches past the moment the bundle was taken
# (activity after this instant is simply not in the bundle). Written last so it
# reflects the true end of collection.
date -u +%Y-%m-%dT%H:%M:%SZ > "$DEST/var/log/openpath/captured-at"

echo "bundle written to: $DEST"
echo "analyze with:  openpath-ai --data-root '$DEST' --all-users --window 'last 24 hours'"
