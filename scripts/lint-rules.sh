#!/usr/bin/env bash
# lint-rules.sh — CHEAP, NON-AUTHORITATIVE check for pre-commit.
# Confirms rule IDs exist on disk, are inside the reserved block, and are unique.
# It does NOT prove the manager loaded them — that is probe.sh's sigma check.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$ROOT/range.env" ]] && source "$ROOT/range.env"

RULES_DIR="${RULES_DIR:-$ROOT/rules}"
MIN="${SIGMA_ID_MIN:-100200}"
MAX="${SIGMA_ID_MAX:-100299}"
EXPECTED="${SIGMA_EXPECTED:-7}"

[[ -d "$RULES_DIR" ]] || { echo "no rules dir at $RULES_DIR" >&2; exit 2; }

ids=$(grep -rhoE 'rule id="[0-9]+"' "$RULES_DIR" | grep -oE '[0-9]+' | sort -n)
count=$(echo "$ids" | grep -c . || true)
uniq_count=$(echo "$ids" | sort -u | grep -c . || true)

rc=0
if [[ "$count" -ne "$uniq_count" ]]; then
  echo "FAIL duplicate rule IDs:"; echo "$ids" | uniq -d; rc=1
fi

out_of_block=$(echo "$ids" | awk -v a="$MIN" -v b="$MAX" '$1<a || $1>b')
if [[ -n "$out_of_block" ]]; then
  echo "FAIL rule IDs outside reserved block ${MIN}-${MAX}:"; echo "$out_of_block"; rc=1
fi

if [[ "$count" -ne "$EXPECTED" ]]; then
  echo "FAIL expected $EXPECTED rules, found $count"; rc=1
fi

# XML well-formedness — Wazuh silently drops malformed files
if command -v xmllint >/dev/null 2>&1; then
  for f in "$RULES_DIR"/*.xml; do
    xmllint --noout "$f" 2>/dev/null || { echo "FAIL malformed XML: $f"; rc=1; }
  done
else
  echo "warn: xmllint absent — XML well-formedness unchecked" >&2
fi

[[ $rc -eq 0 ]] && echo "lint-rules OK ($count rules in ${MIN}-${MAX})"
exit $rc
