#!/usr/bin/env bash
# lint-rules.sh — CHEAP, NON-AUTHORITATIVE check of the rule files in the repo (no docker,
# no range.env required). Gate: tests/test-lint-rules.sh runs it in `just test` (pre-push).
# Checks only properties of the files themselves: at least one rule, IDs unique, IDs inside the
# reserved block, every rules/*.xml well-formed (Wazuh silently drops malformed files).
# It does NOT check how many rules there should be (D5 P5b, variant B'):
#   - pack composition is pinned by the reviewed fixtures: scripts/logtest.sh (*.expected + coverage);
#   - what the live manager loaded is probe.sh's sigma check (SIGMA_EXPECTED in range.env).
# exit 0 OK / 1 lint failure / 2 cannot check (range.env, rules dir or xmllint missing)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/env.sh
source "$ROOT/scripts/lib/env.sh" || { echo "cannot load scripts/lib/env.sh" >&2; exit 2; }
load_range_env "$ROOT" || exit 2

RULES_DIR="${RULES_DIR:-$ROOT/rules}"
MIN="${SIGMA_ID_MIN:-100200}"
MAX="${SIGMA_ID_MAX:-100299}"

[[ -d "$RULES_DIR" ]] || { echo "no rules dir at $RULES_DIR" >&2; exit 2; }
# a gate that silently skips its strongest check cannot fail on it -> cannot check = exit 2
command -v xmllint >/dev/null 2>&1 \
  || { echo "xmllint missing (apt: libxml2-utils) — XML well-formedness cannot be checked" >&2; exit 2; }

ids=$(grep -rhoE 'rule id="[0-9]+"' "$RULES_DIR" | grep -oE '[0-9]+' | sort -n)
count=$(echo "$ids" | grep -c . || true)
uniq_count=$(echo "$ids" | sort -u | grep -c . || true)

rc=0
if [[ "$count" -eq 0 ]]; then
  echo "FAIL no rule IDs found in $RULES_DIR"; rc=1
fi

if [[ "$count" -ne "$uniq_count" ]]; then
  echo "FAIL duplicate rule IDs:"; echo "$ids" | uniq -d; rc=1
fi

out_of_block=$(echo "$ids" | awk -v a="$MIN" -v b="$MAX" 'NF && ($1<a || $1>b)')
if [[ -n "$out_of_block" ]]; then
  echo "FAIL rule IDs outside reserved block ${MIN}-${MAX}:"; echo "$out_of_block"; rc=1
fi

shopt -s nullglob
xml=("$RULES_DIR"/*.xml)
((${#xml[@]} > 0)) || { echo "FAIL no *.xml in $RULES_DIR"; rc=1; }
for f in "${xml[@]}"; do
  xmllint --noout "$f" 2>/dev/null || { echo "FAIL malformed XML: $f"; rc=1; }
done

[[ $rc -eq 0 ]] && echo "lint-rules OK ($count rules in ${MIN}-${MAX})"
exit $rc
