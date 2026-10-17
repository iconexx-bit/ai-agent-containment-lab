#!/usr/bin/env bash
# verdict.sh <probe.json> — the ONLY place a PASS/FAIL decision is made.
#   exit 0 = PASS   exit 1 = FAIL   exit 2 = usage or skip config   exit 70 = malformed input
#   VERDICT_SKIP: ids reported as SKIP (operator) and named in the last line (scripts/lib/skip.sh)
#
# Split from probe.sh deliberately: collection and judgement are separate
# concerns, and negatives.sh must assert on the judgement alone.
set -uo pipefail

FILE="${1:-}"
[[ -n "$FILE" && -f "$FILE" ]] || { echo "usage: verdict.sh <probe.json>" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "verdict: jq missing" >&2; exit 70; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$ROOT/range.env" ]] && source "$ROOT/range.env"
# shellcheck source=lib/skip.sh
source "$ROOT/scripts/lib/skip.sh" || { echo "cannot load scripts/lib/skip.sh" >&2; exit 2; }
skip_init "$ROOT"

jq -e 'type=="object" and .schema==1' "$FILE" >/dev/null 2>&1 \
  || { echo "verdict: not a schema-1 probe artefact" >&2; exit 70; }

# explicit key -> check-id map. No string munging, no surprises.
KEYS=(egress_blocked tripwire_sinkholed sigma_loaded canaries_present sim_ca_present)
declare -A ID=(
  [egress_blocked]=egress
  [tripwire_sinkholed]=tripwire
  [sigma_loaded]=sigma
  [canaries_present]=canaries
  [sim_ca_present]=sim_ca
)

# INVARIANT: every top-level boolean is backed by exactly one checks[] entry.
# An assertion with no method behind it is not an assertion.
for k in "${KEYS[@]}"; do
  n=$(jq --arg id "${ID[$k]}" '[.checks[] | select(.id==$id)] | length' "$FILE")
  if [[ "$n" != "1" ]]; then
    echo "verdict: INVARIANT BROKEN — checks[] has $n entries for '${ID[$k]}', expected 1" >&2
    exit 70
  fi
done

fail=0; skipped=()
printf '%-22s %-6s %s\n' "CHECK" "RESULT" "DETAIL"
for k in "${KEYS[@]}"; do
  v=$(jq -r --arg k "$k" '.[$k]' "$FILE")
  d=$(jq -r --arg id "${ID[$k]}" '[.checks[]|select(.id==$id)][0].detail // ""' "$FILE")
  # top-level boolean and its check.ok must agree, or the collector is buggy
  o=$(jq -r --arg id "${ID[$k]}" '[.checks[]|select(.id==$id)][0].ok' "$FILE")
  if [[ "$v" != "$o" ]]; then
    echo "verdict: INCONSISTENT — $k=$v but checks[${ID[$k]}].ok=$o" >&2
    exit 70
  fi
  if [[ "$VERDICT_SKIP_IDS" == *" ${ID[$k]} "* ]]; then
    printf '%-22s %-6s %s\n' "$k" "SKIP" "(operator: VERDICT_SKIP) NOT VERIFIED — $d"
    skipped+=("${ID[$k]}")
    continue
  fi
  if [[ "$v" == "true" ]]; then
    printf '%-22s %-6s %s\n' "$k" "pass" "$d"
  else
    printf '%-22s %-6s %s\n' "$k" "FAIL" "$d"
    fail=1
  fi
done

echo
sfx=""; ((${#skipped[@]})) && sfx=" (skipped: ${skipped[*]})"
if [[ $fail -eq 0 ]]; then echo "PROBE PASS$sfx"; exit 0; fi
echo "PROBE FAIL$sfx"; exit 1
