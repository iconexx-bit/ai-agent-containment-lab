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
# shellcheck source=lib/env.sh
source "$ROOT/scripts/lib/env.sh" || { echo "cannot load scripts/lib/env.sh" >&2; exit 2; }
load_range_env "$ROOT" || exit 2
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

# TTD (D6b) is DATA, never a condition: an optional ttd.json next to probe.json (written by the operator's
# collector, which reads the live SIEM — lab code may not, tests/test-no-live-writes.sh) is printed as one line.
# It cannot change rc or the last line; anything that is not a plain schema-1 summary is named and ignored.
# Values are checked by jq as integers 0..86400000 (one day) and only then interpolated: nothing from the file is evaluated.
TTD_FILE="$(dirname "$FILE")/ttd.json"
if [[ -f "$TTD_FILE" ]]; then
  ttd=$(jq -r 'if type == "object" and .schema == 1
                  and ([.n, .median_ms, .min_ms, .max_ms] | all(type == "number" and . >= 0 and . == floor and . <= 86400000))
                  and .n >= 1 and .min_ms <= .median_ms and .median_ms <= .max_ms
               then "TTD (data, not judged): n=\(.n) median \(.median_ms) ms (min \(.min_ms), max \(.max_ms))"
               else empty end' "$TTD_FILE" 2>/dev/null) || ttd=""
  if [[ -n $ttd ]]; then echo "$ttd"
  else echo "TTD: ttd.json present but not a valid schema-1 summary — ignored"; fi
fi

echo
sfx=""; ((${#skipped[@]})) && sfx=" (skipped: ${skipped[*]})"
if [[ $fail -eq 0 ]]; then echo "PROBE PASS$sfx"; exit 0; fi
echo "PROBE FAIL$sfx"; exit 1
