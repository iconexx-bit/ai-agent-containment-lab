#!/usr/bin/env bash
# test-verdict-ttd.sh — D6b: verdict.sh shows TTD as DATA. It is never a condition of PASS/FAIL.
#   T0 control: no ttd.json -> no TTD line, PASS rc 0, last line "PROBE PASS"
#   T1 valid ttd.json -> one line "TTD (data, not judged): n=3 median 412 ms (min 380, max 1203)", rc 0
#   T2 a huge TTD (3600000 ms, in range) on a PASS probe -> still PASS rc 0; above one day (86400000 ms) -> ignored
#   T3 valid TTD on a FAIL probe -> rc 1, last line "PROBE FAIL" (data does not rescue a verdict)
#   T4 with a skip -> the last line still names it:  PROBE PASS (skipped: canaries)
#   T5 invalid files are named and ignored, rc unchanged: not JSON, array, wrong schema, strings, floats,
#      negatives, missing field, n=0, min > median, median > max, command-substitution payload (never executed)
#   T5b a valid summary with a payload in an unrelated key is shown and nothing is executed
#   T6 the TTD line comes before the blank line and the last line is untouched (tools grep '^PROBE ')
# Hermetic: temp tree, the REAL verdict.sh.   exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/verdict.sh scripts/lib/skip.sh scripts/lib/env.sh schemas/probe.v1.json; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
command -v jq >/dev/null 2>&1 || { echo "jq missing" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }

tree="$T/tree"; run="$T/run"
mkdir -p "$tree/scripts" "$tree/schemas" "$run" || exit 2
cp "$ROOT/scripts/verdict.sh" "$tree/scripts/" && cp -r "$ROOT/scripts/lib" "$tree/scripts/" \
  && cp "$ROOT/schemas/probe.v1.json" "$tree/schemas/" || exit 2
printf 'RANGE_CIDR=10.66.0.0/16\n' >"$tree/range.env"

probe() { # $1 = path, $2 = true|false (canaries ok)
  jq -n --argjson c "$2" '{schema:1, ts:"2026-10-24T00:00:00Z", range_cidr:"10.66.0.0/16", range_net:"agentlab0",
    egress_blocked:true, tripwire_sinkholed:true, sigma_loaded:true, canaries_present:$c, sim_ca_present:true,
    checks:[{id:"egress",ok:true,method:"f",detail:"d"},{id:"tripwire",ok:true,method:"f",detail:"d"},
            {id:"sigma",ok:true,method:"f",detail:"d"},{id:"canaries",ok:$c,method:"f",detail:"d"},
            {id:"sim_ca",ok:true,method:"f",detail:"d"}]}' >"$1"
}
V() { # $1 = probe file; rest = env; sets out rc
  out=$(env -u VERDICT_SKIP -u NEG_SKIP -u PROBE_SKIP "${@:2}" bash "$tree/scripts/verdict.sh" "$1" 2>&1); rc=$?
}
lastline() { printf '%s\n' "$out" | tail -n1; }
good='{"schema":1,"n":3,"median_ms":412,"min_ms":380,"max_ms":1203}'

probe "$run/probe.json" true
rm -f "$run/ttd.json"
V "$run/probe.json"
{ ((rc == 0)) && [[ $(lastline) == "PROBE PASS" ]] && ! grep -q 'TTD' <<<"$out"; } \
  || no "T0 no ttd.json: no TTD line, rc 0, last line PROBE PASS (rc=$rc)"$'\n'"$out"

printf '%s\n' "$good" >"$run/ttd.json"
V "$run/probe.json"
{ ((rc == 0)) && grep -qxF 'TTD (data, not judged): n=3 median 412 ms (min 380, max 1203)' <<<"$out" \
  && [[ $(lastline) == "PROBE PASS" ]]; } || no "T1 valid ttd.json printed as data, rc 0 (rc=$rc)"$'\n'"$out"
ntl=$(grep -c '^TTD' <<<"$out")
((ntl == 1)) || no "T1 exactly one TTD line (got $ntl)"

printf '%s\n' '{"schema":1,"n":1,"median_ms":3600000,"min_ms":3600000,"max_ms":3600000}' >"$run/ttd.json"
V "$run/probe.json"
{ ((rc == 0)) && [[ $(lastline) == "PROBE PASS" ]] && grep -q 'median 3600000 ms' <<<"$out"; } \
  || no "T2 a huge TTD must not fail a PASS probe (rc=$rc)"$'\n'"$out"
printf '%s\n' '{"schema":1,"n":1,"median_ms":999999999999,"min_ms":999999999999,"max_ms":999999999999}' >"$run/ttd.json"
V "$run/probe.json"
{ ((rc == 0)) && [[ $(lastline) == "PROBE PASS" ]] && grep -q 'ignored' <<<"$out"; } \
  || no "T2b an out-of-range TTD is ignored, never a failure (rc=$rc)"$'\n'"$out"

probe "$run/probe.json" false
printf '%s\n' "$good" >"$run/ttd.json"
V "$run/probe.json"
{ ((rc == 1)) && [[ $(lastline) == "PROBE FAIL" ]] && grep -q '^TTD (data' <<<"$out"; } \
  || no "T3 FAIL probe stays FAIL rc 1 with the TTD line shown (rc=$rc)"$'\n'"$out"

V "$run/probe.json" VERDICT_SKIP=canaries
{ ((rc == 0)) && [[ $(lastline) == "PROBE PASS (skipped: canaries)" ]] && grep -q '^TTD (data' <<<"$out"; } \
  || no "T4 skip named on the last line, TTD still shown (rc=$rc)"$'\n'"$out"

probe "$run/probe.json" true
bad() { # label, content
  printf '%s' "$2" >"$run/ttd.json"; rm -f "$T/pwned"
  V "$run/probe.json"
  { ((rc == 0)) && [[ $(lastline) == "PROBE PASS" ]] && grep -qx 'TTD: ttd.json present but not a valid schema-1 summary — ignored' <<<"$out" \
    && [[ ! -e $T/pwned ]]; } || no "T5 $1: named and ignored, rc 0, nothing executed (rc=$rc)"$'\n'"$out"
}
bad "not json"          'median 412'
bad "array"             '[1,2,3]'
bad "wrong schema"      '{"schema":2,"n":3,"median_ms":412,"min_ms":380,"max_ms":1203}'
bad "strings"           '{"schema":1,"n":"3","median_ms":"412","min_ms":"380","max_ms":"1203"}'
bad "floats"            '{"schema":1,"n":3,"median_ms":412.5,"min_ms":380,"max_ms":1203}'
bad "negative"          '{"schema":1,"n":3,"median_ms":-1,"min_ms":-5,"max_ms":1203}'
bad "missing field"     '{"schema":1,"n":3,"median_ms":412,"min_ms":380}'
bad "n = 0"             '{"schema":1,"n":0,"median_ms":412,"min_ms":380,"max_ms":1203}'
bad "min above median"  '{"schema":1,"n":3,"median_ms":412,"min_ms":500,"max_ms":1203}'
bad "median above max"  '{"schema":1,"n":3,"median_ms":2000,"min_ms":380,"max_ms":1203}'
bad "payload"           '{"schema":1,"n":"$(touch '"$T"'/pwned)","median_ms":"`touch '"$T"'/pwned`","min_ms":1,"max_ms":2}'
# a VALID summary with a payload in an unrelated key is shown as data and nothing is executed
printf '%s' '{"schema":1,"n":3,"median_ms":412,"min_ms":380,"max_ms":1203,"x":"$(touch '"$T"'/pwned)"}' >"$run/ttd.json"; rm -f "$T/pwned"
V "$run/probe.json"
{ ((rc == 0)) && grep -qxF 'TTD (data, not judged): n=3 median 412 ms (min 380, max 1203)' <<<"$out" && [[ ! -e $T/pwned ]]; } \
  || no "T5b valid summary with a payload in another key: shown, nothing executed (rc=$rc)"$'\n'"$out"

# T6 order: TTD line, blank line, verdict line — and nothing after the verdict line
printf '%s\n' "$good" >"$run/ttd.json"
V "$run/probe.json"
mapfile -t L <<<"$out"
n=${#L[@]}
{ [[ ${L[n-1]} == "PROBE PASS" && -z ${L[n-2]} && ${L[n-3]} == TTD* ]]; } \
  || no "T6 order: TTD line, blank line, PROBE line last"$'\n'"$out"

((fail == 0)) && echo "verdict-ttd: PASS (T0-T6; invalid inputs 11/11 named and ignored, nothing executed)"
exit "$fail"
