#!/usr/bin/env bash
# test-evidence-claims.sh — D6 docs (runbook 10.6): the numbers the README publishes are the numbers of the
# committed evidence, and the evidence agrees with itself.
#   E1 docs/evidence/d6-run{1,2}-{ttc,ttd}.json and d6-run2-stop.json exist, schema 1, complete, no errors, n >= 5
#   E2 TTC evidence per run: t0_to_call + call_to_armed == TTC for every cycle; min / median / max recomputed from
#      the samples equal the stated ones (also for both phases)
#   E3 TTD evidence per run: n == samples, min / median / max recomputed, no missing runs
#   E4 README states, per run, the TTC, the phase medians and the TTD of the evidence character for character,
#      and no longer says "re-measurement pending"
#   E5 README names the limits: lower bound, `compose stop`, "not measured"
#   E6 README delivery claim: 100202, 100203, 100204 and 100220 proven one by one; the old "shares that path"
#      and "not yet proven one by one" sentences are gone
#   E7 docs/containment-verdict.json is the README's JSON block (jq -S) and its phases add up
#   E8 stop evidence (run 2): per cycle t0_to_call <= first SIGTERM <= TTC, the lower bound IS the TTC phase of
#      that cycle, min / median / max recomputed, durations present; the README states it
# Every check is proven on a mutated copy first (rule 54): a check that cannot fail is not a check.
# Hermetic: reads tracked files only.   exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v jq >/dev/null 2>&1 || { echo "jq missing" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }

EV=docs/evidence
FILES=(README.md docs/containment-verdict.json "$EV/d6-run1-ttc.json" "$EV/d6-run1-ttd.json" "$EV/d6-run2-ttc.json" "$EV/d6-run2-ttd.json" "$EV/d6-run2-stop.json")

# README with blockquote markers and line breaks flattened: phrases may wrap across lines
flat() { sed 's/^> \{0,1\}//' "$1" | tr '\n' ' ' | tr -s ' '; }
MEDF='def med: sort | if length % 2 == 1 then .[(length - 1) / 2] else ((.[length / 2 - 1] + .[length / 2]) / 2 | floor) end;'

# chk ROOT -> prints one label per violated check, rc 0 when none
chk() {
  local r=$1 bad=0 n f md rf pt pp pd ps
  md="$r/docs/containment-verdict.json"
  e() { echo "$1"; bad=1; }
  for f in "${FILES[@]}"; do [[ -f "$r/$f" ]] || { e "E1 missing $f"; return 1; }; done
  for f in "${FILES[@]:1}"; do jq -e . "$r/$f" >/dev/null 2>&1 || { e "E1 not valid JSON: $f"; return 1; }; done
  rf=$(flat "$r/README.md")
  for n in 1 2; do
    local ttc="$r/$EV/d6-run$n-ttc.json" ttd="$r/$EV/d6-run$n-ttd.json"
    jq -e '.schema == 1 and .complete == true and (.errors | length) == 0 and .n_ok == .n_requested and .n_ok >= 5
           and .pass == .n_ok and (.ttc_ms.samples | length) == .n_ok
           and (.phases.t0_to_call_ms.samples | length) == .n_ok and (.phases.call_to_armed_ms.samples | length) == .n_ok' \
       "$ttc" >/dev/null 2>&1 || e "E1 run $n ttc summary: schema 1, complete, no errors, n >= 5, all PASS"
    jq -e '.schema == 1 and .n >= 5 and (.samples | length) == .n and (.missing_runs | length) == 0' \
       "$ttd" >/dev/null 2>&1 || e "E1 run $n ttd summary: schema 1, n >= 5, samples == n, no missing runs"
    jq -e "$MEDF"'
       . as $s
       | [range(0; .n_ok)] | all(. as $i | $s.phases.t0_to_call_ms.samples[$i] + $s.phases.call_to_armed_ms.samples[$i] == $s.ttc_ms.samples[$i])
       and ($s | [.ttc_ms, .phases.t0_to_call_ms, .phases.call_to_armed_ms]
            | all(.min == (.samples | min) and .max == (.samples | max) and .median == (.samples | med)))' \
       "$ttc" >/dev/null 2>&1 || e "E2 run $n ttc evidence is not consistent (phase sums, min/median/max)"
    jq -e "$MEDF"' .min_ms == (.samples | min) and .max_ms == (.samples | max) and .median_ms == (.samples | med)' \
       "$ttd" >/dev/null 2>&1 || e "E3 run $n ttd evidence: min/median/max do not match the samples"
    pt=$(jq -r --arg n "$n" '"Run \($n): TTC median **\(.ttc_ms.median) ms** (min \(.ttc_ms.min), max \(.ttc_ms.max)) across \(.n_ok) scripted runs"' "$ttc" 2>/dev/null)
    pp=$(jq -r --arg n "$n" '"Run \($n) phases: t0 to call median \(.phases.t0_to_call_ms.median) ms, call to armed median \(.phases.call_to_armed_ms.median) ms"' "$ttc" 2>/dev/null)
    pd=$(jq -r --arg n "$n" '"Run \($n): TTD median **\(.median_ms) ms** (min \(.min_ms), max \(.max_ms)) across \(.n) runs"' "$ttd" 2>/dev/null)
    [[ -n $pt && $rf == *"$pt"* ]] || e "E4 README does not state the TTC of run $n: $pt"
    [[ -n $pp && $rf == *"$pp"* ]] || e "E4 README does not state the phase medians of run $n: $pp"
    [[ -n $pd && $rf == *"$pd"* ]] || e "E4 README does not state the TTD of run $n: $pd"
  done
  [[ $rf != *"re-measurement pending"* ]] || e "E4 README still says re-measurement is pending"
  # E5
  [[ $rf == *"lower bound"* ]]    || e "E5 README does not say TTD is a lower bound"
  [[ $rf == *'`compose stop`'* ]] || e "E5 README does not say call to armed includes compose stop"
  [[ $rf == *"not measured"* ]]   || e "E5 README does not say what is not measured"
  # E6
  [[ $rf == *'delivery to the phone is proven one by one for `100202`, `100203`, `100204` and `100220`'* ]] \
    || e "E6 README does not state the proven delivery of 100202, 100203, 100204 and 100220"
  [[ $rf != *'`100203` shares that path'* ]] || e "E6 README still says 100203 only shares the path"
  [[ $rf != *"not yet proven one by one"* ]] || e "E6 README still has the old 'not yet proven one by one' sentence"
  # E7
  local blk
  blk=$(awk '/^```json$/ {c++; next} /^```$/ && c == 1 {c = 2} c == 1 {print}' "$r/README.md")
  [[ -n $blk ]] && [[ $(jq -S -c . <<<"$blk" 2>/dev/null) == "$(jq -S -c . "$md" 2>/dev/null)" ]] \
    || e "E7 the README JSON block is not docs/containment-verdict.json"
  jq -e '.phases.t0_to_call_ms + .phases.call_to_armed_ms == .containment_ms and (.t0_epoch_ms | type) == "number"' \
     "$md" >/dev/null 2>&1 || e "E7 containment-verdict.json: phases do not add up to containment_ms"
  # E8
  local st="$r/$EV/d6-run2-stop.json" t2="$r/$EV/d6-run2-ttc.json"
  jq -e "$MEDF"'
     .schema == 1 and .n >= 5 and (.missing_runs | length) == 0
     and (.samples | length) == .n and (.lower_samples | length) == .n and (.stop_duration_ms | length) == .n
     and .min_ms == (.samples | min) and .max_ms == (.samples | max) and .median_ms == (.samples | med)' \
     "$st" >/dev/null 2>&1 || e "E8 stop evidence: schema, n, samples, min/median/max"
  jq -e --slurpfile t "$t2" '
     . as $s | [range(0; .n)] | all(. as $i
       | $s.lower_samples[$i] == $t[0].phases.t0_to_call_ms.samples[$i]
         and $s.samples[$i] >= $s.lower_samples[$i] and $s.samples[$i] <= $t[0].ttc_ms.samples[$i])' \
     "$st" >/dev/null 2>&1 || e "E8 stop evidence does not fit the run 2 TTC evidence (lower = t0->call, lower <= first SIGTERM <= TTC)"
  ps=$(jq -r '"Run 2: egress closed no later than median **\(.median_ms) ms** (min \(.min_ms), max \(.max_ms)) after t0; the stop itself took median \(.stop_duration_ms | sort | .[(length - 1) / 2 | floor]) ms"' "$st" 2>/dev/null)
  [[ -n $ps && $rf == *"$ps"* ]] || e "E8 README does not state the stop evidence: $ps"
  return $bad
}

# ---- controls: each mutation of a good copy must trip exactly the check it targets -------------------------
mk() { rm -rf "$T/c"; mkdir -p "$T/c/$EV" || exit 2
       for f in "${FILES[@]}"; do cp "$ROOT/$f" "$T/c/$f" 2>/dev/null; done; }
jqe() { jq "$1" "$T/c/$2" >"$T/x" && mv "$T/x" "$T/c/$2"; }   # jqe filter file-in-copy
ctl() { # label expected-prefix
  local out rc; out=$(chk "$T/c"); rc=$?
  if ((rc != 0)) && grep -q "^$2" <<<"$out"; then ctl_ok=$((ctl_ok + 1)); else no "control $1: want a $2 violation (rc=$rc): ${out:-none}"; fi
}
ctl_ok=0; ctl_all=0
c() { ctl_all=$((ctl_all + 1)); ctl "$@"; }
mk; out=$(chk "$T/c"); rc=$?
((rc == 0)) || no "the real files already violate:"$'\n'"$out"

R=$T/c/README.md
mk; echo 'Re-measurement: re-measurement pending' >>"$R";                                                   c "pending text back" E4
mk; sed -i 's/Run 1: TTC median \*\*[0-9]* ms/Run 1: TTC median **1 ms/' "$R";                              c "README run 1 TTC edited" E4
mk; sed -i 's/Run 2: TTC median \*\*[0-9]* ms/Run 2: TTC median **1 ms/' "$R";                              c "README run 2 TTC edited" E4
mk; sed -i 's/Run 2: TTD median \*\*[0-9]*/Run 2: TTD median **1/' "$R";                                    c "README run 2 TTD edited" E4
mk; sed -i 's/Run 1 phases: t0 to call median [0-9]* ms/Run 1 phases: t0 to call median 1 ms/' "$R";        c "README run 1 phase edited" E4
mk; jqe '.ttc_ms.samples[0] += 1' $EV/d6-run1-ttc.json;                                                     c "run 1 TTC sample edited" E2
mk; jqe '.phases.call_to_armed_ms.median += 1' $EV/d6-run2-ttc.json;                                        c "run 2 phase median edited" E2
mk; jqe '.complete = false' $EV/d6-run2-ttc.json;                                                           c "incomplete evidence" E1
mk; jqe '.missing_runs = [3]' $EV/d6-run1-ttd.json;                                                         c "missing TTD run" E1
mk; jqe '.median_ms += 1' $EV/d6-run2-ttd.json;                                                             c "run 2 TTD median edited" E3
mk; sed -i 's/, `100203`//' "$R";                                                                           c "100203 claim dropped" E6
mk; echo 'Rule `100203` shares that path.' >>"$R";                                                          c "100203 demoted" E6
mk; sed -i 's/lower bound/bound/g' "$R";                                                                    c "lower bound dropped" E5
mk; jqe '.containment_ms += 1' docs/containment-verdict.json;                                               c "verdict json drifts from README" E7
mk; rm "$T/c/$EV/d6-run2-ttd.json";                                                                         c "evidence file missing" E1
mk; jqe '.samples[1] += 100' $EV/d6-run2-stop.json;                                                         c "stop sample edited" E8
mk; jqe '.lower_samples[1] += 1' $EV/d6-run2-stop.json;                                                     c "stop lower bound detached from the TTC phase" E8
mk; jqe '.samples[2] = 99999' $EV/d6-run2-stop.json;                                                        c "first SIGTERM after the TTC" E8
mk; sed -i 's/the stop itself took median [0-9]* ms/the stop itself took median 1 ms/' "$R";                c "README stop duration edited" E8

out=$(chk "$ROOT"); rc=$?
((rc == 0)) || no "the committed README and evidence disagree:"$'\n'"$out"

((fail == 0)) && echo "evidence-claims: PASS (E1-E8 on the committed files; controls ${ctl_ok}/${ctl_all} tripped their check)"
exit "$fail"
