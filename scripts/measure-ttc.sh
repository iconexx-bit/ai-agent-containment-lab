#!/usr/bin/env bash
# measure-ttc.sh [N] — TTC distribution over N full cycles (D6a, runbook 10.6).
#
# One cycle: range-up -> ONE out-of-scope query from agent-runner -> containment-timer.sh (t0 = first
# out-of-scope query of THIS run, arm, verify) -> killswitch off -> range-down. Every cycle starts from a
# range that is down, so t0 can only be this cycle's query. The timer's JSON supplies the phases
# (t0 -> call, call -> armed); this script only runs the loop and reports the distribution (min / median /
# max, with n). It decides nothing about PASS/FAIL beyond the timer's own 60 s verdict per run.
#
# NOT measured here: detection (TTD, alert in the SIEM) and the response decision. The timer is called by
# this script right after the query, so t0 -> call is the floor of "scripted response", not a human or SIEM
# driven one. `call -> armed` includes the arm's `compose stop` of the range: conservative (rule 43).
#
# Side effects: each cycle's query reaches the live SIEM like any agent query (alerts, and at most one push
# per rule per 300 s). Nothing here writes to the SIEM or restarts the Docker daemon.
#
#   MEASURE_NAME     out-of-scope name to query        (default: TRIPWIRE_DOMAIN, canary.tripwire-range.invalid)
#   MEASURE_GAP      seconds between cycles, 0..3600   (default 0)
#   MEASURE_RETRIES  timer attempts per cycle, 1..30   (default 5; the query may not be in the log yet)
#   exit 0  every cycle measured, every TTC under the threshold
#        1  every cycle measured, at least one TTC at or over the threshold
#        2  refused before anything was changed (bad input, killswitch armed, marker, range running)
#        3  a cycle failed or cleanup failed: the summary covers the cycles that did complete
#        130 interrupted (cleanup ran)
# Output: artifacts/measure-<UTC>/{runs.jsonl,summary.json,run-<i>.*.log}
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/env.sh
source "$ROOT/scripts/lib/env.sh" || { echo "cannot load scripts/lib/env.sh" >&2; exit 2; }
load_range_env "$ROOT" strict || exit 2

KS="$ROOT/scripts/killswitch.sh"
AGENT="${AGENT_CONTAINER:-agent-runner}"
MARKER="${RANGE_KILL_MARKER:-/var/lib/range-lab/killswitch.armed}"
# defaults only for UNSET values: an explicitly empty one is malformed and refused below (rule 69)
N="${1-5}"
GAP="${MEASURE_GAP-0}"
RETRIES="${MEASURE_RETRIES-5}"
NAME="${MEASURE_NAME-${TRIPWIRE_DOMAIN:-canary.tripwire-range.invalid}}"

refuse() { echo "REFUSED: $*" >&2; exit 2; }
# numbers and the name come from the environment / argv: validated before any arithmetic or use (rule 69)
[[ $N =~ ^[1-9][0-9]*$ ]] && ((N <= 50))            || refuse "N must be an integer 1..50"
[[ $GAP =~ ^(0|[1-9][0-9]*)$ ]] && ((GAP <= 3600))  || refuse "MEASURE_GAP must be an integer 0..3600"
[[ $RETRIES =~ ^[1-9][0-9]*$ ]] && ((RETRIES <= 30)) || refuse "MEASURE_RETRIES must be an integer 1..30"
[[ $NAME =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || refuse "MEASURE_NAME is not a plain host name"
[[ ${NAME,,} =~ (^|\.)sim\.invalid$ ]] && refuse "MEASURE_NAME is in scope (*.sim.invalid): it would never start the timer"

# ---- guards: before the first change ------------------------------------------------------------------
st=$("$KS" status 2>&1) || refuse "killswitch status failed: $st"
[[ ${st%%$'\n'*} == disarmed ]] || refuse "killswitch is armed — just killswitch-off first"
[[ ! -e $MARKER ]] || refuse "marker $MARKER exists — just killswitch-off first"
running=$(docker ps -q --filter label=com.docker.compose.project=agent-range 2>&1) || refuse "cannot list containers: $running"
[[ -z $running ]] || refuse "range containers are running — just range-down first"

OUT="$ROOT/artifacts/measure-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT" || refuse "cannot create $OUT"
: >"$OUT/runs.jsonl"

# ---- from here on every exit cleans up ------------------------------------------------------------------
final=0
disarmed() { local s; s=$("$KS" status 2>&1); s=${s%%$'\n'*}; [[ $s == disarmed ]]; }
cleanup() {
  local bad=0
  "$KS" off >/dev/null 2>&1
  disarmed || { echo "CLEANUP FAILED: killswitch is still armed" >&2; bad=1; }
  "$ROOT/scripts/range-down.sh" >/dev/null 2>&1
  summarize
  ((bad)) && exit 3
  exit "$final"
}
trap cleanup EXIT
trap 'final=130; exit 130' INT TERM HUP

# one JSON row per cycle: ok rows carry the timer's numbers, error rows carry the reason
row_ok() { # i attempts curl_rc timer_json run_dir
  jq -nc --argjson i "$1" --argjson at "$2" --argjson crc "$3" --argjson t "$4" --arg rd "$5" --arg name "$NAME" \
    '{run:$i, ok:true, attempts:$at, curl_rc:$crc, containment_ms:$t.containment_ms, verdict:$t.verdict,
      t0_to_call_ms:$t.phases.t0_to_call_ms, call_to_armed_ms:$t.phases.call_to_armed_ms,
      t0_epoch_ms:$t.t0_epoch_ms, run_dir:$rd, name:$name}' >>"$OUT/runs.jsonl"
}
row_err() { # i reason
  jq -nc --argjson i "$1" --arg r "$2" '{run:$i, ok:false, error:$r}' >>"$OUT/runs.jsonl"
}

summarize() {
  [[ -s $OUT/runs.jsonl ]] || { echo "no cycle completed — no summary" >&2; return; }
  jq -s --argjson n "$N" --arg name "$NAME" '
    def med: sort | if length % 2 == 1 then .[(length - 1) / 2]
                    else ((.[length / 2 - 1] + .[length / 2]) / 2 | floor) end;
    def dist(f): [.[] | select(.ok) | f] | {min: min, median: med, max: max, samples: .};
    [.[] | select(.ok)] as $ok
    | { schema: 1, n_requested: $n, n_ok: ($ok | length), complete: (($ok | length) == $n),
        name: $name, threshold_ms: 60000,
        pass: ([$ok[] | select(.verdict == "PASS")] | length),
        ttc_ms: (if ($ok | length) > 0 then ($ok | dist(.containment_ms)) else null end),
        phases: (if ($ok | length) > 0 then {t0_to_call_ms: ($ok | dist(.t0_to_call_ms)),
                                              call_to_armed_ms: ($ok | dist(.call_to_armed_ms))} else null end),
        errors: [.[] | select(.ok | not) | {run, error}],
        definition: "TTC = first out-of-scope query of the run (range-dns log) -> killswitch armed and verified; phases: t0->call (timer invoked) and call->armed (arm incl. compose stop, then verify); n counts completed cycles only" }
    ' "$OUT/runs.jsonl" >"$OUT/summary.json" 2>/dev/null || { echo "summary failed" >&2; return; }
  jq -r '"MEASURE n=\(.n_ok)/\(.n_requested)"
         + (if .ttc_ms then " TTC median \(.ttc_ms.median) ms (min \(.ttc_ms.min), max \(.ttc_ms.max)); "
            + "t0->call median \(.phases.t0_to_call_ms.median) ms, call->armed median \(.phases.call_to_armed_ms.median) ms; "
            + "PASS \(.pass)/\(.n_ok) (< \(.threshold_ms) ms)" else " no completed cycle" end)
         + (if .complete then "" else "  INCOMPLETE: \(.errors | length) error(s)" end)' "$OUT/summary.json"
  echo "evidence: $OUT"
}

# ---- one cycle ------------------------------------------------------------------------------------------
cycle() { # i -> 0 measured, 1 error (row written)
  local i=$1 urc crc attempts trc tout ms a b t0e rd
  echo "== run $i/$N"
  "$ROOT/scripts/range-up.sh" >"$OUT/run-$i.up.log" 2>&1; urc=$?
  if ((urc != 0)); then row_err "$i" "range-up rc=$urc (see run-$i.up.log)"; return 1; fi

  crc=0; docker exec "$AGENT" curl -4 -s -m 3 -o /dev/null "http://$NAME/" >/dev/null 2>&1 || crc=$?
  case $crc in
    6|7|28) ;;   # DNS failure / refused (sinkhole) / timeout: the query was made and nothing connected
    *) row_err "$i" "query from $AGENT: curl rc=$crc (want 6, 7 or 28)"; return 1 ;;
  esac

  attempts=0; trc=2; tout=""
  while ((attempts < RETRIES)); do
    attempts=$((attempts + 1))
    tout=$("$ROOT/scripts/containment-timer.sh" 2>"$OUT/run-$i.timer.err"); trc=$?
    ((trc == 2)) || break
    sleep 1
  done
  case $trc in
    0) ;;
    1) row_err "$i" "killswitch did not arm (timer rc=1, see run-$i.timer.err)"; return 1 ;;
    2) row_err "$i" "no out-of-scope query seen in $attempts attempt(s) (timer rc=2, see run-$i.timer.err)"; return 1 ;;
    *) row_err "$i" "timer rc=$trc"; return 1 ;;
  esac
  ms=$(jq -r '.containment_ms // empty' <<<"$tout" 2>/dev/null)
  a=$(jq -r '.phases.t0_to_call_ms // empty' <<<"$tout" 2>/dev/null)
  b=$(jq -r '.phases.call_to_armed_ms // empty' <<<"$tout" 2>/dev/null)
  if [[ ! $ms =~ ^[0-9]+$ || ! $a =~ ^-?[0-9]+$ || ! $b =~ ^[0-9]+$ ]]; then
    row_err "$i" "timer output lacks numeric containment_ms / phases"; return 1
  fi
  # the operator's TTD collector pairs this cycle with its alert by t0, run dir and name: all three must be sane
  t0e=$(jq -r '.t0_epoch_ms // empty' <<<"$tout" 2>/dev/null)
  [[ $t0e =~ ^[0-9]+$ ]] || { row_err "$i" "timer output lacks t0_epoch_ms"; return 1; }
  rd=$(cat "$ROOT/.run-id" 2>/dev/null); rd=${rd#"$ROOT/"}
  [[ $rd =~ ^artifacts/[0-9]{8}T[0-9]{6}Z$ ]] || { row_err "$i" "run dir '$rd' is not artifacts/<UTC stamp>"; return 1; }
  row_ok "$i" "$attempts" "$crc" "$tout" "$rd"
  return 0
}

failed=0
for ((i = 1; i <= N; i++)); do
  cycle "$i"; r=$?
  # tear down after EVERY cycle, measured or not: the next one needs a down range and a disarmed switch
  "$KS" off >/dev/null 2>&1
  "$ROOT/scripts/range-down.sh" >"$OUT/run-$i.down.log" 2>&1
  if ! disarmed; then row_err "$i" "killswitch still armed after cycle teardown"; failed=1; break; fi
  if ((r != 0)); then failed=1; break; fi
  ((i < N && GAP > 0)) && sleep "$GAP"
done

if ((failed)); then final=3
elif jq -e '[.[] | select(.ok and .verdict != "PASS")] | length > 0' -s "$OUT/runs.jsonl" >/dev/null 2>&1; then final=1
fi
exit "$final"
