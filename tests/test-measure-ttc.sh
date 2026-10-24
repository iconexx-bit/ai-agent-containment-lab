#!/usr/bin/env bash
# test-measure-ttc.sh — D6a: TTC phases in the timer and the measurement loop (scripts/measure-ttc.sh).
#  Timer (REAL containment-timer.sh, fake docker log + killswitch):
#   P1 phases present, integers, containment_ms == t0_to_call_ms + call_to_armed_ms exactly, old keys unchanged
#   P2 a first attempt 2 min ago -> containment_ms >= 120000, verdict FAIL     P3 arm that does not arm -> rc 1
#   P4 no query in the log -> rc 2     P5 unparseable timestamp -> rc 2
#  Loop (REAL measure-ttc.sh, stub range-up/down/killswitch/timer so the numbers are scripted):
#   S1 odd n: min / median / max / samples exact; S2 even n: median = floor(mean of the middle two)
#   S3 one run at 60000 ms -> rc 1, all runs still reported     S4 every cycle: up, query, timer, off, down (order)
#   G1-G3 refusals (rc 2, nothing started): killswitch armed, marker, range containers running
#   N1 N / MEASURE_GAP / MEASURE_RETRIES / MEASURE_NAME validation: payloads are refused and never executed
#   R1 timer rc 2 twice then ok -> attempts 3     R2 rc 2 beyond the retries -> rc 3, loop stops, cleanup ran
#   R3 timer rc 1 -> rc 3     R4 range-up fails -> rc 3, no query     R5 curl rc 0 (the agent connected) -> rc 3
#   R6 timer output without phases -> rc 3     R7 killswitch stuck armed after a cycle -> rc 3, loop stops
#   R8 cleanup that cannot disarm -> rc 3      R9 SIGTERM mid-cycle -> rc 130, cleanup ran
#   R10 gap sleeps only BETWEEN cycles         E1 real timer through the loop: phases consistent
#   R11 ok rows carry t0_epoch_ms, name, run_dir (the operator's TTD collector pairs by them)  R12/R13 bad run dir -> rc 3  R14 no t0_epoch_ms -> rc 3
#  Structure (scanner proven on fixtures, rule 54):
#   X1 measure-ttc.sh never touches iptables, systemctl or the daemon; loads range.env once, strict
#   X2 justfile has the measure-ttc recipe running ./scripts/measure-ttc.sh
# Hermetic: temp trees, fake docker/sleep first on PATH.   exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/measure-ttc.sh scripts/containment-timer.sh scripts/lib/env.sh justfile; do
  [[ -f "$ROOT/$f" ]] || { echo "FAIL: missing $f (D6a not applied)"; exit 1; }
done
command -v jq >/dev/null 2>&1 || { echo "jq missing" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }
SIM=/bin/sleep

# ---- the world -------------------------------------------------------------------------------------------
world() { # $1 = name, $2 = real|stub (which timer); prints the tree path
  local d="$T/$1" w="$T/$1/w"
  mkdir -p "$d/scripts" "$d/bin" "$d/artifacts" "$w" || exit 2
  cp "$ROOT/scripts/measure-ttc.sh" "$d/scripts/" && cp -r "$ROOT/scripts/lib" "$d/scripts/" || exit 2
  [[ $2 == real ]] && { cp "$ROOT/scripts/containment-timer.sh" "$d/scripts/" || exit 2; }
  printf 'RANGE_CIDR=10.66.0.0/16\n' >"$d/range.env"
  : >"$w/calls.log"; : >"$w/ttc.queue"; : >"$w/timer.rc"
  # docker: ps, exec (the agent's query), logs (range-dns, for the real timer)
  cat >"$d/bin/docker" <<DOCKER
#!/usr/bin/env bash
W="$w"
echo "docker \$*" >>"\$W/calls.log"
case "\$1" in
  ps) [[ -n \${FAKE_RUNNING:-} ]] && echo c0ffee; exit 0 ;;
  exec) exit "\${FAKE_CURL_RC:-7}" ;;
  logs)
    c=\$(( \$(cat "\$W/logs.count" 2>/dev/null || echo 0) + 1 )); echo "\$c" >"\$W/logs.count"
    (( c <= \${FAKE_NOQUERY_FIRST:-0} )) && exit 0
    if [[ -n \${FAKE_BAD_TS:-} ]]; then echo "garbage dnsmasq[1]: query[A] canary.tripwire-range.invalid from 10.66.1.1"; exit 0; fi
    ts=\$(date -u -d "\${FAKE_LOG_AGE:-2} seconds ago" +%Y-%m-%dT%H:%M:%S.%N)Z
    echo "\$ts dnsmasq[1]: query[A] canary.tripwire-range.invalid from 10.66.1.1"
    echo "\$ts dnsmasq[1]: query[A] health.sim.invalid from 127.0.0.1"
    exit 0 ;;
esac
exit 0
DOCKER
  cat >"$d/bin/sleep" <<SLEEP
#!/usr/bin/env bash
echo "sleep \$*" >>"$w/calls.log"
exit 0
SLEEP
  cat >"$d/scripts/range-up.sh" <<UP
#!/usr/bin/env bash
echo "range-up" >>"$w/calls.log"
[[ -n \${FAKE_UP_HANG:-} ]] && { touch "$w/hang.started"; $SIM 3; }
r="$d/artifacts/\$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "\$r"; echo "\$r" >"$d/.run-id"
[[ -n \${FAKE_BAD_RUNID:-} ]] && echo "\$FAKE_BAD_RUNID" >"$d/.run-id"
exit "\${FAKE_UP_RC:-0}"
UP
  cat >"$d/scripts/range-down.sh" <<DOWN
#!/usr/bin/env bash
echo "range-down" >>"$w/calls.log"; rm -f "$d/.run-id"; exit 0
DOWN
  cat >"$d/scripts/killswitch.sh" <<KS
#!/usr/bin/env bash
echo "ks \$1" >>"$w/calls.log"
case "\$1" in
  status) if [[ -e "$w/ks.armed" ]]; then echo armed; echo "chain ..."; else echo disarmed; fi ;;
  arm)    $SIM 0.2; [[ -n \${FAKE_ARM_NOOP:-} ]] || touch "$w/ks.armed"; [[ -e "$w/ks.armed" ]] && echo "KILLSWITCH ARMED" ;;
  verify) [[ -e "$w/ks.armed" ]] && { echo "KILLSWITCH ARMED"; exit 0; }; echo "KILLSWITCH NOT ARMED" >&2; exit 1 ;;
  off)    [[ -n \${FAKE_OFF_STUCK:-} ]] || rm -f "$w/ks.armed"; echo "KILLSWITCH DISARMED" ;;
esac
exit 0
KS
  if [[ $2 == stub ]]; then # scripted timer: rc queue first, then the value queue "ms a b"
    cat >"$d/scripts/containment-timer.sh" <<TIMER
#!/usr/bin/env bash
echo "timer" >>"$w/calls.log"
rc=\$(head -n1 "$w/timer.rc" 2>/dev/null)
if [[ -n \$rc ]]; then sed -i 1d "$w/timer.rc"; echo "stub timer rc \$rc" >&2; exit "\$rc"; fi
read -r ms a b < <(head -n1 "$w/ttc.queue"); sed -i 1d "$w/ttc.queue"
if [[ -n \${FAKE_NO_T0:-} ]]; then echo "{\"containment_ms\":\$ms,\"verdict\":\"PASS\",\"phases\":{\"t0_to_call_ms\":\$a,\"call_to_armed_ms\":\$b}}"; exit 0; fi
if [[ -n \${FAKE_NO_PHASES:-} ]]; then echo "{\"containment_ms\":\$ms,\"verdict\":\"PASS\"}"; exit 0; fi
v=PASS; ((ms < 60000)) || v=FAIL
touch "$w/ks.armed"   # a successful timer run leaves the switch armed, like the real one
echo "{\"containment_ms\":\$ms,\"threshold_ms\":60000,\"verdict\":\"\$v\",\"t0_epoch_ms\":\${FAKE_T0:-1792800000000},\"phases\":{\"t0_to_call_ms\":\$a,\"call_to_armed_ms\":\$b}}"
exit 0
TIMER
  fi
  chmod +x "$d"/bin/* "$d"/scripts/*.sh
  [[ $(PATH="$d/bin:$PATH" command -v docker) == "$d/bin/docker" ]] || { echo "fake docker not first on PATH" >&2; exit 2; }
  echo "$d"
}
# M: run the loop; sets out rc and OUT (the measure dir)
M() { # $1 = tree, rest = env assignments, then "--" and the script args
  local d=$1; shift; local -a envs=()
  while [[ $# -gt 0 && $1 != -- ]]; do envs+=("$1"); shift; done; shift
  rm -rf "$d/artifacts"/measure-*
  out=$(env -u MEASURE_NAME -u MEASURE_GAP -u MEASURE_RETRIES -u RANGE_KILL_MARKER "${envs[@]}" \
        RANGE_KILL_MARKER="$d/w/marker" PATH="$d/bin:$PATH" bash "$d/scripts/measure-ttc.sh" "$@" 2>&1); rc=$?
  OUT=$(ls -d "$d"/artifacts/measure-* 2>/dev/null | head -n1)
}
calls() { grep -v '^sleep' "$1/w/calls.log" | sed -E 's#^docker exec .*#query#; s#^docker ps.*#ps#; s#^docker .*#docker#' | paste -sd' '; }
summ() { jq -c "$1" "$OUT/summary.json" 2>/dev/null; }

# ---- P: the real timer -----------------------------------------------------------------------------------
timer() { # $1 = tree, rest = env; sets tout trc
  local d=$1; shift
  mkdir -p "$d/artifacts/20261024T000000Z"; echo "$d/artifacts/20261024T000000Z" >"$d/.run-id"
  tout=$(env "$@" PATH="$d/bin:$PATH" bash "$d/scripts/containment-timer.sh" 2>"$d/timer.err"); trc=$?
}
d=$(world p real)
timer "$d"
a=$(jq -r '.phases.t0_to_call_ms' <<<"$tout" 2>/dev/null); b=$(jq -r '.phases.call_to_armed_ms' <<<"$tout" 2>/dev/null)
ms=$(jq -r '.containment_ms' <<<"$tout" 2>/dev/null); e0=$(jq -r '.t0_epoch_ms' <<<"$tout" 2>/dev/null)
{ ((trc == 0)) && [[ $a =~ ^[0-9]+$ && $b =~ ^[0-9]+$ && $ms =~ ^[0-9]+$ && $e0 =~ ^[0-9]+$ ]] && ((ms == a + b)); } \
  || no "P1 phases are integers and containment_ms == t0_to_call + call_to_armed (rc=$trc ms=$ms a=$a b=$b)"$'\n'"$tout"
{ ((b >= 150)) 2>/dev/null; } || no "P1b call_to_armed_ms includes the arm itself (stub arm takes 200 ms; got b=$b)"
{ jq -e '.threshold_ms == 60000 and .verdict == "PASS" and (.first_attempt_log | test("canary.tripwire-range.invalid from 10.66.1.1"))' <<<"$tout" >/dev/null 2>&1; } \
  || no "P1c the original keys keep their meaning (threshold_ms, verdict, first_attempt_log)"$'\n'"$tout"
{ [[ -f "$d/artifacts/20261024T000000Z/containment.json" ]] && cmp -s <(jq -S . <<<"$tout") <(jq -S . "$d/artifacts/20261024T000000Z/containment.json"); } \
  || no "P1d containment.json in the run dir equals stdout"
timer "$d" FAKE_LOG_AGE=120
{ ((trc == 0)) && jq -e '.containment_ms >= 120000 and .verdict == "FAIL"' <<<"$tout" >/dev/null 2>&1; } \
  || no "P2 first attempt 120 s ago: containment_ms >= 120000 and FAIL (rc=$trc)"$'\n'"$tout"
rm -f "$d/w/ks.armed"; timer "$d" FAKE_ARM_NOOP=1
{ ((trc == 1)) && grep -q 'did not arm' "$d/timer.err"; } || no "P3 arm that does not arm: rc 1 (rc=$trc)"
rm -f "$d/w/ks.armed"; echo 0 >"$d/w/logs.count"; timer "$d" FAKE_NOQUERY_FIRST=99
{ ((trc == 2)); } || no "P4 no query in the log: rc 2 (rc=$trc)"
timer "$d" FAKE_BAD_TS=1
{ ((trc == 2)); } || no "P5 unparseable timestamp: rc 2 (rc=$trc)"

# ---- S: statistics ---------------------------------------------------------------------------------------
d=$(world s stub)
printf '30000 100 29900\n10000 50 9950\n20000 70 19930\n' >"$d/w/ttc.queue"
M "$d" -- 3
{ ((rc == 0)) && [[ $(summ '[.n_ok,.n_requested,.complete,.ttc_ms.min,.ttc_ms.median,.ttc_ms.max,.pass]') == '[3,3,true,10000,20000,30000,3]' ]] \
  && [[ $(summ '.ttc_ms.samples') == '[30000,10000,20000]' ]] && [[ $(summ '.phases.t0_to_call_ms') == '{"min":50,"median":70,"max":100,"samples":[100,50,70]}' ]]; } \
  || no "S1 odd n: exact min/median/max/samples (rc=$rc)"$'\n'"$(cat "$OUT/summary.json" 2>/dev/null)"$'\n'"$out"
grep -q '^MEASURE n=3/3 TTC median 20000 ms (min 10000, max 30000)' <<<"$out" || no "S1b the human line states n, median, min, max"$'\n'"$out"
d=$(world s2 stub)
printf '40000 1 39999\n10000 1 9999\n30000 1 29999\n20000 1 19999\n' >"$d/w/ttc.queue"
M "$d" -- 4
{ ((rc == 0)) && [[ $(summ '[.ttc_ms.min,.ttc_ms.median,.ttc_ms.max]') == '[10000,25000,40000]' ]]; } \
  || no "S2 even n: median = mean of the middle two (rc=$rc)"$'\n'"$(summ '.ttc_ms')"
d=$(world s3 stub)
printf '10000 1 9999\n60000 1 59999\n20000 1 19999\n' >"$d/w/ttc.queue"
M "$d" -- 3
{ ((rc == 1)) && [[ $(summ '[.n_ok,.pass,.complete]') == '[3,2,true]' ]]; } \
  || no "S3 one run at the threshold: rc 1, all three reported, pass 2/3 (rc=$rc)"$'\n'"$(summ '.')"
d=$(world s4 stub); printf '1 1 0\n1 1 0\n' >"$d/w/ttc.queue"
M "$d" -- 2
want="ks status ps range-up query timer ks off range-down ks status range-up query timer ks off range-down ks status ks off ks status range-down"
[[ $(calls "$d") == "$want" ]] || no "S4 call order: guards, then per cycle up/query/timer/off/down/status, then final cleanup"$'\n'"got:  $(calls "$d")"$'\n'"want: $want"

# ---- G: refusals — nothing is started --------------------------------------------------------------------
refused() { # label, tree, rc-expected-text
  { ((rc == 2)) && grep -q "REFUSED: $3" <<<"$out" && ! grep -qE '^(range-up|timer|ks off|ks arm)' "$2/w/calls.log" \
    && ! grep -q '^docker exec' "$2/w/calls.log" && [[ -z $OUT ]]; } \
    || no "$1: rc 2, REFUSED '$3', nothing started (rc=$rc)"$'\n'"$out"$'\n'"$(cat "$2/w/calls.log")"
}
d=$(world g1 stub); touch "$d/w/ks.armed"; M "$d" -- 1; refused "G1 killswitch armed" "$d" 'killswitch is armed'
d=$(world g2 stub); touch "$d/w/marker"; M "$d" -- 1; refused "G2 marker present" "$d" 'marker'
d=$(world g3 stub); M "$d" FAKE_RUNNING=1 -- 1; refused "G3 range containers running" "$d" 'range containers are running'
{ [[ -e "$d/w/ks.armed" ]] || ! grep -q 'ks off' "$d/w/calls.log"; } || no "G3b a refusal must not run killswitch off"

# ---- N: validation ---------------------------------------------------------------------------------------
n=0
for bad in 0 abc 3x ' 5' '05' 51 '-1' '5;touch' 'PATH[$(touch '"$T"'/pwned)]' ''; do
  d=$(world "n$n" stub); n=$((n + 1)); rm -f "$T/pwned"
  M "$d" -- "$bad"
  { ((rc == 2)) && grep -q 'REFUSED: N must be' <<<"$out" && [[ ! -e $T/pwned ]] && ! grep -q '^range-up' "$d/w/calls.log"; } \
    || no "N1 N='$bad' refused before anything starts, payload never executed (rc=$rc)"$'\n'"$out"
done
d=$(world nv stub)
for kv in 'MEASURE_GAP=abc' 'MEASURE_GAP=3601' 'MEASURE_GAP=-1' 'MEASURE_GAP=1x' 'MEASURE_RETRIES=0' 'MEASURE_RETRIES=31' 'MEASURE_RETRIES=x' \
          'MEASURE_NAME=a b' 'MEASURE_NAME=a;touch' 'MEASURE_NAME=$(touch pwned)' 'MEASURE_NAME=-bad.example' 'MEASURE_NAME=bad.example-' \
          'MEASURE_NAME=x.sim.invalid' 'MEASURE_NAME=API.SIM.INVALID' 'MEASURE_NAME='; do
  M "$d" "$kv" -- 1
  { ((rc == 2)) && grep -q '^REFUSED:' <<<"$out" && ! grep -q '^range-up' "$d/w/calls.log" && [[ ! -e $T/pwned && ! -e pwned ]]; } \
    || no "N2 $kv refused (rc=$rc)"$'\n'"$out"
done
d=$(world nw stub); printf '1 1 0\n' >"$d/w/ttc.queue"
M "$d" MEASURE_NAME=example.com -- 1
{ ((rc == 0)) && grep -q 'http://example.com/' "$d/w/calls.log"; } || no "N3 a plain out-of-scope name is queried (rc=$rc)"$'\n'"$out"

# ---- R: failure paths --------------------------------------------------------------------------------------
cleaned() { # tree: the last three calls are the final cleanup
  [[ $(grep -v '^sleep' "$1/w/calls.log" | tail -n3 | paste -sd' ') == "ks off ks status range-down" ]]
}
d=$(world r1 stub); printf '2\n2\n' >"$d/w/timer.rc"; printf '15000 10 14990\n' >"$d/w/ttc.queue"
M "$d" -- 1
{ ((rc == 0)) && [[ $(jq -r '.attempts' "$OUT/runs.jsonl") == 3 ]] && [[ $(grep -c '^sleep 1$' "$d/w/calls.log") == 2 ]]; } \
  || no "R1 timer rc 2 twice then ok: attempts 3, two 1-second waits (rc=$rc)"$'\n'"$(cat "$OUT/runs.jsonl" 2>/dev/null)"
d=$(world r2 stub); printf '2\n2\n2\n' >"$d/w/timer.rc"; printf '1 1 0\n1 1 0\n' >"$d/w/ttc.queue"
M "$d" MEASURE_RETRIES=3 -- 2
{ ((rc == 3)) && [[ $(summ '[.n_ok,.complete]') == '[0,false]' ]] && grep -q 'INCOMPLETE: 1 error' <<<"$out" \
  && [[ $(grep -c '^range-up' "$d/w/calls.log") == 1 ]] && cleaned "$d"; } \
  || no "R2 retries exhausted: rc 3, the loop stops after the first failed cycle, cleanup ran (rc=$rc)"$'\n'"$out"
d=$(world r3 stub); printf '1\n' >"$d/w/timer.rc"
M "$d" -- 2
{ ((rc == 3)) && [[ $(jq -r '.error' "$OUT/runs.jsonl") == *'did not arm'* ]] && cleaned "$d" && [[ $(grep -c '^range-up' "$d/w/calls.log") == 1 ]]; } \
  || no "R3 timer rc 1: rc 3, stop, cleanup (rc=$rc)"$'\n'"$out"
d=$(world r4 stub); M "$d" FAKE_UP_RC=70 -- 2
{ ((rc == 3)) && ! grep -q '^docker exec' "$d/w/calls.log" && [[ $(jq -r '.error' "$OUT/runs.jsonl") == 'range-up rc=70'* ]] && cleaned "$d"; } \
  || no "R4 range-up fails: rc 3, no query, cleanup (rc=$rc)"$'\n'"$out"
d=$(world r5 stub); M "$d" FAKE_CURL_RC=0 -- 1
{ ((rc == 3)) && ! grep -q '^timer' "$d/w/calls.log" && [[ $(jq -r '.error' "$OUT/runs.jsonl") == *'curl rc=0'* ]]; } \
  || no "R5 curl rc 0 means the agent connected: rc 3, timer not run (rc=$rc)"$'\n'"$out"
for crc in 1 2 35 126 127; do
  d=$(world "r5$crc" stub); M "$d" FAKE_CURL_RC=$crc -- 1
  { ((rc == 3)) && ! grep -q '^timer' "$d/w/calls.log"; } || no "R5 curl rc $crc is not a clean refusal: rc 3 (rc=$rc)"
done
for crc in 6 28; do
  d=$(world "r5ok$crc" stub); printf '1 1 0\n' >"$d/w/ttc.queue"; M "$d" FAKE_CURL_RC=$crc -- 1
  ((rc == 0)) || no "R5b curl rc $crc (DNS failure / timeout) is a valid query (rc=$rc)"
done
d=$(world r6 stub); printf '1 1 0\n' >"$d/w/ttc.queue"; M "$d" FAKE_NO_PHASES=1 -- 1
{ ((rc == 3)) && [[ $(jq -r '.error' "$OUT/runs.jsonl") == *'lacks numeric'* ]]; } || no "R6 timer output without phases: rc 3 (rc=$rc)"$'\n'"$out"
d=$(world r7 stub); printf '1 1 0\n1 1 0\n' >"$d/w/ttc.queue"; M "$d" FAKE_OFF_STUCK=1 -- 2
{ ((rc == 3)) && grep -q 'still armed after cycle teardown' "$OUT/runs.jsonl" && [[ $(grep -c '^range-up' "$d/w/calls.log") == 1 ]]; } \
  || no "R7 killswitch stuck armed after a cycle: rc 3, the loop stops (rc=$rc)"$'\n'"$out"
grep -q 'CLEANUP FAILED' <<<"$out" || no "R8 a cleanup that cannot disarm says so"$'\n'"$out"
d=$(world r9 stub); printf '1 1 0\n' >"$d/w/ttc.queue"
rm -rf "$d/artifacts"/measure-*
env FAKE_UP_HANG=1 RANGE_KILL_MARKER="$d/w/marker" PATH="$d/bin:$PATH" bash "$d/scripts/measure-ttc.sh" 2 >"$d/term.out" 2>&1 &
pid=$!
for _ in $(seq 1 50); do [[ -e "$d/w/hang.started" ]] && break; $SIM 0.1; done
[[ -e "$d/w/hang.started" ]] || { echo "R9 harness: the cycle never started" >&2; kill "$pid" 2>/dev/null; exit 2; }
kill -TERM "$pid" 2>/dev/null
wait "$pid"; rc9=$?
{ ((rc9 == 130)) && cleaned "$d"; } || no "R9 SIGTERM mid-cycle: cleanup ran, rc 130 (rc=$rc9)"$'\n'"$(cat "$d/term.out")"$'\n'"$(cat "$d/w/calls.log")"

# ---- R11/R12: what the operator's TTD collector needs from every ok row -------------------------------------
d=$(world r11 stub); printf '15000 10 14990\n' >"$d/w/ttc.queue"; M "$d" FAKE_T0=1792800123456 -- 1
{ ((rc == 0)) && jq -e --arg d "$d" '.t0_epoch_ms == 1792800123456 and .name == "canary.tripwire-range.invalid"
     and (.run_dir | test("^artifacts/[0-9]{8}T[0-9]{6}Z$")) and (($d + "/" + .run_dir) | test("^/"))' "$OUT/runs.jsonl" >/dev/null 2>&1 \
  && [[ -d "$d/$(jq -r .run_dir "$OUT/runs.jsonl")" ]]; } \
  || no "R11 ok rows carry t0_epoch_ms, name and a real run_dir (rc=$rc)"$'\n'"$(cat "$OUT/runs.jsonl" 2>/dev/null)"
d=$(world r12 stub); printf '1 1 0\n' >"$d/w/ttc.queue"; M "$d" FAKE_BAD_RUNID=/tmp/x -- 1
{ ((rc == 3)) && [[ $(jq -r '.error' "$OUT/runs.jsonl") == *'is not artifacts/<UTC stamp>'* ]]; } \
  || no "R12 a run dir outside artifacts/<UTC stamp>: rc 3 (rc=$rc)"$'\n'"$out"
d=$(world r14 stub); printf '1 1 0\n' >"$d/w/ttc.queue"; M "$d" FAKE_NO_T0=1 -- 1
{ ((rc == 3)) && [[ $(jq -r '.error' "$OUT/runs.jsonl") == *'lacks t0_epoch_ms'* ]]; } || no "R14 timer output without t0_epoch_ms: rc 3 (rc=$rc)"
d=$(world r13 stub); printf '1 1 0\n' >"$d/w/ttc.queue"; M "$d" FAKE_BAD_RUNID='artifacts/../etc' -- 1
{ ((rc == 3)); } || no "R13 a traversing run dir: rc 3 (rc=$rc)"

# ---- R10 gap ---------------------------------------------------------------------------------------------
d=$(world gap stub); printf '1 1 0\n1 1 0\n1 1 0\n' >"$d/w/ttc.queue"
M "$d" MEASURE_GAP=7 -- 3
{ ((rc == 0)) && [[ $(grep -c '^sleep 7$' "$d/w/calls.log") == 2 ]]; } \
  || no "R10 MEASURE_GAP sleeps between cycles only (2 times for n=3; rc=$rc, got $(grep -c '^sleep 7$' "$d/w/calls.log"))"

# ---- E1 the real timer through the loop ------------------------------------------------------------------
d=$(world e1 real)
M "$d" -- 2
{ ((rc == 0)) && jq -e '.n_ok == 2 and .complete and (.ttc_ms.samples | length) == 2
     and (.phases.t0_to_call_ms.min <= .phases.t0_to_call_ms.median) and (.phases.call_to_armed_ms.min >= 150)
     and ([.ttc_ms.samples, .phases.t0_to_call_ms.samples, .phases.call_to_armed_ms.samples] | transpose | map(.[0] == .[1] + .[2]) | all)' \
     "$OUT/summary.json" >/dev/null 2>&1; } \
  || no "E1 real timer through the loop: n 2/2, every TTC == t0->call + call->armed (rc=$rc)"$'\n'"$(cat "$OUT/summary.json" 2>/dev/null)"$'\n'"$out"

# ---- X structure ----------------------------------------------------------------------------------------
BADRE='(iptables|systemctl|docker[[:space:]]+(restart|stop|rm|kill|network[[:space:]]+(rm|create)))'
scan() { BADRE="$BADRE" awk '{ code=$0; sub(/#.*/, "", code) } code ~ ENVIRON["BADRE"] { printf "%s:%d: %s\n", FILENAME, FNR, $0 }' "$@"; }
cat >"$T/fx.bad" <<'FX'
sudo iptables -I DOCKER-USER 1 -j X
sudo systemctl restart docker
  docker stop range-dns
docker network rm agentlab0
FX
cat >"$T/fx.ok" <<'FX'
# sudo iptables -L is only a comment
"$KS" off >/dev/null 2>&1
docker ps -q --filter label=x
docker exec "$AGENT" curl -4 -s http://x/
FX
nb=$(scan "$T/fx.bad" | wc -l); nk=$(scan "$T/fx.ok" | wc -l)
((nb == 4 && nk == 0)) || { echo "X GUARD UNPROVEN: bad $nb/4, ok $nk/0" >&2; exit 2; }
hits=$(scan "$ROOT/scripts/measure-ttc.sh")
[[ -z $hits ]] || no "X1 measure-ttc.sh touches the firewall, systemd or the daemon directly (use killswitch.sh / range-*.sh):"$'\n'"$hits"
nl=$(grep -cE '^[^#]*load_range_env "\$ROOT" strict' "$ROOT/scripts/measure-ttc.sh"); na=$(grep -cE '^[^#]*load_range_env ' "$ROOT/scripts/measure-ttc.sh")
{ ((nl == 1 && na == 1)); } || no "X1b measure-ttc.sh loads range.env exactly once, strict (strict=$nl all=$na)"
grep -qE '^measure-ttc N="5":' "$ROOT/justfile" && awk '/^measure-ttc N="5":/{f=1;next} f&&/^[^ ]/{exit} f' "$ROOT/justfile" | grep -q '^    ./scripts/measure-ttc.sh {{N}}$' \
  || no "X2 justfile has the measure-ttc recipe running ./scripts/measure-ttc.sh {{N}}"

((fail == 0)) && echo "measure-ttc: PASS (timer P1-P5; loop S1-S4 G1-G3 N1-N3 R1-R14 E1; structure X1-X2; guard 4/4 + 0/4)"
exit "$fail"
