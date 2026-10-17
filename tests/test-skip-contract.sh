#!/usr/bin/env bash
# test-skip-contract.sh — D5 P2a contract for operator skips (verdict.sh + negatives.sh).
#   VERDICT_SKIP: verdict prints the check as "SKIP (operator: VERDICT_SKIP)" and the final line
#     names it ("PROBE PASS (skipped: ...)"); negatives report it UNPROVEN (operator: VERDICT_SKIP),
#     because a check the verdict does not judge cannot detect a break.
#   NEG_SKIP: negatives only (UNPROVEN (operator: NEG_SKIP)); the verdict still judges the check.
#   Excluded controls are never broken. Source precedence: code (NO_NEG) > VERDICT_SKIP > NEG_SKIP.
#   PROBE_SKIP is retired: set at all (even empty; range.env or environment) -> exit 2, nothing run.
#   Unknown id in VERDICT_SKIP / NEG_SKIP -> exit 2 (ids come from schemas/probe.v1.json).
# Hermetic: temp trees, stub probe/docker/sleep (negatives also gets a stub verdict); the real
# docker is never reachable.   exit 0 = pass   exit 1 = assertion failed   exit 2 = harness problem
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/verdict.sh scripts/negatives.sh schemas/probe.v1.json; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
command -v jq >/dev/null 2>&1 || { echo "jq missing" >&2; exit 2; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }
CLEAN=(env -u PROBE_SKIP -u VERDICT_SKIP -u NEG_SKIP)
# every check red: since D5 P2b negatives credit a break only if checks[<target>].ok == false
ALLRED='{"schema":1,"checks":[{"id":"egress","ok":false},{"id":"tripwire","ok":false},{"id":"sigma","ok":false},{"id":"canaries","ok":false},{"id":"sim_ca","ok":false}]}'

tree() { # $1 = name, $2 = range.env line(s); prints the tree path
  local d="$T/$1"
  mkdir -p "$d/scripts" "$d/schemas" "$d/attestation" "$d/bin" || exit 2
  cp "$ROOT/scripts/verdict.sh" "$ROOT/scripts/negatives.sh" "$d/scripts/" || exit 2
  if [[ -d "$ROOT/scripts/lib" ]]; then cp -r "$ROOT/scripts/lib" "$d/scripts/" || exit 2; fi
  cp "$ROOT/schemas/probe.v1.json" "$d/schemas/" || exit 2
  echo "PEM" >"$d/attestation/sim-range-ca.crt"
  printf '%s\nRANGE_CIDR=10.66.0.0/16\n' "$2" >"$d/range.env"
  echo "$d"
}

probe_json() { # $1 = sigma ok (true|false)
  jq -n --argjson s "$1" '{schema:1, ts:"2026-10-17T00:00:00Z", range_cidr:"10.66.0.0/16",
    range_net:"agentlab0", egress_blocked:true, tripwire_sinkholed:true, sigma_loaded:$s,
    canaries_present:true, sim_ca_present:true,
    checks:[{id:"egress",ok:true,method:"stub",detail:"d"},{id:"tripwire",ok:true,method:"stub",detail:"d"},
            {id:"sigma",ok:$s,method:"stub",detail:"d"},{id:"canaries",ok:true,method:"stub",detail:"d"},
            {id:"sim_ca",ok:true,method:"stub",detail:"d"}]}'
}
probe_json true >"$T/ok.json" || exit 2
probe_json false >"$T/sigma-red.json" || exit 2

# ---- verdict.sh ----------------------------------------------------------------------------
V() { # $1 = name, $2 = range.env, $3 = probe json, rest = extra env assignments
  local d; d=$(tree "$1" "$2"); local j="$3"; shift 3
  out=$("${CLEAN[@]}" "$@" bash "$d/scripts/verdict.sh" "$j" 2>&1); rc=$?
  last=$(grep -v '^[[:space:]]*$' <<<"$out" | tail -n1)
}
show() { echo "--- $1 (rc=$rc):"; echo "$out"; }

V v1 'PROBE_SKIP="sigma"' "$T/ok.json"
{ ((rc == 2)) && grep -q 'PROBE_SKIP' <<<"$out" && grep -q 'VERDICT_SKIP' <<<"$out"; } \
  || { no "verdict: PROBE_SKIP in range.env must exit 2 naming PROBE_SKIP and VERDICT_SKIP"; show v1; }
V v2 'PROBE_SKIP=""' "$T/ok.json"
((rc == 2)) || { no "verdict: empty PROBE_SKIP must still exit 2"; show v2; }
V v3 '' "$T/ok.json" PROBE_SKIP=sigma
((rc == 2)) || { no "verdict: PROBE_SKIP from the environment must exit 2"; show v3; }
V v4 'VERDICT_SKIP="canaries"' "$T/ok.json"
{ ((rc == 0)) && grep -qE '^canaries_present +SKIP +\(operator: VERDICT_SKIP\)' <<<"$out" \
  && [[ $last == "PROBE PASS (skipped: canaries)" ]]; } \
  || { no "verdict: VERDICT_SKIP=canaries -> SKIP (operator: VERDICT_SKIP) + 'PROBE PASS (skipped: canaries)'"; show v4; }
V v5 'VERDICT_SKIP="sigmaa"' "$T/ok.json"
{ ((rc == 2)) && grep -q 'sigmaa' <<<"$out"; } || { no "verdict: unknown id must exit 2 naming it"; show v5; }
V v6 'NEG_SKIP="tripwire"' "$T/ok.json"
{ ((rc == 0)) && grep -qE '^tripwire_sinkholed +pass' <<<"$out" && [[ $last == "PROBE PASS" ]]; } \
  || { no "verdict: NEG_SKIP must not affect the verdict"; show v6; }
V v7 '' "$T/sigma-red.json"
{ ((rc == 1)) && [[ $last == "PROBE FAIL" ]]; } || { no "verdict: failing check without skip -> PROBE FAIL rc=1"; show v7; }
V v8 'VERDICT_SKIP="canaries sigma"' "$T/sigma-red.json"
{ ((rc == 0)) && [[ $last == "PROBE PASS (skipped: sigma canaries)" ]]; } \
  || { no "verdict: skipped list in check order -> 'PROBE PASS (skipped: sigma canaries)'"; show v8; }

# ---- negatives.sh --------------------------------------------------------------------------
N() { # $1 = name, $2 = range.env, rest = extra env assignments
  local d; d=$(tree "$1" "$2"); shift 2
  printf '#!/bin/sh\ntouch "%s/probe.ran"\ncat <<"J"\n%s\nJ\n' "$d" "$ALLRED" >"$d/scripts/probe.sh"
  printf '#!/bin/sh\ncase "$1" in *baseline*|*restored*) exit 0;; *) exit 1;; esac\n' >"$d/scripts/verdict.sh"
  printf '#!/bin/sh\necho "$*" >>"%s/docker.log"\nexit 0\n' "$d" >"$d/bin/docker"
  printf '#!/bin/sh\nexit 0\n' >"$d/bin/sleep"
  chmod +x "$d"/scripts/*.sh "$d"/bin/*
  [[ $(PATH="$d/bin:$PATH" command -v docker) == "$d/bin/docker" ]] || { echo "stub docker not first on PATH" >&2; exit 2; }
  out=$("${CLEAN[@]}" "$@" PATH="$d/bin:$PATH" bash "$d/scripts/negatives.sh" 2>&1); rc=$?
  dlog=$(cat "$d/docker.log" 2>/dev/null); ran=0; [[ -e "$d/probe.ran" ]] && ran=1
}

N n1 'PROBE_SKIP="canaries"'
{ ((rc == 2)) && grep -q 'PROBE_SKIP' <<<"$out" && [[ -z $dlog ]] && ((ran == 0)); } \
  || { no "negatives: PROBE_SKIP must exit 2 before any probe or docker call"; show n1; }
N n2 'VERDICT_SKIP="canaries"'
{ ((rc == 3)) && grep -qE '^  canaries +UNPROVEN \(operator: VERDICT_SKIP\)' <<<"$out" \
  && ! grep -q 'userdel' <<<"$dlog"; } \
  || { no "negatives: VERDICT_SKIP=canaries -> UNPROVEN (operator: VERDICT_SKIP), never broken"; show n2; }
N n3 'NEG_SKIP="tripwire"'
{ ((rc == 3)) && grep -qE '^  tripwire +UNPROVEN \(operator: NEG_SKIP\)' <<<"$out" \
  && ! grep -q 'stop range-dns' <<<"$dlog"; } \
  || { no "negatives: NEG_SKIP=tripwire -> UNPROVEN (operator: NEG_SKIP), never broken"; show n3; }
N n4 'VERDICT_SKIP="sigma"'
grep -qE '^  sigma +UNPROVEN \(code: ' <<<"$out" || { no "negatives: code source must win over VERDICT_SKIP"; show n4; }
N n5 $'VERDICT_SKIP="tripwire"\nNEG_SKIP="tripwire"'
grep -qE '^  tripwire +UNPROVEN \(operator: VERDICT_SKIP\)' <<<"$out" \
  || { no "negatives: VERDICT_SKIP must win over NEG_SKIP"; show n5; }
N n6 'NEG_SKIP="bogus"'
{ ((rc == 2)) && grep -q 'bogus' <<<"$out" && [[ -z $dlog ]]; } \
  || { no "negatives: unknown id must exit 2 naming it, before any docker call"; show n6; }
N n7 $'VERDICT_SKIP="canaries"\nNEG_SKIP="tripwire"'
grep -qE '2/5 controls proven falsifiable' <<<"$out" || { no "negatives: count must be 2/5 (egress, sim_ca)"; show n7; }

if ((fail)); then exit 1; fi
echo "skip-contract: PASS (verdict 8/8, negatives 7/7)"
