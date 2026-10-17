#!/usr/bin/env bash
# test-negatives-attribution.sh — D5 P2b: a negative counts only if THE TARGET check went red.
# Fake world (stateful docker + probe built from that state) + the REAL verdict.sh:
#   A1 honest world      -> 4 targets "ok", sigma UNPROVEN (code), rc 3, world restored, no temp left
#   A2 cross-wired probe -> tripwire "INERT (red, but not from tripwire)", rc 1
#   A3 probe crashes     -> tripwire "ERROR (probe crashed ...)", rc 1 (a crash is not a detection)
#   A4 break fails       -> canaries "ERROR (break_canaries failed ...)", rc 1 (nothing was broken)
#   A5 TERM mid-break    -> the active break is undone on exit (egress network back to --internal)
#   A6 structural        -> no fixed /tmp/<name> path in negatives.sh
# Hermetic: the real docker is never reachable.  exit 0 = pass  1 = assertion failed  2 = harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/negatives.sh scripts/verdict.sh scripts/lib/skip.sh schemas/probe.v1.json; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
command -v jq >/dev/null 2>&1 || { echo "jq missing" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }

world() { # $1 = name; builds a tree with a fake world; prints the tree path
  local d="$T/$1" w="$T/$1/world"
  mkdir -p "$d/scripts" "$d/schemas" "$d/attestation" "$d/bin" "$d/tmp" "$w" || exit 2
  cp "$ROOT/scripts/negatives.sh" "$ROOT/scripts/verdict.sh" "$d/scripts/" || exit 2
  cp -r "$ROOT/scripts/lib" "$d/scripts/" || exit 2
  cp "$ROOT/schemas/probe.v1.json" "$d/schemas/" || exit 2
  printf 'PEM fake sim ca\n' >"$d/attestation/sim-range-ca.crt"
  printf 'RANGE_CIDR=10.66.0.0/16\n' >"$d/range.env"
  echo internal >"$w/net"
  cat >"$d/bin/docker" <<DOCKER
#!/usr/bin/env bash
W="$w"
echo "\$*" >>"\$W/docker.log"
case "\$*" in
  "network create --internal"*) echo internal >"\$W/net" ;;
  "network create"*) echo open >"\$W/net" ;;
  "network rm"*) rm -f "\$W/net" ;;
  "stop range-dns") touch "\$W/dns.stopped" ;;
  "start range-dns") rm -f "\$W/dns.stopped" ;;
  "exec "*" userdel ctf-canary") [[ -n \${FAKE_FAIL_USERDEL:-} ]] && exit 1; touch "\$W/canary.deleted" ;;
  "exec "*" useradd "*) rm -f "\$W/canary.deleted" ;;
esac
exit 0
DOCKER
  cat >"$d/bin/sleep" <<SLEEP
#!/usr/bin/env bash
if [[ -n \${FAKE_TERM_WHEN_OPEN:-} && \$(cat "$w/net" 2>/dev/null) == open ]]; then kill -TERM "\$PPID"; fi
exit 0
SLEEP
  cat >"$d/scripts/probe.sh" <<PROBE
#!/usr/bin/env bash
W="$w"
e=true; [[ \$(cat "\$W/net" 2>/dev/null) == internal ]] || e=false
t=true; [[ -e "\$W/dns.stopped" ]] && t=false
c=true; [[ -e "\$W/canary.deleted" ]] && c=false
s=true; [[ \$(head -c3 "$d/attestation/sim-range-ca.crt") == PEM ]] || s=false
if [[ -n \${FAKE_CRASH_ON_TRIPWIRE:-} && \$t == false ]]; then echo "fake probe crash" >&2; exit 1; fi
if [[ -n \${FAKE_CROSSWIRE:-} && \$t == false ]]; then t=true; c=false; fi
jq -n --argjson e \$e --argjson t \$t --argjson c \$c --argjson s \$s '{schema:1, ts:"2026-10-17T00:00:00Z",
  range_cidr:"10.66.0.0/16", range_net:"agentlab0", egress_blocked:\$e, tripwire_sinkholed:\$t,
  sigma_loaded:true, canaries_present:\$c, sim_ca_present:\$s,
  checks:[{id:"egress",ok:\$e,method:"fake",detail:"d"},{id:"tripwire",ok:\$t,method:"fake",detail:"d"},
          {id:"sigma",ok:true,method:"fake",detail:"d"},{id:"canaries",ok:\$c,method:"fake",detail:"d"},
          {id:"sim_ca",ok:\$s,method:"fake",detail:"d"}]}'
PROBE
  chmod +x "$d"/bin/* "$d"/scripts/*.sh
  [[ $(PATH="$d/bin:$PATH" command -v docker) == "$d/bin/docker" ]] || { echo "fake docker not first on PATH" >&2; exit 2; }
  echo "$d"
}
run() { # $1 = name, rest = extra env; sets out rc d
  d=$(world "$1"); shift
  out=$(env -u PROBE_SKIP -u VERDICT_SKIP -u NEG_SKIP "$@" TMPDIR="$d/tmp" PATH="$d/bin:$PATH" \
        bash "$d/scripts/negatives.sh" 2>&1); rc=$?
}
restored() { # world back to baseline and no temp files left
  [[ $(cat "$d/world/net" 2>/dev/null) == internal && ! -e "$d/world/dns.stopped" && ! -e "$d/world/canary.deleted" ]] \
    && [[ $(head -c3 "$d/attestation/sim-range-ca.crt") == PEM ]] && [[ -z $(ls -A "$d/tmp") ]]
}
show() { echo "--- $1 (rc=$rc):"; echo "$out"; }

run a1
{ ((rc == 3)) && grep -qE '^  egress +ok$' <<<"$out" && grep -qE '^  tripwire +ok$' <<<"$out" \
  && grep -qE '^  canaries +ok$' <<<"$out" && grep -qE '^  sim_ca +ok$' <<<"$out" \
  && grep -qE '^  sigma +UNPROVEN \(code: ' <<<"$out" && grep -q '4/5 controls proven falsifiable' <<<"$out"; } \
  || { no "A1 honest world: 4 targets ok, sigma UNPROVEN (code), 4/5, rc 3"; show a1; }
restored || { no "A1 world not restored or temp file left in TMPDIR"; ls -A "$d/world" "$d/tmp"; }

run a2 FAKE_CROSSWIRE=1
{ ((rc == 1)) && grep -qE '^  tripwire +INERT \(red, but not from tripwire\)' <<<"$out" \
  && ! grep -q 'range is recordable' <<<"$out"; } \
  || { no "A2 red verdict from another check must not count: tripwire INERT (red, but not from tripwire), rc 1"; show a2; }

run a3 FAKE_CRASH_ON_TRIPWIRE=1
{ ((rc == 1)) && grep -qE '^  tripwire +ERROR \(probe crashed' <<<"$out"; } \
  || { no "A3 probe crash after a break is ERROR, not a detection (rc 1)"; show a3; }

run a4 FAKE_FAIL_USERDEL=1
{ ((rc == 1)) && grep -qE '^  canaries +ERROR \(break_canaries failed' <<<"$out"; } \
  || { no "A4 a failed break is ERROR (nothing was broken), rc 1"; show a4; }

run a5 FAKE_TERM_WHEN_OPEN=1
{ ((rc != 0)) && [[ $(cat "$d/world/net" 2>/dev/null) == internal ]]; } \
  || { no "A5 TERM during break_egress must restore the --internal network on exit"; show a5; cat "$d/world/net"; }

hits=$(grep -nE '/tmp/[A-Za-z]' "$ROOT/scripts/negatives.sh")
[[ -z $hits ]] || { no "A6 fixed /tmp path in negatives.sh: $hits"; }

if ((fail)); then exit 1; fi
echo "negatives-attribution: PASS (6/6)"
