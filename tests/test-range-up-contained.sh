#!/usr/bin/env bash
# test-range-up-contained.sh — D5 P2b: range-up starts the range ONLY on the contained network.
#   R1 no network       -> created with --internal, probe runs, PROBE PASS, rc 0
#   R2 existing, open   -> rc 4 (Internal=false), nothing started, probe not run
#   R3 existing, wrong ip-range -> rc 4 (srcip exceptions and t0 depend on the agent pool)
#   R4 compose up fails -> rc 70, probe not run
#   R5 network create fails -> rc 70, compose up not run
# Fake docker; the REAL verdict.sh judges a fake all-green probe.   exit 0 pass / 1 fail / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/range-up.sh scripts/verdict.sh scripts/lib/skip.sh schemas/probe.v1.json; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
command -v jq >/dev/null 2>&1 || { echo "jq missing" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }

tree() { # $1 = name, $2 = pre-existing network inspect line ("" = no network); prints path
  local d="$T/$1" w="$T/$1/world"
  mkdir -p "$d/scripts" "$d/schemas" "$d/bin" "$w" || exit 2
  cp "$ROOT/scripts/range-up.sh" "$ROOT/scripts/verdict.sh" "$d/scripts/" || exit 2
  cp -r "$ROOT/scripts/lib" "$d/scripts/" || exit 2
  cp "$ROOT/schemas/probe.v1.json" "$d/schemas/" || exit 2
  printf 'RANGE_CIDR=10.66.0.0/16\n' >"$d/range.env"
  [[ -n $2 ]] && printf '%s\n' "$2" >"$w/net"
  cat >"$d/bin/docker" <<DOCKER
#!/usr/bin/env bash
W="$w"
echo "\$*" >>"\$W/docker.log"
if [[ \$1 == network && \$2 == inspect ]]; then
  [[ -f "\$W/net" ]] || exit 1
  [[ \$3 == -f ]] && cat "\$W/net"
  exit 0
fi
if [[ \$1 == network && \$2 == create ]]; then
  [[ -n \${FAKE_FAIL_CREATE:-} ]] && exit 1
  i=false; s=""; r=""
  for a in "\$@"; do case \$a in --internal) i=true;; --subnet=*) s=\${a#--subnet=};; --ip-range=*) r=\${a#--ip-range=};; esac; done
  echo "\$i \$s \$r" >"\$W/net"; exit 0
fi
if [[ \$1 == compose ]]; then
  case " \$* " in
    *" up "*) [[ -n \${FAKE_FAIL_UP:-} ]] && { echo "fake compose up failure"; exit 1; }; touch "\$W/up.done" ;;
    *" ps "*) echo "[]" ;;
  esac
  exit 0
fi
exit 0
DOCKER
  cat >"$d/scripts/probe.sh" <<PROBE
#!/usr/bin/env bash
touch "$w/probe.ran"
jq -n '{schema:1, ts:"2026-10-17T00:00:00Z", range_cidr:"10.66.0.0/16", range_net:"agentlab0",
  egress_blocked:true, tripwire_sinkholed:true, sigma_loaded:true, canaries_present:true, sim_ca_present:true,
  checks:[{id:"egress",ok:true,method:"fake",detail:"d"},{id:"tripwire",ok:true,method:"fake",detail:"d"},
          {id:"sigma",ok:true,method:"fake",detail:"d"},{id:"canaries",ok:true,method:"fake",detail:"d"},
          {id:"sim_ca",ok:true,method:"fake",detail:"d"}]}'
PROBE
  chmod +x "$d"/bin/* "$d"/scripts/*.sh
  [[ $(PATH="$d/bin:$PATH" command -v docker) == "$d/bin/docker" ]] || { echo "fake docker not first on PATH" >&2; exit 2; }
  echo "$d"
}
run() { # $1 = name, $2 = existing network line, rest = extra env
  d=$(tree "$1" "$2"); shift 2
  out=$(env -u PROBE_SKIP -u VERDICT_SKIP -u NEG_SKIP -u RANGE_NET -u RANGE_CIDR -u RANGE_IP_RANGE "$@" \
        PATH="$d/bin:$PATH" bash "$d/scripts/range-up.sh" 2>&1); rc=$?
  ran=0; [[ -e "$d/world/probe.ran" ]] && ran=1
  up=0; [[ -e "$d/world/up.done" ]] && up=1
}
show() { echo "--- $1 (rc=$rc):"; echo "$out"; cat "$d/world/docker.log" 2>/dev/null; }

run r1 ""
{ ((rc == 0 && ran == 1)) && grep -q 'network create --internal' "$d/world/docker.log" && grep -q '^PROBE PASS$' <<<"$out"; } \
  || { no "R1 missing network is created --internal, probe runs, PROBE PASS rc 0"; show r1; }
run r2 "false 10.66.0.0/16 10.66.1.0/24"
{ ((rc == 4 && ran == 0 && up == 0)) && grep -qi 'not the contained network' <<<"$out"; } \
  || { no "R2 existing non-internal network: rc 4, nothing started, probe not run"; show r2; }
run r3 "true 10.66.0.0/16 10.66.0.0/24"
{ ((rc == 4 && ran == 0 && up == 0)); } || { no "R3 existing network with a wrong ip-range: rc 4, nothing started"; show r3; }
run r4 "" FAKE_FAIL_UP=1
{ ((rc == 70 && ran == 0)); } || { no "R4 compose up failure: rc 70, probe not run"; show r4; }
run r5 "" FAKE_FAIL_CREATE=1
{ ((rc == 70 && up == 0)); } || { no "R5 network create failure: rc 70, compose up not run"; show r5; }

if ((fail)); then exit 1; fi
echo "range-up-contained: PASS (5/5)"
