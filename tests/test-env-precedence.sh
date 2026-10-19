#!/usr/bin/env bash
# test-env-precedence.sh — D5 P3: how lab code loads range.env (scripts/lib/env.sh, runbook rule 44).
#   E1 default: an EXPORTED value wins over range.env; the override is named on stderr, the value never
#   E2 default: nothing exported -> range.env values, stderr silent
#   E3 default: exported value equal to range.env -> no override line
#   E4 strict:  differing exported value -> return 3, refused, value never printed; equal value -> 0
#   E5 no range.env -> return 0      E6 range.env that cannot be sourced -> return 2
#   E7 structural: no tracked code sources range.env directly (guard proven on fixtures first)
#   E8 structural: each script loads range.env exactly once, with the expected mode
#   E9  verdict.sh: VERDICT_SKIP="" exported beats VERDICT_SKIP="canaries" in range.env
#   E10 probe.sh:   SIGMA_EXPECTED=9 exported beats 8 in range.env -> sigma red (the D5 P3 negative path)
#   E11 killswitch.sh (strict): a stray RANGE_CIDR export is refused before any iptables call
# Hermetic: temp trees, stub docker/curl/sudo first on PATH.  exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/verdict.sh scripts/probe.sh scripts/killswitch.sh schemas/probe.v1.json; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
command -v jq >/dev/null 2>&1 || { echo "jq missing" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }
SECRET='S3CR3T-VALUE-not-for-logs'

# ---- E1-E6: the library ----------------------------------------------------------------------
L() { # $1 = range.env content ("" = no file), $2 = mode, rest = env assignments; sets out err rc
  local d; d=$(mktemp -d "$T/lib.XXXX")
  [[ -n $1 ]] && printf '%s\n' "$1" >"$d/range.env"
  local mode=$2; shift 2
  out=$(env -u A -u B "$@" bash -c 'set -u; source "$1/scripts/lib/env.sh" || exit 9
    load_range_env "$2" $3; rc=$?; echo "rc=$rc A=${A-unset} B=${B-unset}"' _ "$ROOT" "$d" "$mode" 2>"$d/err")
  rc=$?; err=$(cat "$d/err")
}
L $'A=file\nB=file' '' A="$SECRET"
{ [[ $out == "rc=0 A=$SECRET B=file" ]] && grep -qx 'range.env: A overridden by environment' <<<"$err" \
  && ! grep -q "$SECRET" <<<"$err" && ! grep -q '\bB\b' <<<"$err"; } \
  || no "E1 exported A must win, override named on stderr, value never printed (out='$out' err='$err')"
L $'A=file\nB=file' ''
{ [[ $out == "rc=0 A=file B=file" && -z $err ]]; } || no "E2 no env: range.env values, silent (out='$out' err='$err')"
L $'A=file\nB=file' '' A=file
{ [[ $out == "rc=0 A=file B=file" && -z $err ]]; } || no "E3 equal export: no override line (out='$out' err='$err')"
L $'A=file\nB=file' strict A="$SECRET"
{ [[ $out == "rc=3 A=file B=file" ]] && grep -q 'A .*refused' <<<"$err" && ! grep -q "$SECRET" <<<"$err"; } \
  || no "E4a strict: differing export refused, rc 3, value never printed (out='$out' err='$err')"
L $'A=file\nB=file' strict A=file
[[ $out == "rc=0 A=file B=file" ]] || no "E4b strict: equal export is fine (out='$out')"
L '' ''
[[ $out == "rc=0 A=unset B=unset" ]] || no "E5 no range.env: rc 0, nothing set (out='$out')"
L 'A=(' ''
[[ $out == rc=2* ]] || no "E6 unsourceable range.env: rc 2 (out='$out' err='$err')"

# ---- E7: no direct source of range.env in tracked code ---------------------------------------
SRC='(^|[;&|[:space:]])(source|\.)[[:space:]]+[^;&|]*range\.env'
scan() { SRC="$SRC" awk '{ code=$0; sub(/#.*/, "", code) } code ~ ENVIRON["SRC"] { printf "%s:%d: %s\n", FILENAME, FNR, $0 }' "$@"; }
cat >"$T/bad" <<'FX'
[[ -f "$ROOT/range.env" ]] && source "$ROOT/range.env"
. "$ROOT/range.env"
    source range.env
x=1; source ./range.env
FX
cat >"$T/ok" <<'FX'
# [[ -f "$ROOT/range.env" ]] && source "$ROOT/range.env"
source "$ROOT/scripts/lib/env.sh" || exit 2
cp "$ROOT/range.env.example" "$ROOT/range.env"
grep -q 'CHANGE_ME' "$ROOT/range.env"
echo "range.env. source it"
FX
nbad=$(scan "$T/bad" | wc -l); nok=$(scan "$T/ok" | wc -l)
if ((nbad != 4 || nok != 0)); then echo "E7 GUARD UNPROVEN: bad $nbad/4, ok $nok/0" >&2; scan "$T/bad" "$T/ok" >&2; exit 2; fi
mapfile -t files < <(cd "$ROOT" && git ls-files -- '*.sh' justfile ':!tests/')
((${#files[@]} > 0)) || { echo "E7 nothing scanned" >&2; exit 2; }
hits=$(cd "$ROOT" && scan "${files[@]}")
[[ -z $hits ]] || no "E7 direct source of range.env (use scripts/lib/env.sh):"$'\n'"$hits"

# ---- E8: one loader call per script, expected mode -------------------------------------------
declare -A MODE=([containment-timer]=strict [killswitch]=strict [negatives]=strict [range-down]=strict
  [range-up]=strict [lint-rules]=default [logtest]=default [preflight]=default [probe]=default [verdict]=default)
for s in $(printf '%s\n' "${!MODE[@]}" | sort); do
  f="$ROOT/scripts/$s.sh"; [[ -f $f ]] || { no "E8 missing scripts/$s.sh"; continue; }
  calls=$(grep -E '^[^#]*load_range_env ' "$f")
  n=$(grep -c . <<<"$calls"); m=default; grep -q 'load_range_env "\$ROOT" strict' <<<"$calls" && m=strict
  { ((n == 1)) && [[ $m == "${MODE[$s]}" ]]; } || no "E8 scripts/$s.sh: $n loader call(s), mode $m, want 1 x ${MODE[$s]}"
done
nj=$(grep -cE '^[^#]*load_range_env "\$PWD" strict' "$ROOT/justfile")
((nj == 2)) || no "E8 justfile: $nj strict loader calls in break-* recipes, want 2"

# ---- E9-E11: real scripts ---------------------------------------------------------------------
tree() { # $1 = name, $2 = range.env; copies scripts + lib + schema; prints path
  local d="$T/$1"
  mkdir -p "$d/scripts" "$d/schemas" "$d/bin" || exit 2
  cp "$ROOT"/scripts/*.sh "$d/scripts/" || exit 2
  if [[ -d "$ROOT/scripts/lib" ]]; then cp -r "$ROOT/scripts/lib" "$d/scripts/" || exit 2; fi
  cp "$ROOT/schemas/probe.v1.json" "$d/schemas/" || exit 2
  printf '%s\n' "$2" >"$d/range.env"
  echo "$d"
}
stubs() { # $1 = tree: stub docker, curl, sudo (each logs its argv)
  local d=$1
  cat >"$d/bin/docker" <<STUB
#!/usr/bin/env bash
echo "\$*" >>"$d/docker.log"
case "\$*" in
  "image inspect"*) exit 0 ;;
  *getent*) echo "0.0.0.0 canary.tripwire-range.invalid" ;;
  run*) exit 7 ;;
esac
exit 0
STUB
  cat >"$d/bin/curl" <<STUB
#!/usr/bin/env bash
echo "\$*" >>"$d/curl.log"
case "\$*" in
  *authenticate*) echo '{"data":{"token":"t"}}' ;;
  *rule_ids=*) echo '{"data":{"total_affected_items":8}}' ;;
  *) exit 7 ;;
esac
STUB
  printf '#!/usr/bin/env bash\necho "$*" >>"%s/sudo.log"\nexit 1\n' "$d" >"$d/bin/sudo"
  chmod +x "$d"/bin/* "$d"/scripts/*.sh
  for c in docker curl sudo; do
    [[ $(PATH="$d/bin:$PATH" command -v $c) == "$d/bin/$c" ]] || { echo "stub $c not first on PATH" >&2; exit 2; }
  done
}
CLEAN=(env -u PROBE_SKIP -u VERDICT_SKIP -u NEG_SKIP -u SIGMA_EXPECTED -u RANGE_CIDR -u RANGE_NET -u RANGE_IP_RANGE)

d=$(tree e9 $'VERDICT_SKIP="canaries"\nRANGE_CIDR=10.66.0.0/16')
jq -n '{schema:1, ts:"2026-10-19T00:00:00Z", range_cidr:"10.66.0.0/16", range_net:"agentlab0",
  egress_blocked:true, tripwire_sinkholed:true, sigma_loaded:true, canaries_present:true, sim_ca_present:true,
  checks:[{id:"egress",ok:true,method:"stub",detail:"d"},{id:"tripwire",ok:true,method:"stub",detail:"d"},
          {id:"sigma",ok:true,method:"stub",detail:"d"},{id:"canaries",ok:true,method:"stub",detail:"d"},
          {id:"sim_ca",ok:true,method:"stub",detail:"d"}]}' >"$d/ok.json" || exit 2
out=$("${CLEAN[@]}" VERDICT_SKIP="" bash "$d/scripts/verdict.sh" "$d/ok.json" 2>"$d/err"); rc=$?
{ ((rc == 0)) && grep -qE '^canaries_present +pass' <<<"$out" && [[ $(tail -n1 <<<"$out") == "PROBE PASS" ]] \
  && grep -q 'VERDICT_SKIP overridden by environment' "$d/err"; } \
  || no "E9 verdict: exported VERDICT_SKIP=\"\" must beat range.env (rc=$rc): $out $(cat "$d/err")"

d=$(tree e10 $'SIGMA_EXPECTED=8\nWAZUH_HOST=127.0.0.1\nWAZUH_USER=u\nWAZUH_PASS=p\nRANGE_CIDR=10.66.0.0/16'); stubs "$d"
sig() { jq -r '.checks[] | select(.id=="sigma") | "\(.ok) \(.detail)"' <<<"$1" 2>/dev/null; }
out=$("${CLEAN[@]}" PATH="$d/bin:$PATH" bash "$d/scripts/probe.sh" 2>"$d/err0"); rc=$?
[[ $rc == 0 && $(sig "$out") == "true loaded=8 expected=8 "* ]] \
  || no "E10a probe without export: sigma true, expected=8 (rc=$rc sigma='$(sig "$out")')"
out=$("${CLEAN[@]}" SIGMA_EXPECTED=9 PATH="$d/bin:$PATH" bash "$d/scripts/probe.sh" 2>"$d/err1"); rc=$?
{ [[ $rc == 0 && $(sig "$out") == "false loaded=8 expected=9 "* ]] \
  && grep -q 'SIGMA_EXPECTED overridden by environment' "$d/err1"; } \
  || no "E10b probe with SIGMA_EXPECTED=9 exported: sigma false, expected=9, override named (rc=$rc sigma='$(sig "$out")')"

d=$(tree e11 $'RANGE_CIDR=10.66.0.0/16\nKILL_CHAIN=RANGE-KILL'); stubs "$d"
out=$("${CLEAN[@]}" PATH="$d/bin:$PATH" bash "$d/scripts/killswitch.sh" status 2>&1); rc=$?
{ ((rc == 0)) && [[ -s "$d/sudo.log" ]]; } || no "E11a killswitch control: status runs without exports (rc=$rc): $out"
rm -f "$d/sudo.log"
out=$("${CLEAN[@]}" RANGE_CIDR=10.99.0.0/16 PATH="$d/bin:$PATH" bash "$d/scripts/killswitch.sh" status 2>&1); rc=$?
{ ((rc == 2)) && [[ ! -e "$d/sudo.log" ]] && grep -q 'RANGE_CIDR .*refused' <<<"$out"; } \
  || no "E11b killswitch: stray RANGE_CIDR export refused, rc 2, no iptables call (rc=$rc): $out"

if ((fail)); then exit 1; fi
echo "env-precedence: PASS (lib 7/7, structural 2/2 + guard 4/4 + 0/5, scripts 5/5)"
