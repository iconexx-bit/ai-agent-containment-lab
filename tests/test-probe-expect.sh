#!/usr/bin/env bash
# test-probe-expect.sh — D5 P5b, variant B: SIGMA_EXPECTED has no default and is validated
# before any arithmetic (runbook 10.6 P5b; rules 21, 29).
#   X0 control: SIGMA_EXPECTED=8 in range.env, API answers 8 -> sigma true loaded=8 expected=8, 2 API calls
#   X1 SIGMA_EXPECTED absent (range.env and environment) -> sigma false "SIGMA_EXPECTED unset", 0 API calls
#   X2 SIGMA_EXPECTED= (empty) in range.env -> same as X1
#   X3 malformed value exported over range.env (default-mode override, the live-negative path):
#      0, -3, abc, 08, 8x, " 8", "8 ", PATH[$(touch canary)]
#      -> sigma false "SIGMA_EXPECTED malformed", 0 API calls, the canary is NOT created
#         (bash arithmetic evaluates array subscripts), no bash arithmetic error on stderr
# Every case: probe rc 0 and valid JSON with all 5 checks (a bad expectation is DATA, not a crash).
# Hermetic: temp trees, stub docker/curl first on PATH.  exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/probe.sh scripts/lib/env.sh schemas/probe.v1.json; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
command -v jq >/dev/null 2>&1 || { echo "jq missing" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
[[ $T != *[[:space:]]* ]] || { echo "temp path contains whitespace: $T" >&2; exit 2; }
fail=0; no() { echo "FAIL: $*"; fail=1; }
PIN='sha256//0vxCZwJEabcdefghijklmnopqrstuvwxyz0123NMe8A='   # syntactically valid, not the real pin

world() { # $1 = name, $2 = SIGMA_EXPECTED line for range.env ("" = no such line); prints path
  local d="$T/$1"
  mkdir -p "$d/scripts" "$d/schemas" "$d/bin" || exit 2
  cp "$ROOT"/scripts/*.sh "$d/scripts/" && cp -r "$ROOT/scripts/lib" "$d/scripts/" \
    && cp "$ROOT/schemas/probe.v1.json" "$d/schemas/" || exit 2
  { [[ -z $2 ]] || printf '%s\n' "$2"
    printf "WAZUH_HOST=127.0.0.1\nWAZUH_USER=ro\nWAZUH_PASS=pw\nWAZUH_API_PIN='%s'\nRANGE_CIDR=10.66.0.0/16\n" "$PIN"
  } >"$d/range.env" || exit 2
  cat >"$d/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  "image inspect"*) exit 0 ;;
  *getent*) echo "0.0.0.0 canary.tripwire-range.invalid" ;;
  run*) exit 7 ;;
esac
exit 0
STUB
  cat >"$d/bin/curl" <<STUB
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$d/curl.argv"
case "\$*" in
  *authenticate*) echo '{"data":{"token":"tok"}}' ;;
  *rule_ids=*) echo '{"data":{"total_affected_items":8}}' ;;
  *) exit 7 ;;
esac
STUB
  chmod +x "$d"/bin/* "$d"/scripts/*.sh
  for c in docker curl; do
    [[ $(PATH="$d/bin:$PATH" command -v $c) == "$d/bin/$c" ]] || { echo "stub $c not first on PATH" >&2; exit 2; }
  done
  echo "$d"
}
CLEAN=(env -u PROBE_SKIP -u VERDICT_SKIP -u NEG_SKIP -u SIGMA_EXPECTED -u WAZUH_PASS -u WAZUH_API_PIN -u WAZUH_USER)
run() { # $1 = world, rest = extra env assignments
  local d=$1; shift
  out=$("${CLEAN[@]}" "$@" PATH="$d/bin:$PATH" bash "$d/scripts/probe.sh" 2>"$d/err"); rc=$?
}
sig() { jq -r '.checks[] | select(.id=="sigma") | "\(.ok) \(.detail)"' <<<"$out" 2>/dev/null; }
nchecks() { jq -r '.checks | length' <<<"$out" 2>/dev/null; }
calls() { [[ -f "$1/curl.argv" ]] || { echo 0; return; }; grep -c 'https://' "$1/curl.argv" || true; }
arith_err() { grep -E 'unbound variable|syntax error|value too great|integer expression' "$1/err" || true; }
shape() { ((rc == 0)) && [[ $(nchecks) == 5 ]]; }   # rc 0 + parseable JSON with all 5 checks

# X0: control
d=$(world x0 'SIGMA_EXPECTED=8'); run "$d"
{ shape && [[ $(sig) == "true loaded=8 expected=8 "* ]] && [[ $(calls "$d") == 2 ]]; } \
  || no "X0 control: sigma true loaded=8 expected=8, 2 API calls (rc=$rc checks=$(nchecks) sigma='$(sig)' calls=$(calls "$d"))"

# X1-X2: no expectation -> no default, no API call
for c in "x1:" "x2:SIGMA_EXPECTED="; do
  id=${c%%:*}; d=$(world "$id" "${c#*:}"); run "$d"
  { shape && [[ $(sig) == false* && $(sig) == *"SIGMA_EXPECTED unset"* ]] && [[ $(calls "$d") == 0 ]]; } \
    || no "${id^^} range.env '${c#*:}': sigma false 'SIGMA_EXPECTED unset', 0 API calls (rc=$rc checks=$(nchecks) sigma='$(sig)' calls=$(calls "$d"))"
done

# X3: malformed -> refused before any arithmetic and before any API call
i=0
for v in 0 -3 abc 08 8x ' 8' '8 ' 'PATH[$(touch @CANARY@)]'; do
  i=$((i+1)); d=$(world "x3-$i" 'SIGMA_EXPECTED=8'); v=${v//@CANARY@/$d/pwned}
  run "$d" SIGMA_EXPECTED="$v"
  e=$(arith_err "$d")
  { shape && [[ $(sig) == false* && $(sig) == *"SIGMA_EXPECTED malformed"* ]] && [[ $(calls "$d") == 0 ]] \
      && [[ ! -e $d/pwned ]] && [[ -z $e ]]; } \
    || no "X3.$i SIGMA_EXPECTED='$v': sigma false 'SIGMA_EXPECTED malformed', 0 API calls, no code run (rc=$rc checks=$(nchecks) sigma='$(sig)' calls=$(calls "$d") pwned=$([[ -e $d/pwned ]] && echo YES || echo no) stderr='${e//$'\n'/ | }')"
done

if ((fail)); then exit 1; fi
echo "probe-expect: PASS (11/11: control, unset 2/2, malformed 8/8 refused before arithmetic and API)"
