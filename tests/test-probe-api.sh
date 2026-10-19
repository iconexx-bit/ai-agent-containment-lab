#!/usr/bin/env bash
# test-probe-api.sh — D5 P5a: how probe.sh talks to the Wazuh API (runbook 10.1, rules 7 and 8).
#   K1 control: pin set, API answers -> sigma true loaded=8 expected=8, exactly 2 API calls
#   K2 secrets never in argv: WAZUH_PASS and the bearer token are absent from every curl argv;
#      they arrive in a curl config (-K) with " and \ escaped
#   K3 every API call is pinned: -k AND --pinnedpubkey "$WAZUH_API_PIN" on each call
#   K4 WAZUH_API_PIN empty -> sigma false, names WAZUH_API_PIN, ZERO API calls (fail closed)
#   K5 WAZUH_API_PIN malformed -> same as K4
#   K6 pin mismatch (curl rc 90) -> sigma false, detail says "pin mismatch" and rc=90, no 2nd call
# Hermetic: temp trees, stub docker/curl first on PATH.  exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/probe.sh scripts/lib/env.sh schemas/probe.v1.json; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
command -v jq >/dev/null 2>&1 || { echo "jq missing" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }
PIN='sha256//0vxCZwJEabcdefghijklmnopqrstuvwxyz0123NMe8A='   # syntactically valid, not the real pin
PASS='p"w\q-S3CR3T'                                         # " and \ must survive the curl config
TOKEN='TOKEN-eyJhbGciOi-not-for-argv'

world() { # $1 = name, $2 = WAZUH_API_PIN line value, $3 = curl scenario (ok|pin90); prints path
  local d="$T/$1"
  mkdir -p "$d/scripts" "$d/schemas" "$d/bin" || exit 2
  cp "$ROOT"/scripts/*.sh "$d/scripts/" && cp -r "$ROOT/scripts/lib" "$d/scripts/" \
    && cp "$ROOT/schemas/probe.v1.json" "$d/schemas/" || exit 2
  # range.env: single quotes keep the password literal for `source`
  printf "SIGMA_EXPECTED=8\nWAZUH_HOST=127.0.0.1\nWAZUH_USER=ro\nWAZUH_PASS='%s'\nWAZUH_API_PIN='%s'\nRANGE_CIDR=10.66.0.0/16\n" \
    "$PASS" "$2" >"$d/range.env" || exit 2
  cat >"$d/bin/docker" <<STUB
#!/usr/bin/env bash
case "\$*" in
  "image inspect"*) exit 0 ;;
  *getent*) echo "0.0.0.0 canary.tripwire-range.invalid" ;;
  run*) exit 7 ;;
esac
exit 0
STUB
  cat >"$d/bin/curl" <<STUB
#!/usr/bin/env bash
# logs argv (one line per call) and the content of any -K/--config file
printf '%s\n' "\$*" >>"$d/curl.argv"
a=("\$@")
for ((i=0; i<\${#a[@]}; i++)); do
  [[ \${a[i]} == -K || \${a[i]} == --config ]] && { cat "\${a[i+1]}"; echo "--"; } >>"$d/curl.cfg"
done
[[ $3 == pin90 ]] && exit 90
case "\$*" in
  *authenticate*) printf '{"data":{"token":"%s"}}\n' '$TOKEN' ;;
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
run() { out=$("${CLEAN[@]}" PATH="$1/bin:$PATH" bash "$1/scripts/probe.sh" 2>"$1/err"); rc=$?; }
sig() { jq -r '.checks[] | select(.id=="sigma") | "\(.ok) \(.detail)"' <<<"$out" 2>/dev/null; }
calls() { [[ -f "$1/curl.argv" ]] || { echo 0; return; }; grep -c 'https://' "$1/curl.argv" || true; }

# K1-K3: happy path
d=$(world k1 "$PIN" ok); run "$d"
{ ((rc == 0)) && [[ $(sig) == "true loaded=8 expected=8 "* ]] && [[ $(calls "$d") == 2 ]]; } \
  || no "K1 control: sigma true loaded=8 expected=8 with 2 API calls (rc=$rc sigma='$(sig)' calls=$(calls "$d"))"
{ ! grep -qF 'S3CR3T' "$d/curl.argv" && ! grep -qF "$TOKEN" "$d/curl.argv"; } \
  || no "K2a password or bearer token present in curl argv (world-readable /proc/<pid>/cmdline)"
{ grep -qxF 'user = "ro:p\"w\\q-S3CR3T"' "$d/curl.cfg" 2>/dev/null \
  && grep -qxF "header = \"Authorization: Bearer $TOKEN\"" "$d/curl.cfg" 2>/dev/null; } \
  || no "K2b credentials and token must reach curl via -K config, \" and \\ escaped (cfg: $({ tr '\n' '|' <"$d/curl.cfg"; } 2>/dev/null | sed 's/S3CR3T/***/g'))"
n=0; while IFS= read -r l; do
  [[ $l == *https://* ]] || continue
  [[ " $l " == *" -k "* && " $l " == *" --pinnedpubkey $PIN "* ]] && n=$((n+1))
done <"$d/curl.argv"
[[ $n == 2 && $(calls "$d") == 2 ]] || no "K3 every API call needs -k and --pinnedpubkey \$WAZUH_API_PIN (pinned $n of $(calls "$d"))"

# K4-K5: no usable pin -> fail closed before any API call
for c in "k4:" "k5:sha256//short"; do
  id=${c%%:*}; d=$(world "$id" "${c#*:}" ok); run "$d"
  { ((rc == 0)) && [[ $(sig) == false* && $(sig) == *WAZUH_API_PIN* ]] && [[ $(calls "$d") == 0 ]]; } \
    || no "${id^^} pin '${c#*:}': sigma false naming WAZUH_API_PIN, 0 API calls (rc=$rc sigma='$(sig)' calls=$(calls "$d"))"
done

# K6: pin mismatch is its own fact, not "authentication failed"
d=$(world k6 "$PIN" pin90); run "$d"
{ ((rc == 0)) && [[ $(sig) == false* && $(sig) == *"pin mismatch"* && $(sig) == *"rc=90"* ]] && [[ $(calls "$d") == 1 ]]; } \
  || no "K6 curl rc 90: sigma false 'pin mismatch … rc=90', 1 call (rc=$rc sigma='$(sig)' calls=$(calls "$d"))"

if ((fail)); then exit 1; fi
echo "probe-api: PASS (6/6: control, argv clean, config escaped, pinned 2/2, fail-closed 2/2, rc 90)"
