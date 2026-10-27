#!/usr/bin/env bash
# test-clab-sarif.sh — A3 integration: the lab's judgement reaches ASCC as SARIF (contract clab/v1).
#   V1 without VERDICT_JSON nothing is written; with it, stdout and rc are byte-for-byte the same
#   V2 VERDICT_JSON (schema verdict/v1): five checks in KEYS order, results = the table, probe sha256 + ts
#   V3 a FAIL check -> result fail, verdict FAIL, rc 1      V4 VERDICT_SKIP -> result skip, named in skipped[]
#   V5 VERDICT_JSON unwritable (missing dir, a directory) -> rc 70 and no "PROBE ..." line
#   V6 malformed probe (rc 70) -> no VERDICT_JSON written
#   E1 emit.sh: SARIF 2.1.0 with $schema = the OASIS errata01 URI (the schema's own id; the old
#      raw.githubusercontent .../sarif-spec/master/Schemata/ path is gone since 2024-05-02), run.properties.schema clab/v1, binding operator_declared + the ARN,
#      six rules and six results in contract order, every location = the declared ARN, sha256 of inputs
#   E2 fail -> kind fail, level = the rule's level   E3 skip -> kind open, level none (not verified)
#   E4 TTC is pass only if every requested cycle completed and passed (pass < n, n_ok < n, !complete -> fail)
#   E5 an ARN that is not an EC2 instance -> rc 2, no output; a payload in the ARN is never executed
#   E6 malformed inputs (a probe given as verdict, reordered checks, a non-TTC file) -> rc 70, no output
#   E7 same inputs -> same bytes   E8 rule ids = schemas/clab.v1.json, probe controls = schemas/probe.v1.json
#   E9 the committed run-3 evidence (docs/evidence/d6-run3-ttc.json) emits TTC pass, median 1598 ms
#   J1 `just probe` writes verdict.json next to probe.json; `just emit-sarif` calls emit.sh
# Hermetic: temp tree, the REAL verdict.sh and emit.sh.   exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/verdict.sh scripts/lib/skip.sh scripts/lib/env.sh schemas/probe.v1.json \
         docs/evidence/d6-run3-ttc.json justfile; do
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
EMIT="$ROOT/integrations/ascc/emit.sh"
ARN="arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f67890"
SCHEMA_URI="https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
RULES='["CLAB-EGRESS-001","CLAB-TRIPWIRE-001","CLAB-SIGMA-001","CLAB-CANARY-001","CLAB-SIMCA-001","CLAB-TTC-001"]'

probe() { # $1 = path, $2 = canaries ok, $3 = egress ok
  jq -n --argjson c "$2" --argjson e "${3:-true}" '{schema:1, ts:"2026-10-24T05:14:00Z", range_cidr:"10.66.0.0/16",
    range_net:"agentlab0", egress_blocked:$e, tripwire_sinkholed:true, sigma_loaded:true, canaries_present:$c,
    sim_ca_present:true,
    checks:[{id:"egress",ok:$e,method:"docker-run",detail:"ip rc=7 dns rc=6"},{id:"tripwire",ok:true,method:"dns",detail:"sinkhole"},
            {id:"sigma",ok:true,method:"wazuh-api",detail:"present=8 expected=8"},{id:"canaries",ok:$c,method:"getent",detail:"3/3"},
            {id:"sim_ca",ok:true,method:"pem-header",detail:"BEGIN CERTIFICATE"}]}' >"$1"
}
V() { # $1 = probe file; rest = env; sets out rc
  out=$(env -u VERDICT_SKIP -u NEG_SKIP -u PROBE_SKIP -u VERDICT_JSON "${@:2}" bash "$tree/scripts/verdict.sh" "$1" 2>&1); rc=$?
}
E() { # args to emit.sh; sets eout erc
  eout=$(bash "$EMIT" "$@" 2>"$T/emit.err"); erc=$?
}
ttc() { # $1 = path, $2 = jq update applied to the committed run-3 summary
  jq "${2:-.}" "$ROOT/docs/evidence/d6-run3-ttc.json" >"$1" || exit 2
}

# ---- V1-V6: verdict.sh VERDICT_JSON --------------------------------------------------------------
probe "$run/probe.json" true
V "$run/probe.json"; out0=$out; rc0=$rc
[[ ! -e $run/verdict.json ]] || no "V1 verdict.json written without VERDICT_JSON"
V "$run/probe.json" VERDICT_JSON="$run/verdict.json"
{ [[ $out == "$out0" ]] && ((rc == rc0 && rc == 0)); } || no "V1 stdout/rc changed by VERDICT_JSON (rc=$rc/$rc0)"$'\n'"$out"
psha=$(sha256sum "$run/probe.json" | cut -d' ' -f1)
jq -e --arg sha "$psha" '.schema == "verdict/v1" and .verdict == "PASS" and .skipped == []
    and .probe == {ts: "2026-10-24T05:14:00Z", sha256: $sha}
    and [.checks[].id] == ["egress","tripwire","sigma","canaries","sim_ca"]
    and [.checks[].key] == ["egress_blocked","tripwire_sinkholed","sigma_loaded","canaries_present","sim_ca_present"]
    and all(.checks[]; .result == "pass") and .checks[2].method == "wazuh-api" and .checks[2].detail == "present=8 expected=8"' \
  "$run/verdict.json" >/dev/null 2>&1 || no "V2 verdict.json content: $(cat "$run/verdict.json" 2>&1)"
cp "$run/verdict.json" "$T/v-pass.json"

probe "$run/probe.json" false
V "$run/probe.json" VERDICT_JSON="$run/verdict.json"
{ ((rc == 1)) && jq -e '.verdict == "FAIL" and .checks[3].result == "fail" and ([.checks[] | select(.result == "fail")] | length) == 1' \
    "$run/verdict.json" >/dev/null 2>&1; } || no "V3 FAIL check must be result fail, verdict FAIL, rc 1 (rc=$rc)"
cp "$run/verdict.json" "$T/v-fail.json"

probe "$run/probe.json" true
V "$run/probe.json" VERDICT_JSON="$run/verdict.json" VERDICT_SKIP="sim_ca"
{ ((rc == 0)) && [[ $(tail -n1 <<<"$out") == "PROBE PASS (skipped: sim_ca)" ]] \
  && jq -e '.verdict == "PASS" and .checks[4].result == "skip" and .skipped == ["sim_ca"]' "$run/verdict.json" >/dev/null 2>&1; } \
  || no "V4 skip must be result skip and listed in skipped (rc=$rc)"
cp "$run/verdict.json" "$T/v-skip.json"

V "$run/probe.json" VERDICT_JSON="$T/no/such/dir/verdict.json"
{ ((rc == 70)) && ! grep -q '^PROBE ' <<<"$out"; } || no "V5 unwritable VERDICT_JSON must be rc 70 without a PROBE line (rc=$rc)"$'\n'"$out"
mkdir -p "$T/isdir"
V "$run/probe.json" VERDICT_JSON="$T/isdir"
{ ((rc == 70)) && ! grep -q '^PROBE ' <<<"$out"; } || no "V5 VERDICT_JSON as a directory must be rc 70 (rc=$rc)"

jq '.canaries_present = false' "$run/probe.json" >"$run/bad.json"
rm -f "$run/v-bad.json"
V "$run/bad.json" VERDICT_JSON="$run/v-bad.json"
{ ((rc == 70)) && [[ ! -e $run/v-bad.json ]]; } || no "V6 malformed probe must be rc 70 with nothing written (rc=$rc)"

# ---- E1-E9: integrations/ascc/emit.sh ------------------------------------------------------------
ttc "$T/ttc.json"
tsha=$(sha256sum "$T/ttc.json" | cut -d' ' -f1)
E "$T/v-pass.json" "$T/ttc.json" "$ARN"
((erc == 0)) || no "E1 emit rc=$erc: $(cat "$T/emit.err")"
jq -e --arg arn "$ARN" --arg psha "$psha" --arg tsha "$tsha" --argjson rules "$RULES" --arg uri "$SCHEMA_URI" '
    ."$schema" == $uri and .version == "2.1.0" and (.runs | length) == 1 and .runs[0] as $r
    | $r.tool.driver.name == "containment-lab"
    and $r.properties.schema == "clab/v1"
    and $r.properties.binding == {method: "operator_declared", resource_arn: $arn}
    and $r.properties.verdict == "PASS"
    and $r.properties.probe.sha256 == $psha and $r.properties.ttc.sha256 == $tsha
    and [$r.tool.driver.rules[].id] == $rules and [$r.results[].ruleId] == $rules
    and all($r.results[]; .kind == "pass" and .level == "none"
            and .locations == [{logicalLocations: [{fullyQualifiedName: $arn, kind: "resource"}]}])
    and [$r.results[].properties.control] == ["egress","tripwire","sigma","canaries","sim_ca","ttc"]' \
  <<<"$eout" >/dev/null 2>&1 || no "E1 clab/v1 shape (all pass)"$'\n'"$eout"

E "$T/v-fail.json" "$T/ttc.json" "$ARN"
jq -e '.runs[0] | .properties.verdict == "FAIL"
    and (.results[3] | .kind == "fail" and .level == "warning" and (.message.text | startswith("canaries_present: FAIL")))
    and ([.results[] | select(.kind == "fail")] | length) == 1' <<<"$eout" >/dev/null 2>&1 \
  || no "E2 a failed check must be kind fail with the rule's level (rc=$erc)"
probe "$run/probe.json" true false
V "$run/probe.json" VERDICT_JSON="$T/v-egress.json"
E "$T/v-egress.json" "$T/ttc.json" "$ARN"
jq -e '.runs[0].results[0] | .kind == "fail" and .level == "error"' <<<"$eout" >/dev/null 2>&1 \
  || no "E2 failed egress must be kind fail, level error"

E "$T/v-skip.json" "$T/ttc.json" "$ARN"
jq -e '.runs[0].results[4] | .kind == "open" and .level == "none" and (.message.text | test("NOT VERIFIED"))' \
  <<<"$eout" >/dev/null 2>&1 || no "E3 a skipped check must be kind open, level none, named NOT VERIFIED"

for mut in '.pass = 4' '.n_ok = 4' '.complete = false'; do
  ttc "$T/ttc-m.json" "$mut"
  E "$T/v-pass.json" "$T/ttc-m.json" "$ARN"
  { ((erc == 0)) && jq -e '.runs[0].results[5] | .ruleId == "CLAB-TTC-001" and .kind == "fail" and .level == "error"' \
      <<<"$eout" >/dev/null 2>&1; } || no "E4 TTC with $mut must be kind fail (rc=$erc)"
done

canary="$T/pwned"
for bad in "arn:aws:s3:::datalake-raw" "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0f9e8d7c6b5a43210" \
           "arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b\$(touch $canary)" "" \
           "$ARN"$'\n'"x" "arn:aws:ec2:us-east-1:12345678901:instance/i-0a1b2c3d4e5f67890"; do
  E "$T/v-pass.json" "$T/ttc.json" "$bad"
  { ((erc == 2)) && [[ -z $eout ]]; } || no "E5 ARN '${bad//$'\n'/\\n}' must be rc 2 with no output (rc=$erc)"
done
[[ ! -e $canary ]] || no "E5 payload in the ARN was executed"
E "$T/v-pass.json" "$T/ttc.json"
((erc == 2)) || no "E5 missing argument must be rc 2 (rc=$erc)"

jq '.checks |= [.[1], .[0]] + .[2:]' "$T/v-pass.json" >"$T/v-order.json"
printf 'not json\n' >"$T/junk.json"
for pair in "$run/probe.json|$T/ttc.json" "$T/v-order.json|$T/ttc.json" "$T/v-pass.json|$T/v-pass.json" \
            "$T/junk.json|$T/ttc.json" "$T/v-pass.json|$T/junk.json"; do
  E "${pair%%|*}" "${pair##*|}" "$ARN"
  { ((erc == 70)) && [[ -z $eout ]]; } || no "E6 malformed input ${pair//$T\//} must be rc 70 with no output (rc=$erc)"
done

E "$T/v-pass.json" "$T/ttc.json" "$ARN"; a=$eout
E "$T/v-pass.json" "$T/ttc.json" "$ARN"
[[ -n $a && $a == "$eout" ]] || no "E7 same inputs must give the same bytes"

want=$(jq -c '."$defs".ruleId.enum' "$ROOT/schemas/clab.v1.json" 2>/dev/null)
[[ $want == "$RULES" ]] || no "E8 schemas/clab.v1.json ruleId enum ($want) != emitter order ($RULES)"
cu=$(jq -r '.properties."$schema".const' "$ROOT/schemas/clab.v1.json" 2>/dev/null)
[[ $cu == "$SCHEMA_URI" ]] || no "E8 schemas/clab.v1.json \$schema const ($cu) != $SCHEMA_URI"
pc=$(jq -c '.properties.checks.items.properties.id.enum' "$ROOT/schemas/probe.v1.json")
ec=$(jq -c '[.runs[0].results[:5][].properties.control]' <<<"$a")
[[ $pc == "$ec" ]] || no "E8 probe controls ($ec) != schemas/probe.v1.json check ids ($pc)"

E "$T/v-pass.json" "$ROOT/docs/evidence/d6-run3-ttc.json" "$ARN"
jq -e '.runs[0].results[5] | .kind == "pass" and .properties.median_ms == 1598 and .properties.n == 5
    and .properties.threshold_ms == 60000' <<<"$eout" >/dev/null 2>&1 \
  || no "E9 committed run-3 TTC evidence must emit pass, median 1598 ms, n=5 (rc=$erc)"

# ---- J1: recipes ---------------------------------------------------------------------------------
probe_recipe=$(awk '/^probe:/{f=1;next} f&&/^[^ #]/{exit} f' "$ROOT/justfile")
grep -qF 'VERDICT_JSON="$RUN/verdict.json" ./scripts/verdict.sh "$RUN/probe.json"' <<<"$probe_recipe" \
  || no "J1 just probe must write verdict.json next to probe.json"
emit_recipe=$(awk '/^emit-sarif /{f=1;next} f&&/^[^ #]/{exit} f' "$ROOT/justfile")
grep -qF './integrations/ascc/emit.sh' <<<"$emit_recipe" || no "J1 just emit-sarif must call integrations/ascc/emit.sh"

if ((fail)); then exit 1; fi
echo "clab-sarif: PASS (verdict json 6/6, emit shape/kinds/ttc/arn/malformed/determinism/contract/evidence 9/9, recipes 2/2)"
