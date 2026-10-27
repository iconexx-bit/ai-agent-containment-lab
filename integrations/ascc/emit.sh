#!/usr/bin/env bash
# emit.sh <verdict.json> <ttc.json> <resource-arn> — the lab's judgement as SARIF 2.1.0 for ASCC (clab/v1).
#
# CONTRACT (integrations/ascc/README.md, schemas/clab.v1.json):
#   stdout  = one SARIF log, run.properties.schema "clab/v1", nothing else
#   exit 0  = emitted   exit 2 = usage or an ARN that is not an EC2 instance ARN   exit 70 = malformed input
#
# Nothing is judged here. Probe controls take verdict.sh's result (VERDICT_JSON, schema "verdict/v1"):
# pass -> kind "pass", fail -> kind "fail", skip -> kind "open" (not verified). The TTC control is
# "pass" only if measure-ttc completed every requested cycle and every cycle passed its threshold.
# The ARN is DECLARED by the operator (binding.method "operator_declared"): no scanner observed that
# the range runs on that instance. No clock, no network, no ASCC code: same inputs -> same bytes.
set -uo pipefail
usage() { echo "usage: emit.sh <verdict.json> <ttc.json> <resource-arn>" >&2; exit 2; }
(($# == 3)) || usage
VERDICT=$1 TTC=$2 ARN=$3
[[ -f $VERDICT && -f $TTC ]] || usage
command -v jq >/dev/null 2>&1 || { echo "emit: jq missing" >&2; exit 70; }
[[ $ARN =~ ^arn:aws(-[a-z]+)*:ec2:[a-z]{2}(-[a-z]+)+-[0-9]:[0-9]{12}:instance/i-[0-9a-f]{8}([0-9a-f]{9})?$ ]] \
  || { echo "emit: not an EC2 instance ARN (arn:aws:ec2:<region>:<account>:instance/i-...)" >&2; exit 2; }

jq -e 'type == "object" and .schema == "verdict/v1" and (.verdict == "PASS" or .verdict == "FAIL")
       and (.probe.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and (.probe.ts | type == "string")
       and ([.checks[].id] == ["egress", "tripwire", "sigma", "canaries", "sim_ca"])
       and all(.checks[]; (.result == "pass" or .result == "fail" or .result == "skip")
                          and (.key | type == "string") and (.method | type == "string") and (.detail | type == "string"))' \
  "$VERDICT" >/dev/null 2>&1 || { echo "emit: $VERDICT is not a verdict/v1 artefact (VERDICT_JSON of verdict.sh)" >&2; exit 70; }
jq -e 'def int: type == "number" and . == floor and . >= 0;
       type == "object" and .schema == 1 and (.complete | type == "boolean")
       and ([.n_requested, .n_ok, .pass, .threshold_ms, .ttc_ms.min, .ttc_ms.median, .ttc_ms.max] | all(int))
       and .n_requested >= 1 and .ttc_ms.min <= .ttc_ms.median and .ttc_ms.median <= .ttc_ms.max' \
  "$TTC" >/dev/null 2>&1 || { echo "emit: $TTC is not a schema-1 TTC summary (measure-ttc)" >&2; exit 70; }
tsha=$(sha256sum "$TTC" | cut -d' ' -f1) && [[ $tsha =~ ^[0-9a-f]{64}$ ]] || { echo "emit: cannot hash $TTC" >&2; exit 70; }

jq -n --slurpfile v "$VERDICT" --slurpfile t "$TTC" --arg arn "$ARN" --arg tsha "$tsha" '
  $v[0] as $v | $t[0] as $t
  | {
      egress:   {id: "CLAB-EGRESS-001",   name: "EgressBlocked",     level: "error",   sev: "8.0",
                 text: "Agent egress outside the range is blocked, by IP and by name"},
      tripwire: {id: "CLAB-TRIPWIRE-001", name: "TripwireSinkholed", level: "error",   sev: "7.5",
                 text: "The tripwire domain resolves to the sinkhole"},
      sigma:    {id: "CLAB-SIGMA-001",    name: "DetectionRulesPresent", level: "warning", sev: "5.5",
                 text: "Detection pack rule files are present in the SIEM (the API lists files on disk; loading is proven only by alerts)"},
      canaries: {id: "CLAB-CANARY-001",   name: "CanariesPresent",   level: "warning", sev: "5.0",
                 text: "Canary accounts are present in the range identity provider"},
      sim_ca:   {id: "CLAB-SIMCA-001",    name: "SimCaPresent",      level: "note",    sev: "3.0",
                 text: "The simulation CA is present (PEM header check)"},
      ttc:      {id: "CLAB-TTC-001",      name: "ContainedInTime",   level: "error",   sev: "8.0",
                 text: "The killswitch contains the agent within the TTC threshold in every measured cycle"}
    } as $r
  | ["egress", "tripwire", "sigma", "canaries", "sim_ca", "ttc"] as $order
  | {kind: {pass: "pass", fail: "fail", skip: "open"}} as $m
  | ($t.complete and $t.n_ok == $t.n_requested and $t.pass == $t.n_requested) as $ttc_ok
  | def loc: [{logicalLocations: [{fullyQualifiedName: $arn, kind: "resource"}]}];
    def level($id; $kind): if $kind == "fail" then $r[$id].level else "none" end;
    def word($res): {pass: "pass", fail: "FAIL", skip: "SKIP (operator: VERDICT_SKIP) NOT VERIFIED"}[$res];
  {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {driver: {
        name: "containment-lab",
        informationUri: "https://github.com/iconexx-bit/ai-agent-containment-lab",
        rules: [$order[] as $c | {
          id: $r[$c].id, name: $r[$c].name, shortDescription: {text: $r[$c].text},
          defaultConfiguration: {level: $r[$c].level},
          properties: {"security-severity": $r[$c].sev, "clab/control": $c}}]}},
      properties: {
        schema: "clab/v1",
        binding: {method: "operator_declared", resource_arn: $arn},
        verdict: $v.verdict,
        probe: $v.probe,
        ttc: {sha256: $tsha}
      },
      results: (
        [$v.checks[] as $c | ($m.kind[$c.result]) as $k | {
          ruleId: $r[$c.id].id, kind: $k, level: level($c.id; $k),
          message: {text: "\($c.key): \(word($c.result)) — \($c.detail)"},
          locations: loc,
          properties: {control: $c.id, method: $c.method}}]
        + [(if $ttc_ok then "pass" else "fail" end) as $k | {
          ruleId: $r.ttc.id, kind: $k, level: level("ttc"; $k),
          message: {text: "TTC median \($t.ttc_ms.median) ms (min \($t.ttc_ms.min), max \($t.ttc_ms.max)); \($t.pass) of \($t.n_requested) cycles under \($t.threshold_ms) ms, \($t.n_ok) completed"},
          locations: loc,
          properties: {control: "ttc", method: "measure-ttc",
                       n: $t.n_requested, median_ms: $t.ttc_ms.median, min_ms: $t.ttc_ms.min,
                       max_ms: $t.ttc_ms.max, threshold_ms: $t.threshold_ms}}]
      )
    }]
  }' || { echo "emit: jq failed" >&2; exit 70; }
