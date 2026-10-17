#!/usr/bin/env bash
# negatives.sh — the ONLY meaningful go/no-go gate.
#
# A green probe on a healthy range proves nothing: it may be green because the
# checks are inert. This harness breaks one control at a time and asserts the
# probe goes RED. 5/5 or the range is not ready to be recorded.
#
#   exit 0 = all negative tests detected
#   exit 1 = a break went undetected, was detected only by ANOTHER check (INERT),
#            or a negative errored (break failed / probe crashed / verdict error)
#   exit 2 = skip configuration error (scripts/lib/skip.sh): nothing was run
#   exit 3 = nothing inert, but some controls are UNPROVEN (listed with source)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$ROOT/range.env" ]] && source "$ROOT/range.env"
# shellcheck source=lib/skip.sh
source "$ROOT/scripts/lib/skip.sh" || { echo "cannot load scripts/lib/skip.sh" >&2; exit 2; }
skip_init "$ROOT"

CANARY_CONTAINER="${CANARY_CONTAINER:-range-idp}"
WAZUH_CONTAINER="${WAZUH_CONTAINER:-wazuh-manager}"
SIM_CA_PATH="${SIM_CA_PATH:-/usr/local/share/ca-certificates/sim-range-ca.crt}"
RANGE_NET="${RANGE_NET:-agentlab0}"
OUT="$ROOT/artifacts/negatives"
mkdir -p "$OUT"

ALL=(egress tripwire sigma canaries sim_ca)
# Controls with no negative in this harness, and why. Reported, never silently dropped.
# Lab code never acts on the live SIEM (tests/test-no-live-writes.sh).
declare -A NO_NEG=(
  [sigma]="no non-destructive negative yet; the old one mutated the LIVE manager"
)
declare -A RESULT
TESTS=(); for t in "${ALL[@]}"; do
  if [[ -n "${NO_NEG[$t]:-}" ]]; then RESULT[$t]="UNPROVEN (code: ${NO_NEG[$t]})"
  elif [[ "$VERDICT_SKIP_IDS" == *" $t "* ]]; then
    RESULT[$t]="UNPROVEN (operator: VERDICT_SKIP) — the verdict does not judge it, so a break cannot be detected"
  elif [[ "$NEG_SKIP_IDS" == *" $t "* ]]; then
    RESULT[$t]="UNPROVEN (operator: NEG_SKIP) — negative not run by operator choice"
  else TESTS+=("$t"); fi
done

COMPOSE="${COMPOSE_FILE:-range/compose.yml}"
_net() { # $1 = extra flags
  docker compose -f "$ROOT/$COMPOSE" down >/dev/null 2>&1
  docker network rm "$RANGE_NET" >/dev/null 2>&1
  docker network create $1 --subnet="${RANGE_CIDR}" --ip-range="${RANGE_IP_RANGE:-10.66.1.0/24}" "$RANGE_NET" >/dev/null 2>&1
  docker compose -f "$ROOT/$COMPOSE" up -d --wait >/dev/null 2>&1
}
break_egress()   { _net ""; }            # без --internal: контейнмент снят
unbreak_egress() { _net "--internal"; }

break_tripwire()   { docker stop range-dns >/dev/null 2>&1; }
unbreak_tripwire() { docker start range-dns >/dev/null 2>&1; sleep 4; }

break_canaries()   { docker exec "$CANARY_CONTAINER" userdel ctf-canary; }
unbreak_canaries() { docker exec "$CANARY_CONTAINER" useradd -M -s /usr/sbin/nologin ctf-canary 2>/dev/null || true; }

SIMCA_BAK=""
break_sim_ca() {
  SIMCA_BAK=$(mktemp "${TMPDIR:-/tmp}/simca.XXXXXX") || return 1
  cp "$ROOT/attestation/sim-range-ca.crt" "$SIMCA_BAK" || return 1
  echo "NOT A CERTIFICATE" > "$ROOT/attestation/sim-range-ca.crt"
}
unbreak_sim_ca() {
  [[ -n $SIMCA_BAK && -f $SIMCA_BAK ]] || { echo "unbreak_sim_ca: no backup to restore" >&2; return 1; }
  cp "$SIMCA_BAK" "$ROOT/attestation/sim-range-ca.crt" && rm -f "$SIMCA_BAK" && SIMCA_BAK=""
}

# A break left active by an interrupted run is undone on exit (TERM/INT included).
ACTIVE=""
restore_active() {
  [[ -n $ACTIVE ]] || return 0
  local a=$ACTIVE; ACTIVE=""
  echo "negatives: restoring $a after interruption" >&2
  "unbreak_$a"
}
trap restore_active EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

run_probe() { # -> verdict rc (0 PASS, 1 FAIL, other = verdict error); 90 = probe crashed
  local f="$OUT/probe.$1.json"
  "$ROOT/scripts/probe.sh" > "$f" 2>"$OUT/probe.$1.stderr" || return 90
  "$ROOT/scripts/verdict.sh" "$f" > "$OUT/verdict.$1.txt" 2>&1
}

echo "== baseline =="
if ! run_probe baseline; then
  echo "BASELINE ALREADY RED — fix the range before running negatives" >&2
  cat "$OUT/verdict.baseline.txt" >&2
  exit 1
fi
echo "baseline: PASS"
echo

overall=0
# A negative counts only if THE TARGET check went red (checks[<t>].ok == false in probe.<t>.json).
# A red verdict caused by another check, a probe crash or a failed break proves nothing.
for t in "${TESTS[@]}"; do
  echo "== break: $t =="
  ACTIVE=$t
  if ! "break_$t"; then
    echo "  ERROR — break_$t failed; the control was not broken"
    RESULT[$t]="ERROR (break_$t failed — nothing was broken)"
    overall=1
  else
    sleep 2
    run_probe "$t"; prc=$?
    case $prc in
      0)
        echo "  NEGATIVE TEST FAILED — probe stayed green after break_$t"
        RESULT[$t]="INERT"; overall=1 ;;
      1)
        tok=$(jq -r --arg id "$t" '[.checks[]? | select(.id == $id)] | if length == 1 then (.[0].ok | tostring) else "missing" end' \
              "$OUT/probe.$t.json" 2>/dev/null) || tok="unreadable"
        case $tok in
          false) echo "  detected (checks[$t].ok=false)"; RESULT[$t]="ok" ;;
          true)  echo "  NOT ATTRIBUTED — verdict red, but checks[$t].ok=true"
                 RESULT[$t]="INERT (red, but not from $t)"; overall=1 ;;
          *)     RESULT[$t]="ERROR (checks[$t] $tok in probe.$t.json)"; overall=1 ;;
        esac ;;
      90)
        RESULT[$t]="ERROR (probe crashed after break_$t; see probe.$t.stderr)"; overall=1 ;;
      *)
        RESULT[$t]="ERROR (verdict rc=$prc after break_$t)"; overall=1 ;;
    esac
  fi
  "unbreak_$t"; ACTIVE=""
  sleep 2
done

echo
echo "== summary =="
pass=0; unproven=()
for t in "${ALL[@]}"; do
  printf '  %-12s %s\n' "$t" "${RESULT[$t]}"
  [[ "${RESULT[$t]}" == "ok" ]] && pass=$((pass+1))
  [[ "${RESULT[$t]}" == UNPROVEN* ]] && unproven+=("$t")
done
echo "  ${pass}/${#ALL[@]} controls proven falsifiable"

# restoration must be verified, not assumed
echo
echo "== post-restore baseline =="
if run_probe restored; then
  echo "  restored: PASS"
else
  echo "  restored: FAIL — un-break left the range dirty" >&2
  cat "$OUT/verdict.restored.txt" >&2
  overall=1
fi

if [[ $overall -eq 0 && ${#unproven[@]} -gt 0 ]]; then
  echo; echo "NEGATIVES INCOMPLETE — unproven: ${unproven[*]} (not recordable)" >&2; exit 3
fi
[[ $overall -eq 0 ]] && { echo; echo "NEGATIVES OK — range is recordable"; exit 0; }
echo; echo "NEGATIVES FAILED" >&2
exit 1
