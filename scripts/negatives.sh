#!/usr/bin/env bash
# negatives.sh — the ONLY meaningful go/no-go gate.
#
# A green probe on a healthy range proves nothing: it may be green because the
# checks are inert. This harness breaks one control at a time and asserts the
# probe goes RED. 5/5 or the range is not ready to be recorded.
#
#   exit 0 = all negative tests detected
#   exit 1 = at least one break went undetected (probe is inert)
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

break_sim_ca() {
  cp "$ROOT/attestation/sim-range-ca.crt" /tmp/simca.bak
  echo "NOT A CERTIFICATE" > "$ROOT/attestation/sim-range-ca.crt"
}
unbreak_sim_ca() { cp /tmp/simca.bak "$ROOT/attestation/sim-range-ca.crt"; }

run_probe() { # -> 0 pass, 1 fail
  local f="$OUT/probe.$1.json"
  "$ROOT/scripts/probe.sh" > "$f" 2>"$OUT/probe.$1.stderr" || return 2
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
for t in "${TESTS[@]}"; do
  echo "== break: $t =="
  "break_$t"
  sleep 2
  if run_probe "$t"; then
    echo "  NEGATIVE TEST FAILED — probe stayed green after break_$t"
    RESULT[$t]="INERT"
    overall=1
  else
    echo "  detected"
    RESULT[$t]="ok"
  fi
  "unbreak_$t"
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
