#!/usr/bin/env bash
# ready.sh — the complete Friday gate. Run this, read the last line, go home.
#
# Readiness is defined as:
#   1. preflight clean
#   2. range comes up and probes green
#   3. all 5 controls proven falsifiable (negatives 5/5)
#   4. killswitch arms
#   5. killswitch SURVIVES `systemctl restart docker`
#   6. range comes back up green afterwards
#
# Anything less is theatre.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
LOG="$ROOT/artifacts/ready-$(date -u +%Y%m%dT%H%M%SZ).log"
mkdir -p "$ROOT/artifacts"

step=0; fails=0
declare -a SUMMARY

run() { # <label> <cmd...>
  step=$((step+1))
  local label="$1"; shift
  echo "" | tee -a "$LOG"
  echo "=== [$step] $label ===" | tee -a "$LOG"
  if "$@" >>"$LOG" 2>&1; then
    SUMMARY+=("PASS  $label")
    echo "    PASS"
  else
    SUMMARY+=("FAIL  $label")
    echo "    FAIL  (see $LOG)"
    fails=$((fails+1))
  fi
}

run "preflight"                 ./scripts/preflight.sh
run "range-up + probe"          ./scripts/range-up.sh
run "negatives 5/5"             ./scripts/negatives.sh
run "killswitch arm"            bash -c 'sudo mkdir -p /var/lib/range-lab && sudo touch /var/lib/range-lab/killswitch.armed && ./scripts/killswitch.sh arm'
run "docker daemon restart"     bash -c 'sudo systemctl restart docker && sleep 8'
run "killswitch survived"       ./scripts/killswitch.sh verify
run "killswitch off"            bash -c 'sudo rm -f /var/lib/range-lab/killswitch.armed && ./scripts/killswitch.sh off'
run "range-down"                ./scripts/range-down.sh
run "range-up again (clean)"    ./scripts/range-up.sh

echo ""
echo "================ READINESS ================"
printf '%s\n' "${SUMMARY[@]}"
echo "==========================================="
echo "log: $LOG"
if [[ $fails -eq 0 ]]; then
  echo "READY TO RECORD"
  exit 0
fi
echo "NOT READY — $fails step(s) failed"
exit 1
