#!/usr/bin/env bash
# test-negatives-report.sh — negatives.sh must account for EVERY probe control.
# A control without a proven negative is reported as UNPROVEN with its source
# (code = no safe negative exists; operator = excluded via PROBE_SKIP) and the run
# exits 3, never "recordable". Silent omission is the failure this test exists for.
# Hermetic: negatives.sh runs in a temp tree with stub probe/verdict/docker/sleep.
#   exit 0 = pass   exit 1 = assertion failed   exit 2 = harness problem
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/scripts/negatives.sh"; [[ -f "$SRC" ]] || { echo "missing $SRC" >&2; exit 2; }
IDS=$(jq -r '.properties.checks.items.properties.id.enum[]' "$ROOT/schemas/probe.v1.json") \
  || { echo "cannot read check ids from schema" >&2; exit 2; }
(( $(wc -l <<<"$IDS") == 5 )) || { echo "schema enum is not 5 ids: $IDS" >&2; exit 2; }

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/scripts" "$T/attestation" "$T/bin"
cp "$SRC" "$T/scripts/negatives.sh"
echo "PEM" >"$T/attestation/sim-range-ca.crt"
printf '#!/bin/sh\necho "{}"\n' >"$T/scripts/probe.sh"
# verdict stub: baseline/restored are green, every probe taken after a break is red
printf '#!/bin/sh\ncase "$1" in *baseline*|*restored*) exit 0;; *) exit 1;; esac\n' >"$T/scripts/verdict.sh"
printf '#!/bin/sh\nexit 0\n' >"$T/bin/docker"; printf '#!/bin/sh\nexit 0\n' >"$T/bin/sleep"
chmod +x "$T"/scripts/*.sh "$T"/bin/*
printf 'PROBE_SKIP="canaries"\nRANGE_CIDR=10.66.0.0/16\n' >"$T/range.env"
# safety: the real docker must be unreachable from the harness (it would stop range-dns)
[[ $(PATH="$T/bin:$PATH" command -v docker) == "$T/bin/docker" ]] || { echo "stub docker not first on PATH" >&2; exit 2; }

out=$(PATH="$T/bin:$PATH" bash "$T/scripts/negatives.sh" 2>&1); rc=$?
fail=0; no(){ echo "FAIL: $*"; fail=1; }
(( rc == 3 )) || no "exit $rc, expected 3 (controls unproven)"
grep -q 'range is recordable' <<<"$out" && no "claims 'range is recordable' with unproven controls"
for id in $IDS; do
  grep -qE "^  ${id}[[:space:]]" <<<"$out" || no "summary omits control '$id'"
done
grep -qE '^  sigma[[:space:]]+UNPROVEN \(code: ' <<<"$out" || no "sigma not UNPROVEN (code: ...)"
grep -qE '^  canaries[[:space:]]+UNPROVEN \(operator: PROBE_SKIP\)' <<<"$out" || no "canaries not UNPROVEN (operator: PROBE_SKIP)"
grep -qE '3/5 controls proven falsifiable' <<<"$out" || no "count is not 3/5"
if (( fail )); then echo "--- negatives.sh output (rc=$rc):"; echo "$out"; exit 1; fi
echo "negatives-report: PASS (5/5 controls accounted for, rc=3)"
