#!/usr/bin/env bash
# range-up.sh — bring the range up and immediately prove it.
# Writes .run-id so every artefact from THIS run lands in one directory.
#   exit = verdict rc (0 PASS, 1 FAIL, 2 skip config) | 4 = network is not the contained one
#          | 70 = infrastructure / collector error (network create, compose up, probe)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$ROOT/range.env" ]] && source "$ROOT/range.env"

RANGE_NET="${RANGE_NET:-agentlab0}"
RANGE_CIDR="${RANGE_CIDR:-10.66.0.0/16}"
COMPOSE_FILE="${COMPOSE_FILE:-compose.range.yml}"
RANGE_IP_RANGE="${RANGE_IP_RANGE:-10.66.1.0/24}"

# one timestamp per run — NOT $(date) inside a make variable, which re-evaluates
RUN="$ROOT/artifacts/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN"
echo "$RUN" > "$ROOT/.run-id"
echo "run-id: $RUN"

# --internal: no default route out of this network at all. Belt; the killswitch
# is the braces.
if ! docker network inspect "$RANGE_NET" >/dev/null 2>&1; then
  docker network create --internal --subnet="$RANGE_CIDR" --ip-range="$RANGE_IP_RANGE" "$RANGE_NET" \
    || { echo "range-up: cannot create $RANGE_NET" >&2; exit 70; }
fi
# An existing network is not trusted: the range starts only on the contained one
# (no route out; the agent pool that t0 and the srcip exceptions depend on).
want="true $RANGE_CIDR $RANGE_IP_RANGE"
got=$(docker network inspect -f '{{.Internal}}{{range .IPAM.Config}} {{.Subnet}} {{.IPRange}}{{end}}' "$RANGE_NET" 2>&1) \
  || { echo "range-up: cannot inspect $RANGE_NET: $got" >&2; exit 70; }
[[ $got == "$want" ]] || {
  echo "range-up: $RANGE_NET is not the contained network (want '$want', got '$got') — refusing to start the range" >&2
  exit 4
}

docker compose -f "$ROOT/$COMPOSE_FILE" up -d --wait 2>&1 | tee "$RUN/up.log"
((PIPESTATUS[0] == 0)) || { echo "range-up: compose up failed (see $RUN/up.log)" >&2; exit 70; }

docker compose -f "$ROOT/$COMPOSE_FILE" ps --format json > "$RUN/services.json" 2>/dev/null || true

"$ROOT/scripts/probe.sh" > "$RUN/probe.json" 2> "$RUN/probe.stderr"
rc=$?
[[ $rc -eq 0 ]] || { echo "probe collector error (exit $rc)" >&2; exit 70; }

"$ROOT/scripts/verdict.sh" "$RUN/probe.json" | tee "$RUN/verdict.txt"
exit "${PIPESTATUS[0]}"
