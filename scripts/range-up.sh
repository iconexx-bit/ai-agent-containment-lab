#!/usr/bin/env bash
# range-up.sh — bring the range up and immediately prove it.
# Writes .run-id so every artefact from THIS run lands in one directory.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$ROOT/range.env" ]] && source "$ROOT/range.env"

RANGE_NET="${RANGE_NET:-agentlab0}"
RANGE_CIDR="${RANGE_CIDR:-10.66.0.0/16}"
COMPOSE_FILE="${COMPOSE_FILE:-compose.range.yml}"

# one timestamp per run — NOT $(date) inside a make variable, which re-evaluates
RUN="$ROOT/artifacts/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN"
echo "$RUN" > "$ROOT/.run-id"
echo "run-id: $RUN"

# --internal: no default route out of this network at all. Belt; the killswitch
# is the braces.
docker network inspect "$RANGE_NET" >/dev/null 2>&1 || \
  docker network create --internal --subnet="$RANGE_CIDR" "$RANGE_NET"

docker compose -f "$ROOT/$COMPOSE_FILE" up -d --wait 2>&1 | tee "$RUN/up.log"

docker compose -f "$ROOT/$COMPOSE_FILE" ps --format json > "$RUN/services.json" 2>/dev/null || true

"$ROOT/scripts/probe.sh" > "$RUN/probe.json" 2> "$RUN/probe.stderr"
rc=$?
[[ $rc -eq 0 ]] || { echo "probe collector error (exit $rc)" >&2; exit 70; }

"$ROOT/scripts/verdict.sh" "$RUN/probe.json" | tee "$RUN/verdict.txt"
exit "${PIPESTATUS[0]}"
