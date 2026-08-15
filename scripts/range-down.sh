#!/usr/bin/env bash
# range-down.sh — full teardown.
# -v is deliberate: a break-test that deleted a canary user must NOT survive
# into the next run via a persisted volume, or negatives.sh will lie.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$ROOT/range.env" ]] && source "$ROOT/range.env"

RANGE_NET="${RANGE_NET:-agentlab0}"
COMPOSE_FILE="${COMPOSE_FILE:-compose.range.yml}"

docker compose -f "$ROOT/$COMPOSE_FILE" down -v --remove-orphans 2>&1 || true
docker network rm "$RANGE_NET" 2>/dev/null || true
rm -f "$ROOT/.run-id"
echo "range down (volumes removed)"
