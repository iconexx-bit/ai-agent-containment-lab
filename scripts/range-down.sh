#!/usr/bin/env bash
# range-down.sh — full teardown.
# -v is deliberate: a break-test that deleted a canary user must NOT survive
# into the next run via a persisted volume, or negatives.sh will lie.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/env.sh
source "$ROOT/scripts/lib/env.sh" || { echo "cannot load scripts/lib/env.sh" >&2; exit 2; }
load_range_env "$ROOT" strict || exit 2

RANGE_NET="${RANGE_NET:-agentlab0}"
COMPOSE_FILE="${COMPOSE_FILE:-range/compose.yml}"

docker compose -f "$ROOT/$COMPOSE_FILE" down -v --remove-orphans 2>&1 || true
docker network rm "$RANGE_NET" 2>/dev/null || true
rm -f "$ROOT/.run-id"
echo "range down (volumes removed)"
