#!/usr/bin/env bash
# killswitch.sh {arm|verify|off|status}
#
# Uses a DEDICATED chain instead of inserting DROP rules straight into
# DOCKER-USER: `-C` gives real idempotency, teardown is one command, and
# duplicate rules become impossible.
#
#   exit 0 = action succeeded / armed
#   exit 1 = not armed when it should be
#   exit 2 = usage
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$ROOT/range.env" ]] && source "$ROOT/range.env"

RANGE_CIDR="${RANGE_CIDR:-10.66.0.0/16}"
KILL_CHAIN="${KILL_CHAIN:-RANGE-KILL}"
COMPOSE_FILE="${COMPOSE_FILE:-compose.range.yml}"
ART_DIR="${ART_DIR:-$ROOT/artifacts/manual}"

IPT="sudo -n iptables"

arm() {
  mkdir -p "$ART_DIR"
  # capture evidence BEFORE tearing anything down
  docker compose -f "$ROOT/$COMPOSE_FILE" logs --no-color \
    > "$ART_DIR/kill.log" 2>/dev/null || true
  docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}' \
    > "$ART_DIR/kill.containers.txt" 2>/dev/null || true

  $IPT -nL "$KILL_CHAIN" >/dev/null 2>&1 || $IPT -N "$KILL_CHAIN"
  $IPT -C "$KILL_CHAIN" -s "$RANGE_CIDR" -j DROP 2>/dev/null \
    || $IPT -A "$KILL_CHAIN" -s "$RANGE_CIDR" -j DROP
  $IPT -C "$KILL_CHAIN" -d "$RANGE_CIDR" -j DROP 2>/dev/null \
    || $IPT -A "$KILL_CHAIN" -d "$RANGE_CIDR" -j DROP
  $IPT -C DOCKER-USER -j "$KILL_CHAIN" 2>/dev/null \
    || $IPT -I DOCKER-USER 1 -j "$KILL_CHAIN"

  docker compose -f "$ROOT/$COMPOSE_FILE" stop >/dev/null 2>&1 || true
  verify
}

verify() {
  if $IPT -C DOCKER-USER -j "$KILL_CHAIN" 2>/dev/null; then
    echo "KILLSWITCH ARMED"
    exit 0
  fi
  echo "KILLSWITCH NOT ARMED" >&2
  exit 1
}

off() {
  $IPT -D DOCKER-USER -j "$KILL_CHAIN" 2>/dev/null || true
  $IPT -F "$KILL_CHAIN" 2>/dev/null || true
  $IPT -X "$KILL_CHAIN" 2>/dev/null || true
  echo "KILLSWITCH DISARMED"
}

status() {
  if $IPT -C DOCKER-USER -j "$KILL_CHAIN" 2>/dev/null; then
    echo "armed"; $IPT -nL "$KILL_CHAIN" --line-numbers
  else
    echo "disarmed"
  fi
}

case "${1:-}" in
  arm)    arm ;;
  verify) verify ;;
  off)    off ;;
  status) status ;;
  *) echo "usage: killswitch.sh {arm|verify|off|status}" >&2; exit 2 ;;
esac
