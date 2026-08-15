#!/usr/bin/env bash
# preflight.sh — everything that must be true BEFORE the range exists.
# exit 0 = go, exit 2 = usage/env problem, exit 70 = internal
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[[ -f "$ROOT/range.env" ]] && source "$ROOT/range.env"

RANGE_NET="${RANGE_NET:-agentlab0}"
RANGE_CIDR="${RANGE_CIDR:-10.66.0.0/16}"
PROBE_IMAGE="${PROBE_IMAGE:-curlimages/curl:8.11.0}"
COMPOSE_FILE="${COMPOSE_FILE:-compose.range.yml}"

fail=0
say()  { printf '  %-28s %s\n' "$1" "$2"; }
bad()  { printf '  %-28s %s\n' "$1" "FAIL: $2"; fail=1; }

echo "== preflight =="

# 1. required binaries -------------------------------------------------------
for b in docker jq dig ip iptables; do
  if command -v "$b" >/dev/null 2>&1; then say "bin:$b" "ok"; else bad "bin:$b" "not installed"; fi
done

# 2. docker compose v2 -------------------------------------------------------
if docker compose version >/dev/null 2>&1; then
  say "docker-compose-v2" "ok"
else
  bad "docker-compose-v2" "'docker compose' unavailable (v1 not supported)"
fi

# 3. compose file present ----------------------------------------------------
if [[ -f "$ROOT/$COMPOSE_FILE" ]]; then
  if docker compose -f "$ROOT/$COMPOSE_FILE" config -q 2>/dev/null; then
    say "compose:syntax" "ok"
  else
    bad "compose:syntax" "docker compose config failed"
  fi
else
  bad "compose:file" "$COMPOSE_FILE missing"
fi

# 4. CIDR collision with host routes ----------------------------------------
# Hyper-V / corporate VPN love 10.x — a silent overlap makes egress tests lie.
net_prefix="${RANGE_CIDR%%/*}"; net_prefix="${net_prefix%.*.*}"   # 10.66
if ip route 2>/dev/null | grep -qE "(^|[[:space:]])${net_prefix}\."; then
  ip route | grep -E "${net_prefix}\." >&2
  bad "cidr:collision" "host route overlaps $RANGE_CIDR"
else
  say "cidr:collision" "none"
fi

# 5. stale range network from a previous run --------------------------------
if docker network inspect "$RANGE_NET" >/dev/null 2>&1; then
  attached=$(docker network inspect "$RANGE_NET" -f '{{len .Containers}}' 2>/dev/null || echo "?")
  if [[ "$attached" != "0" ]]; then
    bad "net:stale" "$RANGE_NET still has $attached container(s) — run 'just range-down'"
  else
    say "net:stale" "empty network exists (ok, will reuse)"
  fi
else
  say "net:stale" "none"
fi

# 6. all range images must be LOCAL — the range network is --internal -------
# A missing image would surface as "egress blocked", which is a false negative.
RANGE_IMAGES=("$PROBE_IMAGE" "4km3/dnsmasq:2.90-r3" "debian:stable-slim")
for img in "${RANGE_IMAGES[@]}"; do
  if docker image inspect "$img" >/dev/null 2>&1; then
    say "image:${img%%:*}" "cached"
  elif docker pull -q "$img" >/dev/null 2>&1; then
    say "image:${img%%:*}" "pulled"
  else
    bad "image:${img%%:*}" "pull failed — $img"
  fi
done

# 6b. simulation CA must exist on the host before compose mounts it ---------
if [[ -f "$ROOT/attestation/sim-range-ca.crt" ]]; then
  say "sim-ca:file" "present"
else
  bad "sim-ca:file" "attestation/sim-range-ca.crt missing — run ./init-lab.sh"
fi

# 7. killswitch chain must NOT be armed from a previous session -------------
if sudo -n iptables -C DOCKER-USER -j "${KILL_CHAIN:-RANGE-KILL}" 2>/dev/null; then
  bad "killswitch:armed" "chain still active — run 'just killswitch-off'"
else
  say "killswitch:armed" "no"
fi

# 8. sudo NOPASSWD reachable (non-interactive runs must not hang) -----------
if sudo -n true 2>/dev/null; then
  say "sudo:nopasswd" "ok"
else
  bad "sudo:nopasswd" "sudo would prompt — install sudoers.d/range-lab"
fi

echo
if [[ $fail -eq 0 ]]; then
  echo "PREFLIGHT OK"
  exit 0
fi
echo "PREFLIGHT FAILED"
exit 2
