#!/usr/bin/env bash
# range-killswitch-arm.sh — installed to /usr/local/bin, invoked by systemd
# after docker.service starts. Docker recreates DOCKER-USER on daemon restart
# and silently drops our jump; without this the killswitch is a placebo.
#
# Re-arms ONLY if a marker file exists, so a normal reboot does not blackhole
# the range when the operator never armed it.
set -uo pipefail

MARKER="${RANGE_KILL_MARKER:-/var/lib/range-lab/killswitch.armed}"
RANGE_CIDR="${RANGE_CIDR:-10.66.0.0/16}"
KILL_CHAIN="${KILL_CHAIN:-RANGE-KILL}"

[[ -f "$MARKER" ]] || { echo "killswitch marker absent — nothing to re-arm"; exit 0; }

# wait for DOCKER-USER to be recreated by the daemon
for _ in $(seq 1 30); do
  iptables -nL DOCKER-USER >/dev/null 2>&1 && break
  sleep 1
done

iptables -nL "$KILL_CHAIN" >/dev/null 2>&1 || iptables -N "$KILL_CHAIN"
iptables -C "$KILL_CHAIN" -s "$RANGE_CIDR" -j DROP 2>/dev/null \
  || iptables -A "$KILL_CHAIN" -s "$RANGE_CIDR" -j DROP
iptables -C "$KILL_CHAIN" -d "$RANGE_CIDR" -j DROP 2>/dev/null \
  || iptables -A "$KILL_CHAIN" -d "$RANGE_CIDR" -j DROP
iptables -C DOCKER-USER -j "$KILL_CHAIN" 2>/dev/null \
  || iptables -I DOCKER-USER 1 -j "$KILL_CHAIN"

echo "killswitch re-armed for $RANGE_CIDR"
