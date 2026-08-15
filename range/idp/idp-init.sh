#!/usr/bin/env bash
# Creates the canary accounts, then idles. No package installs: this container
# has no egress by design.
set -uo pipefail
for u in ${CANARY_USERS:-svc-legacy backup-admin ctf-canary}; do
  id "$u" >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin "$u"
done
echo "canaries: $(getent passwd | grep -cE '^(svc-legacy|backup-admin|ctf-canary):')"
exec sleep infinity
