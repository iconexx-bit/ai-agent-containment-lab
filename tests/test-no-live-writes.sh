#!/usr/bin/env bash
# test-no-live-writes.sh — structural invariant: lab code never acts on the LIVE Wazuh manager.
# Allowed touchpoints: read-only API (probe.sh) and `docker inspect` of its image (logtest.sh).
# Forbidden: any docker exec/cp/start/stop/restart/kill/rm/pause/update/commit aimed at it.
# A negative that breaks the production SIEM is not a test, it is an outage with a log line.
#   exit 0 = clean   exit 1 = violation(s)   exit 2 = guard itself unproven / nothing scanned
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VERB='docker[[:space:]]+(exec|cp|start|stop|restart|kill|rm|pause|update|commit)([[:space:]]|$)'
LIVE='(WAZUH_CONTAINER|\$\{?LIVE([^A-Za-z0-9_]|$)|wazuh-wazuh\.manager-1|wazuh-manager|wazuh\.manager)'

scan() { # files... -> "file:line: code" per violation; code only (text after a '#' is ignored)
  VERB="$VERB" LIVE="$LIVE" awk '   # regexes via ENVIRON: awk -v would eat the backslashes
    { code=$0; sub(/#.*/, "", code) }
    code ~ ENVIRON["VERB"] && code ~ ENVIRON["LIVE"] { printf "%s:%d: %s\n", FILENAME, FNR, $0 }' "$@"
}

# 1. prove the guard can fail and can pass (rule 54) before trusting it on the repo
fx=$(mktemp -d); trap 'rm -rf "$fx"' EXIT
cat >"$fx/bad" <<'FX'
docker exec "$WAZUH_CONTAINER" /var/ossec/bin/wazuh-control restart
  docker cp x "${WAZUH_CONTAINER}:/var/ossec/etc/rules/"
docker exec wazuh-wazuh.manager-1 true
docker restart "$LIVE"
FX
cat >"$fx/ok" <<'FX'
# docker exec "$WAZUH_CONTAINER" mv a b
docker exec "$C" /var/ossec/bin/wazuh-control restart
IMG=$(docker inspect -f '{{.Config.Image}}' "$LIVE")
docker exec "$LIVELY" true
echo "use docker exec on the live manager only via wz-deploy"
FX
nbad=$(scan "$fx/bad" | wc -l); nok=$(scan "$fx/ok" | wc -l)
if (( nbad != 4 || nok != 0 )); then
  echo "GUARD UNPROVEN: bad fixture caught $nbad/4, ok fixture flagged $nok/0" >&2
  scan "$fx/bad" "$fx/ok" >&2; exit 2
fi

# 2. scan tracked code (tests/ excluded: it holds the patterns on purpose)
cd "$ROOT" || exit 2
mapfile -t files < <(git ls-files -- '*.sh' justfile Makefile ':!tests/')
(( ${#files[@]} > 0 )) || { echo "nothing scanned — empty input is RED" >&2; exit 2; }
hits=$(scan "${files[@]}")
if [[ -n "$hits" ]]; then
  printf 'LIVE-WRITE VIOLATION(S):\n%s\n' "$hits"; exit 1
fi
echo "no-live-writes: PASS (guard proven 4/4 + 0/5, scanned ${#files[@]} files)"
