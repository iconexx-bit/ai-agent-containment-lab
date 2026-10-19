#!/usr/bin/env bash
# logtest.sh — run Detection Pack fixtures through wazuh-logtest in an EPHEMERAL manager.
# The live SIEM is never touched: same image + same ossec.conf as the live manager,
# --network none, container AND its anonymous volumes removed on exit. One wazuh-logtest
# session per fixture file, so correlation state never leaks between files.
# Usage: scripts/logtest.sh [fixture.log ...]   (default: detection/fixtures/*.log)
# Output: $OUT/<fixture>.tsv  idx rule_id level alert decoder srcip dns.query event
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/env.sh
source "$ROOT/scripts/lib/env.sh" || { echo "cannot load scripts/lib/env.sh" >&2; exit 2; }
load_range_env "$ROOT" || exit 2
LIVE="${WAZUH_CONTAINER:-wazuh-wazuh.manager-1}"
CONF="${LOGTEST_CONF:-$HOME/homelab/wazuh/single-node/config/wazuh_cluster/wazuh_manager.conf}"
C="range-logtest-$$"
OUT="${LOGTEST_OUT:-$ROOT/artifacts/logtest}"
DEC="$ROOT/decoders/range_decoders.xml"; RUL="${LOGTEST_RULES:-$ROOT/rules/containment.xml}"
DST_DEC=/var/ossec/etc/decoders/range_decoders.xml; DST_RUL=/var/ossec/etc/rules/containment.xml
die(){ echo "logtest: FAIL $*" >&2; exit 1; }
diag(){
  echo "--- wazuh-control status:" >&2
  docker exec "$C" /var/ossec/bin/wazuh-control status >&2 2>&1
  echo "--- analysisd / CRITICAL / ERROR (filebeat, feeds, indexer noise filtered):" >&2
  docker exec "$C" sh -c "grep -E 'analysisd|CRITICAL|ERROR' /var/ossec/logs/ossec.log | grep -vE 'filebeat|content-updater|vulnerability|indexer' | tail -25" >&2
  echo "--- installed pack files:" >&2
  docker exec "$C" ls -l "$DST_DEC" "$DST_RUL" >&2 2>&1
}

[[ -f "$DEC" && -f "$RUL" ]] || die "missing $DEC or $RUL"
IMG=$(docker inspect -f '{{.Config.Image}}' "$LIVE" 2>/dev/null) || die "cannot read image of $LIVE"
if [[ $# -gt 0 ]]; then FILES=("$@"); else FILES=("$ROOT"/detection/fixtures/*.log); fi
mkdir -p "$OUT"
trap 'docker rm -f -v "$C" >/dev/null 2>&1' EXIT

mounts=(-v "$DEC:/wazuh-config-mount/etc/decoders/range_decoders.xml:ro"
        -v "$RUL:/wazuh-config-mount/etc/rules/containment.xml:ro")
if [[ -f "$CONF" ]]; then mounts+=(-v "$CONF:/wazuh-config-mount/etc/ossec.conf:ro"); cdesc="live ossec.conf"
else cdesc="image default ossec.conf (WARNING: VD and feeds enabled)"; fi
docker run -d --name "$C" --network none "${mounts[@]}" "$IMG" >/dev/null || die "docker run $IMG"
echo "logtest: ephemeral manager $C ($IMG, $cdesc), waiting for analysisd..."

wait_analysisd(){ local i; for i in $(seq 1 90); do
  st=$(docker exec "$C" /var/ossec/bin/wazuh-control status 2>/dev/null); grep -q 'wazuh-analysisd is running' <<<"$st" && return 0
  docker exec "$C" grep -q 'wazuh-analysisd: CRITICAL' /var/ossec/logs/ossec.log 2>/dev/null && return 2
  sleep 2; done; return 1; }
wait_analysisd; rc=$?
[[ $rc -eq 0 ]] || { diag; die "analysisd not running (rc=$rc: 2 = CRITICAL in ossec.log, 1 = timeout)"; }

if docker exec "$C" test -f "$DST_RUL" && docker exec "$C" test -f "$DST_DEC"; then
  echo "logtest: config-mount copied rules/ + decoders/ -> D4 install via bind mount is viable"
else
  echo "logtest: config-mount did NOT copy subdirs -> docker cp fallback (D4 must install by copy)"
  docker cp "$DEC" "$C:$DST_DEC" && docker cp "$RUL" "$C:$DST_RUL" || die "docker cp"
  docker exec "$C" sh -c "chown root:wazuh $DST_DEC $DST_RUL && chmod 660 $DST_DEC $DST_RUL && /var/ossec/bin/wazuh-control restart" >/dev/null 2>&1
  wait_analysisd; rc=$?
  [[ $rc -eq 0 ]] || { diag; die "analysisd not running after restart (rc=$rc)"; }
fi

msgs=$(docker exec "$C" sh -c "grep -E 'WARNING|ERROR|CRITICAL' /var/ossec/logs/ossec.log | grep -Ei 'containment|range_decoders|1002[0-9][0-9]|pcre2|different_field|same_srcip|ignore|frequency' | tail -20")
if [[ -n "$msgs" ]]; then echo "$msgs" >&2; die "ruleset load warnings/errors mention the pack"; fi
echo "logtest: pack loaded, no warnings/errors referencing it in ossec.log"
docker exec "$C" cat /var/ossec/logs/ossec.log >"$OUT/ossec.log" 2>/dev/null

parse(){ awk -v OFS='\t' '
  function val(s){ sub(/^[ \t]+[^:]+: \047/, "", s); sub(/\047$/, "", s); return s }
  /^\*\*Phase 1/            { n++; id[n]="-"; lv[n]="-"; al[n]=0; de[n]="-"; ip[n]="-"; q[n]="-"; ev[n]="" }
  /^[ \t]+full event: /     { ev[n]=val($0) }
  /^[ \t]+name: /           { de[n]=val($0) }
  /^[ \t]+srcip: /          { ip[n]=val($0) }
  /^[ \t]+dns\.query: /     { q[n]=val($0) }
  /^[ \t]+id: /             { id[n]=val($0) }
  /^[ \t]+level: /          { lv[n]=val($0) }
  /^\*\*Alert to be generated/ { al[n]=1 }
  END { for (i=1; i<=n; i++) print i, id[i], lv[i], al[i], de[i], ip[i], q[i], ev[i] }'; }

for f in "${FILES[@]}"; do
  b=$(basename "$f" .log); in_n=$(grep -cvE '^(#|[[:space:]]*$)' "$f")
  grep -vE '^(#|[[:space:]]*$)' "$f" | docker exec -i "$C" /var/ossec/bin/wazuh-logtest ${LOGTEST_VERBOSE:+-v} >"$OUT/$b.raw" 2>&1
  parse <"$OUT/$b.raw" >"$OUT/$b.tsv"
  out_n=$(wc -l <"$OUT/$b.tsv")
  echo; echo "== $b: input=$in_n parsed=$out_n $([[ $in_n -eq $out_n ]] && echo OK || echo MISMATCH)"
  awk -F'\t' '{ printf "%3s %-7s L%-3s %-5s %-20s %-15s %s\n", $1, $2, $3, ($4 ? "ALERT" : ""), $5, $6, $7 }' "$OUT/$b.tsv"
done

# --- assertions: per-line expectations, parse completeness, rule coverage ----------------
# *.expected: "<rule_id>\t<alert 0|1>" per input line ('#' lines ignored), frozen after review.
# Coverage runs only on the default fixture set. 100205 is a level-0 routing node: it is
# never a final match by design and is covered by its child 100206.
ROUTING_ONLY="100205"
fail=0
for f in "${FILES[@]}"; do
  b=$(basename "$f" .log); exp="${f%.log}.expected"
  [[ $(grep -cvE '^(#|[[:space:]]*$)' "$f") -eq $(wc -l <"$OUT/$b.tsv") ]] || { echo "FAIL $b: parsed count != input count"; fail=1; }
  if [[ -f "$exp" ]]; then
    if diff <(cut -f2,4 "$OUT/$b.tsv") <(grep -v '^#' "$exp") >"$OUT/$b.diff"; then echo "PASS $b"
    else echo "FAIL $b (line-numbered diff: $OUT/$b.diff)"; cat "$OUT/$b.diff"; fail=1; fi
  else echo "WARN $b: no $(basename "$exp") — observed only, not asserted"; fi
done
if [[ $# -eq 0 ]]; then
  seen=$(for f in "${FILES[@]}"; do cut -f2 "$OUT/$(basename "$f" .log).tsv"; done | sort -u)
  for i in $(grep -oE 'rule id="[0-9]+"' "$RUL" | grep -oE '[0-9]+'); do
    grep -qx "$i" <<<" $ROUTING_ONLY " 2>/dev/null; [[ " $ROUTING_ONLY " == *" $i "* ]] && continue
    grep -qx "$i" <<<"$seen" || { echo "FAIL coverage: rule $i never fired on any fixture"; fail=1; }
  done
fi
[[ $fail -eq 0 ]] && echo "logtest: ALL PASS" || echo "logtest: FAILED"
exit $fail
