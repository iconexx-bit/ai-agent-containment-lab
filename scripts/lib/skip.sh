# shellcheck shell=bash
# scripts/lib/skip.sh — operator skips (D5 P2a). Source AFTER range.env, then: skip_init "$ROOT"
#   VERDICT_SKIP  check ids the verdict reports as "SKIP (operator: VERDICT_SKIP)" instead of judging.
#                 negatives.sh treats them as UNPROVEN: a check the verdict does not judge cannot
#                 detect a break.
#   NEG_SKIP      check ids whose negative is not run (negatives.sh only; the verdict still judges).
#   PROBE_SKIP    retired: it meant both of the above at once. Set at all (even empty) -> exit 2.
# Ids are validated against schemas/probe.v1.json; an unknown id -> exit 2 (a typo must not
# silently skip nothing). Sets VERDICT_SKIP_IDS / NEG_SKIP_IDS as " id1 id2 " (space-padded).
skip_init() {
  local root="$1" ids v t
  local -a arr
  if [[ -n "${PROBE_SKIP+set}" ]]; then
    echo "skip: PROBE_SKIP is retired (D5 P2a); use VERDICT_SKIP (verdict) and/or NEG_SKIP (negatives). Found PROBE_SKIP='${PROBE_SKIP}'" >&2
    exit 2
  fi
  ids=$(jq -r '.properties.checks.items.properties.id.enum[]' "$root/schemas/probe.v1.json" 2>&1) \
    || { echo "skip: cannot read check ids from schemas/probe.v1.json: $ids" >&2; exit 2; }
  [[ -n "$ids" ]] || { echo "skip: no check ids in schemas/probe.v1.json" >&2; exit 2; }
  for v in VERDICT_SKIP NEG_SKIP; do
    read -r -a arr <<<"${!v:-}"
    for t in "${arr[@]}"; do
      grep -qxF -- "$t" <<<"$ids" \
        || { echo "skip: unknown id '$t' in $v (known: $(tr '\n' ' ' <<<"$ids"))" >&2; exit 2; }
    done
    printf -v "${v}_IDS" ' %s ' "${arr[*]}"
  done
}
