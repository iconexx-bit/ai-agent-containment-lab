#!/usr/bin/env bash
# test-stop-grace.sh — D6 finding (runbook 10.6): `compose stop` must not wait docker's 10 s default.
#   Measured 2026-10-24 (docs/evidence/d6-run2-stop.json): range-idp (`exec sleep infinity`) and agent-runner
#   (`sleep infinity`) run as PID 1, which ignores SIGTERM; docker waited its 10 s grace period and sent SIGKILL.
#   The killswitch arm ends with `compose stop`, so the verified TTC was ~10.6 s while egress closed in ~0.4 s.
#   S1 range/compose.yml: every service has a service-level `stop_grace_period`
#   S2 every value is at most 2 s (compose durations: 1500ms, 2s, 1m30s ...; anything unparsable counts as too long)
#   S3 the scanner saw range-dns, range-idp and agent-runner (a parse that sees nothing must not pass)
# The scanner is proven on fixtures first (rule 54): a check that cannot fail is not a check.
# Hermetic: reads range/compose.yml only.   exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$ROOT/range/compose.yml" ]] || { echo "missing range/compose.yml" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }
MAX_MS=2000

# scan FILE -> "service<TAB>ms|none|bad" per service of the top-level `services:` map.
# A service is a key at 2 spaces; its `stop_grace_period` must be a key at exactly 4 spaces (nested ones do not count);
# comments and quotes are stripped; the first value of a service wins.
scan() {
  awk '
    function ms(v,   n, u, tot, ok, s) {
      s = v; tot = 0; ok = 0
      while (match(s, /^[0-9]+(\.[0-9]+)?(ms|s|m|h)/)) {
        n = substr(s, 1, RLENGTH); u = n; sub(/^[0-9.]+/, "", u); sub(/[a-z]+$/, "", n)
        tot += n * (u == "ms" ? 1 : u == "s" ? 1000 : u == "m" ? 60000 : 3600000); s = substr(s, RLENGTH + 1); ok = 1
      }
      return (ok && s == "") ? int(tot) : "bad"
    }
    /^[^ #]/ { if (svc != "") print svc "\t" val
               insvc = ($0 ~ /^services:[ \t]*(#.*)?$/); svc = ""; next }
    insvc && /^  [A-Za-z0-9_.-]+:[ \t]*(#.*)?$/ { if (svc != "") print svc "\t" val
                                                    svc = $1; sub(/:$/, "", svc); val = "none"; next }
    insvc && svc != "" && /^    stop_grace_period:/ && val == "none" {
      v = $0; sub(/^    stop_grace_period:[ \t]*/, "", v); sub(/[ \t]*#.*$/, "", v); gsub(/["\x27]/, "", v)
      val = ms(v); next }
    END { if (svc != "") print svc "\t" val }
  ' "$1"
}

# verdict FILE -> prints violations, rc 0 when none
verdict() {
  local f=$1 out bad=0 s v
  out=$(scan "$f")
  for need in range-dns range-idp agent-runner; do
    grep -q "^$need	" <<<"$out" || { echo "S3 service $need not seen"; bad=1; }
  done
  while IFS=$'\t' read -r s v; do
    [[ -n $s ]] || continue
    if [[ $v == none ]]; then echo "S1 $s has no stop_grace_period"; bad=1
    elif [[ $v == bad ]]; then echo "S2 $s: stop_grace_period is not a duration"; bad=1
    elif ((v > MAX_MS)); then echo "S2 $s: stop_grace_period ${v} ms is over ${MAX_MS} ms"; bad=1; fi
  done <<<"$out"
  return $bad
}

# ---- scanner proven on fixtures ----------------------------------------------------------------------------
mkfx() { # a b c : the line for each service (may be empty)
  { printf 'name: x\nservices:\n'
    printf '  range-dns:\n    image: i\n%s\n    healthcheck:\n      interval: 5s\n' "$1"
    printf '  range-idp:\n    image: i\n%s\n' "$2"
    printf '  agent-runner:\n    image: i\n%s\n    tmpfs: ["/tmp"]\n' "$3"
    printf 'networks:\n  n:\n    external: true\n'; } >"$T/fx.yml"; }
expect() { # label want-prefix(or PASS) a b c
  local l=$1 want=$2; shift 2; mkfx "$@"
  local out rc; out=$(verdict "$T/fx.yml"); rc=$?
  if [[ $want == PASS ]]; then ((rc == 0)) || no "fixture '$l' should pass: $out"
  else ((rc != 0)) && grep -q "^$want" <<<"$out" || no "fixture '$l' should violate $want (rc=$rc): ${out:-none}"; fi
}
G1='    stop_grace_period: 1s'
expect "all 1s"                         PASS "$G1" "$G1" "$G1"
expect "ms and mixed units"             PASS '    stop_grace_period: 1500ms' '    stop_grace_period: "2s"' "    stop_grace_period: '1s' # why"
expect "missing in the middle"          S1   "$G1" '' "$G1"
expect "10s default written out"        S2   "$G1" '    stop_grace_period: 10s' "$G1"
expect "1m"                             S2   "$G1" "$G1" '    stop_grace_period: 1m'
expect "1m30s"                          S2   '    stop_grace_period: 1m30s' "$G1" "$G1"
expect "2001 ms"                        S2   "$G1" "$G1" '    stop_grace_period: 2001ms'
expect "exactly 2 s"                    PASS "$G1" '    stop_grace_period: 2s' "$G1"
expect "not a duration"                 S2   "$G1" '    stop_grace_period: soon' "$G1"
expect "empty value"                    S2   "$G1" "$G1" '    stop_grace_period:'
expect "only in a comment"              S1   "$G1" '    # stop_grace_period: 1s' "$G1"
expect "nested key does not count"      S1   "$G1" "$G1" '    deploy:
      stop_grace_period: 1s'
printf 'name: x\nservices:\n' >"$T/fx.yml"
out=$(verdict "$T/fx.yml"); rc=$?; { ((rc != 0)) && grep -q '^S3' <<<"$out"; } || no "fixture 'no services' must violate S3 (rc=$rc)"
printf 'name: x\nservices:\n  range-dns:\n    image: i\n    stop_grace_period: 1s\n  range-idp:\n    stop_grace_period: 1s\n' >"$T/fx.yml"
out=$(verdict "$T/fx.yml"); rc=$?; { ((rc != 0)) && grep -q '^S3 service agent-runner' <<<"$out"; } || no "fixture 'agent-runner absent' must violate S3 (rc=$rc)"

# ---- the real file ------------------------------------------------------------------------------------------
out=$(verdict "$ROOT/range/compose.yml"); rc=$?
((rc == 0)) || no "range/compose.yml:"$'\n'"$out"
((fail == 0)) && echo "stop-grace: PASS (scanner: fixtures 14/14; range/compose.yml: $(scan "$ROOT/range/compose.yml" | awk -F'\t' '{printf "%s=%sms ", $1, $2}'))"
exit "$fail"
