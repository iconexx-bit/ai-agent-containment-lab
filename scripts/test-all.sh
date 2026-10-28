#!/usr/bin/env bash
# test-all.sh — the lab test suite: every tracked tests/test-*.sh, stdin closed, in git order.
# The one source for `just test`, the pre-push hook (via just) and CI (.github/workflows/test.yml).
#   exit 0 = all passed   exit 1 = a test failed   exit 2 = no tests found
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
mapfile -t ts < <(git ls-files 'tests/test-*.sh')
(( ${#ts[@]} > 0 )) || { echo "no tests found" >&2; exit 2; }
rc=0; n=0
for t in "${ts[@]}"; do n=$((n+1)); echo "== $t"; bash "$t" </dev/null || rc=1; done
echo "ran $n/${#ts[@]} tests, rc=$rc"
exit "$rc"
