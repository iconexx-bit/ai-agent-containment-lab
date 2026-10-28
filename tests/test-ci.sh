#!/usr/bin/env bash
# test-ci.sh — A3: the suite runs in public CI, and CI, `just test` and pre-push run the same script.
#   W1 .github/workflows/test.yml: push (every branch) and pull_request; top-level permissions
#      contents: read and no write anywhere; every `uses:` pinned to a 40-hex SHA with a version
#      comment; every actions/checkout sets persist-credentials: false; a step runs exactly
#      ./scripts/test-all.sh; no continue-on-error
#   W2 one source: the justfile `test` recipe is ./scripts/test-all.sh; .githooks/pre-push runs just test
#   W3 scripts/test-all.sh on fixture repos: all pass -> rc 0 "ran 2/2 tests, rc=0"; one fails ->
#      rc 1 and the others still run; no tests -> rc 2; an untracked test file is not run; a test
#      reading stdin gets EOF instead of hanging
#   W4 README carries the badge of this workflow; .github/dependabot.yml updates github-actions
# Each scanner is proven on a fixture first (rule 54).   exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in README.md justfile .githooks/pre-push; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }
WF="$ROOT/.github/workflows/test.yml"

uses_bad() { # workflow -> "uses:" lines that are not "owner/repo[/path]@<40 hex> # vX.Y.Z"
  grep -E '^[[:space:]]*(-[[:space:]]+)?uses:' "$1" \
    | grep -vE 'uses:[[:space:]]+[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]+v[0-9]+\.[0-9]+\.[0-9]+[[:space:]]*$'
}
printf '      - uses: actions/checkout@v4\n      - uses: a/b@%s # v1.2.3\n      - uses: a/b@%s\n' \
  "$(printf 'a%.0s' {1..40})" "$(printf 'b%.0s' {1..40})" >"$T/fx.yml"
g=$(uses_bad "$T/fx.yml" | wc -l)
((g == 2)) || { echo "GUARD UNPROVEN: uses_bad on fixture -> $g, want 2" >&2; exit 2; }

# ---- W1: the workflow ----------------------------------------------------------------------------
if [[ ! -f $WF ]]; then
  no "W1 .github/workflows/test.yml missing"
else
  grep -qE '^  push:$' "$WF" && grep -qE '^    branches: \["\*\*"\]$' "$WF" || no "W1 must run on push to every branch"
  grep -qE '^  pull_request:' "$WF" || no "W1 must run on pull_request"
  awk '/^permissions:/{f=1;next} f&&/^[^ ]/{exit} f' "$WF" | grep -qE '^  contents: read$' \
    || no "W1 top-level permissions must be contents: read"
  ! grep -qE ':[[:space:]]*write' "$WF" || no "W1 no permission may be write"
  [[ -z $(uses_bad "$WF") ]] || no "W1 unpinned uses: $(uses_bad "$WF" | paste -sd';')"
  nco=$(grep -cE 'uses:[[:space:]]+actions/checkout@' "$WF"); npc=$(grep -cE '^[[:space:]]+persist-credentials: false' "$WF")
  ((nco >= 1 && nco == npc)) || no "W1 checkout steps $nco, persist-credentials: false $npc"
  grep -qE '^[[:space:]]+run: \./scripts/test-all\.sh$' "$WF" || no "W1 a step must run ./scripts/test-all.sh"
  ! grep -q 'continue-on-error' "$WF" || no "W1 continue-on-error would hide a red suite"
fi

# ---- W2: one source ------------------------------------------------------------------------------
body=$(awk '/^test:$/{f=1;next} f&&/^[^ ]/{exit} f&&NF' "$ROOT/justfile" | sed 's/^ *//')
[[ $body == "./scripts/test-all.sh" ]] || no "W2 just test must be exactly ./scripts/test-all.sh, is: $(paste -sd'|' <<<"$body")"
grep -qE '^exec just test' "$ROOT/.githooks/pre-push" || no "W2 pre-push must run just test"

# ---- W3: test-all.sh behaviour -------------------------------------------------------------------
# Fixture repos must not inherit the operator's git config: with commit.gpgsign=true each fixture
# commit would ask for the signing key's passphrase (2026-10-28: five prompts on the VM).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
fx() { # $1 = name, rest = "file:exitcode" tests; prints repo path
  local d="$T/$1"; shift
  mkdir -p "$d/scripts" "$d/tests" || exit 2
  cp "$ROOT/scripts/test-all.sh" "$d/scripts/" 2>/dev/null || return 0
  git -C "$d" init -q || exit 2
  local spec
  for spec in "$@"; do printf '#!/usr/bin/env bash\n%s\n' "${spec#*:}" >"$d/tests/${spec%%:*}"; done
  git -C "$d" add -A && git -C "$d" -c user.email=t@t -c user.name=t -c commit.gpgsign=false commit -qm fx >/dev/null || exit 2
  echo "$d"
}
TA() { out=$(timeout 20 bash "$1/scripts/test-all.sh" 2>&1); rc=$?; }
if [[ -f $ROOT/scripts/test-all.sh ]]; then
  d=$(fx ok "test-a.sh:exit 0" "test-b.sh:exit 0"); TA "$d"
  { ((rc == 0)) && grep -qx 'ran 2/2 tests, rc=0' <<<"$out"; } || no "W3 all pass: rc=$rc $out"
  d=$(fx red "test-a.sh:exit 1" "test-b.sh:echo b-ran; exit 0"); TA "$d"
  { ((rc == 1)) && grep -qx 'ran 2/2 tests, rc=1' <<<"$out" && grep -qx 'b-ran' <<<"$out"; } \
    || no "W3 one failing test must give rc 1 and the rest still run: rc=$rc $out"
  d=$(fx none); TA "$d"
  ((rc == 2)) || no "W3 no tests must be rc 2 (rc=$rc)"
  d=$(fx untracked "test-a.sh:exit 0"); printf '#!/usr/bin/env bash\nexit 1\n' >"$d/tests/test-z.sh"; TA "$d"
  { ((rc == 0)) && grep -qx 'ran 1/1 tests, rc=0' <<<"$out"; } || no "W3 untracked test must not run: rc=$rc $out"
  # stdin of test-all.sh is a pipe that stays open: only its own </dev/null lets `cat` finish
  d=$(fx stdin "test-a.sh:cat >/dev/null; exit 0")
  exec 9< <(exec sleep 600); spid=$!
  out=$(timeout 10 bash "$d/scripts/test-all.sh" <&9 2>&1); rc=$?
  exec 9<&-; kill "$spid" 2>/dev/null
  ((rc == 0)) || no "W3 a test reading stdin must see EOF (rc=$rc; 124 = hung)"
else
  no "W3 scripts/test-all.sh missing"
fi

# ---- W4: badge and updates -----------------------------------------------------------------------
badge='[![tests](https://github.com/iconexx-bit/ai-agent-containment-lab/actions/workflows/test.yml/badge.svg)](https://github.com/iconexx-bit/ai-agent-containment-lab/actions/workflows/test.yml)'
grep -qxF "$badge" "$ROOT/README.md" || no "W4 README must carry the badge of workflows/test.yml"
grep -qE 'package-ecosystem: "github-actions"' "$ROOT/.github/dependabot.yml" 2>/dev/null \
  || no "W4 .github/dependabot.yml must update github-actions"

if ((fail)); then exit 1; fi
echo "ci: PASS (workflow 1/1, one source 2/2, test-all 5/5, badge and updates 2/2; guard 1/1)"
