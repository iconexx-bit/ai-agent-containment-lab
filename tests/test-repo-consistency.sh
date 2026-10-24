#!/usr/bin/env bash
# test-repo-consistency.sh — D5 P5b-fix (runbook 10.6): what the repo states about itself agrees.
#   C1 every ${COMPOSE_FILE:-X} default in tracked scripts names the SAME file
#   C2 that file is tracked in the repo (a default to a missing file only bites without range.env:
#      range-up rc 70, range-down and killswitch silently — `docker compose … || true`)
#   C3 range.env.example COMPOSE_FILE equals that default
#   C4 bootstrap.sh checks for xmllint (lint-rules.sh needs it; `just test` gates on it since P5b)
#   C5 range.env.example sources cleanly: no stderr, every name it assigns is set (bootstrap copies it
#      to range.env; `X=a b` silently runs `b` with X set only for that command)
#   T1 README.md and CLAUDE.md contain no U+2026 ellipsis: public text and agent rules are not
#      truncated pastes (one lived in the public README from e84bcfd until P5b)
# Each scanner is proven on fixtures first (rule 54): a check that cannot fail is not a check.
# Hermetic: reads tracked files only.  exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in range.env.example bootstrap.sh README.md CLAUDE.md; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }

# ---- scanner: ${COMPOSE_FILE:-X} defaults, comments stripped ------------------------------------
defaults() { # files... -> "file:line X" per default
  awk '{ code=$0; sub(/#.*/, "", code)
         while (match(code, /\$\{COMPOSE_FILE:-[^}]+\}/)) {
           printf "%s:%d %s\n", FILENAME, FNR, substr(code, RSTART+16, RLENGTH-17)
           code=substr(code, RSTART+RLENGTH) } }' "$@"
}
cat >"$T/fx.sh" <<'FX'
A="${COMPOSE_FILE:-one.yml}"
# B="${COMPOSE_FILE:-commented.yml}"
docker compose -f "$ROOT/${COMPOSE_FILE:-two.yml}" up   # ${COMPOSE_FILE:-tail.yml}
FX
g=$(defaults "$T/fx.sh" | awk '{print $2}' | paste -sd' ')
[[ $g == "one.yml two.yml" ]] || { echo "GUARD UNPROVEN: defaults() on fixture -> '$g', want 'one.yml two.yml'" >&2; exit 2; }

mapfile -t files < <(cd "$ROOT" && git ls-files -- '*.sh' justfile ':!tests/')
((${#files[@]} > 0)) || { echo "nothing to scan (git ls-files)" >&2; exit 2; }
found=$(cd "$ROOT" && defaults "${files[@]}")
[[ -n $found ]] || { echo "no \${COMPOSE_FILE:-…} default found — scanner or repo changed" >&2; exit 2; }
uniq=$(awk '{print $2}' <<<"$found" | sort -u)
n=$(grep -c . <<<"$uniq")
((n == 1)) || no "C1 COMPOSE_FILE defaults disagree ($n distinct): $(paste -sd';' <<<"$found")"
missing=""
while IFS= read -r f; do
  (cd "$ROOT" && git ls-files --error-unmatch -- "$f" >/dev/null 2>&1) || missing+=" $f"
done <<<"$uniq"
[[ -z $missing ]] || no "C2 COMPOSE_FILE default names a file that is not in the repo:$missing"
ex=$(sed -nE 's/^COMPOSE_FILE=([^[:space:]#]+).*/\1/p' "$ROOT/range.env.example")
if [[ -z $ex ]]; then no "C3 range.env.example has no COMPOSE_FILE line"
else
  bad=$(awk -v e="$ex" '$2 != e' <<<"$found")
  [[ -z $bad ]] || no "C3 range.env.example COMPOSE_FILE=$ex differs from: $(paste -sd';' <<<"$bad")"
fi

# ---- C4: bootstrap dependency list -------------------------------------------------------------
deps=$(sed -nE 's/^for b in (.*); do$/\1/p' "$ROOT/bootstrap.sh")
if [[ -z $deps ]]; then no "C4 dependency loop 'for b in …; do' not found in bootstrap.sh"
else [[ " $deps " == *" xmllint "* ]] || no "C4 bootstrap.sh does not check xmllint (deps: $deps)"
fi

# ---- C5: the example config sources cleanly ----------------------------------------------------
srcchk() { # file -> stderr of sourcing it + names it assigns that end up unset (clean env, set -u)
  env -i PATH=/usr/bin:/bin "$BASH" -c 'set -u; source "$1" || echo "source rc=$?"
    for n in $(sed -nE "s/^([A-Za-z_][A-Za-z0-9_]*)=.*/\1/p" "$1"); do [[ -n ${!n+x} ]] || echo "unset: $n"; done' _ "$1" 2>&1
}
printf 'A=1\nB="x y"\n' >"$T/ok.env"; printf 'A=1\nB=x y\n' >"$T/bad.env"
o1=$(srcchk "$T/ok.env"); o2=$(srcchk "$T/bad.env")
[[ -z $o1 && $o2 == *"unset: B"* ]] || { echo "GUARD UNPROVEN: srcchk ok='$o1' bad='$o2'" >&2; exit 2; }
o=$(srcchk "$ROOT/range.env.example")
[[ -z $o ]] || no "C5 range.env.example does not source cleanly: $(paste -sd'|' <<<"$o")"

# ---- T1: no truncation marker in public text / agent rules ------------------------------------
E=$'\xe2\x80\xa6'
printf 'complete line\n' >"$T/clean.md"; printf 'cut here %s rest\n' "$E" >"$T/cut.md"
c1=$(grep -cF -- "$E" "$T/clean.md"); c2=$(grep -cF -- "$E" "$T/cut.md")
[[ $c1 == 0 && $c2 == 1 ]] || { echo "GUARD UNPROVEN: ellipsis scan clean=$c1/0 cut=$c2/1" >&2; exit 2; }
for f in README.md CLAUDE.md; do
  hits=$(grep -nF -- "$E" "$ROOT/$f"); rc=$?
  ((rc == 2)) && { echo "grep failed on $f" >&2; exit 2; }
  [[ -z $hits ]] || no "T1 $f contains the truncation marker at line(s) $(cut -d: -f1 <<<"$hits" | paste -sd,)"
done

if ((fail)); then exit 1; fi
echo "repo-consistency: PASS (compose default 3/3, bootstrap xmllint, example sources cleanly, no truncation 2/2; guards 3/3)"
