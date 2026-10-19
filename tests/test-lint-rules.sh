#!/usr/bin/env bash
# test-lint-rules.sh — D5 P5b, variant B': lint-rules.sh checks only properties of the rule files
# themselves, needs no range.env, and is a gate (this test runs in `just test` -> pre-push).
#   L1 the repo pack, no range.env, SIGMA_EXPECTED unset -> rc 0 "lint-rules OK"
#   L2 no rule count: SIGMA_EXPECTED=999 exported, or SIGMA_EXPECTED=7 in range.env -> still rc 0
#   L3 duplicate rule ID                       -> rc 1 "FAIL duplicate rule IDs"
#   L4 rule ID outside the reserved block      -> rc 1 "FAIL rule IDs outside reserved block"
#   L5 malformed XML                           -> rc 1 "FAIL malformed XML"
#   L6 a rules file with zero rules            -> rc 1 "FAIL no rule IDs" (empty input = RED, rule 21)
#   L7 xmllint not on PATH                     -> rc 2 naming xmllint (cannot check != pass)
#   L8 no rules dir                            -> rc 2
# Hermetic: temp trees.  exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/lint-rules.sh scripts/lib/env.sh; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
compgen -G "$ROOT/rules/*.xml" >/dev/null || { echo "no rules/*.xml in repo" >&2; exit 2; }
command -v xmllint >/dev/null 2>&1 || { echo "xmllint missing (apt: libxml2-utils) — L5 cannot be proven" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }

world() { # $1 = name, $2 = rules source: "repo" | "none" | "-" (XML on stdin -> rules/pack.xml); prints path
  local d="$T/$1"
  mkdir -p "$d/scripts/lib" || exit 2
  cp "$ROOT/scripts/lint-rules.sh" "$d/scripts/" && cp "$ROOT/scripts/lib/env.sh" "$d/scripts/lib/" || exit 2
  case $2 in
    repo) cp -r "$ROOT/rules" "$d/rules" || exit 2 ;;
    none) ;;
    -) mkdir -p "$d/rules" && cat >"$d/rules/pack.xml" || exit 2 ;;
  esac
  echo "$d"
}
pack() { # rule IDs -> a well-formed pack on stdout
  printf '<group name="t,">\n'
  for i in "$@"; do printf '  <rule id="%s" level="3"><match>x</match><description>t</description></rule>\n' "$i"; done
  printf '</group>\n'
}
CLEAN=(env -u SIGMA_EXPECTED -u SIGMA_ID_MIN -u SIGMA_ID_MAX -u RULES_DIR)
run() { # $1 = world, rest = extra env assignments
  local d=$1; shift
  out=$("${CLEAN[@]}" "$@" "$BASH" "$d/scripts/lint-rules.sh" 2>&1); rc=$?
}
show() { printf '%s' "$out" | tr '\n' '|' | cut -c1-240; }

# L1: the repo pack as it is
d=$(world l1 repo); run "$d"
{ ((rc == 0)) && [[ $out == *"lint-rules OK ("* ]]; } || no "L1 repo pack without range.env: rc 0 'lint-rules OK' (rc=$rc out='$(show)')"

# L2: the expected count is not lint's business (it lives in range.env, for probe.sh only)
d=$(world l2 repo); run "$d" SIGMA_EXPECTED=999; r1=$rc; o1=$(show)
printf 'SIGMA_EXPECTED=7\n' >"$d/range.env"; run "$d"
{ ((r1 == 0 && rc == 0)); } || no "L2 lint must not compare a rule count: exported 999 -> rc=$r1 ('$o1'), range.env 7 -> rc=$rc ('$(show)')"

# L3-L6: lint failures, each with its reason
d=$(pack 100200 100201 100201 | world l3 -); run "$d"
{ ((rc == 1)) && [[ $out == *"FAIL duplicate rule IDs"* ]]; } || no "L3 duplicate ID: rc 1 'FAIL duplicate rule IDs' (rc=$rc out='$(show)')"
d=$(pack 100200 100300 | world l4 -); run "$d"
{ ((rc == 1)) && [[ $out == *"FAIL rule IDs outside reserved block"* ]]; } || no "L4 ID outside block: rc 1 (rc=$rc out='$(show)')"
d=$(pack 100200 100201 | sed 's#</group>##' | world l5 -); run "$d"
{ ((rc == 1)) && [[ $out == *"FAIL malformed XML"* ]]; } || no "L5 malformed XML: rc 1 'FAIL malformed XML' (rc=$rc out='$(show)')"
d=$(pack | world l6 -); run "$d"
{ ((rc == 1)) && [[ $out == *"FAIL no rule IDs"* ]]; } || no "L6 zero rules: rc 1 'FAIL no rule IDs' (rc=$rc out='$(show)')"

# L7: xmllint absent -> cannot check, exit 2 (a gate must not silently skip its strongest check)
d=$(world l7 repo); mkdir -p "$d/nox" || exit 2
for t in dirname grep sort uniq awk sed cat; do
  p=$(command -v "$t") || { echo "harness: $t missing" >&2; exit 2; }
  ln -s "$p" "$d/nox/$t" || exit 2
done
[[ -z $(PATH="$d/nox" command -v xmllint) ]] || { echo "harness: xmllint still on the reduced PATH" >&2; exit 2; }
run "$d" PATH="$d/nox"
{ ((rc == 2)) && [[ $out == *xmllint* ]]; } || no "L7 no xmllint: rc 2 naming xmllint (rc=$rc out='$(show)')"

# L8: no rules dir
d=$(world l8 none); run "$d"
((rc == 2)) || no "L8 no rules dir: rc 2 (rc=$rc out='$(show)')"

if ((fail)); then exit 1; fi
echo "lint-rules: PASS (8/8: repo pack, no count, duplicate, block, XML, zero rules, no xmllint, no dir)"
