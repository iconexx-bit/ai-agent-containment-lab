#!/usr/bin/env bash
# test-readme-ascc.sh — A3: what the README says about the video and about ASCC is backed by the repo.
#   R1 the video link names its run and value, and both are the ones demo/recording.md records;
#      the caption says the figure is superseded (the current TTC is in the README below it)
#   R2 one "## Feeding ASCC" section: links ASCC and integrations/ascc/README.md, names clab/v1,
#      operator_declared, and says the binding is not a test of the instance
#   R3 its numbers: TTC median = docs/evidence/d6-run3-ttc.json; "6 of 6" = rules in schemas/clab.v1.json
#   R4 every `just <recipe>` it names exists in the justfile; every repo path it names exists
# Each scanner is proven on a fixture first (rule 54).   exit 0 pass / 1 assertion / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in README.md demo/recording.md docs/evidence/d6-run3-ttc.json justfile; do
  [[ -f "$ROOT/$f" ]] || { echo "missing $f" >&2; exit 2; }
done
command -v jq >/dev/null 2>&1 || { echo "jq missing" >&2; exit 2; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }

section() { # file -> body of "## Feeding ASCC" up to the next "## " heading
  awk '/^## Feeding ASCC$/{f=1;next} f&&/^## /{exit} f' "$1"
}
recipes() { # text on stdin -> recipe names after "just "
  grep -oE '`just [a-z][a-z-]*' | sed 's/^`just //' | sort -u
}
printf '# x\n\n## Feeding ASCC\n\nuse `just probe` and `just emit-sarif ARN`\n\n## Other\n\n`just nope`\n' >"$T/fx.md"
g=$(section "$T/fx.md" | recipes | paste -sd' ')
[[ $g == "emit-sarif probe" ]] || { echo "GUARD UNPROVEN: section/recipes -> '$g'" >&2; exit 2; }

# ---- R1: video caption ---------------------------------------------------------------------------
video=$(grep -F 'demo/containment-demo-final.mp4' "$ROOT/README.md")
run=$(grep -oE 'run=[0-9]{8}T[0-9]{6}Z' "$ROOT/demo/recording.md" | head -1 | cut -d= -f2)
ms=$(grep -oE 'containment_ms=[0-9]+' "$ROOT/demo/recording.md" | head -1)
[[ -n $run && -n $ms ]] || no "R1 demo/recording.md records no run id / containment_ms"
{ [[ $video == *"\`$run\`"* ]] && [[ $video == *"\`$ms\`"* ]] && [[ $video == *superseded* ]]; } \
  || no "R1 video caption must name run $run, $ms and say superseded: $video"

# ---- R2: the section -----------------------------------------------------------------------------
n=$(grep -c '^## Feeding ASCC$' "$ROOT/README.md")
((n == 1)) || no "R2 README has $n '## Feeding ASCC' sections, want 1"
body=$(section "$ROOT/README.md")
for want in '](https://github.com/iconexx-bit/ascc)' '](integrations/ascc/README.md)' '`clab/v1`' \
            '`operator_declared`' 'not that the instance was tested'; do
  grep -qF -- "$want" <<<"$body" || no "R2 section must contain: $want"
done

# ---- R3: numbers ---------------------------------------------------------------------------------
med=$(jq -r '.ttc_ms.median' "$ROOT/docs/evidence/d6-run3-ttc.json")
grep -qF "TTC median $med ms" <<<"$body" || no "R3 section must carry: TTC median $med ms (d6-run3-ttc.json)"
if [[ -f $ROOT/schemas/clab.v1.json ]]; then
  k=$(jq -r '."$defs".ruleId.enum | length' "$ROOT/schemas/clab.v1.json")
  grep -qF "$k of $k controls pass" <<<"$body" || no "R3 section must carry: $k of $k controls pass"
else no "R3 schemas/clab.v1.json missing"; fi

# ---- R4: recipes and paths -----------------------------------------------------------------------
while IFS= read -r r; do
  grep -qE "^${r}( |:)" "$ROOT/justfile" || no "R4 just $r: no such recipe"
done < <(recipes <<<"$body")
while IFS= read -r p; do
  [[ -e $ROOT/$p ]] || no "R4 path $p does not exist"
done < <(grep -oE '`(integrations|schemas|docs|scripts)/[A-Za-z0-9_./-]+`' <<<"$body" | tr -d '`' | sort -u)

if ((fail)); then exit 1; fi
echo "readme-ascc: PASS (video caption 1/1, section 1/1, numbers 2/2, recipes and paths; guard 1/1)"
