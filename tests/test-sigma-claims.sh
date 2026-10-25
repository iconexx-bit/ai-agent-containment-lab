#!/usr/bin/env bash
# test-sigma-claims.sh — O13 (runbook, 2026-10-25): the sigma check proves rule FILES are present as the
# Wazuh API lists them, not that analysisd LOADED them. Ephemeral 4.14.8 manager, run 20261025T004327Z:
# a rule file added without a restart was listed by GET /rules (after the API's 10 s RBAC file-list cache,
# framework/wazuh/rbac/utils.py:15) while analysisd did not alert on it until a restart.
#   S1 no tracked text (outside docs/evidence, which are copies of past runs) claims the sigma check
#      shows what the manager LOADED
#   S2 probe.sh reports the count as present=N, not loaded=N
#   S3 README's sigma row names what the check proves (files on disk), where the proof is (O13) and
#      where loaded-in-analysisd is shown instead (an alert end to end)
#   S4 the JSON key sigma_loaded is kept (schema probe.v1 contract) and probe.sh says so where it sets it
# Each scanner is proven on fixtures first (rule 54).  exit 0 pass / 1 fail / 2 harness
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; no() { echo "FAIL: $*"; fail=1; }

# ---- S1 scanner: phrasings that claim the sigma check shows what is LOADED ----------------------------
CLAIM='Detection rules loaded|level B \(authoritative\): loaded by|MUST have loaded|what the live manager loaded|loaded — that is probe\.sh sigma'
printf '%s\n' '| Detection rules loaded (`sigma` check) |' '# 3. SIGMA RULES — level B (authoritative): loaded by the Wazuh manager.' \
  '# exact number of containment rules your manager MUST have loaded — a range' \
  '#   - what the live manager loaded is probe.sh'"'"'s sigma check' '# loaded — that is probe.sh sigma). Gated' >"$T/bad"
printf '%s\n' '| Detection rule files present (`sigma` check) |' '# NOT what analysisd loaded (O13)' 'loaded-in-analysisd is not proven' >"$T/ok"
nb=$(grep -cE "$CLAIM" "$T/bad"); nk=$(grep -cE "$CLAIM" "$T/ok")
((nb == 5 && nk == 0)) || { echo "GUARD UNPROVEN: S1 scanner bad=$nb/5 ok=$nk/0" >&2; exit 2; }
mapfile -t files < <(cd "$ROOT" && git ls-files -- ':!docs/evidence/' ':!tests/test-sigma-claims.sh')
((${#files[@]} > 0)) || { echo "nothing scanned" >&2; exit 2; }
hits=$(cd "$ROOT" && grep -nE "$CLAIM" -- "${files[@]}" 2>/dev/null)
[[ -z $hits ]] || no "S1 text still claims the sigma check shows what is LOADED: $(paste -sd'|' <<<"$hits")"

# ---- S2 probe.sh detail ---------------------------------------------------------------------------------
P="$ROOT/scripts/probe.sh"
code=$(sed 's/#.*//' "$P")
grep -qE '"present=\$' <<<"$code" || no "S2 probe.sh does not report present=N for the sigma count"
grep -qE '"loaded=\$' <<<"$code" && no "S2 probe.sh still reports loaded=N"

# ---- S3 README sigma row --------------------------------------------------------------------------------
row=$(grep -E '\(`sigma` check\)' "$ROOT/README.md")
[[ -n $row ]] || no "S3 README has no sigma row"
for w in 'files on disk' 'O13' 'analysisd' 'alert'; do
  grep -qF -- "$w" <<<"$row" || no "S3 README sigma row does not say '$w'"
done

# ---- S4 the JSON key stays, explained ---------------------------------------------------------------------
grep -q '"sigma_loaded"' "$ROOT/schemas/probe.v1.json" || no "S4 schema key sigma_loaded removed (needs a schema version bump)"
grep -qE '^#.*sigma_loaded.*(probe\.v1|schema)' "$P" || no "S4 probe.sh does not explain why the key is still called sigma_loaded"

if ((fail)); then exit 1; fi
echo "sigma-claims: PASS (S1 no 'loaded' claims, S2 present=N, S3 README row, S4 key kept and explained; guards 1/1)"
