# shellcheck shell=bash
# scripts/lib/env.sh — the ONLY way lab code loads range.env (D5 P3; runbook rule 44).
#   load_range_env ROOT [strict]
# range.env is sourced, then every name it assigns is checked against the caller's EXPORTED
# environment (VAR=x script, export VAR=x):
#   default  the environment wins; each override is named on stderr (the value never is).
#   strict   an exported value that differs from range.env is refused (return 3): scripts that
#            draw a safety boundary (network, killswitch, metric) never run on a stray export.
# Names not assigned in range.env are not touched. No range.env -> nothing loaded, return 0.
# Returns 0 ok, 2 range.env failed to source, 3 strict refusal. The caller decides the exit code.
load_range_env() {
  local _le_f="$1/range.env" _le_mode="${2:-}" _le_n _le_bad=0
  local -A _le_env=()
  local -a _le_names=()
  [[ -z $_le_mode || $_le_mode == strict ]] || { echo "load_range_env: unknown mode '$_le_mode'" >&2; return 2; }
  [[ -f $_le_f ]] || return 0
  while IFS= read -r _le_n; do _le_env[$_le_n]=${!_le_n}; done < <(compgen -e)
  # shellcheck source=/dev/null
  source "$_le_f" || { echo "range.env: cannot source $_le_f" >&2; return 2; }
  mapfile -t _le_names < <(sed -nE 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p' "$_le_f" | sort -u)
  for _le_n in "${_le_names[@]}"; do
    [[ -n ${_le_env[$_le_n]+set} && ${!_le_n-} != "${_le_env[$_le_n]}" ]] || continue
    if [[ $_le_mode == strict ]]; then
      echo "range.env: $_le_n is exported with a value that differs from range.env — refused (strict)" >&2
      _le_bad=1
    else
      printf -v "$_le_n" '%s' "${_le_env[$_le_n]}"
      echo "range.env: $_le_n overridden by environment" >&2
    fi
  done
  ((_le_bad == 0)) || return 3
}
