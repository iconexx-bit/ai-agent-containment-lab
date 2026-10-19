# shellcheck shell=bash
# scripts/lib/no-neg.sh — controls with NO safe negative in negatives.sh, and why. Data only.
#   key   = check id from schemas/probe.v1.json (validated by skip_init; unknown id -> exit 2)
#   value = the reason, non-empty; reported as "UNPROVEN (code: <reason>)", the control is never broken
# Precedence in negatives.sh: code (this file) > VERDICT_SKIP > NEG_SKIP.
# Empty since D5 P3: sigma got a non-destructive negative (expectation mutation, see negatives.sh).
declare -A NO_NEG=()
