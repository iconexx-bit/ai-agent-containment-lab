set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := false

_default:
    @just --list

# --- lifecycle --------------------------------------------------------------

preflight:
    ./scripts/preflight.sh

range-up:
    ./scripts/range-up.sh

range-down:
    ./scripts/range-down.sh

# --- verification -----------------------------------------------------------

# collect evidence into the current run dir and judge it
probe:
    #!/usr/bin/env bash
    set -uo pipefail
    RUN=$(cat .run-id 2>/dev/null || echo "artifacts/adhoc")
    mkdir -p "$RUN"
    ./scripts/probe.sh > "$RUN/probe.json" 2> "$RUN/probe.stderr" || exit 70
    VERDICT_JSON="$RUN/verdict.json" ./scripts/verdict.sh "$RUN/probe.json" | tee "$RUN/verdict.txt"
    exit "${PIPESTATUS[0]}"

# A3: the current run's judgement (verdict.json of `just probe`) + a TTC summary as SARIF clab/v1 for ASCC.
# ARN = the EC2 instance the operator DECLARES the agent runs on (binding operator_declared, never observed).
# Parameters are exported ($), never interpolated into the script text: the ARN is validated by emit.sh.
emit-sarif $ARN $TTC="docs/evidence/d6-run3-ttc.json":
    #!/usr/bin/env bash
    set -uo pipefail
    RUN=$(cat .run-id 2>/dev/null || echo "artifacts/adhoc")
    [[ -f "$RUN/verdict.json" ]] || { echo "no $RUN/verdict.json: run just probe first" >&2; exit 2; }
    ./integrations/ascc/emit.sh "$RUN/verdict.json" "$TTC" "$ARN" > "$RUN/clab.sarif.json.tmp" \
      && mv -f "$RUN/clab.sarif.json.tmp" "$RUN/clab.sarif.json" \
      && echo "$RUN/clab.sarif.json $(sha256sum "$RUN/clab.sarif.json" | cut -c1-12)" \
      || { rc=$?; rm -f "$RUN/clab.sarif.json.tmp"; exit "$rc"; }

# cheap check of rules/*.xml: IDs unique, inside 100200-100299, XML well-formed (NOT what the manager
# has — the files its API lists are probe.sh sigma, O13). Gated by `just test` via tests/test-lint-rules.sh
lint-rules:
    ./scripts/lint-rules.sh

# validate probe.json against the schema
schema-check:
    #!/usr/bin/env bash
    set -euo pipefail
    RUN=$(cat .run-id 2>/dev/null || echo "artifacts/adhoc")
    python3 -c "import jsonschema" 2>/dev/null || pip install --quiet jsonschema
    python3 - "$RUN/probe.json" schemas/probe.v1.json <<'PY'
    import json,sys,jsonschema
    d=json.load(open(sys.argv[1])); s=json.load(open(sys.argv[2]))
    jsonschema.validate(d,s); print("schema ok")
    PY

# D6a: N range cycles (default 5) -> TTC min/median/max with n; needs sudo (killswitch); each query reaches the live SIEM
measure-ttc N="5":
    ./scripts/measure-ttc.sh {{N}}

# THE gate. 5/5 or do not record.
verify-negatives:
    ./scripts/negatives.sh

# all lab tests (hermetic, no live services); the pre-push hook runs this
test:
    #!/usr/bin/env bash
    set -uo pipefail
    mapfile -t ts < <(git ls-files 'tests/test-*.sh')
    (( ${#ts[@]} > 0 )) || { echo "no tests found" >&2; exit 2; }
    rc=0; n=0
    for t in "${ts[@]}"; do n=$((n+1)); echo "== $t"; bash "$t" </dev/null || rc=1; done
    echo "ran $n/${#ts[@]} tests, rc=$rc"
    exit "$rc"

# full friday gate: preflight -> up -> live negatives -> killswitch arm/verify/off -> down -> up.
# Never restarts the Docker daemon; that is `just verify-persistence`.
ready:
    ./scripts/ready.sh

# --- killswitch -------------------------------------------------------------

killswitch:
    #!/usr/bin/env bash
    set -uo pipefail
    RUN=$(cat .run-id 2>/dev/null || echo "artifacts/adhoc")
    sudo mkdir -p /var/lib/range-lab && sudo touch /var/lib/range-lab/killswitch.armed
    ART_DIR="$RUN" ./scripts/killswitch.sh arm

killswitch-verify:
    ./scripts/killswitch.sh verify

killswitch-off:
    sudo rm -f /var/lib/range-lab/killswitch.armed
    ./scripts/killswitch.sh off

killswitch-status:
    ./scripts/killswitch.sh status

# restart the Docker daemon TWICE and prove the killswitch survives (O14 C / O17). Stops every container on
# the host: typed confirmation, hc-ping.timer stopped (rule 38), range down. Not part of `just ready`.
verify-persistence:
    ./scripts/verify-persistence.sh

# --- negative tests (individual) -------------------------------------------

break-egress:
    #!/usr/bin/env bash
    set -uo pipefail
    source scripts/lib/env.sh || exit 2
    load_range_env "$PWD" strict || exit 2
    docker network connect bridge "$CANARY_CONTAINER"

break-canaries:
    #!/usr/bin/env bash
    set -uo pipefail
    source scripts/lib/env.sh || exit 2
    load_range_env "$PWD" strict || exit 2
    docker exec "$CANARY_CONTAINER" userdel ctf-canary

# --- artefacts --------------------------------------------------------------

show:
    #!/usr/bin/env bash
    RUN=$(cat .run-id 2>/dev/null || echo "artifacts/adhoc")
    echo "run: $RUN"; jq . "$RUN/probe.json"

clean:
    rm -rf artifacts/ .run-id
