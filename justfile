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
    ./scripts/verdict.sh "$RUN/probe.json" | tee "$RUN/verdict.txt"
    exit "${PIPESTATUS[0]}"

# cheap pre-commit check: rule IDs present on disk (NOT authoritative)
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

# THE gate. 5/5 or do not record.
verify-negatives:
    ./scripts/negatives.sh

# full friday gate: preflight -> up -> negatives -> docker restart -> killswitch
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

# --- negative tests (individual) -------------------------------------------

break-egress:
    #!/usr/bin/env bash
    set -uo pipefail
    source range.env
    docker network connect bridge "$CANARY_CONTAINER"

break-canaries:
    #!/usr/bin/env bash
    set -uo pipefail
    source range.env
    docker exec "$CANARY_CONTAINER" userdel ctf-canary

break-sigma:
    #!/usr/bin/env bash
    set -uo pipefail
    source range.env
    docker exec "$WAZUH_CONTAINER" mv /var/ossec/etc/rules/containment.xml /tmp/

break-docker:
    sudo systemctl restart docker

# --- artefacts --------------------------------------------------------------

show:
    #!/usr/bin/env bash
    RUN=$(cat .run-id 2>/dev/null || echo "artifacts/adhoc")
    echo "run: $RUN"; jq . "$RUN/probe.json"

clean:
    rm -rf artifacts/ .run-id
