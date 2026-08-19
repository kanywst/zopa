#!/usr/bin/env bash
# End-to-end check: start Envoy with zopa.wasm as a proxy-wasm filter,
# hit it with curl, assert HTTP statuses. This is the only suite that
# exercises the real proxy-wasm ABI -- configure, the three phase
# callbacks, body buffering, and send_local_response. The generic-ABI
# suites call `evaluate` directly and can't reach any of it.
#
# Two scenarios, each with its own bootstrap and its own Envoy process:
#
#   request  envoy.yaml         allow iff method == GET
#   phases   envoy-phases.yaml  allow_body + allow_response rules
#
# Environment:
#   ZOPA_TEST_PORT          data plane port      (default 10070)
#   ZOPA_TEST_BACKEND_PORT  loopback upstream    (default 10071)
#   ZOPA_TEST_ADMIN_PORT    admin port           (default 9931)
#   ZOPA_ENVOY_RUNTIME      wasm runtime         (default wamr)
#   KEEP_LOG=1              keep the Envoy logs on exit

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WASM="$ROOT/zig-out/bin/zopa.wasm"
EXAMPLE_DIR="$ROOT/examples/envoy"

if [[ ! -f "$WASM" ]]; then
    echo "missing $WASM -- run 'zig build' first" >&2
    exit 2
fi
if ! command -v envoy >/dev/null 2>&1; then
    echo "envoy not on PATH -- 'brew install envoy'" >&2
    exit 2
fi

PORT=${ZOPA_TEST_PORT:-10070}
BACKEND_PORT=${ZOPA_TEST_BACKEND_PORT:-10071}
ADMIN_PORT=${ZOPA_TEST_ADMIN_PORT:-9931}
# Homebrew Envoy ships wamr; the upstream release binary ships v8.
RUNTIME=${ZOPA_ENVOY_RUNTIME:-envoy.wasm.runtime.wamr}

WORK=$(mktemp -d -t zopa.envoy.XXXXXX)
ENVOY_PID=
LOG=

cleanup() {
    stop_envoy
    if [[ "${KEEP_LOG:-0}" != "1" ]]; then
        rm -rf "$WORK"
    else
        echo "envoy logs retained under $WORK"
    fi
}
trap cleanup EXIT

stop_envoy() {
    if [[ -n "$ENVOY_PID" ]] && kill -0 "$ENVOY_PID" 2>/dev/null; then
        kill "$ENVOY_PID" 2>/dev/null || true
        wait "$ENVOY_PID" 2>/dev/null || true
    fi
    ENVOY_PID=
}

# start_envoy <template-basename>
start_envoy() {
    local template="$EXAMPLE_DIR/$1"
    # Envoy picks the bootstrap parser by file extension, so the
    # generated config has to keep a `.yaml` name.
    local run_yaml="$WORK/$1"
    LOG="$WORK/$1.log"

    # sed in BSD/macOS handles `s|a|b|g` fine.
    sed \
        -e "s|__WASM_PATH__|$WASM|g" \
        -e "s|__PORT__|$PORT|g" \
        -e "s|__BACKEND_PORT__|$BACKEND_PORT|g" \
        -e "s|__ADMIN_PORT__|$ADMIN_PORT|g" \
        -e "s|__RUNTIME__|$RUNTIME|g" \
        "$template" > "$run_yaml"

    envoy -c "$run_yaml" --log-level warn --component-log-level wasm:debug > "$LOG" 2>&1 &
    ENVOY_PID=$!

    # Wait until the admin /ready endpoint reports LIVE.
    local ready=0
    for _ in $(seq 1 80); do
        if curl -sf "http://127.0.0.1:$ADMIN_PORT/ready" 2>/dev/null | grep -q LIVE; then
            ready=1
            break
        fi
        if ! kill -0 "$ENVOY_PID" 2>/dev/null; then
            echo "envoy died during startup ($1)" >&2
            cat "$LOG" >&2
            exit 1
        fi
        sleep 0.1
    done
    if [[ "$ready" != 1 ]]; then
        echo "envoy never reached LIVE ($1)" >&2
        cat "$LOG" >&2
        exit 1
    fi
}

failed=0

# check <name> <expected-status> [curl args...] -- path defaults to /
check() {
    local name=$1 expected_status=$2
    shift 2
    local actual
    actual=$(curl -s -o /dev/null -w "%{http_code}" "$@")
    if [[ "$actual" == "$expected_status" ]]; then
        echo "PASS  $name (HTTP $actual)"
    else
        echo "FAIL  $name: got HTTP $actual, expected $expected_status"
        failed=$((failed + 1))
    fi
}

base="http://127.0.0.1:$PORT"

# ---------------------------------------------------------------------------
# Scenario 1: request-headers phase.
# ---------------------------------------------------------------------------
echo "-- scenario: request ($RUNTIME)"
start_envoy envoy.yaml

check "GET / -> 200 allow"               200 -X GET "$base/"
check "POST / -> 403 deny"               403 -X POST "$base/"
check "DELETE / -> 403 deny"             403 -X DELETE "$base/"
check "GET / with headers -> 200 allow"  200 -X GET -H "X-User: kt" "$base/"

stop_envoy

# ---------------------------------------------------------------------------
# Scenario 2: body and response phases.
# ---------------------------------------------------------------------------
echo
echo "-- scenario: phases ($RUNTIME)"
start_envoy envoy-phases.yaml

check "GET / -> 200 (no body rule input)" 200 -X GET "$base/"

check "POST amount=50 -> 200 allow" 200 \
    -X POST -H "Content-Type: application/json" \
    --data '{"amount":50}' "$base/"

check "POST amount=5000 -> 403 body deny" 403 \
    -X POST -H "Content-Type: application/json" \
    --data '{"amount":5000}' "$base/"

check "POST non-JSON body -> 200 (default allows)" 200 \
    -X POST -H "Content-Type: text/plain" \
    --data 'not json at all' "$base/"

# A body split across chunks must be buffered before evaluation. With
# the filter returning Continue on non-final chunks, Envoy forwards
# each fragment as it arrives and the final callback sees only the
# tail -- so the deny rule would miss an `amount` that landed in an
# earlier chunk. Pad the front so `amount` cannot be in the last
# fragment.
python3 - "$WORK/chunked.json" <<'PY'
import json, sys
payload = {"pad": "x" * 40000, "amount": 5000}
with open(sys.argv[1], "w") as f:
    json.dump(payload, f)
PY
check "POST chunked body, amount in first chunk -> 403" 403 \
    -X POST -H "Content-Type: application/json" \
    -H "Transfer-Encoding: chunked" \
    --data-binary "@$WORK/chunked.json" "$base/"

# Over the 64 KiB buffer cap. The payload would be ALLOWED if zopa saw
# all of it (amount is under the limit), so a pass here means zopa
# decided on a prefix -- the exact fail-open this denies.
python3 - "$WORK/oversized.json" <<'PY'
import json, sys
payload = {"amount": 50, "pad": "x" * 100000}
with open(sys.argv[1], "w") as f:
    json.dump(payload, f)
PY
check "POST body over the 64 KiB cap -> 403 fail closed" 403 \
    -X POST -H "Content-Type: application/json" \
    --data-binary "@$WORK/oversized.json" "$base/"

check "GET /teapot -> 503 response deny" 503 -X GET "$base/teapot"

if (( failed > 0 )); then
    echo
    echo "$failed test(s) failed; envoy log follows:" >&2
    cat "$LOG" >&2
    exit 1
fi
echo
echo "all tests passed"
