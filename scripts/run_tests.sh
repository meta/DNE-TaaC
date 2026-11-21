#!/usr/bin/env bash
set -euo pipefail

DOCKER_IMAGE="${TAAC_TEST_IMAGE:-fboss-taac}"

usage() {
    echo "Usage: $0 [--image IMAGE] [--skip-smoke] [--regen-thrift] [-- PYTEST_ARGS...]"
    echo ""
    echo "Run OSS unit tests and smoke test inside the Docker build environment."
    echo ""
    echo "Options:"
    echo "  --image IMAGE     Docker image to use (default: \$TAAC_TEST_IMAGE or fboss-taac)"
    echo "  --skip-smoke      Skip the dry-run smoke test"
    echo "  --regen-thrift    Regenerate thrift bindings before running tests"
    echo ""
    echo "Everything after '--' is forwarded to pytest."
    echo ""
    echo "Examples:"
    echo "  $0                                          # run all tests + smoke"
    echo "  $0 --skip-smoke                             # unit tests only"
    echo "  $0 --regen-thrift                           # regen thrift first"
    echo "  $0 --image ghcr.io/org/fboss-taac:latest   # use a specific image"
    echo "  $0 -- taac/runner/tests/ -v -k retry        # run a subset (smoke still runs)"
    exit 1
}

SKIP_SMOKE=0
REGEN_THRIFT=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)
            DOCKER_IMAGE="$2"
            shift 2
            ;;
        --skip-smoke)
            SKIP_SMOKE=1
            shift
            ;;
        --regen-thrift)
            REGEN_THRIFT=1
            shift
            ;;
        --help|-h)
            usage
            ;;
        --)
            shift
            break
            ;;
        *)
            break
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_DOCKER="$REPO_ROOT/docker/run_taac_docker.sh"

DOCKER_ARGS=(--image "$DOCKER_IMAGE")
if [[ "$REGEN_THRIFT" -eq 1 ]]; then
    DOCKER_ARGS+=(--regen)
fi

echo "==> Running unit tests"
"$RUN_DOCKER" "${DOCKER_ARGS[@]}" run python3 -m pytest "$@"

if [[ "$SKIP_SMOKE" -eq 0 ]]; then
    echo ""
    echo "==> Running dry-run smoke test"
    "$RUN_DOCKER" "${DOCKER_ARGS[@]}" run python3 -m taac.runner.oss_entry_point \
        --test-configs /workspace/examples/live_smoke_config.py \
        --dut fakedut123 \
        --device-info-csv /workspace/examples/topology/sample_device_info.csv \
        --circuit-info-csv /workspace/examples/topology/sample_circuit_info.csv \
        --dry-run 2>&1 | tee /tmp/taac_smoke.log
    # An image built without TAAC_GIT_SHA prints "Image commit: unknown".
    if grep -q 'Image commit: unknown' /tmp/taac_smoke.log; then
        echo "Smoke test failed: image has no git sha stamp" >&2
        exit 1
    fi
    echo "Smoke test passed"
fi
