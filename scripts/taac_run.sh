#!/bin/bash
# Short wrapper around the OSS TAAC boilerplate invocation.
#
# Usage:
#   ./scripts/taac_run.sh <dut> <test-config> [playbook ...] [oss_entry_point flags ...]
#
# Examples:
#   ./scripts/taac_run.sh <dut> taac/testconfigs/oss/snake_config.py test_snake_agent_coldboot
#   ./scripts/taac_run.sh <dut> taac/testconfigs/oss/snake_config.py test_snake_warmboot --ixia-session-id 58 --skip-ixia-cleanup
#   ./scripts/taac_run.sh <dut> taac/testconfigs/oss/snake_config.py --list-tests
#
# The first two positional arguments are the DUT and the test config, both
# mandatory: no default config, so a run can never quietly pick up one you
# didn't name. The path is resolved in the container, whose working directory
# is /workspace (the repo root), so a repo-relative path works as-is.
# Following bare words (not starting with '-') are playbooks. Everything from
# the first '-'-prefixed argument onward is passed through verbatim to
# taac.runner.oss_entry_point.
#
# Defaults (only added when the corresponding flag is absent from the
# pass-through arguments):
#   --ixia-api-server  $TAAC_IXIA_API_SERVER  (required unless passed)
#   --circuit-info-csv /workspace/taac/oss_topology_info/circuit_info.csv
#   --device-info-csv  /workspace/taac/oss_topology_info/device_info.csv
#
# Thrift bindings are regenerated from the workspace's .thrift files on every
# run, so a container image older than the repo can't silently drop
# newly added TestConfig fields. Set TAAC_REGEN=0 to use the image's baked-in
# bindings instead.
#
# TAAC_SSH_USER / TAAC_SSH_PASSWORD default to root/root when unset; export
# them (e.g. via ~/.taac-secrets) to override. See docker/README.md.
# TAAC_ITERATION defaults to 2 (snake triage); unset/override for full runs.

set -euo pipefail

# Print the header comment block (everything above the first blank line) as
# help, so it can't drift out of sync with a hardcoded line range.
usage() {
    awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0" >&2
    exit 1
}

[[ $# -ge 1 ]] || usage
case "$1" in -*|-h|--help) usage ;; esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DUT="$1"
shift

# Mandatory second positional: a run must name its own test config. Checking
# the .py suffix here (the entry point rejects anything else anyway) makes a
# playbook name in the config slot a usage error before the container starts.
if [[ $# -lt 1 || "$1" == -* || "$1" != *.py ]]; then
    echo "Error: second argument must be a test config .py path," \
         "e.g. taac/testconfigs/oss/snake_config.py" >&2
    usage
fi
TEST_CONFIG="$1"
shift

PLAYBOOKS=()
while [[ $# -gt 0 && "$1" != -* ]]; do
    PLAYBOOKS+=("$1")
    shift
done
PASSTHROUGH=("$@")

has_flag() {
    local flag="$1" arg
    for arg in "${PASSTHROUGH[@]}"; do
        [[ "$arg" == "$flag" || "$arg" == "$flag"=* ]] && return 0
    done
    return 1
}

CMD=(python3 -m taac.runner.oss_entry_point --dut "$DUT" --test-configs "$TEST_CONFIG")
[[ ${#PLAYBOOKS[@]} -gt 0 ]] && CMD+=(--playbook "${PLAYBOOKS[@]}")

has_flag --ixia-api-server \
    || CMD+=(--ixia-api-server "${TAAC_IXIA_API_SERVER:?set TAAC_IXIA_API_SERVER}")
has_flag --circuit-info-csv \
    || CMD+=(--circuit-info-csv /workspace/taac/oss_topology_info/circuit_info.csv)
has_flag --device-info-csv \
    || CMD+=(--device-info-csv /workspace/taac/oss_topology_info/device_info.csv)

CMD+=("${PASSTHROUGH[@]}")

export TAAC_OSS=1
export TAAC_SSH_USER="${TAAC_SSH_USER:-root}"
export TAAC_SSH_PASSWORD="${TAAC_SSH_PASSWORD:-root}"
# Triage default for configs that read TAAC_ITERATION (today: oss snake).
export TAAC_ITERATION="${TAAC_ITERATION:-2}"

DOCKER_OPTS=()
[[ "${TAAC_REGEN:-1}" == 0 ]] || DOCKER_OPTS+=(--regen)

echo "TAAC_OSS=1 TAAC_ITERATION=${TAAC_ITERATION} TAAC_SSH_USER=${TAAC_SSH_USER} TAAC_SSH_PASSWORD=<redacted> \\" >&2
echo "  ${REPO_ROOT}/docker/run_taac_docker.sh ${DOCKER_OPTS[*]+${DOCKER_OPTS[*]} }run ${CMD[*]}" >&2

exec "${REPO_ROOT}/docker/run_taac_docker.sh" "${DOCKER_OPTS[@]}" run "${CMD[@]}"
