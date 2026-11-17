#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# Inspect topology requirements for one or more TAAC test configs.
#
# Wraps `python3 -m taac.runner.inspect` inside the TAAC Docker container.
# All arguments are forwarded verbatim to the inspector.
#
# Usage:
#   ./scripts/inspect_topology.sh --test-configs taac/testconfigs/configerator/jsw_ptp.py
#   ./scripts/inspect_topology.sh --dir taac/testconfigs/fboss_solution_tests/
#   ./scripts/inspect_topology.sh --dir taac/testconfigs/ --devices 2 --ixia-ports 4
#   ./scripts/inspect_topology.sh --test-configs <config.py> --verbose

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "$SCRIPT_DIR/../docker/run_taac_docker.sh" run python3 -m taac.runner.inspect "$@"
