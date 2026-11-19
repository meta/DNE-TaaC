#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# Print topology requirements for TAAC test configs inside the TAAC Docker
# container. Arguments are passed to `python3 -m taac.runner.topology_inspector`.
#
# Usage:
#   ./scripts/inspect_topology.sh --test-configs examples/live_smoke_config.py
#   ./scripts/inspect_topology.sh --dir taac/testconfigs/oss/ --verbose
#   ./scripts/inspect_topology.sh --dir <dir> --devices 2 --ixia-ports 4
#   ./scripts/inspect_topology.sh --test-configs <config.py> --test-name NAME

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "$SCRIPT_DIR/../docker/run_taac_docker.sh" run python3 -m taac.runner.topology_inspector "$@"
