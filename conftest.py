# pyre-unsafe
"""Pytest collection configuration for OSS-compatible unit tests.

Many test files under taac/ depend on internal (non-OSS) modules such as
``neteng.*``, ``taac.internal``, or ``taac.health_check``.  These cannot
be collected in the open-source Docker image and are excluded below so
that ``python3 -m pytest`` exits cleanly.

When a test file is ported to work without internal dependencies, remove
its entry (or its parent directory) from the appropriate list.
"""

import os

import pytest
from taac.libs.collectors.registry import clear_collectors


@pytest.fixture(autouse=True)
def _reset_collector_registry():
    """Reset the process-wide collector registry between tests.

    ``taac_runner.run_test_case`` stamps ``set_test_case_start_time(time.time())``
    on every playbook iteration, so any test exercising it leaks a live
    timestamp into tests that assert on the unset-anchor fallback.
    """
    yield
    clear_collectors()


# ---------------------------------------------------------------------------
# Directories where *every* test depends on non-OSS modules.
# ---------------------------------------------------------------------------
_NON_OSS_TEST_DIRS = [
    "taac/health_checks",
    "taac/ixia/tests",
    "taac/libs/fpf/tests",
    "taac/steps/tests",
    "taac/tasks",
]

# ---------------------------------------------------------------------------
# Individual files that are either non-OSS tests or non-test modules
# (production code whose ``test_`` prefix causes pytest to pick them up).
# ---------------------------------------------------------------------------
_NON_OSS_TEST_FILES = [
    # Imports taac.testconfigs.routing.factories, which needs taac.abstractions.
    "taac/playbooks/routing/tests/test_bgp_attribute_churn_playbook.py",
    # Non-test modules (production code with test_ prefix)
    "taac/test_configs.py",
    "taac/libs/test_setup_orchestrator.py",
    "taac/utils/test_config_utils.py",
]

# ---------------------------------------------------------------------------
# Files inside a _NON_OSS_TEST_DIRS directory that DO run in the OSS image.
# The directory bans above are blanket ones -- most of taac/health_checks
# cannot even be imported here -- but a handful of files are OSS-clean, and
# ignoring them means a health-check change lands with no unit coverage at
# all. Each entry below is verified green in the OSS image; add one only
# after `run_tests.sh -- <path>` passes on its own.
# ---------------------------------------------------------------------------
_OSS_READY_TEST_FILES = [
    "taac/health_checks/device_health_checks/test_cpu_utilization_report_only.py",
    "taac/health_checks/device_health_checks/test_new_characterization_health_checks.py",
    "taac/health_checks/device_health_checks/test_l2_entry_threshold_observe_deadline.py",
    "taac/health_checks/device_health_checks/tests/test_pfc_counter_health_checks.py",
    # Pure unit test of dlb_resource_analysis.analyze with SimpleNamespace routes.
    "taac/health_checks/device_health_checks/tests/test_dlb_resource_analysis_snapshot.py",
    "taac/health_checks/tests/test_collector_max_summary.py",
    "taac/health_checks/ixia_health_checks/test_ixia_port_stats_health_check.py",
    "taac/health_checks/snapshot_health_checks/test_qos_queue_byte_counters.py",
    "taac/health_checks/snapshot_health_checks/test_bgp_peers_pre_snapshot_settle.py",
    "taac/health_checks/snapshot_health_checks/test_port_speed_health_check.py",
    "taac/health_checks/tests/test_healthcheck_definitions_systemctl.py",
    # Runs the production grep-window command against a local fixture log; only
    # the remote transport is mocked, so no non-OSS import.
    "taac/health_checks/device_health_checks/test_oomd_kill_health_check.py",
    # Drives IxiaPacketLossHealthCheck._run with a MagicMock traffic generator
    # and a patched clock -- no IXIA, no non-OSS import.
    "taac/health_checks/ixia_health_checks/test_ixia_loss_recovery_window.py",
    "taac/health_checks/ixia_health_checks/test_ixia_frames_flowed.py",
    "taac/health_checks/device_health_checks/tests/test_port_transceiver_health_check.py",
    # BGP state / core-dump coverage: OSS-clean tests for these checks, since
    # their existing test files import neteng.netcastle.
    "taac/health_checks/device_health_checks/test_bgp_session_allowlist_guard.py",
    "taac/health_checks/device_health_checks/test_bgp_route_count_report_only.py",
    "taac/health_checks/device_health_checks/test_ecmp_group_count_report.py",
    "taac/health_checks/device_health_checks/test_core_dump_path_oss.py",
    "taac/health_checks/device_health_checks/test_lldp_paced_retry_window.py",
    # Pure unit tests: mocked driver and IXIA, Ixia built with __init__ patched.
    "taac/health_checks/device_health_checks/test_route_convergence_time_health_check.py",
    "taac/health_checks/device_health_checks/test_bgp_rib_fib_consistency_health_check.py",
    "taac/health_checks/tests/test_common_utils.py",
    "taac/health_checks/tests/test_convergence_observer.py",
    "taac/tasks/tests/test_oss_gating.py",
    "taac/health_checks/snapshot_health_checks/test_cpu_queue_failure_window.py",
    # Pure unit test: Ixia via __new__, config element mocked.
    "taac/ixia/tests/test_ipv4_ecn_bits.py",
]

# Build absolute paths relative to this conftest's directory (repo root).
_HERE = os.path.dirname(__file__)


def _parents_up_to(path, root):
    """Every directory between ``path`` and ``root``, exclusive of ``root``."""
    parents = []
    current = os.path.dirname(path)
    while current and current != root:
        parents.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return parents


collect_ignore = [os.path.join(_HERE, f) for f in _NON_OSS_TEST_FILES]
collect_ignore_glob = [os.path.join(_HERE, d, "**") for d in _NON_OSS_TEST_DIRS]

_OSS_READY_ABS = {os.path.join(_HERE, f) for f in _OSS_READY_TEST_FILES}

# The directory globs prune whole trees, so pytest never descends far enough to
# ask about an allowlisted file. Re-admit its parent directories too.
_OSS_READY_PARENTS = {
    parent for path in _OSS_READY_ABS for parent in _parents_up_to(path, _HERE)
}


def pytest_ignore_collect(collection_path, config):
    """Re-admit the allowlisted files the directory globs above would drop.

    Returning False short-circuits pytest's own collect_ignore_glob handling;
    returning None everywhere else leaves the blanket directory bans intact.
    """
    path = str(collection_path)
    if path in _OSS_READY_ABS or path in _OSS_READY_PARENTS:
        return False
    return None
