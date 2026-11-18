# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Tests for TC52 target-scoped HRT restart null handling."""

import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from taac.constants import TestDevice
from taac.health_checks.device_health_checks.fpf_hrt_bulk_convergence_health_check import (
    FpfHrtBulkConvergenceHealthCheck,
)
from taac.health_checks.device_health_checks.fpf_hrt_plane_status_health_check import (
    FpfHrtPlaneStatusHealthCheck,
)
from taac.health_checks.device_health_checks.fpf_hrt_remote_failure_convergence_health_check import (
    FpfHrtRemoteFailureConvergenceHealthCheck,
)
from taac.health_checks.device_health_checks.fpf_prod_hrt_prefix_stability_health_check import (
    FpfProdHrtPrefixStabilityHealthCheck,
)
from taac.libs.fpf.fpf_prod_hrt_prefix import PrefixReachability
from taac.libs.fpf.fpf_stress_checks import (
    HrtBulkCollector,
    HrtBulkRow,
    HrtPlaneStatusCollector,
    HrtPlaneStatusRow,
    HrtRemoteFailureCollector,
    HrtRemoteFailureRow,
    ProdHrtPrefixCollector,
    ProdHrtPrefixRow,
)
from taac.health_check.health_check import types as hc_types

BULK_MODULE = (
    "neteng.test_infra.dne.taac.health_checks.device_health_checks."
    "fpf_hrt_bulk_convergence_health_check"
)
RF_MODULE = (
    "neteng.test_infra.dne.taac.health_checks.device_health_checks."
    "fpf_hrt_remote_failure_convergence_health_check"
)
PLANE_MODULE = (
    "neteng.test_infra.dne.taac.health_checks.device_health_checks."
    "fpf_hrt_plane_status_health_check"
)
PROD_MODULE = (
    "neteng.test_infra.dne.taac.health_checks.device_health_checks."
    "fpf_prod_hrt_prefix_stability_health_check"
)
RESTARTED = "twshared1352.03.mwg2"
UNAFFECTED = "twshared1388.03.mwg2"
WINDOW_START = 1_700_000_000.0
RESTART_TS = WINDOW_START + 10
RESTART_COMPLETION_TS = WINDOW_START + 20
WINDOW_END = WINDOW_START + 40
EXPECTED = 4032
PROD_PREFIX = "2401:db00:292a:a270::/64"


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f%z"
    )


def _bulk_row(host: str, offset: float, count: int, *, valid: bool = True):
    return HrtBulkRow(
        timestamp=_ts(WINDOW_START + offset),
        host=host,
        device_id=0,
        lane_counts=[count] if valid else [],
        unique=count,
        valid=valid,
        notes="" if valid else "error: connection refused",
        plane_ids=[0],
    )


def _rf_row(host: str, offset: float, count: int, *, valid: bool = True):
    return HrtRemoteFailureRow(
        timestamp=_ts(WINDOW_START + offset),
        host=host,
        device_id=0,
        lane_counts=[count] if valid else [],
        unique=count,
        valid=valid,
        notes="" if valid else "error: EOF",
        plane_ids=[0],
    )


def _plane_row(host: str, offset: float, state: str, *, valid: bool = True):
    return HrtPlaneStatusRow(
        timestamp=_ts(WINDOW_START + offset),
        host=host,
        device_id=0,
        plane_states={0: state} if valid else {},
        valid=valid,
        notes="" if valid else "error: connection refused",
    )


def _prod_state() -> PrefixReachability:
    return PrefixReachability(
        reachable_planes=[0],
        drained_planes=[],
        unreachable_planes=[],
        plane_up=[0],
        plane_down=[],
        device_ids=[0],
    )


def _prod_row(host: str, offset: float, *, valid: bool = True):
    return ProdHrtPrefixRow(
        timestamp=_ts(WINDOW_START + offset),
        host=host,
        prefixes={PROD_PREFIX: _prod_state()} if valid else {},
    )


class HrtRestartNullPolicyTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.device = MagicMock(spec=TestDevice)

    async def _run_bulk(self, rows, hosts):
        collector = HrtBulkCollector(
            hosts=hosts, device_ids=[0], plane_ids=[0], supernet="5000::/16"
        )
        collector.rows = rows
        check = FpfHrtBulkConvergenceHealthCheck(logger=MagicMock())
        with (
            patch(f"{BULK_MODULE}.get_collector", return_value=collector),
            patch(f"{BULK_MODULE}.get_test_case_start_time", return_value=WINDOW_START),
            patch(f"{BULK_MODULE}.get_restart_time", return_value=RESTART_TS),
            patch(
                f"{BULK_MODULE}.get_restart_completion_time",
                return_value=RESTART_COMPLETION_TS,
            ),
            patch(
                f"{BULK_MODULE}.everpaste_details_suffix",
                new=AsyncMock(return_value=""),
            ),
        ):
            return await check._run(
                self.device,
                hc_types.BaseHealthCheckIn(),
                {
                    "use_live_collectors": True,
                    "lanes": [0],
                    "device_ids": [0],
                    "expected_per_lane": {0: EXPECTED},
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "signal3_stability_duration_sec": 0,
                    "restart_tolerant_hosts": [RESTARTED],
                },
            )

    async def _run_rf(self, rows, hosts):
        collector = HrtRemoteFailureCollector(
            hosts=hosts, device_ids=[0], plane_ids=[0], supernet="5000::/16"
        )
        collector.rows = rows
        check = FpfHrtRemoteFailureConvergenceHealthCheck(logger=MagicMock())
        with (
            patch(f"{RF_MODULE}.get_collector", return_value=collector),
            patch(f"{RF_MODULE}.get_test_case_start_time", return_value=WINDOW_START),
            patch(f"{RF_MODULE}.get_restart_time", return_value=RESTART_TS),
            patch(
                f"{RF_MODULE}.get_restart_completion_time",
                return_value=RESTART_COMPLETION_TS,
            ),
            patch(
                f"{RF_MODULE}.everpaste_details_suffix",
                new=AsyncMock(return_value=""),
            ),
        ):
            return await check._run(
                self.device,
                hc_types.BaseHealthCheckIn(),
                {
                    "use_live_collectors": True,
                    "lanes": [0],
                    "device_ids": [0],
                    "expected_per_lane": {0: 0},
                    "direction": "stable",
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "restart_tolerant_hosts": [RESTARTED],
                },
            )

    async def _run_plane(self, rows, hosts):
        collector = HrtPlaneStatusCollector(hosts=hosts, device_ids=[0], num_planes=1)
        collector.rows = rows
        check = FpfHrtPlaneStatusHealthCheck(logger=MagicMock())
        with (
            patch(f"{PLANE_MODULE}.get_collector", return_value=collector),
            patch(
                f"{PLANE_MODULE}.get_test_case_start_time",
                return_value=WINDOW_START,
            ),
            patch(f"{PLANE_MODULE}.get_restart_time", return_value=RESTART_TS),
            patch(
                f"{PLANE_MODULE}.get_restart_completion_time",
                return_value=RESTART_COMPLETION_TS,
            ),
            patch(
                f"{PLANE_MODULE}.everpaste_details_suffix",
                new=AsyncMock(return_value=""),
            ),
        ):
            return await check._run(
                self.device,
                hc_types.BaseHealthCheckIn(),
                {
                    "mode": "all_up",
                    "expected_planes": [0],
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "restart_tolerant_hosts": [RESTARTED],
                },
            )

    async def _run_prod(self, rows, hosts):
        prefixes_by_host = {host: [PROD_PREFIX] for host in hosts}
        collector = ProdHrtPrefixCollector(
            hosts=hosts,
            device_id=0,
            prefixes_by_host=prefixes_by_host,
        )
        collector.rows = rows
        check = FpfProdHrtPrefixStabilityHealthCheck(logger=MagicMock())
        with (
            patch(f"{PROD_MODULE}.get_collector", return_value=collector),
            patch(f"{PROD_MODULE}.get_restart_time", return_value=RESTART_TS),
            patch(
                f"{PROD_MODULE}.get_restart_completion_time",
                return_value=RESTART_COMPLETION_TS,
            ),
            patch(
                f"{PROD_MODULE}.everpaste_details_suffix",
                new=AsyncMock(return_value=""),
            ),
        ):
            return await check._run(
                self.device,
                hc_types.BaseHealthCheckIn(),
                {
                    "prefixes_by_host": prefixes_by_host,
                    "window_start": WINDOW_START,
                    "window_end": WINDOW_END,
                    "restart_tolerant_hosts": [RESTARTED],
                },
            )

    async def test_restarted_host_bulk_and_rf_tolerate_outage_nulls(self):
        bulk = await self._run_bulk(
            [
                _bulk_row(RESTARTED, 5, EXPECTED),
                _bulk_row(RESTARTED, 12, 0, valid=False),
                _bulk_row(RESTARTED, 25, EXPECTED),
            ],
            [RESTARTED],
        )
        rf = await self._run_rf(
            [
                _rf_row(RESTARTED, 5, 0),
                _rf_row(RESTARTED, 12, 0, valid=False),
                _rf_row(RESTARTED, 25, 0),
            ],
            [RESTARTED],
        )

        self.assertEqual(bulk.status, hc_types.HealthCheckStatus.PASS)
        self.assertEqual(rf.status, hc_types.HealthCheckStatus.PASS)

    async def test_restarted_host_prod_and_plane_tolerate_outage_nulls(self):
        prod = await self._run_prod(
            [
                _prod_row(RESTARTED, 5),
                _prod_row(RESTARTED, 12, valid=False),
                _prod_row(RESTARTED, 25),
            ],
            [RESTARTED],
        )
        plane = await self._run_plane(
            [
                _plane_row(RESTARTED, 5, "UP"),
                _plane_row(RESTARTED, 12, "", valid=False),
                _plane_row(RESTARTED, 25, "UP"),
            ],
            [RESTARTED],
        )

        self.assertEqual(prod.status, hc_types.HealthCheckStatus.PASS)
        self.assertEqual(plane.status, hc_types.HealthCheckStatus.PASS)

    async def test_unaffected_host_prod_and_plane_null_remain_strict(self):
        prod = await self._run_prod(
            [
                _prod_row(RESTARTED, 5),
                _prod_row(RESTARTED, 12, valid=False),
                _prod_row(RESTARTED, 25),
                _prod_row(UNAFFECTED, 5),
                _prod_row(UNAFFECTED, 12, valid=False),
                _prod_row(UNAFFECTED, 25),
            ],
            [RESTARTED, UNAFFECTED],
        )
        plane = await self._run_plane(
            [
                _plane_row(RESTARTED, 5, "UP"),
                _plane_row(RESTARTED, 12, "", valid=False),
                _plane_row(RESTARTED, 25, "UP"),
                _plane_row(UNAFFECTED, 5, "UP"),
                _plane_row(UNAFFECTED, 12, "", valid=False),
                _plane_row(UNAFFECTED, 25, "UP"),
            ],
            [RESTARTED, UNAFFECTED],
        )

        self.assertEqual(prod.status, hc_types.HealthCheckStatus.FAIL)
        self.assertEqual(plane.status, hc_types.HealthCheckStatus.FAIL)

    async def test_unaffected_host_null_remains_strict(self):
        bulk = await self._run_bulk(
            [
                _bulk_row(RESTARTED, 5, EXPECTED),
                _bulk_row(RESTARTED, 12, 0, valid=False),
                _bulk_row(RESTARTED, 25, EXPECTED),
                _bulk_row(UNAFFECTED, 5, EXPECTED),
                _bulk_row(UNAFFECTED, 12, 0, valid=False),
                _bulk_row(UNAFFECTED, 25, EXPECTED),
            ],
            [RESTARTED, UNAFFECTED],
        )
        rf = await self._run_rf(
            [
                _rf_row(RESTARTED, 5, 0),
                _rf_row(RESTARTED, 12, 0, valid=False),
                _rf_row(RESTARTED, 25, 0),
                _rf_row(UNAFFECTED, 5, 0),
                _rf_row(UNAFFECTED, 12, 0, valid=False),
                _rf_row(UNAFFECTED, 25, 0),
            ],
            [RESTARTED, UNAFFECTED],
        )

        self.assertEqual(bulk.status, hc_types.HealthCheckStatus.FAIL)
        self.assertEqual(rf.status, hc_types.HealthCheckStatus.FAIL)

    async def test_valid_dirty_bulk_row_fails(self):
        result = await self._run_bulk(
            [
                _bulk_row(RESTARTED, 5, EXPECTED),
                _bulk_row(RESTARTED, 12, 0, valid=False),
                _bulk_row(RESTARTED, 25, EXPECTED - 1),
                _bulk_row(RESTARTED, 30, EXPECTED),
            ],
            [RESTARTED],
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_missing_post_outage_recovery_fails(self):
        result = await self._run_rf(
            [
                _rf_row(RESTARTED, 5, 0),
                _rf_row(RESTARTED, 12, 0, valid=False),
            ],
            [RESTARTED],
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("no valid recovery sample", result.message)

    async def test_final_valid_rf_regression_fails(self):
        result = await self._run_rf(
            [
                _rf_row(RESTARTED, 5, 0),
                _rf_row(RESTARTED, 12, 0, valid=False),
                _rf_row(RESTARTED, 25, 0),
                _rf_row(RESTARTED, 30, 1),
            ],
            [RESTARTED],
        )

        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)


if __name__ == "__main__":
    unittest.main()
