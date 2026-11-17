#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""``threshold=0`` on the OSS CPU check means report-only, not fail-on-anything.

The violation test is guarded on ``svc_threshold > 0``. Without that guard a
zero threshold means "fail on any nonzero CPU" -- the exact opposite of the
intent -- so this pins the semantics rather than the wiring. It matches the
memory check, where 0 has always meant "no global check".

Report-only exists because the transceiver re-poll burst after a service or
agent restart pushes qsfp_service and the hw agent far above their medians for
one or two polls, by a margin that varies run to run. A ceiling in that band
gates on which poll caught the burst, so a config can record the peak
instead of gating on it.
"""

import typing as t
import unittest
from unittest.mock import MagicMock

from taac.health_checks.device_health_checks.cpu_utilization_health_check import (
    CpuUtilizationHealthCheck,
)
from taac.libs.collectors.cpu_utilization_collector import (
    CpuUtilizationCollector,
)
from taac.libs.collectors.registry import (
    clear_collectors,
    register_collector,
    set_test_case_start_time,
)
from taac.health_check.health_check import types as hc_types


_SERVICES = ["qsfp_service", "bgpd"]


def _collector_with_peaks(peaks: t.Dict[str, float]) -> CpuUtilizationCollector:
    """A started-looking collector holding one row of known CPU percentages."""
    collector = CpuUtilizationCollector(
        driver=MagicMock(),
        services=list(peaks),
        host="dut01",
        tmp_path="/dev/null",
    )
    collector.rows.append(
        collector._make_sample(
            timestamp="",
            epoch=1000.0,
            per_service=dict(peaks),
            notes="",
        )
    )
    return collector


class CpuReportOnlyTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        clear_collectors()
        self.device = MagicMock()
        self.device.name = "dut01"
        self.check = CpuUtilizationHealthCheck(MagicMock())

    def tearDown(self) -> None:
        clear_collectors()

    async def _run(self, peaks, check_params) -> hc_types.HealthCheckResult:
        collector = _collector_with_peaks(peaks)
        register_collector("cpu_utilization", collector)
        set_test_case_start_time(0.0)
        params = {"window_start": 0.0, "window_end": 2000.0, **check_params}
        return await self.check._run_oss_via_collector(
            self.device,
            list(peaks),
            params.get("threshold", 0),
            params.get("threshold_by_service", {}),
            params,
        )

    async def test_zero_threshold_passes_a_peak_over_one_hundred_percent(self) -> None:
        """A re-poll burst can exceed 100%; report-only must not
        fail on it."""
        result = await self._run(
            {"qsfp_service": 120.0, "bgpd": 0.12}, {"threshold": 0}
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_zero_threshold_still_reports_the_peak(self) -> None:
        """Report-only is worthless if the number never reaches the message --
        the summary table shows the result message, not the check's log lines."""
        result = await self._run(
            {"qsfp_service": 120.0, "bgpd": 0.12}, {"threshold": 0}
        )
        self.assertIn("120.00%", result.message)
        self.assertIn("no limit", result.message)

    async def test_per_service_override_gates_only_that_service(self) -> None:
        """A positive per-service threshold still fails while the rest stay
        report-only."""
        result = await self._run(
            {"qsfp_service": 120.0, "bgpd": 0.12},
            {"threshold": 0, "threshold_by_service": {"qsfp_service": 90.0}},
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("qsfp_service", result.message)
        self.assertNotIn("bgpd:", result.message)

    async def test_positive_threshold_still_gates(self) -> None:
        """The guard must not disable gating for ordinary positive values."""
        result = await self._run({"qsfp_service": 95.0}, {"threshold": 70.0})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)

    async def test_positive_threshold_passes_under_the_ceiling(self) -> None:
        result = await self._run({"qsfp_service": 42.5}, {"threshold": 70.0})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_no_collector_skips_rather_than_passes(self) -> None:
        """A missing collector must not read as a clean run."""
        set_test_case_start_time(0.0)
        result = await self.check._run_oss_via_collector(
            self.device, _SERVICES, 0, {}, {"window_start": 0.0, "window_end": 2000.0}
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.SKIP)


if __name__ == "__main__":
    unittest.main()
