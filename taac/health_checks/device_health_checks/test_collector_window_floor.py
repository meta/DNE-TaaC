#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""A precheck's default window is too narrow to contain a collector sample.

The runner stamps the test-case start immediately before prechecks run, so
``[test_case_start_time, now]`` comes out 0-1s wide while the collector polls
every 5s. Unwidened, both measurement checks find no sample and return SKIP,
losing the check entirely -- and where the memory check is a precheck only,
that is its only measurement.

The ODS path sleeps before querying and widens any window under 60s. These
pin the collector-path equivalent.
"""

import asyncio
import time
import typing as t
import unittest
from unittest.mock import MagicMock

from taac.health_checks.device_health_checks.cpu_utilization_health_check import (
    CpuUtilizationHealthCheck,
)
from taac.health_checks.device_health_checks.memory_utilization_health_check import (
    MemoryUtilizationHealthCheck,
)
from taac.libs.collectors.cpu_utilization_collector import CpuUtilizationCollector
from taac.libs.collectors.memory_utilization_collector import (
    MemoryUtilizationCollector,
)
from taac.libs.collectors.registry import (
    clear_collectors,
    register_collector,
    set_test_case_start_time,
)
from taac.health_check.health_check import types as hc_types


_HOST = "dut01"
_POLL_INTERVAL = 5.0
# Well above the seeded samples: PASS means a sample was found and evaluated.
_CPU_THRESHOLD_PCT = 70.0
# Playbook start, as the runner stamps it just before prechecks run.
_TEST_CASE_START = 3000.0


def _seed(collector, epochs: t.Sequence[float], per_service) -> None:
    """Rows at ``epochs``, as a collector polling every 5s would have left."""
    for epoch in epochs:
        collector.rows.append(
            collector._make_sample(
                timestamp="",
                epoch=epoch,
                per_service=dict(per_service),
                notes="",
            )
        )


class TestCollectorWindowFloor(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        clear_collectors()
        self.device = MagicMock()
        self.device.name = _HOST
        # Every sample predates the playbook: the collector starts at test
        # setUp and the last poll lands before the precheck fires.
        self.epochs = [_TEST_CASE_START - 10.0, _TEST_CASE_START - 5.0]

    def tearDown(self) -> None:
        clear_collectors()

    async def _run_memory(self, window_end: float) -> hc_types.HealthCheckResult:
        collector = MemoryUtilizationCollector(
            driver=MagicMock(),
            services=["bgpd"],
            host=_HOST,
            interval_sec=_POLL_INTERVAL,
            tmp_path="/dev/null",
        )
        _seed(collector, self.epochs, {"bgpd": 1024})
        register_collector("memory_utilization", collector)
        set_test_case_start_time(_TEST_CASE_START)
        params = {"window_end": window_end}
        return await MemoryUtilizationHealthCheck(
            MagicMock()
        )._run_oss_via_collector(self.device, ["bgpd"], 0, {}, params)

    async def _run_cpu(self, window_end: float) -> hc_types.HealthCheckResult:
        collector = CpuUtilizationCollector(
            driver=MagicMock(),
            services=["bgpd"],
            host=_HOST,
            interval_sec=_POLL_INTERVAL,
            tmp_path="/dev/null",
        )
        _seed(collector, self.epochs, {"bgpd": 1.5})
        register_collector("cpu_utilization", collector)
        set_test_case_start_time(_TEST_CASE_START)
        params = {"window_end": window_end}
        return await CpuUtilizationHealthCheck(MagicMock())._run_oss_via_collector(
            self.device, ["bgpd"], _CPU_THRESHOLD_PCT, {}, params
        )

    async def test_memory_zero_width_precheck_window_evaluates(self) -> None:
        """window_end == test_case_start_time: a zero-width precheck window."""
        result = await self._run_memory(_TEST_CASE_START)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_memory_one_second_precheck_window_evaluates(self) -> None:
        result = await self._run_memory(_TEST_CASE_START + 1.0)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_cpu_zero_width_precheck_window_evaluates(self) -> None:
        result = await self._run_cpu(_TEST_CASE_START)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_memory_still_skips_when_collector_has_no_samples(self) -> None:
        """The floor widens the window; it must not invent a verdict. A
        collector that has genuinely never polled still SKIPs."""
        self.epochs = []
        result = await self._run_memory(_TEST_CASE_START)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.SKIP)

    # -- A precheck that fires before the collector's first poll ------------------
    #
    # A config whose setup tasks are all no-ops runs its prechecks right after
    # the collectors start, before the first poll (an SSH round trip) lands. No
    # backward widening finds a row that does not exist yet; the check has to
    # wait for it.

    def _live(self, collector) -> None:
        """Make the collector look like its polling thread is running."""
        collector._thread = MagicMock()
        collector._thread.is_alive.return_value = True

    def _land_polls_later(self, collector, polls: t.Sequence[t.Tuple[float, t.Dict]]) -> None:
        """Append one row per ``(delay, per_service)``, as the poll loop would."""

        async def _poll() -> None:
            for delay, per_service in polls:
                await asyncio.sleep(delay)
                collector.rows.append(
                    collector._make_sample(
                        timestamp="",
                        epoch=time.time(),
                        per_service=dict(per_service),
                        notes="",
                    )
                )

        asyncio.get_running_loop().create_task(_poll())

    async def test_memory_waits_for_a_running_collectors_first_poll(self) -> None:
        collector = MemoryUtilizationCollector(
            driver=MagicMock(),
            services=["bgpd"],
            host=_HOST,
            interval_sec=0.5,
            tmp_path="/dev/null",
        )
        self._live(collector)
        self._land_polls_later(collector, [(0.2, {"bgpd": 1024})])
        register_collector("memory_utilization", collector)
        now = time.time()
        set_test_case_start_time(now)
        result = await MemoryUtilizationHealthCheck(
            MagicMock()
        )._run_oss_via_collector(self.device, ["bgpd"], 0, {}, {"window_end": now})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_cpu_waits_past_its_valueless_first_poll(self) -> None:
        collector = CpuUtilizationCollector(
            driver=MagicMock(),
            services=["bgpd"],
            host=_HOST,
            interval_sec=0.5,
            tmp_path="/dev/null",
        )
        self._live(collector)
        # CPU% is a delta against the previous poll: the first row is all None.
        self._land_polls_later(collector, [(0.2, {"bgpd": None}), (0.2, {"bgpd": 1.5})])
        register_collector("cpu_utilization", collector)
        now = time.time()
        set_test_case_start_time(now)
        result = await CpuUtilizationHealthCheck(MagicMock())._run_oss_via_collector(
            self.device, ["bgpd"], _CPU_THRESHOLD_PCT, {}, {"window_end": now}
        )
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)

    async def test_memory_running_collector_that_never_polls_still_skips(self) -> None:
        """The wait is bounded by three poll intervals; past that the SKIP stands."""
        collector = MemoryUtilizationCollector(
            driver=MagicMock(),
            services=["bgpd"],
            host=_HOST,
            interval_sec=0.2,
            tmp_path="/dev/null",
        )
        self._live(collector)
        register_collector("memory_utilization", collector)
        now = time.time()
        set_test_case_start_time(now)
        result = await MemoryUtilizationHealthCheck(
            MagicMock()
        )._run_oss_via_collector(self.device, ["bgpd"], 0, {}, {"window_end": now})
        self.assertEqual(result.status, hc_types.HealthCheckStatus.SKIP)


if __name__ == "__main__":
    unittest.main()
