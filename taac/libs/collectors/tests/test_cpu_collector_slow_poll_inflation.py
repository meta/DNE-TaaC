# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""A slow SSH poll must not inflate CpuUtilizationCollector's CPU%.

Each poll opens a fresh SSH connection, and a round trip can take anything up
to POLL_TIMEOUT_SEC (120 s). The DUT reads ``CPUUsageNSec`` when the command
runs, i.e. at the END of a slow round trip. When the poll was stamped BEFORE
the round trip, the CPU time of the whole delay was divided by one normal
interval: a single slow poll can read as roughly ten times the true rate.
Stamped at the reply, the delay trips the collector's gap check
and resets the baseline, and a moderately slow poll is divided by the right span.

These tests drive the real collector with a fake clock and a fake driver whose
service burns exactly 1.5 CPU cores, so the true CPU% is 150% throughout.
"""

import typing as t
import unittest
from unittest import mock

from taac.libs.collectors.cpu_utilization_collector import CpuUtilizationCollector
from taac.libs.collectors.service_polling_collector import ServicePollingCollector

TRUE_PCT = 150.0  # the fake service burns exactly 1.5 CPU cores
INTERVAL_S = 5.0  # the collector's default poll interval
FAST_SSH_S = 0.2


class _FakeDut:
    """A clock plus a service whose cumulative CPU time grows at TRUE_PCT."""

    def __init__(self) -> None:
        self.now = 1_000.0
        self._start = self.now
        self.latencies: t.List[float] = []  # per-poll SSH latency, consumed in order

    def time(self) -> float:
        return self.now

    async def run_cmd(self, _cmd: str) -> str:
        # The round trip spends this long BEFORE the DUT reads its counter,
        # like a slow connect / key exchange / busy sshd.
        self.now += self.latencies.pop(0) if self.latencies else FAST_SSH_S
        cpu_ns = int(TRUE_PCT / 100 * (self.now - self._start) * 1e9)
        return f"Id=agent.service\nLoadState=loaded\nActiveState=active\nCPUUsageNSec={cpu_ns}"


class TestSlowPollDoesNotInflateCpu(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.dut = _FakeDut()
        driver = mock.MagicMock()
        driver.async_run_cmd_on_shell = mock.AsyncMock(side_effect=self.dut.run_cmd)
        driver.async_get_systemctl_service_name = mock.AsyncMock(
            side_effect=lambda service: service
        )
        self.collector = CpuUtilizationCollector(
            driver=driver, services=["agent"], host="dut", tmp_path="/dev/null",
            interval_sec=INTERVAL_S,
        )
        patcher = mock.patch(
            f"{ServicePollingCollector.__module__}.time.time", self.dut.time
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    async def _poll(self, ssh_latency: float = FAST_SSH_S) -> t.Optional[float]:
        self.dut.latencies.append(ssh_latency)
        await self.collector._poll_once()
        self.dut.now += INTERVAL_S  # _run_loop's asyncio.sleep(interval_sec)
        return self.collector.rows[-1].per_service["agent"]

    async def _pct(self, ssh_latency: float = FAST_SSH_S) -> float:
        value = await self._poll(ssh_latency)
        assert value is not None, "expected a CPU% sample, got a baseline reset"
        return value

    async def test_fast_polls_report_the_true_rate(self) -> None:
        self.assertIsNone(await self._poll())  # the first poll only sets the baseline
        for _ in range(3):
            self.assertAlmostEqual(await self._pct(), TRUE_PCT, places=6)

    async def test_a_slow_poll_is_dropped_not_inflated(self) -> None:
        # Stamped before the round trip, a single slow poll can read as roughly
        # ten times the true rate.
        await self._poll()
        await self._poll()
        self.assertIsNone(await self._poll(ssh_latency=43.0))
        self.assertIn("slow-ssh=43.0s", self.collector.rows[-1].notes)
        # The baseline is re-established by the slow poll, so the next one is right.
        self.assertAlmostEqual(await self._pct(), TRUE_PCT, places=6)

    async def test_no_slow_poll_ever_reads_above_the_true_rate(self) -> None:
        await self._poll()
        for latency in (1.0, 5.0, 8.0, 12.0, 20.0, 33.0, 60.0, 110.0):
            with self.subTest(ssh_latency=latency):
                value = await self._poll(ssh_latency=latency)
                if value is not None:
                    self.assertAlmostEqual(value, TRUE_PCT, places=6)

    async def test_a_moderately_slow_poll_is_divided_by_the_right_span(self) -> None:
        # 8 s keeps the gap under 3 x interval, so the sample is kept -- and is correct.
        await self._poll()
        await self._poll()
        self.assertAlmostEqual(await self._pct(ssh_latency=8.0), TRUE_PCT, places=6)
        self.assertIn("slow-ssh=8.0s", self.collector.rows[-1].notes)

    async def test_fast_polls_carry_no_slow_ssh_note(self) -> None:
        await self._poll()
        await self._poll()
        self.assertNotIn("slow-ssh", self.collector.rows[-1].notes)


if __name__ == "__main__":
    unittest.main()
