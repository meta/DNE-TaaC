# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
import typing as t
import unittest
from unittest.mock import AsyncMock, MagicMock

from taac.libs.collectors.memory_utilization_collector import (
    MemoryUtilizationCollector,
)


def _make_driver(
    mem_by_service: t.Dict[str, t.Any],
    anon_by_service: t.Optional[t.Dict[str, t.Any]] = None,
) -> MagicMock:
    """Fake the batched SSH call: ``systemctl show`` blocks for every unit,
    then one ``Id=/MemoryAnon=`` block per unit as the collector's appended
    loop prints. ``anon_by_service=None`` means the loop printed nothing."""
    driver = MagicMock()

    async def _run(cmd: str) -> str:
        units = cmd.split("systemctl show ", 1)[1].split(" -p ")[0].split()
        blocks = []
        for unit in units:
            if unit in mem_by_service:
                blocks.append(
                    f"Id={unit}.service\nLoadState=loaded\nActiveState=active\n"
                    f"MemoryCurrent={mem_by_service[unit]}"
                )
            else:
                blocks.append(
                    f"Id={unit}.service\nLoadState=not-found\n"
                    f"ActiveState=inactive\nMemoryCurrent="
                )
        if anon_by_service is not None:
            for unit in units:
                blocks.append(
                    f"Id={unit}.service\nMemoryAnon={anon_by_service.get(unit, '')}"
                )
        return "\n\n".join(blocks)

    driver.async_run_cmd_on_shell = AsyncMock(side_effect=_run)
    driver.async_get_systemctl_service_name = AsyncMock(
        side_effect=lambda service: service
    )
    return driver


class TestMemoryUtilizationCollector(unittest.IsolatedAsyncioTestCase):
    async def test_poll_stores_bytes_directly(self) -> None:
        """Memory stores the raw MemoryCurrent value -- no delta."""
        driver = _make_driver({"agent": 100_000_000})
        collector = MemoryUtilizationCollector(
            driver=driver, services=["agent"], host="dut1", tmp_path="/dev/null"
        )
        await collector._poll_once()
        self.assertEqual(len(collector.rows), 1)
        self.assertEqual(collector.rows[0].per_service["agent"], 100_000_000)

    async def test_anon_is_preferred_over_memory_current(self) -> None:
        """MemoryCurrent is the whole cgroup, page cache included; the check
        gates on process memory, so anon wins when both are present."""
        driver = _make_driver(
            {"qsfp_service": 2_000_000_000, "bgpd": 17_000_000},
            anon_by_service={"qsfp_service": 60_000_000, "bgpd": 15_000_000},
        )
        collector = MemoryUtilizationCollector(
            driver=driver,
            services=["qsfp_service", "bgpd"],
            host="dut1",
            tmp_path="/dev/null",
        )
        await collector._poll_once()
        self.assertEqual(
            collector.rows[0].per_service,
            {"qsfp_service": 60_000_000, "bgpd": 15_000_000},
        )

    async def test_missing_anon_falls_back_to_memory_current(self) -> None:
        """A cgroup-v1 DUT has no ``anon`` key; the loop prints an empty
        value and the sample degrades to MemoryCurrent rather than None."""
        driver = _make_driver({"agent": 100_000_000}, anon_by_service={})
        collector = MemoryUtilizationCollector(
            driver=driver, services=["agent"], host="dut1", tmp_path="/dev/null"
        )
        await collector._poll_once()
        self.assertEqual(collector.rows[0].per_service["agent"], 100_000_000)

    async def test_single_ssh_call_per_poll(self) -> None:
        """The anon read rides along in the same batched shell command."""
        driver = _make_driver({"agent": 1}, anon_by_service={"agent": 1})
        collector = MemoryUtilizationCollector(
            driver=driver, services=["agent"], host="dut1", tmp_path="/dev/null"
        )
        await collector._poll_once()
        self.assertEqual(driver.async_run_cmd_on_shell.await_count, 1)
        cmd = driver.async_run_cmd_on_shell.await_args.args[0]
        self.assertIn("memory.stat", cmd)
        self.assertIn("MemoryAnon=", cmd)

    async def test_not_set_memory_current_produces_none(self) -> None:
        """systemd reports '[not set]' for MemoryCurrent when cgroup is missing."""
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            return_value=(
                "Id=agent.service\nLoadState=loaded\nActiveState=active\n"
                "MemoryCurrent=[not set]"
            )
        )
        driver.async_get_systemctl_service_name = AsyncMock(
            side_effect=lambda service: service
        )
        collector = MemoryUtilizationCollector(
            driver=driver, services=["agent"], host="dut1", tmp_path="/dev/null"
        )
        await collector._poll_once()
        self.assertIsNone(collector.rows[0].per_service["agent"])


if __name__ == "__main__":
    unittest.main()
