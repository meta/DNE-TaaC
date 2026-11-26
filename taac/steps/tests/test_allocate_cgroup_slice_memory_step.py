# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.steps import step_definitions as module
from taac.steps.step_definitions import AllocateCgroupSliceMemory

_GIB = 1024**3


def _step(memory_current: str) -> AllocateCgroupSliceMemory:
    step = object.__new__(AllocateCgroupSliceMemory)
    step.hostname = "dut1"
    step.driver = AsyncMock()
    step.driver.logger = MagicMock()
    step.driver.async_get_memory_total.return_value = 64 * _GIB
    step.driver.async_check_if_file_exists.return_value = True
    step.driver.async_run_cmd_on_shell.return_value = memory_current
    step.logger = MagicMock()
    return step


_PARAMS = {
    "total_memory_pct_decimal": 0.25,
    "slice_name": "system",
    "duration": 180,
    "minimum_memory_allocation": 0,
}


class AllocateCgroupSliceMemoryTest(unittest.IsolatedAsyncioTestCase):
    async def _run(self, step, oss):
        ods = AsyncMock(return_value=4 * _GIB)
        with (
            patch.object(module, "async_get_memory_current_pct", ods),
            patch.object(module, "run_in_thread", MagicMock()) as run_in_thread,
            patch.object(module, "TAAC_OSS", oss),
        ):
            await step.run(MagicMock(), _PARAMS)
        return run_in_thread, ods

    async def test_oss_reads_memory_current_from_the_dut_not_ods(self) -> None:
        step = _step(f"{4 * _GIB}\n")
        run_in_thread, ods = await self._run(step, oss=True)

        ods.assert_not_awaited()
        step.driver.async_run_cmd_on_shell.assert_any_await(
            "cat /sys/fs/cgroup/system.slice/memory.current"
        )
        # Target 16 GiB minus current 4 GiB leaves 12 GiB.
        self.assertIn(" -m 12288 ", run_in_thread.call_args.kwargs["cmd"])

    async def test_oss_raises_when_memory_current_is_not_a_number(self) -> None:
        # A cgroup v1 DUT has no such file.
        step = _step("cat: No such file or directory")
        with self.assertRaisesRegex(Exception, "cgroup v2"):
            await self._run(step, oss=True)

    async def test_without_oss_the_step_still_queries_ods(self) -> None:
        step = _step("")
        run_in_thread, ods = await self._run(step, oss=False)

        ods.assert_awaited_once()
        for call in step.driver.async_run_cmd_on_shell.await_args_list:
            self.assertNotIn("memory.current", call.args[0])
        run_in_thread.assert_called_once()


if __name__ == "__main__":
    unittest.main()
