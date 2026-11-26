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
    async def _run(self, step, oss, meta_internal=False, params=None):
        ods = AsyncMock(return_value=4 * _GIB)
        with (
            patch.object(module, "async_get_memory_current_pct", ods),
            patch.object(module, "run_in_thread", MagicMock()) as run_in_thread,
            patch.object(module, "TAAC_OSS", oss),
            patch.object(module, "TAAC_OSS_META_INTERNAL", meta_internal),
        ):
            await step.run(MagicMock(), params or _PARAMS)
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

    async def test_pure_oss_pushes_the_allocator_over_any_existing_copy(self) -> None:
        # The mock says the file exists, but the step still writes it.
        step = _step("0")
        await self._run(step, oss=True)

        step.driver.async_write_file_on_device.assert_awaited_once()
        script_source, remote_path = (
            step.driver.async_write_file_on_device.await_args.args
        )
        self.assertEqual(remote_path, module.OSS_MEMORY_PRESSURE_PATH)
        self.assertIn("child_cgroup_path", script_source)
        step.driver.async_check_if_file_exists.assert_not_awaited()

    async def test_pure_oss_ignores_an_executable_path_from_the_caller(self) -> None:
        step = _step("0")
        params = dict(_PARAMS, executable_path="/opt/memory_pressure")
        run_in_thread, _ods = await self._run(step, oss=True, params=params)

        _source, remote_path = step.driver.async_write_file_on_device.await_args.args
        self.assertEqual(remote_path, module.OSS_MEMORY_PRESSURE_PATH)
        self.assertNotIn("/opt/memory_pressure", run_in_thread.call_args.kwargs["cmd"])

    async def test_pure_oss_runs_the_allocator_with_python3_and_keeps_its_output(
        self,
    ) -> None:
        step = _step("0")
        run_in_thread, _ods = await self._run(step, oss=True)

        cmd = run_in_thread.call_args.kwargs["cmd"]
        self.assertTrue(cmd.startswith(f"python3 {module.OSS_MEMORY_PRESSURE_PATH} "))
        self.assertIn(f"> {module.OSS_MEMORY_PRESSURE_LOG} 2>&1", cmd)
        self.assertNotIn(">>", cmd)

    async def test_meta_internal_keeps_the_meta_binary(self) -> None:
        step = _step("0")
        params = dict(_PARAMS, executable_path="/opt/custom_pressure")
        run_in_thread, ods = await self._run(
            step, oss=True, meta_internal=True, params=params
        )

        step.driver.async_write_file_on_device.assert_not_awaited()
        step.driver.async_check_if_file_exists.assert_awaited_once_with(
            "/opt/custom_pressure"
        )
        ods.assert_not_awaited()
        cmd = run_in_thread.call_args.kwargs["cmd"]
        self.assertTrue(cmd.startswith("/opt/custom_pressure -c system.slice "))
        self.assertNotIn(module.OSS_MEMORY_PRESSURE_LOG, cmd)

    async def test_meta_internal_raises_when_the_meta_binary_is_missing(self) -> None:
        step = _step("0")
        step.driver.async_check_if_file_exists.return_value = False
        with self.assertRaises(Exception):
            await self._run(step, oss=True, meta_internal=True)

        step.driver.async_write_file_on_device.assert_not_awaited()

    async def test_without_oss_the_step_does_not_push_or_redirect(self) -> None:
        step = _step("")
        run_in_thread, _ods = await self._run(step, oss=False)

        step.driver.async_write_file_on_device.assert_not_awaited()
        cmd = run_in_thread.call_args.kwargs["cmd"]
        self.assertTrue(cmd.startswith("/opt/memory_pressure "))
        self.assertNotIn(module.OSS_MEMORY_PRESSURE_LOG, cmd)


if __name__ == "__main__":
    unittest.main()
