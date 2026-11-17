# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Under OSS neither /opt/memory_pressure nor the ODS memory query exists on
the DUT; the step must push the stand-in script and read memory.current off
the DUT instead of hard-raising. Meta's existing behaviour (raise if the
binary is missing, query ODS) must be unaffected."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.steps import step_definitions as module
from taac.steps.step_definitions import AllocateCgroupSliceMemory


def _step() -> AllocateCgroupSliceMemory:
    step = object.__new__(AllocateCgroupSliceMemory)
    step.hostname = "dut.example.com"
    step.driver = AsyncMock()
    step.driver.logger = MagicMock()
    step.driver.async_get_memory_total.return_value = 64 * 1024**3
    step.driver.async_run_cmd_on_shell.return_value = "0\n"
    step.logger = MagicMock()
    return step


_PARAMS = {
    "total_memory_pct_decimal": 0.25,
    "slice_name": "system",
    "duration": 180,
    "minimum_memory_allocation": 10480,
    "oom_score_adj": 1000,
}


class AllocateCgroupSliceMemoryOssTest(unittest.IsolatedAsyncioTestCase):
    async def _run(self, step, oss, params=None):
        ods = AsyncMock(return_value=0)
        with patch.object(module, "async_get_memory_current_pct", ods), patch.object(
            module, "run_in_thread", MagicMock()
        ) as run_in_thread, patch.object(module, "TAAC_OSS", oss):
            await step.run(MagicMock(), params or _PARAMS)
        return run_in_thread, ods

    async def test_oss_pushes_the_stand_in_over_any_existing_copy(self) -> None:
        """Pushed unconditionally (the file-exists mock says it is already
        there): a DUT that ran an older stand-in would otherwise keep it
        forever, and a stale allocator fails as a wrong stress profile
        rather than as an error."""
        step = _step()
        step.driver.async_check_if_file_exists.return_value = True
        await self._run(step, oss=True)

        step.driver.async_write_file_on_device.assert_awaited_once()
        script_source, remote_path = (
            step.driver.async_write_file_on_device.await_args.args
        )
        self.assertEqual(remote_path, module.OSS_MEMORY_PRESSURE_PATH)
        self.assertIn("child_cgroup_path", script_source)

    async def test_oss_never_writes_to_metas_binary_path(self) -> None:
        """TAAC_OSS is a framework mode, not a DUT type; never overwrite
        /opt/memory_pressure."""
        step = _step()
        step.driver.async_check_if_file_exists.return_value = True
        run_in_thread, _ods = await self._run(step, oss=True)

        _source, remote_path = step.driver.async_write_file_on_device.await_args.args
        self.assertNotEqual(remote_path, "/opt/memory_pressure")
        self.assertNotIn(
            "/opt/memory_pressure", run_in_thread.call_args.kwargs["cmd"]
        )

    async def test_an_explicit_executable_path_is_ignored_under_oss(self) -> None:
        """TAAC_OSS is a framework mode, not a DUT type; never overwrite
        /opt/memory_pressure. An explicit executable_path must not win: the
        healthcheck's marker/log paths are fixed to OSS_MEMORY_PRESSURE_PATH."""
        step = _step()
        step.driver.async_check_if_file_exists.return_value = True
        params = dict(_PARAMS, executable_path="/opt/memory_pressure")
        await self._run(step, oss=True, params=params)

        _source, remote_path = step.driver.async_write_file_on_device.await_args.args
        self.assertEqual(remote_path, module.OSS_MEMORY_PRESSURE_PATH)

    async def test_oss_reads_memory_current_off_the_dut_not_ods(self) -> None:
        """async_get_memory_current_pct is a Meta-only ODS query that raises
        NotImplementedError under OSS."""
        step = _step()
        step.driver.async_check_if_file_exists.return_value = True
        _run_in_thread, ods = await self._run(step, oss=True)

        ods.assert_not_awaited()
        step.driver.async_run_cmd_on_shell.assert_any_await(
            "cat /sys/fs/cgroup/system.slice/memory.current"
        )

    async def test_oss_keeps_the_stand_ins_output_on_the_dut(self) -> None:
        step = _step()
        step.driver.async_check_if_file_exists.return_value = True
        run_in_thread, _ods = await self._run(step, oss=True)

        cmd = run_in_thread.call_args.kwargs["cmd"]
        # ">" not ">>": the log is about this invocation, not every past one.
        self.assertIn(f"> {module.OSS_MEMORY_PRESSURE_LOG} 2>&1", cmd)
        self.assertNotIn(">>", cmd)
        # /tmp is noexec on hardened images, so go through the interpreter.
        self.assertTrue(cmd.startswith(f"python3 {module.OSS_MEMORY_PRESSURE_PATH} "))

    async def test_the_oss_log_is_truncated_at_push_not_only_at_launch(
        self,
    ) -> None:
        """A device whose memory_to_allocate works out to <=0 takes the
        early return before ever launching the allocator, but the script
        push already stamped a fresh marker (its mtime). Without truncating
        the log at push time too, a stale log from a previous run would be
        misread as this run's evidence of a launch that never happened."""
        step = _step()
        step.driver.async_check_if_file_exists.return_value = True
        step.driver.async_run_cmd_on_shell.return_value = f"{64 * 1024**3}"
        params = dict(_PARAMS, minimum_memory_allocation=0)
        run_in_thread, _ods = await self._run(step, oss=True, params=params)

        run_in_thread.assert_not_called()
        step.driver.async_run_cmd_on_shell.assert_any_await(
            f": > {module.OSS_MEMORY_PRESSURE_LOG}"
        )

    async def test_unreadable_memory_current_raises(self) -> None:
        """On a cgroup-v1/hybrid DUT this unified path does not exist. The
        allocation size is derived from this number, so a quiet 0 would
        silently allocate the full target instead of target-minus-current."""
        step = _step()
        step.driver.async_check_if_file_exists.return_value = True
        step.driver.async_run_cmd_on_shell.return_value = "cat: No such file"
        with self.assertRaises(Exception) as caught:
            await self._run(step, oss=True)
        self.assertIn("cgroup v2", str(caught.exception))

    async def test_meta_still_raises_when_the_binary_is_missing(self) -> None:
        step = _step()
        step.driver.async_check_if_file_exists.return_value = False
        with self.assertRaises(Exception):
            await self._run(step, oss=False)

        step.driver.async_write_file_on_device.assert_not_awaited()

    async def test_meta_path_unaffected_when_binary_is_present(self) -> None:
        step = _step()
        step.driver.async_check_if_file_exists.return_value = True
        run_in_thread, ods = await self._run(step, oss=False)

        step.driver.async_write_file_on_device.assert_not_awaited()
        ods.assert_awaited_once()
        run_in_thread.assert_called_once()
        # No OSS log redirection on the Meta command line.
        self.assertNotIn(
            module.OSS_MEMORY_PRESSURE_LOG, run_in_thread.call_args.kwargs["cmd"]
        )


if __name__ == "__main__":
    unittest.main()
