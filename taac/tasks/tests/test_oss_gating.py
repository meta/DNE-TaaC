# pyre-unsafe
"""Tasks that behave differently under TAAC_OSS=1."""

import base64
import importlib
import inspect
import os
import typing as t
import unittest
from unittest.mock import AsyncMock, create_autospec, MagicMock, patch

from taac.driver.fboss_switch import FbossSwitch
from taac.tasks.all import (
    AllocateCgroupSliceMemory,
    AssertThriftRateLimitEnabledTask,
    CoopApplyPatchersTask,
    CoopApplyPatchersV2,
)
from taac.test_as_a_config import types as taac_types

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

_PACKAGE = "taac" if TAAC_OSS else "neteng.test_infra.dne.taac"
all_tasks = importlib.import_module(f"{_PACKAGE}.tasks.all")


class OssGatingTest(unittest.IsolatedAsyncioTestCase):
    async def test_allocate_cgroup_slice_memory_is_a_no_op_under_oss(self) -> None:
        logger = MagicMock()
        task = AllocateCgroupSliceMemory(hostname="dut1", logger=logger)
        with (
            patch.object(all_tasks, "TAAC_OSS", True),
            patch.object(
                all_tasks, "async_get_device_driver", new_callable=AsyncMock
            ) as get_driver,
        ):
            await task.run({"hostname": "dut1", "slice_name": "workload"})
        get_driver.assert_not_awaited()
        logger.warning.assert_called_once()

    def test_thrift_rate_limit_probe_reads_the_oss_agent_config(self) -> None:
        for oss, expected in (
            (True, "/etc/coop/agent.conf"),
            (False, "/etc/coop/agent/current"),
        ):
            with patch.object(all_tasks, "TAAC_OSS", oss):
                self.assertEqual(
                    AssertThriftRateLimitEnabledTask.agent_config_path(), expected
                )
                b64 = AssertThriftRateLimitEnabledTask._build_probe_cmd().split()[1]
                self.assertIn(expected, base64.b64decode(b64).decode())

    async def _run_oss_apply(
        self, params: dict, apply_error: t.Optional[Exception] = None
    ) -> tuple:
        """Run CoopApplyPatchersTask on the OSS patcher with a mocked driver.

        Autospecced against the real driver so a method the task calls cannot
        quietly disappear from FbossSwitch and leave these tests green.
        """
        task = CoopApplyPatchersTask(logger=MagicMock())
        driver = create_autospec(FbossSwitch, instance=True)
        if apply_error is not None:
            driver.async_apply_patchers.side_effect = apply_error
        with (
            patch.object(all_tasks, "TAAC_OSS", True),
            patch.object(all_tasks, "oss_config_patcher_enabled", return_value=True),
            patch.object(
                all_tasks, "async_get_device_driver", new_callable=AsyncMock
            ) as get_driver,
        ):
            get_driver.return_value = driver
            if apply_error is not None:
                with self.assertRaises(type(apply_error)):
                    await task.run(params)
            else:
                await task.run(params)
        return driver, get_driver

    @staticmethod
    def _call_names(driver: AsyncMock) -> list:
        return [c[0] for c in driver.mock_calls if c[0]]

    async def test_coop_apply_patchers_warmboot_under_oss(self) -> None:
        driver, get_driver = await self._run_oss_apply(
            {"hostnames": ["dut1"], "do_warmboot": True}
        )

        get_driver.assert_awaited_once_with("dut1")
        driver.async_apply_patchers.assert_awaited_once_with(
            taac_types.ApplyPatcherMethod.AGENT_WARMBOOT, coldboot=False
        )
        driver.async_remove_cold_boot_file.assert_not_awaited()

    async def test_coop_apply_patchers_coldboot_clears_the_flag_after(self) -> None:
        driver, _ = await self._run_oss_apply(
            {"hostnames": ["dut1"], "do_coldboot": True}
        )

        driver.async_apply_patchers.assert_awaited_once_with(None, coldboot=True)
        names = self._call_names(driver)
        self.assertLess(
            names.index("async_apply_patchers"),
            names.index("async_remove_cold_boot_file"),
        )

    async def test_coop_apply_patchers_no_boot_flags_under_oss(self) -> None:
        driver, _ = await self._run_oss_apply({"hostnames": ["dut1"]})

        driver.async_apply_patchers.assert_awaited_once_with(None, coldboot=False)
        driver.async_remove_cold_boot_file.assert_not_awaited()

    async def test_coop_apply_patchers_covers_every_hostname_under_oss(self) -> None:
        driver, get_driver = await self._run_oss_apply(
            {"hostnames": ["dut1", "dut2"], "do_coldboot": True}
        )

        self.assertEqual(
            [c.args[0] for c in get_driver.await_args_list], ["dut1", "dut2"]
        )
        self.assertEqual(driver.async_apply_patchers.await_count, 2)
        self.assertEqual(driver.async_remove_cold_boot_file.await_count, 2)

    async def test_coop_apply_patchers_clears_the_cold_boot_flag_on_failure(
        self,
    ) -> None:
        """A flag left behind silently cold boots the next warm boot: the
        agents do not delete it and /dev/shm outlives every restart."""
        driver, _ = await self._run_oss_apply(
            {"hostnames": ["dut1"], "do_coldboot": True},
            apply_error=RuntimeError("activate failed"),
        )

        driver.async_remove_cold_boot_file.assert_awaited_once()

    def test_apply_patchers_signature_matches_what_the_tasks_pass(self) -> None:
        """A name the task passes has to be one the driver reads."""
        sig = inspect.signature(FbossSwitch.async_apply_patchers)
        self.assertIsNone(sig.parameters["apply_patcher_method"].default)
        self.assertIs(sig.parameters["coldboot"].default, False)

    async def test_coop_apply_patchers_v2_forwards_the_requested_method(
        self,
    ) -> None:
        """The driver acts on ``apply_patcher_method``, so what
        this task forwards decides the boot type of every
        ``coop_apply_patchers_v2`` task. Params carry the raw int; the driver
        must receive the member it names."""
        for method in taac_types.ApplyPatcherMethod:
            with self.subTest(method=method.name):
                driver = create_autospec(FbossSwitch, instance=True)
                with patch.object(
                    all_tasks, "async_get_device_driver", new_callable=AsyncMock
                ) as get_driver:
                    get_driver.return_value = driver
                    await CoopApplyPatchersV2(logger=MagicMock()).run(
                        {
                            "hostnames": ["dut.example.com"],
                            "apply_patcher_method": method.value,
                        }
                    )
                driver.async_apply_patchers.assert_awaited_once_with(
                    apply_patcher_method=method
                )
