# Copyright (c) Meta Platforms, Inc. and affiliates.

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from later.unittest import TestCase
from taac.constants import (  # oss-rewrite (force ShipIt re-export to taac.* root)
    TestDevice,
    TestTopology,
)
from taac.libs.parameter_evaluator import ParameterEvaluator
from taac.steps import step_definitions
from taac.steps.step_definitions import SystemRebootStep
from taac.test_as_a_config import types as taac_types

_WEDGE_POWER = "/usr/local/bin/wedge_power.sh"
_BOOT_ID_CMD = "cat /proc/sys/kernel/random/boot_id"


class SystemRebootStepBmcCommandTest(TestCase):
    def setUp(self) -> None:
        super().setUp()
        device = MagicMock(spec=TestDevice)
        device.name = "fsw001.p001.f01.snc1"
        device.attributes = MagicMock(
            operating_system="FBOSS",
            role="",
            device_name="fsw001",
            hardware="",
            ai_zone="",
        )
        self.step = SystemRebootStep(
            name="test_system_reboot",
            device=device,
            topology=MagicMock(spec=TestTopology),
            test_case_results=[],
            test_config=MagicMock(spec=taac_types.TestConfig),
            test_case_name="test_case",
            test_case_start_time=time.time(),
            parameter_evaluator=MagicMock(spec=ParameterEvaluator),
            step=MagicMock(spec=taac_types.Step),
        )
        self.driver = AsyncMock()
        self.step.driver = self.driver
        self.driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=["boot-a\n", "boot-b\n"]
        )
        bmc = patch.object(step_definitions, "run_bmc_cmd_hwcontrol")
        self.bmc_mock = bmc.start()
        self.addCleanup(bmc.stop)
        ping = patch.object(step_definitions, "wait_for_ping_reachable")
        ping.start()
        self.addCleanup(ping.stop)
        lab_ssh_enabled = patch.object(
            step_definitions, "lab_ssh_transport_enabled", return_value=False
        )
        self.lab_ssh_enabled = lab_ssh_enabled.start()
        self.addCleanup(lab_ssh_enabled.stop)
        lab_ssh_exec = patch.object(
            step_definitions, "lab_ssh_async_exec", new_callable=AsyncMock
        )
        self.lab_ssh_exec = lab_ssh_exec.start()
        self.addCleanup(lab_ssh_exec.stop)
        sleep = patch.object(step_definitions.asyncio, "sleep", new_callable=AsyncMock)
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)

    async def _run(
        self,
        trigger: taac_types.SystemRebootTrigger,
        params: dict | None = None,
    ) -> None:
        await self.step.run(taac_types.SystemRebootInput(trigger=trigger), params or {})

    def _lab_ssh_result(self, exit_code: int, stdout: str = "") -> SimpleNamespace:
        return SimpleNamespace(
            exit_code=exit_code, stdout=stdout, stderr="", timed_out=False
        )

    async def test_bmc_power_reset_power_cycles_whole_system(self) -> None:
        await self._run(taac_types.SystemRebootTrigger.BMC_POWER_RESET)
        self.bmc_mock.assert_called_once_with(
            "fsw001.p001.f01.snc1", f"{_WEDGE_POWER} reset -s"
        )

    async def test_bmc_microserver_only_reset_resets_microserver(self) -> None:
        await self._run(taac_types.SystemRebootTrigger.BMC_MICROSERVER_ONLY_RESET)
        self.bmc_mock.assert_called_once_with(
            "fsw001.p001.f01.snc1", f"{_WEDGE_POWER} reset"
        )

    async def test_lab_ssh_transport_runs_bmc_reset_on_the_oob_host(self) -> None:
        self.lab_ssh_enabled.return_value = True
        self.lab_ssh_exec.return_value = self._lab_ssh_result(
            0, "Power reset x86 (userver) ... Done\n"
        )

        await self._run(taac_types.SystemRebootTrigger.BMC_MICROSERVER_ONLY_RESET)

        self.lab_ssh_exec.assert_awaited_once_with(
            host="fsw001-oob.p001.f01.snc1",
            command=f"{_WEDGE_POWER} reset",
            timeout_sec=60,
            username="root",
        )
        self.bmc_mock.assert_not_called()

    async def test_lab_ssh_bmc_command_failure_raises(self) -> None:
        self.lab_ssh_enabled.return_value = True
        self.lab_ssh_exec.return_value = self._lab_ssh_result(
            1, "wedge_power.sh: error"
        )

        with self.assertRaisesRegex(RuntimeError, "failed on fsw001-oob"):
            await self._run(taac_types.SystemRebootTrigger.BMC_MICROSERVER_ONLY_RESET)

    async def test_power_cycle_dropping_the_bmc_session_is_not_a_failure(self) -> None:
        self.lab_ssh_enabled.return_value = True
        self.lab_ssh_exec.return_value = self._lab_ssh_result(-1)

        await self._run(taac_types.SystemRebootTrigger.BMC_POWER_RESET)

        self.lab_ssh_exec.assert_awaited_once_with(
            host="fsw001-oob.p001.f01.snc1",
            command=f"{_WEDGE_POWER} reset -s",
            timeout_sec=60,
            username="root",
        )
        self.bmc_mock.assert_not_called()

    async def test_empty_boot_id_baseline_fails_before_reboot(self) -> None:
        for baseline in ("", " \n"):
            with self.subTest(baseline=baseline):
                self.driver.async_run_cmd_on_shell.reset_mock()
                self.driver.async_run_cmd_on_shell.side_effect = [baseline, "boot-a\n"]

                with self.assertRaisesRegex(RuntimeError, "empty boot_id"):
                    await self._run(
                        taac_types.SystemRebootTrigger.BMC_MICROSERVER_ONLY_RESET
                    )

                self.driver.async_run_cmd_on_shell.assert_awaited_once_with(
                    _BOOT_ID_CMD
                )
                self.bmc_mock.assert_not_called()

    async def test_reset_that_never_rebooted_fails(self) -> None:
        """A host that stayed up passes ping and SSH; the boot ID gives it away."""
        self.driver.async_run_cmd_on_shell.side_effect = None
        self.driver.async_run_cmd_on_shell.return_value = "boot-a\n"

        with self.assertRaisesRegex(RuntimeError, "did not reboot"):
            await self._run(
                taac_types.SystemRebootTrigger.BMC_MICROSERVER_ONLY_RESET,
                {"reboot_verify_timeout": 0},
            )

    async def test_boot_id_reads_that_fail_mid_reboot_are_retried(self) -> None:
        self.driver.async_run_cmd_on_shell.side_effect = [
            "boot-a\n",
            ConnectionError("device down"),
            "boot-a\n",
            "boot-b\n",
        ]

        await self._run(taac_types.SystemRebootTrigger.FULL_SYSTEM_REBOOT)

        self.assertEqual(
            [_BOOT_ID_CMD] * 4,
            [
                call.args[0]
                for call in self.driver.async_run_cmd_on_shell.await_args_list
            ],
        )

    async def test_changed_boot_id_is_accepted_after_the_deadline(self) -> None:
        self.driver.async_run_cmd_on_shell = AsyncMock(return_value="boot-b\n")

        await self.step._async_wait_for_new_boot_id(
            "boot-a",
            time.time() - 1000,
            taac_types.SystemRebootTrigger.FULL_SYSTEM_REBOOT,
            900,
        )

        self.driver.async_run_cmd_on_shell.assert_awaited_once_with(_BOOT_ID_CMD)
        self.sleep.assert_not_awaited()
