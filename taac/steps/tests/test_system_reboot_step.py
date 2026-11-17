# Copyright (c) Meta Platforms, Inc. and affiliates.

import time
import unittest
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
from taac.test_as_a_config.thrift_types import Step


class SystemRebootStepDownWaitTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        device = MagicMock(spec=TestDevice)
        device.name = "test_device"
        attributes = MagicMock()
        attributes.operating_system = "FBOSS"
        attributes.role = ""
        attributes.device_name = "test_device"
        attributes.hardware = ""
        attributes.ai_zone = ""
        device.attributes = attributes
        self.step = SystemRebootStep(
            name="test_reboot",
            device=device,
            topology=MagicMock(spec=TestTopology),
            test_case_results=[],
            test_config=MagicMock(),
            test_case_name="test_case",
            test_case_start_time=time.time(),
            parameter_evaluator=MagicMock(spec=ParameterEvaluator),
            step=MagicMock(spec=Step),
        )
        self.step.driver = AsyncMock()

    async def _run(self, reachable, bmc_error=None):
        with patch.object(step_definitions, "TAAC_OSS", True), patch.object(
            step_definitions, "run_bmc_cmd_hwcontrol", side_effect=bmc_error
        ), patch.object(
            step_definitions, "is_host_ping_reachable", reachable, create=True
        ), patch.object(
            step_definitions, "wait_for_ping_reachable", create=True
        ) as up_wait, patch.object(step_definitions.asyncio, "sleep", AsyncMock()):
            await self.step.run(
                taac_types.SystemRebootInput(
                    trigger=taac_types.SystemRebootTrigger.BMC_POWER_RESET
                ),
                {"reboot_down_timeout_s": 0},
            )
        return up_wait

    async def test_device_never_down_raises(self):
        with self.assertRaisesRegex(RuntimeError, "never went down"):
            await self._run(MagicMock(return_value=True))

    async def test_device_down_proceeds_to_up_wait(self):
        up_wait = await self._run(MagicMock(return_value=False))
        up_wait.assert_called_once()
        self.assertIs(up_wait.call_args.kwargs["use_ipv6"], True)

    async def test_one_lost_reply_is_not_down(self):
        """ping -c 5 -w 10 fails on a single dropped reply from a live DUT."""
        with self.assertRaisesRegex(RuntimeError, "never went down"):
            await self._run(MagicMock(side_effect=[False] + [True] * 10))

    async def test_failed_probes_are_spaced_out(self):
        """An instant failure (DNS, no route) must not make 3 probes in a second."""
        sleep = AsyncMock()
        with patch.object(step_definitions.asyncio, "sleep", sleep), patch.object(
            step_definitions, "TAAC_OSS", True
        ), patch.object(step_definitions, "run_bmc_cmd_hwcontrol"), patch.object(
            step_definitions,
            "is_host_ping_reachable",
            MagicMock(return_value=False),
            create=True,
        ), patch.object(step_definitions, "wait_for_ping_reachable", create=True):
            await self.step.run(
                taac_types.SystemRebootInput(
                    trigger=taac_types.SystemRebootTrigger.BMC_POWER_RESET
                ),
                {"reboot_down_timeout_s": 0},
            )
        self.assertEqual(
            [c.args for c in sleep.await_args_list].count((5,)),
            step_definitions._REBOOT_DOWN_CONSECUTIVE_PROBES - 1,
        )

    async def test_never_down_names_the_swallowed_bmc_error(self):
        with self.assertRaisesRegex(RuntimeError, "wedge_power.sh: not found"):
            await self._run(
                MagicMock(return_value=True),
                bmc_error=RuntimeError("wedge_power.sh: not found"),
            )


class SystemRebootStepSyncTest(unittest.IsolatedAsyncioTestCase):
    """The DUT flushes dirty pages before any reset, so a late config write is not lost."""

    setUp = SystemRebootStepDownWaitTest.setUp

    async def _run(self, trigger, operating_system="FBOSS", sync_out="SYNCED\n"):
        self.step.device.attributes.operating_system = operating_system
        self.step.device.attributes.hardware = "WEDGE800BNHP"
        order = MagicMock()
        order.attach_mock(self.step.driver.async_full_system_reboot, "reboot")
        self.step.driver.async_run_cmd_on_shell.return_value = sync_out
        order.attach_mock(self.step.driver.async_run_cmd_on_shell, "sync")
        order.attach_mock(MagicMock(), "bmc")
        with patch.object(step_definitions, "TAAC_OSS", False), patch.object(
            step_definitions, "run_bmc_cmd_hwcontrol", order.bmc
        ), patch.object(
            step_definitions, "wait_for_ping_reachable", create=True
        ), patch.object(
            SystemRebootStep, "_async_read_boot_id", AsyncMock(return_value=None)
        ), patch.object(step_definitions.asyncio, "sleep", AsyncMock()):
            await self.step.run(taac_types.SystemRebootInput(trigger=trigger), {})
        return order

    async def test_syncs_before_every_trigger(self):
        for trigger, issued in (
            (taac_types.SystemRebootTrigger.FULL_SYSTEM_REBOOT, "reboot"),
            (taac_types.SystemRebootTrigger.BMC_POWER_RESET, "bmc"),
            (taac_types.SystemRebootTrigger.BMC_MICROSERVER_ONLY_RESET, "bmc"),
        ):
            with self.subTest(trigger=trigger.name):
                self.setUp()
                order = await self._run(trigger)
                names = [c[0] for c in order.mock_calls]
                self.assertEqual(names.index("sync"), 0)
                self.assertLess(names.index("sync"), names.index(issued))
                self.assertEqual(
                    order.mock_calls[0].args[0], "sync && echo SYNCED"
                )

    async def test_missing_sync_marker_warns_and_still_reboots(self):
        self.step.logger = MagicMock()
        order = await self._run(
            taac_types.SystemRebootTrigger.FULL_SYSTEM_REBOOT, sync_out=""
        )
        self.step.logger.warning.assert_called_once()
        self.assertIn("sync", self.step.logger.warning.call_args.args[0])
        self.assertIn("reboot", [c[0] for c in order.mock_calls])

    async def test_non_fboss_device_issues_no_sync(self):
        order = await self._run(
            taac_types.SystemRebootTrigger.FULL_SYSTEM_REBOOT, operating_system="EOS"
        )
        self.assertNotIn("sync", [c[0] for c in order.mock_calls])


BOOT_A = "11111111-2222-3333-4444-555555555555"
BOOT_B = "66666666-7777-8888-9999-000000000000"


class SystemRebootStepBootIdTest(unittest.IsolatedAsyncioTestCase):
    """A reset counts once the device reports a new boot ID, however long the BMC call blocked."""

    setUp = SystemRebootStepDownWaitTest.setUp

    async def _run_boot(self, boot_ids, reachable, bmc_error=None, timeout_s=900):
        self.step.driver.async_run_cmd_on_shell = AsyncMock(side_effect=boot_ids)
        with patch.object(step_definitions, "TAAC_OSS", True), patch.object(
            step_definitions, "run_bmc_cmd_hwcontrol", side_effect=bmc_error
        ), patch.object(
            step_definitions, "is_host_ping_reachable", reachable, create=True
        ), patch.object(
            step_definitions, "wait_for_ping_reachable", create=True
        ) as up_wait, patch.object(step_definitions.asyncio, "sleep", AsyncMock()):
            await self.step.run(
                taac_types.SystemRebootInput(
                    trigger=taac_types.SystemRebootTrigger.BMC_MICROSERVER_ONLY_RESET
                ),
                {"reboot_boot_id_timeout_s": timeout_s, "reboot_down_timeout_s": 0},
            )
        return up_wait

    async def test_back_up_before_the_bmc_call_returns_passes(self):
        """The BMC call can block until the host has already cycled: no down window is ever seen."""
        up_wait = await self._run_boot(
            ["SYNCED", BOOT_A, BOOT_B],
            MagicMock(return_value=True),
            bmc_error=RuntimeError("rc=1"),
        )
        up_wait.assert_called_once()

    async def test_unchanged_boot_id_raises(self):
        with self.assertRaisesRegex(RuntimeError, "did not reboot.*rc=1"):
            await self._run_boot(
                ["SYNCED"] + [BOOT_A] * 5,
                MagicMock(return_value=True),
                bmc_error=RuntimeError("rc=1"),
                timeout_s=0,
            )

    async def test_waits_through_the_down_window(self):
        reachable = MagicMock(side_effect=[True, False, False, True])
        await self._run_boot(["SYNCED", BOOT_A, BOOT_A, BOOT_B], reachable)
        self.assertEqual(reachable.call_count, 4)

    async def test_unreadable_before_falls_back_to_the_down_watch(self):
        with self.assertRaisesRegex(RuntimeError, "never went down"):
            await self._run_boot(OSError("ssh refused"), MagicMock(return_value=True))


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
        # Only the command mapping and the post-SSH boot-ID check are under
        # test: the netcastle path skips the OSS pre-ping boot-ID / down-window
        # waits, and the pre-reset sync, which have their own cases above.
        oss = patch.object(step_definitions, "TAAC_OSS", False)
        oss.start()
        self.addCleanup(oss.stop)
        sync = patch.object(SystemRebootStep, "_sync_to_disk", new_callable=AsyncMock)
        sync.start()
        self.addCleanup(sync.stop)
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


if __name__ == "__main__":
    unittest.main()
