# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

import subprocess
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock

from taac.driver.driver_constants import wedge_qsfp_util_cmd
from taac.steps.step_definitions import FLAP_PAUSE_REMEDIATION_S, InterfaceFlapStep


def _expand(cmd: str) -> str:
    """What the DUT shell runs: expand the command without executing wedge_qsfp_util."""
    return subprocess.run(
        ["bash", "-c", f"echo {cmd}"], capture_output=True, text=True, check=True
    ).stdout.strip()


class WedgeQsfpUtilDescriptorTest(unittest.IsolatedAsyncioTestCase):
    def test_root_present_adds_the_flag(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(
                _expand(f"{wedge_qsfp_util_cmd(root)} --set_low_power eth1/1/1"),
                f"wedge_qsfp_util --platform_descriptor_config_path {root} --set_low_power eth1/1/1",
            )

    def test_root_missing_keeps_the_plain_command(self) -> None:
        self.assertEqual(
            _expand(
                f"{wedge_qsfp_util_cmd('/nonexistent/descriptors')} --set_low_power eth1/1/1"
            ),
            "wedge_qsfp_util --set_low_power eth1/1/1",
        )

    async def test_flap_step_uses_it_batched_and_sequential(self) -> None:
        for sequential, expected in ((False, 1), (True, 2)):
            step = InterfaceFlapStep.__new__(InterfaceFlapStep)
            step.driver = AsyncMock()
            step.logger = MagicMock()
            await step.flap_with_shell_cmd(
                ["eth1/1/1", "eth1/2/1"], "--set_low_power", sequential
            )
            cmds = [
                c.args[0] for c in step.driver.async_run_cmd_on_shell.await_args_list
            ]
            self.assertEqual(len(cmds), expected)
            self.assertTrue(
                all(c.startswith(wedge_qsfp_util_cmd()) for c in cmds), cmds
            )

    async def test_down_flaps_pause_remediation_and_up_flaps_resume_it(self) -> None:
        ports = ["eth1/1/1", "eth1/2/1"]
        pause = "async_wedge_qsfp_util_pause_remediation"
        cases = (
            (
                "--set_low_power",
                [pause, "async_run_cmd_on_shell"],
                FLAP_PAUSE_REMEDIATION_S,
            ),
            (
                "--tx_disable",
                [pause, "async_run_cmd_on_shell"],
                FLAP_PAUSE_REMEDIATION_S,
            ),
            ("--clear_low_power", ["async_run_cmd_on_shell", pause], 0),
            ("--tx_enable", ["async_run_cmd_on_shell", pause], 0),
            ("--qsfp-reset", ["async_run_cmd_on_shell"], None),
        )
        for subcmd, order, duration in cases:
            step = InterfaceFlapStep.__new__(InterfaceFlapStep)
            step.driver = AsyncMock()
            step.logger = MagicMock()
            await step.flap_with_shell_cmd(ports, subcmd, False)
            self.assertEqual([c[0] for c in step.driver.method_calls], order, subcmd)
            if duration is not None:
                step.driver.async_wedge_qsfp_util_pause_remediation.assert_awaited_once_with(
                    duration, ports=ports
                )

    async def test_failed_down_flap_resumes_and_reraises(self) -> None:
        for failing in ("pause", "shell"):
            calls = []

            async def pause(duration, ports=()):
                calls.append(("pause", duration))
                if failing == "pause" and len(calls) == 1:
                    raise RuntimeError("boom")

            async def shell(cmd, *args, **kwargs):
                calls.append(("shell", None))
                if failing == "shell":
                    raise RuntimeError("boom")

            step = InterfaceFlapStep.__new__(InterfaceFlapStep)
            step.driver = MagicMock(
                async_wedge_qsfp_util_pause_remediation=pause,
                async_run_cmd_on_shell=shell,
            )
            step.logger = MagicMock()
            with self.assertRaisesRegex(RuntimeError, "boom"):
                await step.flap_with_shell_cmd(["eth1/1/1"], "--set_low_power", False)
            self.assertEqual(calls[0], ("pause", FLAP_PAUSE_REMEDIATION_S), failing)
            self.assertEqual(calls[-1], ("pause", 0), failing)

    async def test_unconfirmed_resume_after_an_up_flap_warns_instead_of_failing(
        self,
    ) -> None:
        # The ports are already up; a pause left behind expires within FLAP_PAUSE_REMEDIATION_S.
        step = InterfaceFlapStep.__new__(InterfaceFlapStep)
        step.driver = AsyncMock()
        step.driver.async_wedge_qsfp_util_pause_remediation.side_effect = RuntimeError(
            "not confirmed"
        )
        step.logger = MagicMock()
        await step.flap_with_shell_cmd(["eth1/1/1"], "--clear_low_power", False)
        step.logger.warning.assert_called_once()

    async def test_failed_up_flap_still_resumes_and_reraises(self) -> None:
        calls = []

        async def pause(duration, ports=()):
            calls.append(("pause", duration))

        async def shell(cmd, *args, **kwargs):
            calls.append(("shell", None))
            raise RuntimeError("boom")

        step = InterfaceFlapStep.__new__(InterfaceFlapStep)
        step.driver = MagicMock(
            async_wedge_qsfp_util_pause_remediation=pause, async_run_cmd_on_shell=shell
        )
        step.logger = MagicMock()
        with self.assertRaisesRegex(RuntimeError, "boom"):
            await step.flap_with_shell_cmd(["eth1/1/1"], "--tx_enable", False)
        self.assertEqual(calls, [("shell", None), ("pause", 0)])


if __name__ == "__main__":
    unittest.main()
