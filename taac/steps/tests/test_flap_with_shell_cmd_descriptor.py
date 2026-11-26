# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
import subprocess
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock

from taac.driver.driver_constants import wedge_qsfp_util_cmd
from taac.steps.step_definitions import InterfaceFlapStep


def _expand(cmd: str) -> str:
    return subprocess.run(
        ["bash", "-c", f"echo {cmd}"], capture_output=True, text=True, check=True
    ).stdout.strip()


class WedgeQsfpUtilDescriptorTest(unittest.IsolatedAsyncioTestCase):
    def test_root_present_adds_the_flag(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(
                _expand(f"{wedge_qsfp_util_cmd(root)} --set_low_power eth1/1/1"),
                "wedge_qsfp_util --platform_descriptor_config_path "
                f"{root} --set_low_power eth1/1/1",
            )

    def test_root_missing_keeps_the_plain_command(self) -> None:
        cmd = wedge_qsfp_util_cmd("/nonexistent/descriptors")
        self.assertEqual(
            _expand(f"{cmd} --set_low_power eth1/1/1"),
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


if __name__ == "__main__":
    unittest.main()
