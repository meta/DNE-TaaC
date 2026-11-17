# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

import unittest
from unittest.mock import AsyncMock, MagicMock

from taac.driver.fboss_switch import FbossSwitch


class PauseRemediationDriverTest(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _switch(stdout: str) -> FbossSwitch:
        sw = FbossSwitch.__new__(FbossSwitch)
        sw.hostname = "dut1"
        sw.logger = MagicMock()
        sw.async_run_cmd_on_shell = AsyncMock(return_value=stdout)
        return sw

    async def test_every_port_confirmed_passes(self) -> None:
        sw = self._switch(
            "PauseRemediation set for port eth1/1/1\nPauseRemediation set for port eth1/2/1\n"
        )
        await sw.async_wedge_qsfp_util_pause_remediation(
            60, ports=["eth1/1/1", "eth1/2/1"]
        )
        self.assertIn(
            "eth1/1/1 eth1/2/1 --pause_remediation 60",
            sw.async_run_cmd_on_shell.await_args.args[0],
        )

    async def test_unconfirmed_port_raises(self) -> None:
        sw = self._switch("PauseRemediation set for port eth1/1/1\n")
        with self.assertRaisesRegex(RuntimeError, "eth1/2/1"):
            await sw.async_wedge_qsfp_util_pause_remediation(
                60, ports=["eth1/1/1", "eth1/2/1"]
            )

    async def test_global_pause_is_not_checked(self) -> None:
        await self._switch("").async_wedge_qsfp_util_pause_remediation(60)

    async def test_resume_sends_one_second_since_zero_is_a_no_op_flag(self) -> None:
        sw = self._switch("PauseRemediation set for port eth1/1/1\n")
        await sw.async_wedge_qsfp_util_pause_remediation(0, ports=["eth1/1/1"])
        self.assertTrue(
            sw.async_run_cmd_on_shell.await_args.args[0].endswith(
                "eth1/1/1 --pause_remediation 1"
            )
        )

    async def test_a_line_for_another_port_does_not_confirm(self) -> None:
        sw = self._switch("PauseRemediation set for port eth1/1/10\n")
        with self.assertRaisesRegex(RuntimeError, "eth1/1/1'"):
            await sw.async_wedge_qsfp_util_pause_remediation(60, ports=["eth1/1/1"])



if __name__ == "__main__":
    unittest.main()
