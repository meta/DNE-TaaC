# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Flap commands run with a bounded SSH connection setup.

A connection that never comes up would otherwise hold the flap until its burst
deadline; with ``connect_timeout`` it raises before the command starts, which
the flap task retries.
"""

import importlib
import logging
import os
import unittest
from unittest import mock

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

FBOSS_SWITCH_MODULE = (
    "taac.driver.fboss_switch"
    if TAAC_OSS
    else "neteng.test_infra.dne.taac.driver.fboss_switch"
)

fboss_switch = importlib.import_module(FBOSS_SWITCH_MODULE)
FbossSwitch = fboss_switch.FbossSwitch

PORTS = ("eth1/5/1", "eth1/5/5")


class FlapConnectTimeoutTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.switch = FbossSwitch("dut.example.com", logging.getLogger(__name__))
        self.shell = mock.AsyncMock(return_value="")
        self.switch.async_run_cmd_on_shell = self.shell

    async def test_every_flap_command_bounds_the_connection_setup(self):
        # Symmetric mode adds a final tx_enable after its cycles.
        for mode, extra, calls in (
            ("loop", {}, 2),
            ("symmetric", {"up_time_sec": 0}, 3),
        ):
            with self.subTest(mode=mode):
                self.shell.reset_mock()
                await self.switch.async_do_rapid_interface_flaps(
                    PORTS, interval_to_link_up=0, total_flaps=2, **extra
                )

                self.assertEqual(self.shell.await_count, calls)
                for call in self.shell.await_args_list:
                    self.assertEqual(
                        call.kwargs["connect_timeout"],
                        FbossSwitch._FLAP_SSH_CONNECT_TIMEOUT_S,
                    )
                if mode == "symmetric":
                    self.assertTrue(
                        self.shell.await_args_list[-1].args[0].endswith(
                            " -tx_enable eth1/5/1 eth1/5/5"
                        )
                    )


if __name__ == "__main__":
    unittest.main()
