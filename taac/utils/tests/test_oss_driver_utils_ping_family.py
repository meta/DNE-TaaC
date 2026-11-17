# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

import unittest
from unittest.mock import MagicMock, patch


class PingFamilyTest(unittest.TestCase):
    """A management network without IPv6 makes ``ping -6`` fail at once."""

    def _cmd(self, getaddrinfo):
        from taac.utils import oss_driver_utils

        with patch.object(oss_driver_utils.socket, "getaddrinfo", getaddrinfo), patch.object(
            oss_driver_utils.subprocess, "run", return_value=MagicMock(returncode=0)
        ) as run:
            oss_driver_utils.is_host_ping_reachable("dut.example.com", use_ipv6=True)
        return run.call_args.args[0]

    def test_host_without_an_ipv6_address_is_pinged_over_ipv4(self):
        import socket

        self.assertNotIn("-6", self._cmd(MagicMock(side_effect=socket.gaierror)))

    def test_ipv4_fallback_is_logged_once_per_host(self):
        import socket

        from taac.utils import oss_driver_utils

        oss_driver_utils._IPV4_FALLBACK_LOGGED.discard("dut.example.com")
        log = MagicMock()
        with patch.object(
            oss_driver_utils.socket, "getaddrinfo", side_effect=socket.gaierror
        ), patch.object(
            oss_driver_utils.subprocess, "run", return_value=MagicMock(returncode=0)
        ):
            for _ in range(3):
                oss_driver_utils.is_host_ping_reachable("dut.example.com", ping_logger=log)
        self.assertEqual(log.info.call_count, 1)

    def test_host_with_an_ipv6_address_keeps_ipv6(self):
        self.assertIn("-6", self._cmd(MagicMock(return_value=[("addr",)])))


if __name__ == "__main__":
    unittest.main()
