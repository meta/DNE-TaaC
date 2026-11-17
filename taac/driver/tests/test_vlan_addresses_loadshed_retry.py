# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
import ipaddress
import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from taac.driver.fboss_switch import FbossSwitch
from thrift.python.exceptions import ApplicationError, ApplicationErrorType

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

_PACKAGE = "taac" if TAAC_OSS else "neteng.test_infra.dne.taac"


def _intf(vlan_id: int, cidr: str) -> SimpleNamespace:
    net = ipaddress.ip_interface(cidr)
    addr = SimpleNamespace(ip=SimpleNamespace(addr=net.ip.packed), prefixLength=net.network.prefixlen)
    return SimpleNamespace(vlanId=vlan_id, address=[addr])


class VlanAddressesLoadshedRetryTest(unittest.IsolatedAsyncioTestCase):
    def _switch(self, side_effect) -> FbossSwitch:
        sw = FbossSwitch.__new__(FbossSwitch)
        sw.async_get_all_interfaces = AsyncMock(side_effect=side_effect)
        return sw

    async def test_loadshedding_is_retried(self) -> None:
        shed = ApplicationError(ApplicationErrorType.LOADSHEDDING, "ThriftMethoRateLimit")
        sw = self._switch([shed, shed, {1: _intf(2100, "2001:db8::1/64")}])
        with patch(f"{_PACKAGE}.driver.fboss_switch.asyncio.sleep", new=AsyncMock()):
            self.assertEqual(["2001:db8::1/64"], await sw.async_get_vlan_addresses(2100))
        self.assertEqual(3, sw.async_get_all_interfaces.await_count)

    async def test_other_application_errors_raise(self) -> None:
        err = ApplicationError(ApplicationErrorType.UNKNOWN, "boom")
        sw = self._switch([err])
        with self.assertRaises(ApplicationError):
            await sw.async_get_vlan_addresses(2100)
        self.assertEqual(1, sw.async_get_all_interfaces.await_count)
