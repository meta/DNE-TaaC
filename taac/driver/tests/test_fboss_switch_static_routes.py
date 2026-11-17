# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

import ipaddress
import logging
import os
import unittest
from unittest import mock

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

_PACKAGE = "taac" if TAAC_OSS else "neteng.test_infra.dne.taac"

import importlib

fboss_switch = importlib.import_module(f"{_PACKAGE}.driver.fboss_switch")
oss_coop_patcher = importlib.import_module(f"{_PACKAGE}.driver.oss_coop_patcher")
oss_taac_lib_utils = importlib.import_module(f"{_PACKAGE}.utils.oss_taac_lib_utils")
FbossSwitch = fboss_switch.FbossSwitch


class _FakeAgentClient:
    def __init__(self):
        self.added = []
        self.deleted = []

    async def addUnicastRoutes(self, client_id, routes):
        self.added.append((client_id, routes))

    async def deleteUnicastRoutes(self, client_id, prefixes):
        self.deleted.append((client_id, prefixes))

    async def getPlatformMapping(self):
        return "platform-mapping"


class _FakeAgentCtx:
    def __init__(self, client=None):
        self._client = client or _FakeAgentClient()

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, *exc_info):
        return False


class StaticRoutePatcherTest(unittest.IsolatedAsyncioTestCase):
    """OSS static-route patcher: thrift routes in place of a COOP patcher."""

    def setUp(self):
        # The OSS patchers are pure-OSS only; see test_oss_config_patcher_gate.
        for flag, value in (("TAAC_OSS", True), ("TAAC_OSS_META_INTERNAL", False)):
            flag_patcher = mock.patch.object(oss_taac_lib_utils, flag, value)
            flag_patcher.start()
            self.addCleanup(flag_patcher.stop)
        fboss_switch._STATIC_ROUTE_PREFIXES.clear()
        self.addCleanup(fboss_switch._STATIC_ROUTE_PREFIXES.clear)
        self.switch = FbossSwitch("dut1", logging.getLogger(__name__))
        self.client = _FakeAgentClient()
        patcher = mock.patch.object(
            FbossSwitch,
            "async_agent_client",
            property(lambda _self: _FakeAgentCtx(self.client)),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    async def test_add_programs_routes_with_static_route_client_id(self):
        name = await self.switch.async_add_static_route_patcher(
            {"2001:db8:dead::/64": ["2001:db8::1", "2001:db8::2"]},
            "ecmp_nh_stressor_patcher",
            is_patcher_name_uuid_needed=False,
        )
        self.assertEqual(name, "ecmp_nh_stressor_patcher")
        self.assertEqual(len(self.client.added), 1)

        client_id, routes = self.client.added[0]
        self.assertEqual(client_id, int(fboss_switch.ClientID.STATIC_ROUTE))
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].dest.prefixLength, 64)
        self.assertEqual(
            routes[0].dest.ip.addr,
            ipaddress.ip_address("2001:db8:dead::").packed,
        )
        self.assertEqual(
            [nh.addr for nh in routes[0].nextHopAddrs],
            [
                ipaddress.ip_address("2001:db8::1").packed,
                ipaddress.ip_address("2001:db8::2").packed,
            ],
        )

    async def test_v4_prefix_is_packed_as_four_bytes(self):
        await self.switch.async_add_static_route_patcher(
            {"192.0.2.0/24": ["198.51.100.1"]},
            "v4_patcher",
            is_patcher_name_uuid_needed=False,
        )
        _, routes = self.client.added[0]
        self.assertEqual(routes[0].dest.prefixLength, 24)
        self.assertEqual(len(routes[0].dest.ip.addr), 4)

    async def test_unregister_withdraws_exactly_what_was_added(self):
        await self.switch.async_add_static_route_patcher(
            {"2001:db8:1::/64": ["2001:db8::1"]},
            "p1",
            is_patcher_name_uuid_needed=False,
        )
        await self.switch.async_add_static_route_patcher(
            {"2001:db8:2::/64": ["2001:db8::1"]},
            "p2",
            is_patcher_name_uuid_needed=False,
        )
        await self.switch.async_coop_unregister_patchers("p1")

        self.assertEqual(len(self.client.deleted), 1)
        client_id, prefixes = self.client.deleted[0]
        self.assertEqual(client_id, int(fboss_switch.ClientID.STATIC_ROUTE))
        self.assertEqual(
            [p.ip.addr for p in prefixes],
            [ipaddress.ip_address("2001:db8:1::").packed],
        )

        # p2 survives its sibling's withdrawal
        await self.switch.async_coop_unregister_patchers("p2")
        self.assertEqual(
            [p.ip.addr for p in self.client.deleted[1][1]],
            [ipaddress.ip_address("2001:db8:2::").packed],
        )

    async def test_a_patcher_that_added_no_prefix_still_pops_its_key(self):
        """An empty prefix map is still an owned registration. Branching on
        truthiness fell through to the config-patcher scan and left the key in
        the registry forever."""
        await self.switch.async_add_static_route_patcher(
            {}, "empty_patcher", is_patcher_name_uuid_needed=False
        )
        self.assertIn(("dut1", "empty_patcher"), fboss_switch._STATIC_ROUTE_PREFIXES)
        await self.switch.async_coop_unregister_patchers("empty_patcher")
        self.assertEqual(self.client.deleted, [])
        self.assertNotIn(
            ("dut1", "empty_patcher"), fboss_switch._STATIC_ROUTE_PREFIXES
        )

    async def test_failed_withdrawal_remains_available_to_retry(self):
        await self.switch.async_add_static_route_patcher(
            {"2001:db8:1::/64": ["2001:db8::1"]},
            "retry_route", is_patcher_name_uuid_needed=False,
        )
        with mock.patch.object(
            self.client, "deleteUnicastRoutes",
            side_effect=ConnectionError("SW agent down"),
        ):
            with self.assertRaises(ConnectionError):
                await self.switch.async_coop_unregister_patchers("retry_route")
        await self.switch.async_coop_unregister_patchers("retry_route")
        self.assertEqual(len(self.client.deleted), 1)
        self.assertEqual(
            self.client.deleted[0][1][0].ip.addr,
            ipaddress.ip_address("2001:db8:1::").packed,
        )
        self.assertNotIn(("dut1", "retry_route"), fboss_switch._STATIC_ROUTE_PREFIXES)

    async def test_withdrawal_survives_a_new_driver_instance(self):
        """The step that withdraws is never the one that added.

        async_get_device_driver builds a fresh FbossSwitch per step, so a
        per-instance registry would make the withdrawal path dead code.
        """
        await self.switch.async_add_static_route_patcher(
            {"2001:db8:9::/64": ["2001:db8::1"]},
            "ecmp_nh_stressor_patcher",
            is_patcher_name_uuid_needed=False,
        )
        later_step_driver = FbossSwitch("dut1", logging.getLogger(__name__))
        await later_step_driver.async_coop_unregister_patchers(
            "ecmp_nh_stressor_patcher"
        )
        self.assertEqual(len(self.client.deleted), 1)
        self.assertEqual(
            [p.ip.addr for p in self.client.deleted[0][1]],
            [ipaddress.ip_address("2001:db8:9::").packed],
        )

    async def test_registry_is_scoped_per_host(self):
        await self.switch.async_add_static_route_patcher(
            {"2001:db8:a::/64": ["2001:db8::1"]},
            "shared_name",
            is_patcher_name_uuid_needed=False,
        )
        other_host = FbossSwitch("dut2", logging.getLogger(__name__))
        await other_host.async_coop_unregister_patchers("shared_name")
        # dut2 never registered it, so dut1's routes must survive
        self.assertEqual(self.client.deleted, [])

    async def test_fib_overflow_is_logged_not_raised(self):
        """An ECMP overload playbook drives the agent past its hardware limit;
        the thrift FbossFibUpdateError that reports it must not abort the step."""
        from neteng.fboss.ctrl.types import FbossFibUpdateError

        async def reject(client_id, routes):
            raise FbossFibUpdateError(
                vrf2failedAddUpdatePrefixes={0: [r.dest for r in routes]}
            )

        self.client.addUnicastRoutes = reject
        name = await self.switch.async_add_static_route_patcher(
            {"2001:db8:ab::1/128": ["2001:db8::1"]},
            "ecmp_nh_stressor_patcher",
            is_patcher_name_uuid_needed=False,
        )
        self.assertEqual(name, "ecmp_nh_stressor_patcher")
        # Still tracked, so cleanup withdraws whatever the agent did accept.
        self.assertEqual(
            len(fboss_switch._STATIC_ROUTE_PREFIXES[("dut1", name)]), 1
        )

    def test_add_static_route_patcher_has_a_reachable_docstring(self):
        """The docstring caveat must sit above the guard clause, not below it,
        or it becomes a discarded expression statement and __doc__ is None."""
        doc = FbossSwitch.async_add_static_route_patcher.__doc__ or ""
        self.assertIn("config reload", doc)

    async def test_uuid_suffix_makes_the_name_unique(self):
        first = await self.switch.async_add_static_route_patcher(
            {"2001:db8:b::/64": ["2001:db8::1"]}, "p"
        )
        second = await self.switch.async_add_static_route_patcher(
            {"2001:db8:b::/64": ["2001:db8::1"]}, "p"
        )
        self.assertTrue(first.startswith("p") and len(first) > 1)
        self.assertNotEqual(first, second)

    async def test_unregister_delegates_to_the_config_patcher(self):
        with mock.patch.object(
            oss_coop_patcher, "async_unregister", return_value=True
        ) as unregister:
            await self.switch.async_coop_unregister_patchers("vlan_patcher", "agent")
        unregister.assert_awaited_once_with(
            self.switch, "agent", "vlan_patcher", install_now=False
        )

    async def test_unregister_without_config_drops_every_config_holding_it(self):
        """A patcher sent to bgpcpp and bgpcpp_softdrain under one name."""
        with (
            mock.patch.object(
                oss_coop_patcher,
                "find_configs",
                return_value=["bgpcpp", "bgpcpp_softdrain"],
            ),
            mock.patch.object(
                oss_coop_patcher, "async_unregister", return_value=True
            ) as unregister,
        ):
            await self.switch.async_coop_unregister_patchers("add_bgp_peers")
        self.assertEqual(
            [
                mock.call(self.switch, "bgpcpp", "add_bgp_peers", install_now=False),
                mock.call(
                    self.switch, "bgpcpp_softdrain", "add_bgp_peers", install_now=False
                ),
            ],
            unregister.await_args_list,
        )

    async def test_unregister_unknown_patcher_is_a_noop(self):
        """EcmpMemberStaticRouteStep unregisters before it adds anything."""
        with mock.patch.object(oss_coop_patcher, "find_configs", return_value=[]):
            await self.switch.async_coop_unregister_patchers("never_registered")
        self.assertEqual(self.client.deleted, [])


class PlatformMappingTest(unittest.IsolatedAsyncioTestCase):
    async def test_platform_mapping_comes_from_the_agent(self):
        switch = FbossSwitch("dut1", logging.getLogger(__name__))
        with mock.patch.object(
            FbossSwitch, "async_agent_client", property(lambda _self: _FakeAgentCtx())
        ):
            self.assertEqual(
                "platform-mapping", await switch.async_get_platform_mapping()
            )


if __name__ == "__main__":
    unittest.main()
