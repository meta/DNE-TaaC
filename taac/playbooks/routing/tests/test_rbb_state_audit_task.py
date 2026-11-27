# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for the structured RBB state-audit registered task."""

import ipaddress
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from taac.constants import TestCaseFailure
from taac.driver.driver_constants import SystemctlServiceStatus
from taac.tasks.rbb_state_audit_task import RbbStateAuditTask
from taac.tasks.registry import TASK_NAME_TO_CLASS

_MODULE = "taac.tasks.rbb_state_audit_task"
_DRIVER = f"{_MODULE}.async_get_device_driver"
_CLIENT = f"{_MODULE}._client_id"


def _binary(address: str, if_name: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        addr=ipaddress.ip_address(address).packed,
        ifName=if_name,
    )


def _route(prefix: str) -> SimpleNamespace:
    network = ipaddress.ip_network(prefix, strict=True)
    return SimpleNamespace(
        dest=SimpleNamespace(
            ip=SimpleNamespace(addr=network.network_address.packed),
            prefixLength=network.prefixlen,
        ),
    )


def _fib_detail(
    route: SimpleNamespace,
    *,
    clients: tuple[tuple[int, bool | None], ...] = ((786, True),),
    next_hops: tuple[SimpleNamespace, ...] = (),
) -> SimpleNamespace:
    return SimpleNamespace(
        dest=route.dest,
        nextHopMulti=[
            SimpleNamespace(clientId=client_id, isPreferred=is_preferred)
            for client_id, is_preferred in clients
        ],
        nextHops=[SimpleNamespace(address=address) for address in next_hops],
        adminDistance=None,
    )


def _driver() -> MagicMock:
    driver = MagicMock()
    driver.async_get_route_table_by_client = AsyncMock(return_value=[])
    driver.async_get_route_table_details = AsyncMock(return_value=[])
    driver.async_get_ndp_table = AsyncMock(return_value=[])
    driver.async_get_interface_name_to_port_id_and_vlan_id = AsyncMock(
        return_value=SimpleNamespace(port_id=1, vlan_id=2001)
    )
    driver.async_get_service_status = AsyncMock(
        return_value=SystemctlServiceStatus.ACTIVE
    )
    driver.async_get_interfaces_operational_state = AsyncMock(return_value={})
    driver.async_run_cmd_on_shell = AsyncMock(return_value="")
    return driver


class RbbStateAuditTaskTest(unittest.IsolatedAsyncioTestCase):
    def test_task_is_registered(self) -> None:
        self.assertIs(TASK_NAME_TO_CLASS["rbb_state_audit"], RbbStateAuditTask)

    async def test_exact_client_route_and_fib_pass(self) -> None:
        driver = _driver()
        route = _route("2001:db8:0:2::1/128")
        driver.async_get_route_table_by_client.return_value = [route]
        driver.async_get_route_table_details.return_value = [
            _fib_detail(
                route,
                next_hops=(_binary("fe80::2", "fboss2001"),),
            )
        ]
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_CLIENT, return_value=786),
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
        ):
            await task.run(
                {
                    "routes": [
                        {
                            "prefix": "2001:db8:0:2::1/128",
                            "client": "OPENR",
                            "next_hops": ["fe80::2"],
                            "interfaces": ["fboss2001"],
                        }
                    ]
                }
            )

        driver.async_get_route_table_by_client.assert_awaited_once_with(786)
        driver.async_get_route_table_details.assert_awaited_once()

    async def test_route_under_wrong_client_is_reported_missing(self) -> None:
        driver = _driver()
        driver.async_get_route_table_by_client.return_value = []
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_CLIENT, return_value=786),
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(TestCaseFailure, "OPENR client RIB"),
        ):
            await task.run(
                {
                    "gate": "phase1:TC-01",
                    "routes": [
                        {
                            "prefix": "192.0.2.2/32",
                            "client": "OPENR",
                        }
                    ],
                }
            )

    async def test_route_in_rib_but_absent_from_fib_fails(self) -> None:
        driver = _driver()
        driver.async_get_route_table_by_client.return_value = [_route("192.0.2.2/32")]
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_CLIENT, return_value=786),
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(TestCaseFailure, "absent from the agent FIB"),
        ):
            await task.run({"routes": [{"prefix": "192.0.2.2/32", "client": "OPENR"}]})

    async def test_fib_prefix_owned_by_different_client_fails(self) -> None:
        driver = _driver()
        route = _route("192.0.2.2/32")
        driver.async_get_route_table_by_client.return_value = [route]
        driver.async_get_route_table_details.return_value = [
            _fib_detail(route, clients=((0, True),))
        ]
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_CLIENT, return_value=786),
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(TestCaseFailure, "preferred FIB owner is not OPENR"),
        ):
            await task.run({"routes": [{"prefix": "192.0.2.2/32", "client": "OPENR"}]})

    async def test_nonpreferred_expected_client_does_not_claim_fib_ownership(
        self,
    ) -> None:
        driver = _driver()
        route = _route("192.0.2.2/32")
        driver.async_get_route_table_by_client.return_value = [route]
        driver.async_get_route_table_details.return_value = [
            _fib_detail(route, clients=((786, False), (0, True)))
        ]
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_CLIENT, return_value=786),
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(TestCaseFailure, "preferred FIB owner"),
        ):
            await task.run({"routes": [{"prefix": "192.0.2.2/32", "client": "OPENR"}]})

    async def test_exact_next_hop_mismatch_fails(self) -> None:
        driver = _driver()
        route = _route("192.0.2.2/32")
        driver.async_get_route_table_by_client.return_value = [route]
        driver.async_get_route_table_details.return_value = [
            _fib_detail(
                route,
                next_hops=(_binary("fe80::99", "fboss2001"),),
            )
        ]
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_CLIENT, return_value=786),
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(TestCaseFailure, "next hops"),
        ):
            await task.run(
                {
                    "routes": [
                        {
                            "prefix": "192.0.2.2/32",
                            "client": "OPENR",
                            "next_hops": ["fe80::2"],
                        }
                    ]
                }
            )

    async def test_link_local_ecmp_count_uses_resolved_next_hops(self) -> None:
        driver = _driver()
        route = _route("192.0.2.2/32")
        driver.async_get_route_table_by_client.return_value = [route]
        driver.async_get_route_table_details.return_value = [
            _fib_detail(
                route,
                next_hops=(
                    _binary("fe80::2", "fboss2001"),
                    _binary("fe80::3", "fboss2002"),
                ),
            )
        ]
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_CLIENT, return_value=786),
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
        ):
            await task.run(
                {
                    "routes": [
                        {
                            "prefix": "192.0.2.2/32",
                            "client": "OPENR",
                            "next_hop_count": 2,
                            "next_hop_interface_count": 2,
                            "next_hop_scope": "link_local",
                        }
                    ]
                }
            )

    async def test_ecmp_cardinality_and_scope_mismatch_fail(self) -> None:
        driver = _driver()
        route = _route("192.0.2.2/32")
        driver.async_get_route_table_by_client.return_value = [route]
        driver.async_get_route_table_details.return_value = [
            _fib_detail(
                route,
                next_hops=(_binary("2001:db8::2", "fboss2001"),),
            )
        ]
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_CLIENT, return_value=786),
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
            self.assertRaises(TestCaseFailure) as context,
        ):
            await task.run(
                {
                    "routes": [
                        {
                            "prefix": "192.0.2.2/32",
                            "client": "OPENR",
                            "next_hop_count": 2,
                            "next_hop_interface_count": 2,
                            "next_hop_scope": "link_local",
                        }
                    ]
                }
            )

        message = str(context.exception)
        self.assertIn("next-hop count", message)
        self.assertIn("interface count", message)
        self.assertIn("link-local", message)

    async def test_link_local_ndp_is_bound_to_interface_vlan_and_state(self) -> None:
        driver = _driver()
        driver.async_get_ndp_table.return_value = [
            SimpleNamespace(
                ip=_binary("fe80::2"),
                state="REACHABLE",
                interfaceID=2001,
            ),
            SimpleNamespace(
                ip=_binary("fe80::3"),
                state="REACHABLE",
                interfaceID=2002,
            ),
        ]
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with patch(_DRIVER, new_callable=AsyncMock, return_value=driver):
            await task.run(
                {
                    "ndp": [
                        {
                            "interface": "eth1/1",
                            "address_scope": "link_local",
                            "states": ["REACHABLE"],
                        }
                    ]
                }
            )

        driver.async_get_interface_name_to_port_id_and_vlan_id.assert_awaited_once_with(
            "eth1/1"
        )

    async def test_ndp_on_wrong_vlan_or_in_wrong_state_fails(self) -> None:
        driver = _driver()
        driver.async_get_ndp_table.return_value = [
            SimpleNamespace(ip=_binary("fe80::2"), state="STALE", interfaceID=2001),
            SimpleNamespace(ip=_binary("fe80::3"), state="REACHABLE", interfaceID=2002),
        ]
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(TestCaseFailure, "NDP link_local"),
        ):
            await task.run(
                {
                    "ndp": [
                        {
                            "interface": "eth1/1",
                            "address_scope": "link_local",
                            "states": ["REACHABLE"],
                        }
                    ]
                }
            )

    async def test_inactive_service_and_down_interface_are_both_reported(self) -> None:
        driver = _driver()
        driver.async_get_service_status.return_value = SystemctlServiceStatus.FAILED
        driver.async_get_interfaces_operational_state.return_value = {"eth1/1": False}
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
            self.assertRaises(TestCaseFailure) as context,
        ):
            await task.run(
                {
                    "active_services": ["OPENR"],
                    "interfaces_up": ["eth1/1"],
                }
            )

        message = str(context.exception)
        self.assertIn("service openr", message)
        self.assertIn("eth1/1", message)

    async def test_mysid_tokens_must_belong_to_same_entry(self) -> None:
        driver = _driver()
        driver.async_run_cmd_on_shell.return_value = (
            "2001:db8:27cc:: OTHER_BEHAVIOR\n"
            "2001:db8:27d6:: ADJACENCY_MICRO_SID Resolved via: fboss2"
        )
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(TestCaseFailure, "MySID"),
        ):
            await task.run(
                {
                    "mysids": [
                        {
                            "sid": "2001:db8:27cc::",
                            "behavior": "ADJACENCY_MICRO_SID",
                            "require_resolved": True,
                        }
                    ]
                }
            )

    async def test_mysid_multiline_entry_passes(self) -> None:
        driver = _driver()
        driver.async_run_cmd_on_shell.return_value = (
            "MySid: 2001:db8:27cc::/48\n"
            "    Type: ADJACENCY_MICRO_SID\n"
            "    Resolved via: fe80::2@fboss2001\n"
            "MySid: 2001:db8:27d6::/48\n"
            "    Type: DECAPSULATE_AND_LOOKUP\n"
        )
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with patch(_DRIVER, new_callable=AsyncMock, return_value=driver):
            await task.run(
                {
                    "mysids": [
                        {
                            "sid": "2001:db8:27cc::",
                            "behavior": "ADJACENCY_MICRO_SID",
                            "require_resolved": True,
                        }
                    ]
                }
            )

    async def test_mysid_address_match_is_exact_not_substring(self) -> None:
        driver = _driver()
        driver.async_run_cmd_on_shell.return_value = (
            "MySid: 2001:db8:27cc::10/128\n"
            "    Type: ADJACENCY_MICRO_SID\n"
            "    Resolved via: fe80::2@fboss2001\n"
        )
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_DRIVER, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(TestCaseFailure, "MySID"),
        ):
            await task.run(
                {
                    "mysids": [
                        {
                            "sid": "2001:db8:27cc::1",
                            "behavior": "ADJACENCY_MICRO_SID",
                            "require_resolved": True,
                        }
                    ]
                }
            )

    async def test_empty_or_invalid_profile_fails_before_device_connection(
        self,
    ) -> None:
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())
        with patch(_DRIVER, new_callable=AsyncMock) as get_driver:
            with self.assertRaisesRegex(ValueError, "at least one assertion"):
                await task.run({})
            with self.assertRaises(ValueError):
                await task.run(
                    {
                        "ndp": [
                            {
                                "interface": "eth1/1",
                                "address_scope": "global",
                            }
                        ]
                    }
                )
            with self.assertRaisesRegex(ValueError, "must be a boolean"):
                await task.run(
                    {
                        "routes": [
                            {
                                "prefix": "192.0.2.2/32",
                                "client": "OPENR",
                                "require_fib": "false",
                            }
                        ]
                    }
                )
            with self.assertRaisesRegex(ValueError, "unsupported fields"):
                await task.run(
                    {
                        "ndp": [
                            {
                                "interface": "eth1/1",
                                "address_scope": "link_local",
                                "address_network": "fe80::/10",
                            }
                        ]
                    }
                )
        get_driver.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
