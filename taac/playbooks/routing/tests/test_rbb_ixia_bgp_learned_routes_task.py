# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for exact IXIA IPv6 BGP learned-route evidence."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from taac.constants import TestCaseFailure
from taac.tasks.rbb_ixia_bgp_learned_routes_task import (
    RbbIxiaBgpLearnedRoutesTask,
    _table_prefixes,
    _table_routes,
)


def _peer(table, *, filter_value=False):
    learned = SimpleNamespace(
        State="ready",
        Table=SimpleNamespace(find=MagicMock(return_value=[table])),
    )
    return SimpleNamespace(
        FilterIpV6Unicast=SimpleNamespace(
            Values=[filter_value], Single=MagicMock()
        ),
        GetIPv6LearnedInfo=MagicMock(),
        LearnedInfo=SimpleNamespace(find=MagicMock(return_value=learned)),
    )


class RbbIxiaBgpLearnedRoutesTaskTest(unittest.IsolatedAsyncioTestCase):
    def test_table_parser_extracts_prefixes_and_standard_communities(self) -> None:
        table = SimpleNamespace(
            Columns=["IPv6 Prefix", "Communities"],
            Values=[["2001:db8:67::/64", "65000:67 65000:68"]],
        )

        self.assertEqual(
            _table_routes(table),
            {"2001:db8:67::/64": {"65000:67", "65000:68"}},
        )

    def test_table_parser_combines_network_and_prefix_length(self) -> None:
        table = SimpleNamespace(
            Columns=["Network Address", "Prefix Length", "Next Hop"],
            Values=[["2001:db8:100::", "64", "2001:db8::1"]],
        )

        self.assertEqual(_table_prefixes(table), {"2001:db8:100::/64"})

    async def test_exact_prefix_and_community_pass_and_restore_filter(self) -> None:
        table = SimpleNamespace(
            Columns=["IPv6 Prefix", "Communities"],
            Values=[["2001:db8:67::/64", "65000:68"]],
        )
        peer = _peer(table)
        ixia = MagicMock()
        ixia.find_bgp_ipv6_peer.return_value = peer
        task = RbbIxiaBgpLearnedRoutesTask(ixia=ixia, logger=MagicMock())

        await task.run(
            {
                "port_identifier": "r2.example:eth1/5",
                "expected_prefixes": ["2001:db8:67::/64"],
                "expected_communities": {
                    "2001:db8:67::/64": ["65000:68"]
                },
            }
        )

        self.assertEqual(
            peer.FilterIpV6Unicast.Single.call_args_list,
            [unittest.mock.call(True), unittest.mock.call(False)],
        )
        self.assertEqual(ixia.apply_changes.call_count, 2)

    async def test_resolves_basic_port_generated_peer_name(self) -> None:
        table = SimpleNamespace(
            Columns=["IPv6 Prefix", "Communities"],
            Values=[["2001:db8:1::/64", "65000:1"]],
        )
        peer = _peer(table, filter_value=True)
        ixia = MagicMock()
        peer.Name = "BGP_PEER_V6_D0_R2:ETH1/1/1"
        ixia.find_bgp_ipv6_peer.return_value = None
        ixia.find_bgp_peers.return_value = [peer]
        task = RbbIxiaBgpLearnedRoutesTask(ixia=ixia, logger=MagicMock())

        await task.run(
            {
                "port_identifier": "r2:eth1/1/1",
                "expected_prefixes": ["2001:db8:1::/64"],
            }
        )

        self.assertEqual(
            ixia.find_bgp_ipv6_peer.call_args_list,
            [
                unittest.mock.call("r2:eth1/1/1"),
                unittest.mock.call("D0_r2:eth1/1/1"),
                unittest.mock.call("R2:ETH1/1/1"),
                unittest.mock.call("D0_R2:ETH1/1/1"),
            ],
        )
        ixia.find_bgp_peers.assert_called_once_with()

    async def test_forbidden_community_requires_attribute_view(self) -> None:
        peer = _peer(
            SimpleNamespace(
                Columns=["IPv6 Prefix"], Values=[["2001:db8:67::/64"]]
            ),
            filter_value=True,
        )
        ixia = MagicMock()
        ixia.find_bgp_ipv6_peer.return_value = peer
        task = RbbIxiaBgpLearnedRoutesTask(ixia=ixia, logger=MagicMock())

        with self.assertRaisesRegex(
            TestCaseFailure, "community_view_available=False"
        ):
            await task.run(
                {
                    "port_identifier": "r2.example:eth1/5",
                    "expected_prefixes": ["2001:db8:67::/64"],
                    "forbidden_communities": {
                        "2001:db8:67::/64": ["65000:67"]
                    },
                    "timeout_seconds": 0.01,
                    "poll_interval_seconds": 0.001,
                }
            )


if __name__ == "__main__":
    unittest.main()
