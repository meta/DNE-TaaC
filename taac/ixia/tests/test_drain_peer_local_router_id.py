# Copyright (c) Meta Platforms, Inc. and affiliates.

"""Drain-peer LocalRouterID: the generated peer classes expose it as a
plain value list, not a Multivalue, so the Increment call the setter
was written with raises AttributeError on a real chassis. These tests
exercise the setter directly against both representations, without a
network dependency.
"""

import typing as t
import unittest
from unittest.mock import MagicMock, patch

from ixia.ixia import types as ixia_types
from taac.ixia.ixia import Ixia


class _Incrementing:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def Increment(self, *, start_value: str, step_value: str) -> None:
        self.calls.append({"start_value": start_value, "step_value": step_value})


class _ListPeer:
    def __init__(
        self,
        values: list[str],
        *,
        update_error: Exception | None = None,
        set_attribute_error: Exception | None = None,
        silent_ignore: bool = False,
    ) -> None:
        self.LocalRouterID = values
        self.updates: list[dict[str, t.Any]] = []
        self.set_attributes: list[tuple[str, t.Any]] = []
        self._update_error = update_error
        self._set_attribute_error = set_attribute_error
        self._silent_ignore = silent_ignore

    def update(self, **kwargs: t.Any) -> None:
        if self._update_error is not None:
            raise self._update_error
        self.updates.append(kwargs)
        if not self._silent_ignore and "LocalRouterID" in kwargs:
            self.LocalRouterID = kwargs["LocalRouterID"]

    def _set_attribute(self, name: str, value: t.Any) -> None:
        if self._set_attribute_error is not None:
            raise self._set_attribute_error
        self.LocalRouterID = value
        self.set_attributes.append((name, value))


class _IncrementPeer:
    def __init__(self) -> None:
        self.LocalRouterID = _Incrementing()
        self.updated = False

    def update(self, **kwargs: t.Any) -> None:
        self.updated = True


def _ixia() -> Ixia:
    with patch.object(Ixia, "__init__", lambda self: None):
        ixia = Ixia()
    ixia.logger = MagicMock()
    ixia._tracer = None
    ixia.teardown_session = True
    return ixia


def _config(name: str) -> ixia_types.BgpPeerConfig:
    return ixia_types.BgpPeerConfig(bgp_peer_name=name)


class DrainPeerLocalRouterIdTest(unittest.TestCase):
    def test_a_non_drain_peer_is_untouched(self) -> None:
        peer = _ListPeer(["10.0.0.1"])
        _ixia()._maybe_set_drain_peer_local_router_id(
            bgp_peer_obj=t.cast(t.Any, peer),
            bgp_peer_config=_config("BGP_MAIN"),
            port_identifier="dut:Ethernet1",
            desired_bgp_name="BGP_MAIN",
        )
        self.assertEqual(peer.updates, [])

    def test_a_multivalue_router_id_gets_the_increment_pattern(self) -> None:
        peer = _IncrementPeer()
        _ixia()._maybe_set_drain_peer_local_router_id(
            bgp_peer_obj=t.cast(t.Any, peer),
            bgp_peer_config=_config("BGP_POOL_DRAIN"),
            port_identifier="dut:Ethernet1",
            desired_bgp_name="BGP_POOL_DRAIN",
        )
        self.assertEqual(
            peer.LocalRouterID.calls,
            [{"start_value": "200.0.0.1", "step_value": "0.0.0.1"}],
        )
        self.assertFalse(peer.updated)

    def test_a_list_router_id_gets_one_stepped_value_per_entry(self) -> None:
        peer = _ListPeer(["10.0.0.9", "10.0.0.10"])
        ixia = _ixia()
        ixia._maybe_set_drain_peer_local_router_id(
            bgp_peer_obj=t.cast(t.Any, peer),
            bgp_peer_config=_config("BGP_POOL_DRAIN"),
            port_identifier="dut:Ethernet1",
            desired_bgp_name="BGP_POOL_DRAIN",
        )
        self.assertEqual(peer.updates, [{"LocalRouterID": ["200.0.0.1", "200.0.0.2"]}])
        t.cast(MagicMock, ixia.logger.info).assert_called_once()

    def test_an_update_that_rejects_the_field_falls_back_to_set_attribute(
        self,
    ) -> None:
        peer = _ListPeer(
            ["10.0.0.9"],
            update_error=TypeError("unexpected keyword argument 'LocalRouterID'"),
        )
        _ixia()._maybe_set_drain_peer_local_router_id(
            bgp_peer_obj=t.cast(t.Any, peer),
            bgp_peer_config=_config("BGP_POOL_DRAIN"),
            port_identifier="dut:Ethernet1",
            desired_bgp_name="BGP_POOL_DRAIN",
        )
        self.assertEqual(peer.updates, [])
        self.assertEqual(peer.set_attributes, [("localRouterID", ["200.0.0.1"])])

    def test_an_update_that_silently_ignores_the_field_falls_back(
        self,
    ) -> None:
        peer = _ListPeer(["10.0.0.9"], silent_ignore=True)
        ixia = _ixia()
        ixia._maybe_set_drain_peer_local_router_id(
            bgp_peer_obj=t.cast(t.Any, peer),
            bgp_peer_config=_config("BGP_POOL_DRAIN"),
            port_identifier="dut:Ethernet1",
            desired_bgp_name="BGP_POOL_DRAIN",
        )
        self.assertEqual(peer.set_attributes, [("localRouterID", ["200.0.0.1"])])
        t.cast(MagicMock, ixia.logger.info).assert_called_once()

    def test_when_neither_write_works_setup_continues_with_defaults(
        self,
    ) -> None:
        peer = _ListPeer(
            ["10.0.0.9"],
            update_error=TypeError("unexpected keyword argument"),
            set_attribute_error=RuntimeError("server refused"),
        )
        ixia = _ixia()
        ixia._maybe_set_drain_peer_local_router_id(
            bgp_peer_obj=t.cast(t.Any, peer),
            bgp_peer_config=_config("BGP_POOL_DRAIN"),
            port_identifier="dut:Ethernet1",
            desired_bgp_name="BGP_POOL_DRAIN",
        )
        self.assertEqual(peer.set_attributes, [])
        t.cast(MagicMock, ixia.logger.warning).assert_called_once()
        t.cast(MagicMock, ixia.logger.info).assert_not_called()

    def test_an_ipv6_base_steps_ipv6_values(self) -> None:
        peer = _ListPeer(["2001:db8::9", "2001:db8::10"])
        with (
            patch.object(Ixia, "_DRAIN_PEER_LOCAL_ROUTER_ID_BASE", "2001:db8::1"),
            patch.object(Ixia, "_DRAIN_PEER_LOCAL_ROUTER_ID_STEP", "::1"),
        ):
            _ixia()._maybe_set_drain_peer_local_router_id(
                bgp_peer_obj=t.cast(t.Any, peer),
                bgp_peer_config=_config("BGP_POOL_DRAIN"),
                port_identifier="dut:Ethernet1",
                desired_bgp_name="BGP_POOL_DRAIN",
            )
        self.assertEqual(
            peer.updates, [{"LocalRouterID": ["2001:db8::1", "2001:db8::2"]}]
        )

    def test_an_unparseable_base_soft_fails_instead_of_failing_setup(
        self,
    ) -> None:
        peer = _ListPeer(["10.0.0.9"])
        ixia = _ixia()
        with patch.object(Ixia, "_DRAIN_PEER_LOCAL_ROUTER_ID_BASE", "not-an-address"):
            ixia._maybe_set_drain_peer_local_router_id(
                bgp_peer_obj=t.cast(t.Any, peer),
                bgp_peer_config=_config("BGP_POOL_DRAIN"),
                port_identifier="dut:Ethernet1",
                desired_bgp_name="BGP_POOL_DRAIN",
            )
        self.assertEqual(peer.updates, [])
        t.cast(MagicMock, ixia.logger.warning).assert_called_once()

    def test_an_empty_list_gets_the_single_base_value(self) -> None:
        peer = _ListPeer([])
        _ixia()._maybe_set_drain_peer_local_router_id(
            bgp_peer_obj=t.cast(t.Any, peer),
            bgp_peer_config=_config("BGP_POOL_DRAIN"),
            port_identifier="dut:Ethernet1",
            desired_bgp_name="BGP_POOL_DRAIN",
        )
        self.assertEqual(peer.updates, [{"LocalRouterID": ["200.0.0.1"]}])

    def test_a_peer_with_no_name_is_untouched(self) -> None:
        peer = _ListPeer(["10.0.0.1"])
        config = ixia_types.BgpPeerConfig(bgp_peer_name="")
        _ixia()._maybe_set_drain_peer_local_router_id(
            bgp_peer_obj=t.cast(t.Any, peer),
            bgp_peer_config=config,
            port_identifier="dut:Ethernet1",
            desired_bgp_name="",
        )
        self.assertEqual(peer.updates, [])


if __name__ == "__main__":
    unittest.main()
