# Copyright (c) Meta Platforms, Inc. and affiliates.
"""BGP route properties under a new prefix pool are found-or-created.

Newer IxNetwork builds auto-create the BgpIPRouteProperty /
BgpV6IPRouteProperty with the prefix pool, and a second add() is rejected at
commit. Older builds do not create it, so add() is still needed there, but
only as the fallback of a find-or-create.
"""

import ast
import os
import typing as t
import unittest
from unittest.mock import MagicMock, mock_open, patch

from ixia.ixia import types as ixia_types
from taac.ixia.ixia import DeviceGroupIndex, Ixia

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

_IXIA_MODULE = "taac.ixia.ixia" if TAAC_OSS else "neteng.test_infra.dne.taac.ixia.ixia"

_ROUTE_PROPERTY_ATTRS = ("BgpIPRouteProperty", "BgpV6IPRouteProperty")


def _find_or_create_fallbacks(tree: ast.AST) -> t.Set[int]:
    """ids of calls that are the else-arm of `<found> if <found> else X.add()`."""
    return {id(node.orelse) for node in ast.walk(tree) if isinstance(node, ast.IfExp)}


def _is_route_property_target(node: ast.expr) -> bool:
    """True if `node` evaluates to a restpy route-property accessor."""
    # ip_prefix_pool.BgpV6IPRouteProperty.add()
    if isinstance(node, ast.Attribute):
        return node.attr in _ROUTE_PROPERTY_ATTRS
    # cls = getattr(pool, attr); cls.add()
    if isinstance(node, ast.Name):
        return "route_property" in node.id
    return False


class _MultiValue:
    def __init__(self) -> None:
        self.values: t.List[object] = []

    def Single(self, value: object) -> None:
        self.values.append(value)

    def Custom(self, **kwargs: object) -> None:
        self.values.append(kwargs)


class _RouteProperty:
    """Like a restpy find() result: one object that is also its own result list."""

    def __len__(self) -> int:
        return 1

    def __getitem__(self, index: int) -> "_RouteProperty":
        if index not in (0, -1):
            raise IndexError(index)
        return self

    def __init__(self) -> None:
        self.NextHopType = _MultiValue()
        self.NextHopIPType = _MultiValue()
        self.NextHopIncrementMode = _MultiValue()
        self.Ipv6NextHop = _MultiValue()
        self.EnableCommunity = _MultiValue()
        self.NoOfCommunities = 0
        self.BgpCommunitiesList = MagicMock()
        self.BgpCommunitiesList.find.return_value = []
        self.ImportBgpRoutes = MagicMock()


class _RoutePropertyAccessor:
    """`auto_created=True` models builds that create the property with the pool
    and reject a second add(); `False` models builds that do not."""

    def __init__(self, auto_created: bool) -> None:
        self.route_property = _RouteProperty()
        self.auto_created = auto_created
        self.add_calls = 0
        self.find_calls = 0

    def add(self) -> "_RouteProperty":
        self.add_calls += 1
        if self.auto_created:
            raise Exception("Unable to add bgpV6IPRouteProperty")
        return self.route_property

    def find(self) -> t.Any:
        self.find_calls += 1
        return self.route_property if self.auto_created else []


class _PrefixPool:
    def __init__(self, auto_created: bool) -> None:
        self.NumberOfAddresses = 1
        self.NetworkAddress = _MultiValue()
        self.PrefixLength = _MultiValue()
        self.BgpIPRouteProperty = _RoutePropertyAccessor(auto_created)
        self.BgpV6IPRouteProperty = _RoutePropertyAccessor(auto_created)


class _PrefixPoolAccessor:
    def __init__(self, pool: "_PrefixPool") -> None:
        self._pool = pool

    def add(self, **_kwargs: object) -> "_PrefixPool":
        return self._pool


def _make_ixia() -> Ixia:
    with patch.object(Ixia, "__init__", lambda self: None):
        ixia = Ixia()
    ixia.logger = MagicMock()
    return ixia


def _make_config() -> "ixia_types.CustomNetworkGroupConfig":
    return ixia_types.CustomNetworkGroupConfig(
        device_group_name="dg",
        network_group_name="ECMP_PREFIX_POOL",
        network_group_multiplier=2048,
        prefix_start_value="6000:ee::",
        prefix_length=64,
        nexthop_start_value="2001:db8:1101:a::a000",
        nexthop_increments="::1",
        ecmp_width=63,
        network_group_index=0,
    )


def _device_group(pool: _PrefixPool) -> MagicMock:
    network_group = MagicMock()
    network_group.Ipv4PrefixPools = _PrefixPoolAccessor(pool)
    network_group.Ipv6PrefixPools = _PrefixPoolAccessor(pool)
    device_group = MagicMock()
    device_group.NetworkGroup.add.return_value = network_group
    device_group.NetworkGroup.find.return_value = None
    return device_group


class TestCustomNetworkGroupRouteProperty(unittest.TestCase):
    def test_reuses_an_auto_created_route_property(self) -> None:
        pool = _PrefixPool(auto_created=True)
        device_group = _device_group(pool)

        _make_ixia()._create_custom_network_group(
            device_group, _make_config(), DeviceGroupIndex(device_group=device_group)
        )

        accessor = pool.BgpV6IPRouteProperty
        self.assertEqual(accessor.add_calls, 0)
        self.assertEqual(accessor.route_property.NextHopIPType.values, ["ipv6"])


class TestImportBgpRoutesRouteProperty(unittest.TestCase):
    def _import(self, pool: _PrefixPool, family: "ixia_types.IpAddressFamily") -> None:
        ixia = _make_ixia()
        ixia.import_bgp_attribute_profile_from_configerator = MagicMock(
            return_value="header\nrow1\nrow2\n"
        )
        device_group = _device_group(pool)
        params = ixia_types.ImportBgpRoutesParams(
            bgp_route_import_file_path="routes/import.csv",
            network_group_index=0,
            multiplier=1,
        )
        with (
            patch(f"{_IXIA_MODULE}.Files"),
            patch(f"{_IXIA_MODULE}.os.makedirs"),
            patch(f"{_IXIA_MODULE}.open", mock_open(), create=True),
        ):
            ixia.import_bgp_routes(
                port_identifier="p1",
                ip_address_family=family,
                import_bgp_routes_params_list=[params],
                device_group_obj=device_group,
                device_group_index=DeviceGroupIndex(device_group=device_group),
            )

    def test_reuses_an_auto_created_route_property(self) -> None:
        pool = _PrefixPool(auto_created=True)
        self._import(pool, ixia_types.IpAddressFamily.IPV6)

        accessor = pool.BgpV6IPRouteProperty
        self.assertEqual(accessor.add_calls, 0)
        self.assertEqual(accessor.route_property.NextHopIPType.values, ["ipv6"])
        accessor.route_property.ImportBgpRoutes.assert_called_once()

    def test_creates_the_route_property_when_none_exists(self) -> None:
        pool = _PrefixPool(auto_created=False)
        self._import(pool, ixia_types.IpAddressFamily.IPV4)

        accessor = pool.BgpIPRouteProperty
        self.assertEqual((accessor.find_calls, accessor.add_calls), (1, 1))
        self.assertEqual(accessor.route_property.NextHopIPType.values, ["ipv4"])
        accessor.route_property.ImportBgpRoutes.assert_called_once()

    def test_no_unconditional_route_property_add_call_sites(self) -> None:
        """Static guard: every route-property add() in ixia.py is the else-arm
        of a find-or-create, for both the direct attribute spelling and the
        getattr-indirected `*_route_property_cls` one."""
        import taac.ixia.ixia as ixia_module

        with open(ixia_module.__file__) as f:
            tree = ast.parse(f.read())
        fallbacks = _find_or_create_fallbacks(tree)
        offenders = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add"
            and _is_route_property_target(node.func.value)
            and id(node) not in fallbacks
        ]
        self.assertEqual(offenders, [], "route-property add() without find() first")


if __name__ == "__main__":
    unittest.main()
