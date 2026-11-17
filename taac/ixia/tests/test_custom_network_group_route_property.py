# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Route-property objects are reached with find() before any add().

restpy's BgpIPRouteProperty/BgpV6IPRouteProperty.add() is a
batch-add (ConfigAssistant) API. Outside a batch context it raises
"This feature is only available with Batch Assistance"
(ixnetwork_restpy/base.py, Base._add_xpath). When IxNetwork has already
created the route property under a prefix pool, find() must be used and
add() must not be called; add() is acceptable only as the fallback of a
find-or-create for builds that do not auto-create it.
"""

import ast
import typing as t
import unittest
from unittest.mock import MagicMock, patch

from ixia.ixia import types as ixia_types
from taac.ixia.ixia import DeviceGroupIndex, Ixia

_BATCH_ONLY = "This feature is only available with Batch Assistance"

# Route-property attributes whose add() is batch-only in restpy.
_ROUTE_PROPERTY_ATTRS = ("BgpIPRouteProperty", "BgpV6IPRouteProperty")


def _find_or_create_fallbacks(tree: ast.AST) -> t.Set[int]:
    """ids of calls that are the else-arm of `<found> if <found> else X.add()`."""
    return {
        id(node.orelse) for node in ast.walk(tree) if isinstance(node, ast.IfExp)
    }


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


class _BatchOnlyRoutePropertyAccessor:
    """Mirrors restpy: add() is batch-only, find() returns the live object."""

    def __init__(self) -> None:
        self.route_property = _RouteProperty()
        self.add_calls = 0
        self.find_calls = 0

    def add(self) -> "_RouteProperty":
        self.add_calls += 1
        raise Exception(_BATCH_ONLY)

    def find(self) -> "_RouteProperty":
        self.find_calls += 1
        return self.route_property


class _PrefixPool:
    def __init__(self) -> None:
        self.NumberOfAddresses = 1
        self.NetworkAddress = _MultiValue()
        self.PrefixLength = _MultiValue()
        self.BgpV6IPRouteProperty = _BatchOnlyRoutePropertyAccessor()


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
        device_group_name="rogue_dg",
        network_group_name="ECMP_PREFIX_POOL",
        network_group_multiplier=2048,
        prefix_start_value="6000:ee::",
        prefix_length=64,
        nexthop_start_value="2001:db8:1101:a::a000",
        nexthop_increments="::1",
        ecmp_width=63,
        network_group_index=0,
    )


class TestCustomNetworkGroupRouteProperty(unittest.TestCase):
    """The create branch must not add() a route property that already exists."""

    def test_create_custom_network_group_uses_find_not_add(self) -> None:
        pool = _PrefixPool()
        network_group = MagicMock()
        network_group.Ipv6PrefixPools = _PrefixPoolAccessor(pool)
        device_group = MagicMock()
        device_group.NetworkGroup.add.return_value = network_group
        device_group_index = DeviceGroupIndex(device_group=device_group)

        _make_ixia()._create_custom_network_group(
            device_group, _make_config(), device_group_index
        )

        accessor = pool.BgpV6IPRouteProperty
        self.assertEqual(
            accessor.add_calls,
            0,
            "route-property add() is batch-only outside a batch context; "
            "the create branch must reuse the one find() returns",
        )
        self.assertEqual(accessor.find_calls, 1)
        # The route property found must actually be configured.
        self.assertEqual(accessor.route_property.NextHopIPType.values, ["ipv6"])

    def test_no_unconditional_route_property_add_call_sites(self) -> None:
        """Static guard: no unconditional route-property add() in ixia.py.

        Catches both spellings — the direct attribute access and the
        getattr-indirected `<afi>_route_property_cls` used by
        import_bgp_routes. The else-arm of a find-or-create conditional
        is allowed.
        """
        source_path = Ixia.__module__.replace(".", "/") + ".py"
        import taac.ixia.ixia as ixia_module

        tree = ast.parse(open(ixia_module.__file__).read())
        fallbacks = _find_or_create_fallbacks(tree)
        offenders = [
            f"{source_path}:{node.lineno}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add"
            and _is_route_property_target(node.func.value)
            and id(node) not in fallbacks
        ]
        self.assertEqual(
            offenders,
            [],
            f"route-property add() without a find() first: {offenders}",
        )


if __name__ == "__main__":
    unittest.main()
