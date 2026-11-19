# Copyright (c) Meta Platforms, Inc. and affiliates.

import logging
import unittest

from taac.ixia.taac_ixia import TaacIxia


class _Active:
    def __init__(self, cell_count: int) -> None:
        self._values = [True] * cell_count

    def Single(self, value: bool) -> None:
        self._values = [value] * len(self._values)

    @property
    def Values(self) -> list[bool]:
        return list(self._values)


class _Route:
    def __init__(self, cell_count: int) -> None:
        self.Active = _Active(cell_count)
        self.refresh_count = 0

    def refresh(self) -> None:
        self.refresh_count += 1


class _Lifecycle:
    def __init__(self, name: str) -> None:
        self.Name = name
        self.stop_count = 0
        self.start_count = 0

    def Stop(self) -> None:
        self.stop_count += 1

    def Start(self) -> None:
        self.start_count += 1


class _Harness(TaacIxia):
    def __init__(self) -> None:
        self.logger = logging.getLogger("dlb-pool-route-toggle-test")
        self.apply_count = 0
        self.arp_ns_device_groups: list[str] = []
        self.shells = {
            pool: (
                _Lifecycle(f"dg-{pool}"),
                _Lifecycle(f"ng-{pool}"),
                object(),
                _Route(8),
            )
            for pool in ("silver-a", "silver-b")
        }

    def _find_dlb_ng_dg(self, pool_name: str):
        return self.shells[pool_name]

    def apply_changes(self) -> None:
        self.apply_count += 1

    def _send_arp_ns_on_device_group(self, device_group) -> None:
        self.arp_ns_device_groups.append(device_group.Name)


class DlbPoolRouteToggleTest(unittest.TestCase):
    def test_two_route_pools_toggle_atomically_with_exact_active_readback(self) -> None:
        harness = _Harness()

        state = harness.set_dlb_route_pools_active(
            pool_names=["silver-a", "silver-b"],
            active=False,
            expected_route_cells=8,
            settle_time_after_start=0,
        )

        self.assertEqual(
            {
                "silver-a": {"route_cells": 8, "active_cells": 0},
                "silver-b": {"route_cells": 8, "active_cells": 0},
            },
            state,
        )
        self.assertEqual(1, harness.apply_count)
        for device_group, network_group, _pool, route in harness.shells.values():
            self.assertEqual(1, device_group.stop_count)
            self.assertEqual(1, network_group.stop_count)
            self.assertEqual(1, device_group.start_count)
            self.assertEqual(1, network_group.start_count)
            self.assertEqual([False] * 8, route.Active.Values)
            self.assertEqual(1, route.refresh_count)
        self.assertEqual([], harness.arp_ns_device_groups)

    def test_enable_resolves_neighbors_only_after_verified_route_readback(self) -> None:
        harness = _Harness()
        for _dg, _ng, _pool, route in harness.shells.values():
            route.Active.Single(False)

        state = harness.set_dlb_route_pools_active(
            pool_names=["silver-a", "silver-b"],
            active=True,
            expected_route_cells=8,
            settle_time_after_start=0,
        )

        self.assertEqual(8, state["silver-a"]["active_cells"])
        self.assertEqual(8, state["silver-b"]["active_cells"])
        self.assertEqual(
            ["dg-silver-a", "dg-silver-b"],
            harness.arp_ns_device_groups,
        )
