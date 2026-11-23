# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Catalog tests for Phase-1 RBB core ECMP profiles."""

import unittest

from taac.testconfigs.routing.util.bgp_rbb_core_ecmp_profiles import (
    CORE_ECMP_SUITE_TESTPLAN_IDS,
    RbbCoreEcmpAction,
    RbbCoreEcmpCoverage,
    build_rbb_core_ecmp_profiles,
    select_rbb_core_ecmp_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology(path_count=2):
    paths = tuple(
        CorePortChannel(f"port-channel{index}", (f"eth1/{index}",))
        for index in range(1, path_count + 1)
    )
    return RbbTopology(
        r1=NodeTopology(
            "r1",
            "r1.example",
            paths,
            (IxiaEdge("eth1/10", "1/1"),),
        ),
        r2=NodeTopology(
            "r2",
            "r2.example",
            paths,
            (IxiaEdge("eth1/10", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


class RbbCoreEcmpProfilesTest(unittest.TestCase):
    def test_catalog_maps_all_three_requirements_in_dependency_order(self) -> None:
        profiles = build_rbb_core_ecmp_profiles(_topology())

        self.assertEqual(
            tuple(profile.testplan_id for profile in profiles),
            CORE_ECMP_SUITE_TESTPLAN_IDS,
        )
        self.assertEqual(
            tuple(profile.action for profile in profiles),
            (
                RbbCoreEcmpAction.OPENR_PATH_SELECTION,
                RbbCoreEcmpAction.OPENR_ECMP,
                RbbCoreEcmpAction.BGP_ECMP_TRAFFIC,
            ),
        )
        self.assertEqual(profiles[0].coverage, RbbCoreEcmpCoverage.ADAPTED)
        self.assertTrue(
            all(
                profile.coverage is RbbCoreEcmpCoverage.FULL for profile in profiles[1:]
            )
        )

    def test_selection_preserves_catalog_order_and_rejects_unknowns(self) -> None:
        profiles = build_rbb_core_ecmp_profiles(_topology())
        selected = select_rbb_core_ecmp_profiles(
            profiles, ["phase1:TC-08", "phase1:TC-02"]
        )
        self.assertEqual(
            [profile.testplan_id for profile in selected],
            ["phase1:TC-02", "phase1:TC-08"],
        )
        with self.assertRaisesRegex(ValueError, "unknown"):
            select_rbb_core_ecmp_profiles(profiles, ["phase1:TC-999"])

    def test_requires_two_symmetric_core_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least two"):
            build_rbb_core_ecmp_profiles(_topology(path_count=1))

        topology = _topology(path_count=2)
        asymmetric = RbbTopology(
            r1=topology.r1,
            r2=NodeTopology(
                "r2",
                "r2.example",
                topology.r2.core_pcs + (CorePortChannel("port-channel3", ("eth1/3",)),),
                topology.r2.ixia_edges,
            ),
            ixia_chassis=topology.ixia_chassis,
        )
        with self.assertRaisesRegex(ValueError, "symmetric"):
            build_rbb_core_ecmp_profiles(asymmetric)


if __name__ == "__main__":
    unittest.main()
