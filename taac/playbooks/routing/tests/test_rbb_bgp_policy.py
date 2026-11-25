# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Contract tests for Phase-2 TC-65--68 policy lifecycle."""

import unittest
from types import SimpleNamespace

from taac.tasks.rbb_bgp_policy_lifecycle_task import (
    RbbBgpPolicyLifecycleTask,
    _prefix_key,
)
from taac.tasks.rbb_ixia_bgp_learned_routes_task import (
    RbbIxiaBgpLearnedRoutesTask,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_bgp_policy_test_config import (
    create_rbb_bgp_policy_test_config,
)
from taac.testconfigs.routing.util.bgp_rbb_policy_profiles import (
    BGP_POLICY_PROFILES,
    TC65_UNDRAIN_COMMUNITY,
    select_rbb_bgp_policy_profiles,
    tc65_undrain_policy,
    tc66_export_policy,
    tc67_export_policy,
    tc68_import_policy,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology() -> RbbTopology:
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="policy-r1.example",
            core_pcs=(CorePortChannel("port-channel1", ("eth1/1",)),),
            ixia_edges=(IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="policy-r2.example",
            core_pcs=(CorePortChannel("port-channel1", ("eth1/1",)),),
            ixia_edges=(IxiaEdge("eth1/6", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


class RbbBgpPolicyContractTest(unittest.TestCase):
    def test_task_is_registered(self) -> None:
        from taac.tasks.registry import TASK_NAME_TO_CLASS
        self.assertIs(
            TASK_NAME_TO_CLASS[RbbBgpPolicyLifecycleTask.NAME],
            RbbBgpPolicyLifecycleTask,
        )
        self.assertIs(
            TASK_NAME_TO_CLASS[RbbIxiaBgpLearnedRoutesTask.NAME],
            RbbIxiaBgpLearnedRoutesTask,
        )

    def test_bgp_thrift_prefix_is_decoded_without_route_dest_wrapper(self) -> None:
        prefix = SimpleNamespace(
            prefix_bin=bytes.fromhex("20010db8000000650000000000000000"),
            num_bits=64,
        )
        self.assertEqual(_prefix_key(prefix), "2001:db8:0:65::/64")

    def test_catalog_is_only_requested_phase2_cases(self) -> None:
        self.assertEqual(
            [p.testplan_id for p in BGP_POLICY_PROFILES],
            ["phase2:TC-65", "phase2:TC-66", "phase2:TC-67", "phase2:TC-68"],
        )
        self.assertEqual(
            [
                p.testplan_id
                for p in select_rbb_bgp_policy_profiles(
                    ["phase2:TC-68", "phase2:TC-65"]
                )
            ],
            ["phase2:TC-65", "phase2:TC-68"],
        )

    def test_policies_encode_expected_matches_and_actions(self) -> None:
        _, tc65 = tc65_undrain_policy()
        _, tc66 = tc66_export_policy()
        _, tc67 = tc67_export_policy()
        _, tc68 = tc68_import_policy()
        self.assertIn(TC65_UNDRAIN_COMMUNITY, str(tc65))
        self.assertIn("local_pref': 100", str(tc65))
        self.assertIn("'type': 6", str(tc66))
        self.assertIn("'action_type': 3", str(tc67))
        self.assertIn("'compare_operator': 2", str(tc68))

    def test_config_has_four_playbooks_and_ixia_inputs(self) -> None:
        config = create_rbb_bgp_policy_test_config(_topology())
        self.assertEqual(
            [p.name for p in config.playbooks],
            [p.playbook_name for p in BGP_POLICY_PROFILES],
        )
        scales = (
            config.basic_port_configs[1]
            .device_group_configs[0]
            .v6_bgp_config.route_scales
        )
        self.assertEqual([s.network_group_index for s in scales], [0, 1, 2, 3])
        self.assertEqual(
            list(scales[0].v6_route_scale.bgp_communities),
            [TC65_UNDRAIN_COMMUNITY],
        )
        self.assertEqual(
            config.basic_traffic_item_configs[0].name, "RBB_P2_TC65_UNDRAIN"
        )

    def test_tc13_is_not_part_of_policy_suite(self) -> None:
        self.assertNotIn("TC-13", str(BGP_POLICY_PROFILES))


if __name__ == "__main__":
    unittest.main()
