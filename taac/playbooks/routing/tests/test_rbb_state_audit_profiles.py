# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for immutable RBB state-audit profiles and coverage catalog."""

import json
import unittest
from dataclasses import FrozenInstanceError

from taac.testconfigs.routing.util.bgp_rbb_state_profiles import (
    EXISTING_PR46_TESTPLAN_IDS,
    TESTPLAN_ID_TO_PLAYBOOK,
    RbbAuditCoverage,
    RbbRouteExpectation,
    RbbStateAuditProfile,
    build_rbb_state_audit_profiles,
    select_rbb_state_audit_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology(core_count: int = 2) -> RbbTopology:
    pcs = tuple(
        CorePortChannel(f"port-channel{index + 1}", (f"eth1/{index + 1}",))
        for index in range(core_count)
    )
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="audit-r1.example",
            core_pcs=pcs,
            ixia_edges=(IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="audit-r2.example",
            core_pcs=pcs,
            ixia_edges=(IxiaEdge("eth1/5", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


class RbbStateAuditProfileTest(unittest.TestCase):
    def test_catalog_has_stable_unique_testplan_and_playbook_mapping(self) -> None:
        self.assertEqual(
            list(TESTPLAN_ID_TO_PLAYBOOK),
            [
                "phase1:TC-01",
                "phase1:TC-04",
                "phase1:TC-07",
                "phase2:TC-110",
                "phase2:TC-111",
                "phase2:TC-112",
                "phase1:TC-10",
            ],
        )
        self.assertEqual(
            len(TESTPLAN_ID_TO_PLAYBOOK), len(set(TESTPLAN_ID_TO_PLAYBOOK.values()))
        )
        self.assertEqual(list(TESTPLAN_ID_TO_PLAYBOOK)[-1], "phase1:TC-10")

    def test_pr46_existing_case_is_mapped_but_not_duplicated(self) -> None:
        profiles = build_rbb_state_audit_profiles(_topology())
        self.assertEqual(EXISTING_PR46_TESTPLAN_IDS, {"phase1:TC-04"})
        self.assertNotIn("phase1:TC-04", {profile.testplan_id for profile in profiles})
        self.assertEqual(
            TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-04"], "bgp_rbb_srv6_3_usids"
        )

    def test_default_selection_contains_only_full_runnable_cases(self) -> None:
        selected = select_rbb_state_audit_profiles(
            build_rbb_state_audit_profiles(_topology())
        )
        self.assertEqual(
            [profile.testplan_id for profile in selected],
            ["phase1:TC-01", "phase2:TC-110", "phase2:TC-111"],
        )
        self.assertTrue(
            all(profile.coverage is RbbAuditCoverage.FULL for profile in selected)
        )

    def test_partial_cases_record_gaps_and_require_explicit_opt_in(self) -> None:
        profiles = build_rbb_state_audit_profiles(_topology())
        partial = [
            profile
            for profile in profiles
            if profile.coverage is RbbAuditCoverage.PARTIAL
        ]
        self.assertEqual(
            [profile.testplan_id for profile in partial],
            ["phase1:TC-07", "phase2:TC-112", "phase1:TC-10"],
        )
        self.assertTrue(all(profile.unmet_requirements for profile in partial))
        with self.assertRaisesRegex(ValueError, "allow_partial"):
            select_rbb_state_audit_profiles(profiles, [partial[0].testplan_id])
        self.assertEqual(
            select_rbb_state_audit_profiles(
                profiles, [partial[0].testplan_id], allow_partial=True
            ),
            (partial[0],),
        )

    def test_unknown_duplicate_and_existing_only_selection_fail_closed(self) -> None:
        profiles = build_rbb_state_audit_profiles(_topology())
        with self.assertRaisesRegex(ValueError, "unknown"):
            select_rbb_state_audit_profiles(profiles, ["phase9:TC-999"])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            select_rbb_state_audit_profiles(profiles, ["phase1:TC-01", "phase1:TC-01"])
        with self.assertRaisesRegex(ValueError, "already covered"):
            select_rbb_state_audit_profiles(profiles, ["phase1:TC-04"])

    def test_multi_core_topology_expands_one_ndp_expectation_per_core_and_dut(
        self,
    ) -> None:
        profile = next(
            profile
            for profile in build_rbb_state_audit_profiles(_topology(3))
            if profile.testplan_id == "phase2:TC-111"
        )
        self.assertEqual(len(profile.ndp), 6)
        self.assertEqual(
            [(item.role, item.interface) for item in profile.ndp],
            [
                ("r1", "eth1/1"),
                ("r1", "eth1/2"),
                ("r1", "eth1/3"),
                ("r2", "eth1/1"),
                ("r2", "eth1/2"),
                ("r2", "eth1/3"),
            ],
        )
        self.assertTrue(all(item.address_scope == "link_local" for item in profile.ndp))

    def test_openr_inventory_is_exact_and_fib_required_on_both_duts(self) -> None:
        profile = next(
            profile
            for profile in build_rbb_state_audit_profiles(_topology())
            if profile.testplan_id == "phase1:TC-01"
        )
        self.assertEqual(len(profile.routes), 4)
        self.assertEqual({route.role for route in profile.routes}, {"r1", "r2"})
        self.assertTrue(all(route.client == "OPENR" for route in profile.routes))
        self.assertTrue(all(route.require_fib for route in profile.routes))
        self.assertTrue(all(route.next_hop_count == 2 for route in profile.routes))
        self.assertTrue(
            all(route.next_hop_interface_count == 2 for route in profile.routes)
        )
        self.assertTrue(
            all(route.next_hop_scope == "link_local" for route in profile.routes)
        )
        self.assertEqual(
            {route.prefix.split("/")[-1] for route in profile.routes}, {"32", "128"}
        )

    def test_openr_reachability_requires_link_local_ecmp_per_core_path(self) -> None:
        profile = next(
            profile
            for profile in build_rbb_state_audit_profiles(_topology(3))
            if profile.testplan_id == "phase2:TC-110"
        )
        self.assertEqual(len(profile.routes), 4)
        self.assertTrue(all(route.next_hop_count == 3 for route in profile.routes))
        self.assertTrue(
            all(route.next_hop_interface_count == 3 for route in profile.routes)
        )
        self.assertTrue(
            all(route.next_hop_scope == "link_local" for route in profile.routes)
        )

    def test_profile_metadata_and_resolved_route_contract_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid RBB testplan ID"):
            RbbStateAuditProfile(
                testplan_id="TC-1",
                playbook_name="bad",
                title="bad",
                coverage=RbbAuditCoverage.FULL,
                routes=(RbbRouteExpectation("r1", "192.0.2.2/32", "OPENR"),),
            )
        with self.assertRaisesRegex(ValueError, "require_fib"):
            RbbRouteExpectation(
                "r1",
                "192.0.2.2/32",
                "OPENR",
                require_fib=False,
                next_hop_count=2,
            )

    def test_target_roles_are_immutable_validated_and_exact(self) -> None:
        r2_route = (RbbRouteExpectation("r2", "192.0.2.1/32", "OPENR"),)
        profile = RbbStateAuditProfile(
            testplan_id="phase2:TC-1",
            playbook_name="rbb_r2_only",
            title="R2-only state audit",
            coverage=RbbAuditCoverage.FULL,
            target_roles=("r2",),
            routes=r2_route,
        )
        self.assertEqual(profile.target_roles, ("r2",))
        self.assertTrue(profile.to_task_params("r2")["routes"])
        with self.assertRaisesRegex(ValueError, "does not target"):
            profile.to_task_params("r1")

        common = {
            "testplan_id": "phase2:TC-2",
            "playbook_name": "invalid_target_roles",
            "title": "invalid target roles",
            "coverage": RbbAuditCoverage.FULL,
            "routes": r2_route,
        }
        with self.assertRaisesRegex(TypeError, "immutable tuple"):
            RbbStateAuditProfile(**common, target_roles=["r2"])  # pyre-ignore[6]
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            RbbStateAuditProfile(**common, target_roles=())
        with self.assertRaisesRegex(ValueError, "duplicates"):
            RbbStateAuditProfile(**common, target_roles=("r2", "R2"))
        with self.assertRaisesRegex(ValueError, "must be 'r1' or 'r2'"):
            RbbStateAuditProfile(**common, target_roles=("tail",))
        with self.assertRaisesRegex(ValueError, "exactly match"):
            RbbStateAuditProfile(**common, target_roles=("r1", "r2"))

    def test_profiles_are_frozen_and_task_projection_is_json_safe(self) -> None:
        profile = build_rbb_state_audit_profiles(_topology())[0]
        with self.assertRaises(FrozenInstanceError):
            profile.title = "mutated"  # pyre-ignore[41]
        for role in ("r1", "r2"):
            payload = profile.to_task_params(role)
            json.dumps(payload)
            self.assertTrue(payload["routes"])


if __name__ == "__main__":
    unittest.main()
