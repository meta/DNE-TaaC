# Copyright (c) Meta Platforms, Inc. and affiliates.

import json
import unittest

from taac.testconfigs.npi.qza_rtsw_dlb_case18_test_config import (
    BoundedChenabCase18Shape,
    build_capability_preflight_commands,
    CASE18_SHAPE,
    QZA_RTSW001_CHENAB_DLB_CASE18_QUICK_TEST_CONFIG,
)
from taac.test_as_a_config import types as taac_types


def _ixia_calls(playbook: taac_types.Playbook) -> list[dict]:
    calls = []
    for stage in playbook.stages or []:
        for step in stage.steps or []:
            if step.name != taac_types.StepName.INVOKE_IXIA_API_STEP:
                continue
            assert step.step_params is not None
            params = json.loads(step.step_params.json_params or "{}")
            params["args"] = json.loads(params.get("args_json") or "{}")
            calls.append(params)
    return calls


class BoundedChenabCase18ShapeTest(unittest.TestCase):
    def test_source_caps_derive_bounded_shape_without_th6_member_constants(
        self,
    ) -> None:
        self.assertEqual(256, CASE18_SHAPE.raw_ars_groups)
        self.assertEqual(75, CASE18_SHAPE.ars_resource_percentage)
        self.assertEqual(2, CASE18_SHAPE.make_before_break_buffer)
        self.assertEqual(190, CASE18_SHAPE.primary_group_ceiling)
        self.assertEqual(0, CASE18_SHAPE.baseline_primary_groups)
        self.assertEqual(190, CASE18_SHAPE.gold_groups)
        self.assertEqual(8, CASE18_SHAPE.silver_groups)
        self.assertEqual(2, CASE18_SHAPE.group_width)
        self.assertEqual(600, CASE18_SHAPE.runtime_sec)
        self.assertEqual(9, CASE18_SHAPE.cycle_count)

    def test_shape_rejects_unverified_or_non_ecmp_inputs(self) -> None:
        with self.assertRaisesRegex(ValueError, "raw_ars_groups"):
            BoundedChenabCase18Shape(raw_ars_groups=0)
        with self.assertRaisesRegex(ValueError, "group_width"):
            BoundedChenabCase18Shape(group_width=1)
        with self.assertRaisesRegex(ValueError, "baseline_primary_groups"):
            BoundedChenabCase18Shape(baseline_primary_groups=190)

    def test_preflight_fails_closed_on_platform_modes_flags_and_baseline(self) -> None:
        preflight_commands = build_capability_preflight_commands(CASE18_SHAPE)
        commands = "\n".join(preflight_commands)
        for required in (
            "MINIPACK3N",
            "flowletSwitchingEnable",
            "enable_ecmp_resource_manager",
            "PER_PACKET_QUALITY",
            "FIXED_ASSIGNMENT",
            "primary_ecmp_groups_count",
            "backup_ecmp_groups_count",
        ):
            self.assertIn(required, commands)
        self.assertIn("1", commands)
        self.assertIn("0", commands)
        self.assertNotIn("ArsObjectId", commands)
        self.assertTrue(
            all(not command.startswith("bash ") for command in preflight_commands)
        )


class QzaRtswDlbCase18ConfigTest(unittest.TestCase):
    def test_config_owns_only_safe_ixia12_ports(self) -> None:
        config = QZA_RTSW001_CHENAB_DLB_CASE18_QUICK_TEST_CONFIG
        self.assertEqual("QZA_RTSW001_CHENAB_DLB_CASE18_QUICK", config.name)
        self.assertEqual(1, len(config.endpoints))
        connections = config.endpoints[0].direct_ixia_connections or []
        self.assertEqual({"1/11", "1/12"}, {c.ixia_port for c in connections})
        self.assertNotIn("1/13", {c.ixia_port for c in connections})
        self.assertNotIn("1/14", {c.ixia_port for c in connections})

    def test_dut_peer_group_negotiates_add_path_for_width_two_routes(self) -> None:
        config = QZA_RTSW001_CHENAB_DLB_CASE18_QUICK_TEST_CONFIG
        peer_group_task = next(
            task
            for task in config.setup_tasks or []
            if task.task_name == "coop_register_patcher"
            and "c_peer_group" in (task.params.json_params or "")
        )
        outer = json.loads(peer_group_task.params.json_params or "{}")
        patcher_args = json.loads(outer["patcher_args"])
        self.assertEqual("BOTH", patcher_args["add_path"])

    def test_rogue_port_gets_existing_flowlet_profile_before_bgp_apply(self) -> None:
        setup_tasks = QZA_RTSW001_CHENAB_DLB_CASE18_QUICK_TEST_CONFIG.setup_tasks or []
        flowlet_task = next(
            task
            for task in setup_tasks
            if task.task_name == "coop_register_patcher"
            and "a0_rogue_flowlet_profile" in (task.params.json_params or "")
        )
        flowlet_outer = json.loads(flowlet_task.params.json_params or "{}")
        self.assertEqual(
            "configure_port_flowlet_config_names",
            flowlet_outer["py_func_name"],
        )
        self.assertEqual(
            {"eth1/2/5": "uplink_flowlet_config"},
            json.loads(flowlet_outer["patcher_args"]),
        )

        apply_configs = []
        for task in setup_tasks:
            if task.task_name != "coop_apply_patchers":
                continue
            apply_configs.append(
                json.loads(task.params.json_params or "{}")["config_name"]
            )
        self.assertEqual(["agent", "bgpcpp"], apply_configs)

    def test_config_has_one_case18_with_nine_off_on_cycles(self) -> None:
        config = QZA_RTSW001_CHENAB_DLB_CASE18_QUICK_TEST_CONFIG
        playbooks = config.playbooks or []
        self.assertEqual(1, len(playbooks))
        playbook = playbooks[0]
        self.assertEqual("CASE_18_DLB_ECMP_FLAP_LONGEVITY_QUICK", playbook.name)
        calls = _ixia_calls(playbook)
        toggles = [c for c in calls if c["api_name"] == "set_dlb_route_pools_active"]
        self.assertEqual(18, len(toggles))
        self.assertEqual(
            [False, True] * 9,
            [c["args"]["active"] for c in toggles],
        )
        self.assertEqual(
            {("DLB_SILVER_PREFIX_POOL_A", "DLB_SILVER_PREFIX_POOL_B")},
            {tuple(c["args"]["pool_names"]) for c in toggles},
        )
        self.assertEqual(
            {8},
            {c["args"]["expected_route_cells"] for c in toggles},
        )

    def test_config_mutates_only_bounded_width_two_gold_and_silver_csvs(self) -> None:
        playbooks = QZA_RTSW001_CHENAB_DLB_CASE18_QUICK_TEST_CONFIG.playbooks or []
        calls = _ixia_calls(playbooks[0])
        mutations = [c for c in calls if c["api_name"] == "apply_pool_mutations"]
        self.assertEqual(2, len(mutations))
        self.assertTrue(all(len(m["args"]["pool_csvs"]) == 2 for m in mutations))
        self.assertEqual(
            {"DLB_GOLD_PREFIX_POOL_A", "DLB_GOLD_PREFIX_POOL_B"},
            {row[1] for row in mutations[0]["args"]["pool_csvs"]},
        )
        self.assertEqual(
            {"DLB_SILVER_PREFIX_POOL_A", "DLB_SILVER_PREFIX_POOL_B"},
            {row[1] for row in mutations[-1]["args"]["pool_csvs"]},
        )

    def test_four_bgp_peers_form_two_equal_as_multipath_pairs(self) -> None:
        config = QZA_RTSW001_CHENAB_DLB_CASE18_QUICK_TEST_CONFIG
        peers_task = next(
            task
            for task in config.setup_tasks or []
            if task.task_name == "coop_register_patcher"
            and "d_peers" in (task.params.json_params or "")
        )
        outer = json.loads(peers_task.params.json_params or "{}")
        patcher_args = json.loads(outer["patcher_args"])
        peers = json.loads(patcher_args["peer_configs"])
        self.assertEqual(4, len(peers))
        self.assertEqual(
            ["4200000211", "4200000211", "4200000212", "4200000212"],
            [peer["remote_as_4_byte"] for peer in peers],
        )

    def test_snapshot_offset_counts_baseline_and_fixed_silver_groups(self) -> None:
        playbooks = QZA_RTSW001_CHENAB_DLB_CASE18_QUICK_TEST_CONFIG.playbooks or []
        playbook = playbooks[0]
        postchecks = playbook.postchecks or []
        dlb_check = postchecks[0]
        assert dlb_check.check_params is not None
        params = json.loads(dlb_check.check_params.json_params or "{}")
        self.assertEqual(8, params["snapshot_expected_extra_groups"])

    def test_programmed_state_checks_use_strict_primary_and_backup_counters(
        self,
    ) -> None:
        playbooks = QZA_RTSW001_CHENAB_DLB_CASE18_QUICK_TEST_CONFIG.playbooks or []
        playbook = playbooks[0]
        serialized = str(playbook)
        self.assertIn("primary_ecmp_groups_count", serialized)
        self.assertIn("backup_ecmp_groups_count", serialized)
        self.assertIn("sleep 5", serialized)
        self.assertNotIn("&& exit 0", serialized)
        self.assertNotIn("ArsObjectId", serialized)
