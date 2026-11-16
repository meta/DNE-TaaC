# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from taac.libs.fpf.fpf_warmboot import warmboot_phase_satisfied
from taac.testconfigs.fpf import (
    fpf_hardening_common,
    fpf_shared_injection_suite,
    fpf_tc15_interface_disable,
)
from taac.utils.json_thrift_utils import json_to_thrift
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types


def _params(step) -> dict:
    return json.loads(step.step_params.json_params)


def _custom_step_names(playbook) -> list[str]:
    return [
        name
        for stage in playbook.stages
        for step in stage.steps or []
        if (name := _params(step).get("custom_step_name")) is not None
    ]


def _checks_by_id(playbook) -> dict:
    return {check.check_id: check for check in playbook.postchecks or []}


def _check_params(check) -> dict:
    if check.check_params is None or check.check_params.json_params is None:
        return {}
    return json.loads(check.check_params.json_params)


_RESTART_TOLERANT_CHECK_NAMES = {
    hc_types.CheckName.FPF_HRT_BULK_CONVERGENCE_CHECK,
    hc_types.CheckName.FPF_HRT_REMOTE_FAILURE_CONVERGENCE_CHECK,
    hc_types.CheckName.FPF_PROD_HRT_PREFIX_STABILITY_CHECK,
    hc_types.CheckName.FPF_HRT_PLANE_STATUS_CHECK,
}

_WB_ODS_ENTITIES = [
    f"gtsw{gtsw:03d}.{pod}.c087.mwg2"
    for pod in ("l1002", "l1001")
    for gtsw in range(1, 5)
]
_WB_ODS_ENTITY_DESC = ",".join(_WB_ODS_ENTITIES)


class FpfWarmbootConditionTest(unittest.TestCase):
    def test_complete_requires_all_warmboot_and_session_signals(self) -> None:
        healthy = {
            "hrt.warm_boot.enabled": 1,
            "hrt.warm_boot.ready": 1,
            "hrt.handover.devices_complete": 8,
            "hrt.convergence.state": 1,
            "hrt.subscribers.connected": 32,
        }

        self.assertTrue(warmboot_phase_satisfied(healthy, "complete", 8, 32))
        for key in healthy:
            with self.subTest(key=key):
                degraded = dict(healthy)
                degraded[key] = 0
                self.assertFalse(warmboot_phase_satisfied(degraded, "complete", 8, 32))

    def test_handover_window_requires_converged_but_not_complete(self) -> None:
        in_window = {
            "hrt.warm_boot.enabled": 1,
            "hrt.convergence.state": 1,
            "hrt.handover.devices_complete": 3,
        }

        self.assertTrue(
            warmboot_phase_satisfied(
                in_window,
                "converged_pre_handover",
                8,
                32,
            )
        )
        completed = dict(in_window)
        completed["hrt.handover.devices_complete"] = 8
        self.assertFalse(
            warmboot_phase_satisfied(
                completed,
                "converged_pre_handover",
                8,
                32,
            )
        )

    def test_unknown_phase_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown warmboot phase"):
            warmboot_phase_satisfied({}, "unknown", 8, 32)


class FpfWarmbootNetworkEventConfigTest(unittest.TestCase):
    def test_current_twshared_pair_accepts_single_interface_override(self) -> None:
        with patch.dict(
            os.environ,
            {"TAAC_FPF_LINK_DRAIN_INTERFACE": "eth1/37/1"},
        ):
            interface = fpf_hardening_common.fpf_link_drain_interface(
                ["twshared1354.03.mwg2", "twshared1379.03.mwg2"]
            )

        self.assertEqual(interface, "eth1/37/1")

    def test_shared_suite_contains_wb10_through_wb14(self) -> None:
        config = (
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()
        )
        names = [playbook.name for playbook in config.playbooks]
        expected = [
            "fpf_wb10_interface_disable_warmboot_disrupt",
            "fpf_wb10_interface_disable_warmboot_restore",
            "fpf_wb11_stsw_drain_warmboot",
            "fpf_wb12_link_drain_warmboot_disrupt",
            "fpf_wb12_link_drain_warmboot_restore",
            "fpf_wb13_warmboot_then_link_drain_disrupt",
            "fpf_wb13_warmboot_then_link_drain_restore",
            "fpf_wb14_simultaneous_link_drain_warmboot_disrupt",
            "fpf_wb14_simultaneous_link_drain_warmboot_restore",
        ]

        self.assertTrue(set(expected).issubset(names))
        self.assertEqual([name for name in names if name in expected], expected)
        self.assertTrue(
            {
                "fpf_tc15_interface_disable_disrupt",
                "fpf_tc15_interface_disable_restore",
                "fpf_tc17_link_drain_disrupt",
                "fpf_tc17_link_drain_restore",
                "fpf_tc54_stsw_device_drain_disrupt",
                "fpf_tc35_stsw_undrain_reinject_longevity",
            }.issubset(names)
        )

    def test_warmboot_trigger_order_matches_each_case(self) -> None:
        config = (
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()
        )
        by_name = {playbook.name: playbook for playbook in config.playbooks}

        wb10 = _custom_step_names(
            by_name["fpf_wb10_interface_disable_warmboot_disrupt"]
        )
        self.assertLess(
            wb10.index("fpf_set_interface_admin"), wb10.index("fpf_restart_hrt")
        )
        self.assertLess(
            wb10.index("fpf_restart_hrt"), wb10.index("fpf_wait_hrt_warmboot")
        )

        wb10_restore = _custom_step_names(
            by_name["fpf_wb10_interface_disable_warmboot_restore"]
        )
        self.assertLess(
            wb10_restore.index("fpf_set_interface_admin"),
            wb10_restore.index("fpf_wait_hrt_warmboot"),
        )

        wb12 = _custom_step_names(by_name["fpf_wb12_link_drain_warmboot_disrupt"])
        self.assertLess(
            wb12.index("fpf_drain_interface"), wb12.index("fpf_restart_hrt")
        )
        self.assertLess(
            wb12.index("fpf_restart_hrt"), wb12.index("fpf_wait_hrt_warmboot")
        )

        wb13 = _custom_step_names(by_name["fpf_wb13_warmboot_then_link_drain_disrupt"])
        self.assertLess(
            wb13.index("fpf_restart_hrt"), wb13.index("fpf_wait_hrt_warmboot")
        )
        self.assertLess(
            wb13.index("fpf_wait_hrt_warmboot"), wb13.index("fpf_drain_interface")
        )

        wb14 = _custom_step_names(
            by_name["fpf_wb14_simultaneous_link_drain_warmboot_disrupt"]
        )
        self.assertIn("fpf_restart_hrt_and_link_drain", wb14)

    def test_warmboot_cases_preserve_control_health_check_contracts(self) -> None:
        config = (
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()
        )
        by_name = {playbook.name: playbook for playbook in config.playbooks}
        control_by_warmboot = {
            "fpf_wb10_interface_disable_warmboot_disrupt": "fpf_tc15_interface_disable_disrupt",
            "fpf_wb10_interface_disable_warmboot_restore": "fpf_tc15_interface_disable_restore",
            "fpf_wb12_link_drain_warmboot_disrupt": "fpf_tc17_link_drain_disrupt",
            "fpf_wb12_link_drain_warmboot_restore": "fpf_tc17_link_drain_restore",
            "fpf_wb13_warmboot_then_link_drain_disrupt": "fpf_tc17_link_drain_disrupt",
            "fpf_wb13_warmboot_then_link_drain_restore": "fpf_tc17_link_drain_restore",
            "fpf_wb14_simultaneous_link_drain_warmboot_disrupt": "fpf_tc17_link_drain_disrupt",
            "fpf_wb14_simultaneous_link_drain_warmboot_restore": "fpf_tc17_link_drain_restore",
        }

        for warmboot_name, control_name in control_by_warmboot.items():
            with self.subTest(warmboot=warmboot_name, control=control_name):
                warmboot = by_name[warmboot_name]
                control = by_name[control_name]
                self.assertEqual(warmboot.prechecks, control.prechecks)
                self.assertEqual(warmboot.snapshot_checks, control.snapshot_checks)
                self.assertEqual(
                    [
                        (check.name, check.check_id)
                        for check in warmboot.postchecks or []
                    ],
                    [
                        (check.name, check.check_id)
                        for check in control.postchecks or []
                    ],
                )
                for wb_check, control_check in zip(
                    warmboot.postchecks or [], control.postchecks or []
                ):
                    wb_params = _check_params(wb_check)
                    control_params = _check_params(control_check)
                    if (
                        warmboot_name.endswith("_disrupt")
                        and wb_check.name in _RESTART_TOLERANT_CHECK_NAMES
                    ):
                        self.assertEqual(
                            wb_params.pop("restart_tolerant_hosts"),
                            [fpf_shared_injection_suite.WARMBOOT_HOST],
                        )
                    if wb_check.name == hc_types.CheckName.GENERIC_ODS_CHECK:
                        self.assertEqual(
                            wb_params.pop("entity_desc"), _WB_ODS_ENTITY_DESC
                        )
                        control_params.pop("entity_desc")
                    self.assertEqual(wb_params, control_params)

    def test_wb11_is_one_atomic_drain_warmboot_restore_playbook(self) -> None:
        config = (
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()
        )
        by_name = {playbook.name: playbook for playbook in config.playbooks}
        wb11 = by_name["fpf_wb11_stsw_drain_warmboot"]
        control_disrupt = by_name["fpf_tc54_stsw_device_drain_disrupt"]
        control_restore = by_name["fpf_tc35_stsw_undrain_reinject_longevity"]
        self.assertEqual(
            [name for name in by_name if name.startswith("fpf_wb11_")],
            ["fpf_wb11_stsw_drain_warmboot"],
        )
        self.assertEqual(wb11.prechecks, control_disrupt.prechecks)
        self.assertEqual(
            [(check.name, check.check_id) for check in wb11.postchecks or []],
            [
                (check.name, check.check_id)
                for check in control_restore.postchecks or []
            ],
        )

        steps = [step for stage in wb11.stages for step in stage.steps or []]
        custom_names = [_params(step).get("custom_step_name") for step in steps]
        precondition = _params(steps[0])
        self.assertEqual(precondition["custom_step_name"], "fpf_verify_disruption")
        self.assertEqual(precondition["mode"], "drain")
        self.assertFalse(precondition["expect_drained"])
        self.assertEqual(
            precondition["interfaces"],
            [
                fpf_shared_injection_suite.fpf_link_drain_interface(
                    fpf_shared_injection_suite.GPU_HOSTS
                )
            ],
        )
        restart_index = custom_names.index("fpf_restart_hrt")
        wait_index = custom_names.index("fpf_wait_hrt_warmboot")
        drain_indices = [
            index
            for index, step in enumerate(steps)
            if _params(step).get("custom_step_name") == "fpf_drain_interface"
        ]
        self.assertEqual(len(drain_indices), 2)
        self.assertLess(drain_indices[0], restart_index)
        self.assertLess(restart_index, wait_index)

        validation_index = next(
            index
            for index, step in enumerate(steps)
            if step.name == taac_types.StepName.VALIDATION_STEP
        )
        self.assertLess(wait_index, validation_index)
        self.assertLess(validation_index, drain_indices[1])
        validation_json = steps[validation_index].input_json
        self.assertIsNotNone(validation_json)
        if validation_json is None:
            raise AssertionError("WB-11 mid-stage validation has no input")
        validation = json_to_thrift(validation_json, taac_types.ValidationInput)
        self.assertEqual(validation.stage, taac_types.ValidationStage.MID_TEST)
        self.assertEqual(
            [(check.name, check.check_id) for check in validation.point_in_time_checks],
            [
                (check.name, check.check_id)
                for check in control_disrupt.postchecks or []
            ],
        )

    def test_every_wb_ods_check_uses_four_gtsws_in_both_pods(self) -> None:
        config = (
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()
        )
        warmboot = [
            playbook
            for playbook in config.playbooks
            if playbook.name.startswith("fpf_wb")
        ]
        expected_counts = {
            "fpf_wb10_interface_disable_warmboot_disrupt": 1,
            "fpf_wb10_interface_disable_warmboot_restore": 4,
            "fpf_wb11_stsw_drain_warmboot": 8,
            "fpf_wb12_link_drain_warmboot_disrupt": 0,
            "fpf_wb12_link_drain_warmboot_restore": 4,
            "fpf_wb13_warmboot_then_link_drain_disrupt": 0,
            "fpf_wb13_warmboot_then_link_drain_restore": 4,
            "fpf_wb14_simultaneous_link_drain_warmboot_disrupt": 0,
            "fpf_wb14_simultaneous_link_drain_warmboot_restore": 4,
        }

        self.assertCountEqual([playbook.name for playbook in warmboot], expected_counts)
        for playbook in warmboot:
            checks = list(playbook.postchecks or [])
            if playbook.name == "fpf_wb11_stsw_drain_warmboot":
                validation_step = next(
                    step
                    for stage in playbook.stages
                    for step in stage.steps or []
                    if step.name == taac_types.StepName.VALIDATION_STEP
                )
                validation_json = validation_step.input_json
                self.assertIsNotNone(validation_json)
                if validation_json is None:
                    raise AssertionError("WB-11 validation step has no input")
                checks.extend(
                    json_to_thrift(
                        validation_json, taac_types.ValidationInput
                    ).point_in_time_checks
                )
            ods_checks = [
                check
                for check in checks
                if check.name == hc_types.CheckName.GENERIC_ODS_CHECK
            ]
            self.assertEqual(len(ods_checks), expected_counts[playbook.name])
            for check in ods_checks:
                with self.subTest(playbook=playbook.name, check=check.check_id):
                    self.assertEqual(
                        _check_params(check)["entity_desc"], _WB_ODS_ENTITY_DESC
                    )

    def test_every_wb_disrupt_hrt_check_is_restart_tolerant(self) -> None:
        config = (
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()
        )
        disruptions = [
            playbook
            for playbook in config.playbooks
            if playbook.name.startswith("fpf_wb")
            and (
                playbook.name.endswith("_disrupt")
                or playbook.name == "fpf_wb11_stsw_drain_warmboot"
            )
        ]

        self.assertEqual(len(disruptions), 5)
        for playbook in disruptions:
            checks = list(playbook.postchecks or [])
            if playbook.name == "fpf_wb11_stsw_drain_warmboot":
                validation_step = next(
                    step
                    for stage in playbook.stages
                    for step in stage.steps or []
                    if step.name == taac_types.StepName.VALIDATION_STEP
                )
                validation_json = validation_step.input_json
                self.assertIsNotNone(validation_json)
                if validation_json is None:
                    raise AssertionError("WB-11 validation step has no input")
                checks = list(
                    json_to_thrift(
                        validation_json, taac_types.ValidationInput
                    ).point_in_time_checks
                )
            tolerant_checks = [
                check for check in checks if check.name in _RESTART_TOLERANT_CHECK_NAMES
            ]
            self.assertTrue(tolerant_checks, playbook.name)
            for check in tolerant_checks:
                with self.subTest(playbook=playbook.name, check=check.check_id):
                    self.assertEqual(
                        _check_params(check)["restart_tolerant_hosts"],
                        [fpf_shared_injection_suite.WARMBOOT_HOST],
                    )

    def test_wb10_disrupt_enforces_full_tc15_contract_at_ten_seconds(self) -> None:
        config = (
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()
        )
        by_name = {playbook.name: playbook for playbook in config.playbooks}
        disrupt = by_name["fpf_wb10_interface_disable_warmboot_disrupt"]
        checks = _checks_by_id(disrupt)

        required = {
            "fpf_hrt_bulk_disrupt",
            "fpf_remote_failure_impacted_vf1",
            "fpf_remote_failure_unimpacted_stable_vf1",
            "fpf_remote_failure_unimpacted_stable_vf2",
            "fpf_prod_hrt_prefix_transition",
            "fpf_prod_switch_route_withdrawal",
            "fpf_hrt_fsdb_session_disrupt",
            "fpf_host_spray_disrupt",
            "ods_in_discard_loss_expected",
        }
        self.assertTrue(required.issubset(checks), required - set(checks))

        remote_failure = _check_params(checks["fpf_remote_failure_impacted_vf1"])
        self.assertEqual(remote_failure["max_convergence_sec"], 10)
        transition = _check_params(checks["fpf_prod_hrt_prefix_transition"])
        self.assertEqual(transition["max_transition_sec"], 10)
        self.assertEqual(
            transition["prefixes_by_host"],
            fpf_shared_injection_suite.PROD_PREFIXES_BY_HOST,
        )
        self.assertEqual(
            transition["impacted_planes_by_host"],
            {host: [0] for host in fpf_shared_injection_suite.GPU_HOSTS},
        )
        switch_withdrawal = _check_params(checks["fpf_prod_switch_route_withdrawal"])
        self.assertEqual(switch_withdrawal["mode"], "disruption")
        self.assertEqual(switch_withdrawal["deadline_sec"], 10)
        self.assertCountEqual(
            switch_withdrawal["scalar_expectations"],
            [
                [collector, gtsw, 0]
                for gtsw in fpf_shared_injection_suite.OBSERVER_GTSWS
                for collector in ("bgp_prod_route", "fsdb_prod_route")
            ],
        )

    def test_prod_route_collectors_cover_bgp_and_fsdb_on_both_observers(self) -> None:
        config = (
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()
        )
        collector_task = next(
            task
            for task in config.setup_tasks or []
            if task.task_name == "fpf_start_collectors"
        )
        params_json = collector_task.params.json_params
        self.assertIsNotNone(params_json)
        if params_json is None:
            raise AssertionError("collector task has no JSON params")
        params = json.loads(params_json)
        prod_namespace = next(
            namespace
            for namespace in params["additional_namespaces"]
            if namespace["name"] == "prod_route"
        )

        self.assertEqual(
            prod_namespace["subnet_prefix"],
            fpf_shared_injection_suite.PROD_TARGET_PREFIX,
        )
        self.assertEqual(
            prod_namespace["bgp_gtsws"],
            fpf_shared_injection_suite.OBSERVER_GTSWS,
        )
        self.assertEqual(
            prod_namespace["fsdb_gtsws"],
            fpf_shared_injection_suite.OBSERVER_GTSWS,
        )
        self.assertEqual(prod_namespace["poll_interval_sec"], 1.0)

    def test_wb10_uses_31_sessions_while_down_and_32_after_restore(self) -> None:
        config = (
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()
        )
        by_name = {playbook.name: playbook for playbook in config.playbooks}

        disrupt_waits = [
            _params(step)
            for stage in by_name["fpf_wb10_interface_disable_warmboot_disrupt"].stages
            for step in stage.steps or []
            if _params(step).get("custom_step_name") == "fpf_wait_hrt_warmboot"
        ]
        restore_waits = [
            _params(step)
            for stage in by_name["fpf_wb10_interface_disable_warmboot_restore"].stages
            for step in stage.steps or []
            if _params(step).get("custom_step_name") == "fpf_wait_hrt_warmboot"
        ]

        self.assertEqual(
            [params["expected_subscribers"] for params in disrupt_waits], [31]
        )
        self.assertEqual(
            [params["expected_subscribers"] for params in restore_waits], [32]
        )

    def test_tc15_disruption_sl_as_are_ten_seconds(self) -> None:
        configs = [
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config(),
            fpf_tc15_interface_disable.create_fpf_tc15_test_config(),
        ]
        for config in configs:
            with self.subTest(config=config.name):
                disrupt = next(
                    playbook
                    for playbook in config.playbooks
                    if playbook.name == "fpf_tc15_interface_disable_disrupt"
                )
                checks = _checks_by_id(disrupt)
                self.assertEqual(
                    _check_params(checks["fpf_remote_failure_impacted_vf1"])[
                        "max_convergence_sec"
                    ],
                    10,
                )
                self.assertEqual(
                    _check_params(checks["fpf_prod_hrt_prefix_transition"])[
                        "max_transition_sec"
                    ],
                    10,
                )

    def test_link_drain_cases_cleanup_only_their_owned_mutation(self) -> None:
        config = (
            fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()
        )
        by_name = {playbook.name: playbook for playbook in config.playbooks}
        for base_name in (
            "fpf_wb12_link_drain_warmboot",
            "fpf_wb13_warmboot_then_link_drain",
            "fpf_wb14_simultaneous_link_drain_warmboot",
        ):
            with self.subTest(playbook=base_name):
                disrupt = by_name[f"{base_name}_disrupt"]
                restore = by_name[f"{base_name}_restore"]
                steps = [step for stage in disrupt.stages for step in stage.steps or []]
                mutation = next(
                    _params(step)
                    for step in steps
                    if _params(step).get("custom_step_name")
                    in {
                        "fpf_drain_interface",
                        "fpf_restart_hrt_and_link_drain",
                    }
                )
                cleanup = _params(list(restore.cleanup_steps or [])[0])
                self.assertEqual(cleanup["custom_step_name"], "fpf_conditional_undrain")
                self.assertEqual(cleanup["mutation_token"], mutation["mutation_token"])
                self.assertTrue(cleanup["best_effort"])

    def test_agent_ssh_skip_omits_incomplete_warmboot_cases(self) -> None:
        with patch.dict(os.environ, {"TAAC_FPF_SKIP_TWSHARED_SSH": "1"}):
            config = fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()

        self.assertFalse(
            any(playbook.name.startswith("fpf_wb") for playbook in config.playbooks)
        )

    def test_external_baseline_mode_runs_only_collectors_in_setup(self) -> None:
        with patch.dict(
            os.environ,
            {
                "TAAC_FPF_EXTERNAL_IB_TRAFFIC": "1",
                "TAAC_FPF_PREINJECTED_PREFIXES": "1",
                "TAAC_FPF_COLLECTOR_BASELINE_SEC": "30",
            },
        ):
            config = fpf_shared_injection_suite.create_fpf_shared_injection_suite_test_config()

        setup_tasks = list(config.setup_tasks or [])
        self.assertEqual(
            [task.task_name for task in setup_tasks], ["fpf_start_collectors"]
        )
        collector_json = setup_tasks[0].params.json_params
        self.assertIsNotNone(collector_json)
        if collector_json is None:
            raise AssertionError("collector task has no JSON params")
        collector_params = json.loads(collector_json)
        self.assertEqual(collector_params["baseline_collection_sec"], 30)
        teardown_names = [task.task_name for task in config.teardown_tasks or []]
        self.assertIn("fpf_stop_collectors", teardown_names)
        self.assertIn("fpf_ensure_interfaces_enabled", teardown_names)
        self.assertNotIn("fpf_stop_ib_traffic", teardown_names)
        self.assertNotIn("fpf_withdraw_vf_groups", teardown_names)
        self.assertNotIn("fpf_restart_service", teardown_names)

        custom_steps = {
            _params(step).get("custom_step_name")
            for playbook in config.playbooks
            for stage in playbook.stages
            for step in stage.steps or []
            if step.step_params is not None
        }
        self.assertNotIn("fpf_ensure_traffic", custom_steps)
        self.assertNotIn("fpf_restart_ib_traffic", custom_steps)
        wb11_disrupt = next(
            playbook
            for playbook in config.playbooks
            if playbook.name == "fpf_wb11_stsw_drain_warmboot"
        )
        self.assertIn(
            "fpf_host_spray",
            {check.check_id for check in wb11_disrupt.postchecks or []},
        )


if __name__ == "__main__":
    unittest.main()
