# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

# pyre-unsafe

"""Structural coverage for the MWG2 twshared standalone campaign."""

import importlib
import json
import os
import unittest
from unittest.mock import patch, PropertyMock

from taac.libs.fpf import fpf_prod_prefix_map
from taac.libs.fpf.fpf_host_profiles import (
    MWG2_TWSHARED_1354_1379,
)
from taac.libs.fpf.fpf_stress_checks import (
    DEFAULT_SCALE_RECOVERY_POLL_DURATION_BUDGET_SEC,
)
from taac.testconfigs.fpf import (
    fpf_hardening_common,
    fpf_shared_injection_suite,
    fpf_tc32_downlink_flaps,
    fpf_tc33_gtsw_stsw_links_down,
    fpf_tc35_stsw_undrain_reinject,
    fpf_tc36_stsw_all_connections_down,
    fpf_tc37_nic_side_link_flap,
    fpf_tc38_persistent_ndp_clear,
    fpf_tc40_cont_interface_flaps,
    fpf_tc42_cont_flaps_wedge_restart,
    fpf_tc43_cont_flaps_bgp_restart,
    fpf_tc44_cont_flaps_fsdb_restart,
    fpf_tc45_scale_up_4k_8k,
    fpf_tc46_scale_down_8k_4k,
    fpf_tc54_stsw_device_drain,
    fpf_tc55_gtsw_device_reboot,
)
from taac.test_as_a_config import types as taac_types

SERVER = "twshared1352.03.mwg2"
CLIENT = "twshared1388.03.mwg2"
TW_ENV = {
    "FPF_GPU_HOSTS": f"{SERVER},{CLIENT}",
    "FPF_HRT_DEVICE_IDS": "0,1,2,3,4,5,6,7",
    "FPF_HRT_LANES": "0,1,2,3",
    "FPF_HRT_VF1_DEVICE_IDS": "0,2,4,6",
    "FPF_HRT_VF2_DEVICE_IDS": "1,3,5,7",
    "FPF_VF_GROUP_PODS": "16",
    "FPF_VF_PREFIXES_PER_POD": "252",
    "TAAC_FPF_IB_BINARY": "/root/ib_write_bw",
    "TAAC_FPF_IB_DEVICE": "mlx5_bveth0",
    "TAAC_FPF_LINK_DRAIN_INTERFACE": "eth1/41/5",
}
MODULES = [
    fpf_tc33_gtsw_stsw_links_down,
    fpf_tc35_stsw_undrain_reinject,
    fpf_tc36_stsw_all_connections_down,
    fpf_tc37_nic_side_link_flap,
    fpf_tc38_persistent_ndp_clear,
    fpf_tc40_cont_interface_flaps,
    fpf_tc42_cont_flaps_wedge_restart,
    fpf_tc43_cont_flaps_bgp_restart,
    fpf_tc44_cont_flaps_fsdb_restart,
    fpf_tc45_scale_up_4k_8k,
    fpf_tc46_scale_down_8k_4k,
    fpf_tc54_stsw_device_drain,
    fpf_tc55_gtsw_device_reboot,
]


def _params(value) -> dict:
    return json.loads(value.params.json_params)


def _step_params(value) -> dict:
    return json.loads(value.step_params.json_params)


def _steps(playbook) -> list:
    return [step for stage in playbook.stages for step in (stage.steps or [])]


class TestTwsharedCampaignConfigs(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.env = patch.dict(os.environ, TW_ENV)
        cls.env.start()
        os.environ.pop("TAAC_FPF_SKIP_SSH_DEPS", None)
        os.environ.pop("TAAC_FPF_SKIP_IB_TRAFFIC", None)
        importlib.reload(fpf_hardening_common)
        for module in MODULES:
            importlib.reload(module)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.env.stop()

    def test_all_requested_configs_use_exact_8x4_collectors_and_traffic(self):
        configs = [
            module.TEST_CONFIG
            for module in MODULES
            if module is not fpf_tc40_cont_interface_flaps
        ]
        self.assertEqual(len(configs), 12)
        for config in configs:
            with self.subTest(config=config.name):
                collector = next(
                    task
                    for task in config.setup_tasks
                    if task.task_name == "fpf_start_collectors"
                )
                collector_params = _params(collector)
                self.assertEqual(collector_params["hosts"], [SERVER, CLIENT])
                self.assertEqual(collector_params["hrt_device_ids"], list(range(8)))
                self.assertEqual(collector_params["hrt_plane_ids"], [0, 1, 2, 3])
                self.assertEqual(collector_params["subnet_prefix"], "5000::/16")
                self.assertEqual(
                    set(collector_params["prod_prefixes_by_host"]),
                    {SERVER, CLIENT},
                )

                traffic = next(
                    task
                    for task in config.setup_tasks
                    if task.task_name == "fpf_start_ib_traffic"
                )
                traffic_params = _params(traffic)
                self.assertEqual(traffic_params["server"], SERVER)
                self.assertEqual(traffic_params["clients"], [CLIENT])
                self.assertEqual(traffic_params["binary_path"], "/root/ib_write_bw")
                self.assertEqual(traffic_params["device"], "mlx5_bveth0")
                self.assertEqual(traffic_params["gid_iface"], "bveth0")

    def test_restart_flap_cases_inherit_tc40_fail_closed_contract(self):
        expected = {
            fpf_tc42_cont_flaps_wedge_restart.TEST_CONFIG.name: taac_types.Service.AGENT,
            fpf_tc43_cont_flaps_bgp_restart.TEST_CONFIG.name: taac_types.Service.BGP,
            fpf_tc44_cont_flaps_fsdb_restart.TEST_CONFIG.name: taac_types.Service.FSDB,
        }
        for module in (
            fpf_tc42_cont_flaps_wedge_restart,
            fpf_tc43_cont_flaps_bgp_restart,
            fpf_tc44_cont_flaps_fsdb_restart,
        ):
            with self.subTest(config=module.TEST_CONFIG.name):
                flap = next(
                    step
                    for step in _steps(module.TEST_CONFIG.playbooks[0])
                    if _step_params(step).get("custom_step_name")
                    == "fpf_multi_gtsw_rapid_flap"
                )
                params = _step_params(flap)
                self.assertTrue(params["fail_closed"])
                self.assertTrue(params["require_exact_neighbor_hosts"])
                self.assertEqual(
                    params["expected_interfaces"],
                    ["eth1/41/5", "eth1/41/6", "eth1/41/7", "eth1/41/8"],
                )
                self.assertEqual(params["duration_sec"], 300)
                self.assertEqual(params["down_time_sec"], 7.0)
                self.assertEqual(params["up_time_sec"], 7.0)
                self.assertEqual(params["churn_every_sec"], 120)
                self.assertEqual(
                    params["churn_service"],
                    int(expected[module.TEST_CONFIG.name].value),
                )

    def test_mapping_sensitive_cases_use_validated_server_circuit(self):
        self.assertEqual(
            [c.a_end_interface for c in fpf_tc36_stsw_all_connections_down.CIRCUITS],
            ["eth1/41/5", "eth1/41/6", "eth1/41/7", "eth1/41/8"],
        )
        nic_down = next(
            step
            for step in _steps(fpf_tc37_nic_side_link_flap.TEST_CONFIG.playbooks[0])
            if _step_params(step).get("custom_step_name") == "fpf_nic_mstreg_paos"
        )
        self.assertEqual(
            _step_params(nic_down),
            {
                "custom_step_name": "fpf_nic_mstreg_paos",
                "host": SERVER,
                "dev": 0,
                "lane": 0,
                "admin_up": False,
                "state_timeout_sec": 30.0,
                "state_poll_interval_sec": 1.0,
                "verify_link_health": False,
            },
        )

        tc38_spray = next(
            check
            for check in fpf_tc38_persistent_ndp_clear.TEST_CONFIG.playbooks[
                0
            ].postchecks
            if check.check_id == "ndp_clear_host_spray"
        )
        self.assertEqual(
            json.loads(tc38_spray.check_params.json_params)["excluded_lanes_by_host"],
            {SERVER: ["beth0"]},
        )
        tc38_clear = next(
            step
            for step in _steps(fpf_tc38_persistent_ndp_clear.TEST_CONFIG.playbooks[0])
            if _step_params(step).get("custom_step_name") == "fpf_ndp_clear_loop"
        )
        self.assertEqual(
            _step_params(tc38_clear),
            {
                "custom_step_name": "fpf_ndp_clear_loop",
                "target_interface": "eth1/41/5",
                "neighbor_host": SERVER,
                "every_sec": 4,
                "duration_sec": 120,
            },
        )
        tc38_stable = next(
            playbook
            for playbook in fpf_shared_injection_suite.TEST_CONFIG.playbooks
            if playbook.name == "fpf_tc38_persistent_ndp_clear_stable"
        )
        historical_ids = {
            "fpf_prod_hrt_prefix_stability_precheck",
            "fpf_hrt_system_memory_precheck",
            "fpf_hrt_driver_disconnect_precheck",
        }
        self.assertTrue(
            historical_ids.isdisjoint(
                {
                    check.check_id
                    for check in (tc38_stable.prechecks or [])
                    if check.check_id
                }
            )
        )
        tc38_stable_custom_names = [
            _step_params(step).get("custom_step_name")
            for step in _steps(tc38_stable)
            if step.name == taac_types.StepName.CUSTOM_STEP
        ]
        self.assertIn("fpf_verify_recovered_state", tc38_stable_custom_names)
        self.assertIn("record_fpf_recovered_baseline_time", tc38_stable_custom_names)

    def test_stsw_drain_reinject_is_split_and_has_scoped_cleanup(self):
        tc35_steps = _steps(fpf_tc35_stsw_undrain_reinject.TEST_CONFIG.playbooks[0])
        tc35_injections = [
            _step_params(step)
            for step in tc35_steps
            if step.name == taac_types.StepName.FPF_BGP_PREFIX_INJECTION_STEP
        ]
        self.assertEqual(
            {params["prefix_base"] for params in tc35_injections},
            {"5000:dd::/64", "5000:ee::/64"},
        )

        tc54 = fpf_tc54_stsw_device_drain.TEST_CONFIG
        drain = next(
            step
            for step in _steps(tc54.playbooks[0])
            if _step_params(step).get("custom_step_name") == "fpf_drain_interface"
            and _step_params(step).get("is_drain")
        )
        self.assertEqual(
            _step_params(drain)["target_device"],
            fpf_tc54_stsw_device_drain.DRAIN_TARGET_STSW,
        )
        cleanup = list(tc54.playbooks[0].cleanup_steps or [])
        self.assertEqual(
            _step_params(cleanup[0])["target_device"],
            fpf_tc54_stsw_device_drain.DRAIN_TARGET_STSW,
        )
        self.assertFalse(_step_params(cleanup[0])["is_drain"])
        self.assertEqual(
            {
                _step_params(step)["prefix_base"]
                for step in cleanup[1:]
                if step.name == taac_types.StepName.FPF_BGP_PREFIX_INJECTION_STEP
            },
            {"5000:dd::/64", "5000:ee::/64"},
        )
        drain_check = next(
            check
            for check in tc54.playbooks[0].postchecks
            if check.check_id == "fpf_hrt_plane_status_drain"
        )
        drain_params = json.loads(drain_check.check_params.json_params)
        self.assertEqual(drain_params["mode"], "drain")
        self.assertEqual(drain_params["expected_planes"], [0, 1, 2, 3])
        self.assertEqual(
            drain_params["impacted_tuples_by_host_device"],
            {
                host: {"0": [0], "2": [0], "4": [0], "6": [0]}
                for host in (SERVER, CLIENT)
            },
        )

    def test_scale_cases_render_two_vf_operations_per_scale_transition(self):
        tc45_steps = [
            _step_params(step)
            for step in _steps(fpf_tc45_scale_up_4k_8k.TEST_CONFIG.playbooks[0])
            if step.name == taac_types.StepName.FPF_BGP_PREFIX_INJECTION_STEP
        ]
        self.assertEqual(
            [params["count"] for params in tc45_steps], [4000, 4000, 8000, 8000]
        )
        self.assertEqual(
            [params["prefix_base"] for params in tc45_steps],
            ["5000:dd::/64", "5000:ee::/64", "5000:dd::/64", "5000:ee::/64"],
        )

        tc46_steps = [
            _step_params(step)
            for step in _steps(fpf_tc46_scale_down_8k_4k.TEST_CONFIG.playbooks[0])
            if step.name == taac_types.StepName.FPF_BGP_PREFIX_INJECTION_STEP
        ]
        self.assertEqual(
            [params["withdraw_only"] for params in tc46_steps],
            [False, False, True, True],
        )
        self.assertEqual(
            [params["prefix_base"] for params in tc46_steps[-2:]],
            ["5000:dd:fa0::/64", "5000:ee:fa0::/64"],
        )

    def test_tc45_has_exact_4k_checkpoint_before_8k_mutation(self):
        playbook = fpf_tc45_scale_up_4k_8k.TEST_CONFIG.playbooks[0]
        steps = _steps(playbook)
        descriptions = [step.description or "" for step in steps]
        checkpoint = next(
            step
            for step in steps
            if step.name == taac_types.StepName.VALIDATION_STEP
            and "exact 4K" in (step.description or "")
        )
        checkpoint_index = steps.index(checkpoint)
        scale_up_index = descriptions.index("Scale up: 8000 prefixes from 5000:dd::/64")
        marker_index = descriptions.index("Record TC45 4K-to-8K mutation time")
        self.assertLess(checkpoint_index, marker_index)
        self.assertEqual(marker_index + 1, scale_up_index)

        rendered = json.loads(checkpoint.input_json)["point_in_time_checks"]
        by_id = {check["check_id"]: check for check in rendered}
        count_checks = [
            check
            for check_id, check in by_id.items()
            if check_id.startswith("fpf_tc45_4k_fsdb_")
            or check_id.startswith("fpf_tc45_4k_bgp_")
            or check_id.startswith("fpf_tc45_4k_hrt_lane")
        ]
        self.assertEqual(len(count_checks), 8)
        for check in count_checks:
            params = json.loads(check["check_params"]["json_params"])
            self.assertTrue(params["use_mutation_time"])
            self.assertTrue(params["require_final_exact"])
        session_params = json.loads(
            by_id["fpf_tc45_4k_hrt_sessions"]["check_params"]["json_params"]
        )
        self.assertEqual(session_params["expected_session_count"], 32)
        self.assertEqual(session_params["device_ids"], list(range(8)))
        self.assertEqual(session_params["planes_per_device"], 4)
        traffic_params = json.loads(
            by_id["fpf_tc45_4k_traffic"]["check_params"]["json_params"]
        )
        self.assertEqual(traffic_params["hosts"], [SERVER, CLIENT])
        self.assertEqual(traffic_params["lookback_sec"], 60)

    def test_scale_playbooks_use_baseline_and_mutation_windows(self):
        for module in (fpf_tc45_scale_up_4k_8k, fpf_tc46_scale_down_8k_4k):
            with self.subTest(config=module.TEST_CONFIG.name):
                ramp = module.TEST_CONFIG.playbooks[0]
                prechecks = {
                    check.check_id: check for check in ramp.prechecks if check.check_id
                }
                for check_id in (
                    "fpf_prod_hrt_prefix_stability_precheck",
                    "fpf_hrt_system_memory_precheck",
                    "fpf_hrt_driver_disconnect_precheck",
                ):
                    precheck_params = json.loads(
                        prechecks[check_id].check_params.json_params
                    )
                    self.assertEqual(precheck_params["lookback_sec"], 120)
                    self.assertFalse(precheck_params["use_test_case_start_time"])

                convergence = [
                    check
                    for check in ramp.postchecks
                    if check.check_id
                    and (
                        "convergence_lane" in check.check_id
                        or "remote_failure_stable" in check.check_id
                    )
                ]
                self.assertTrue(convergence)
                for check in convergence:
                    params = json.loads(check.check_params.json_params)
                    self.assertTrue(params["use_mutation_time"])
                    if "remote_failure" in check.check_id:
                        self.assertEqual(params["direction"], "scale_recovery")
                        self.assertEqual(params["poll_grace_sec"], 10.0)
                        self.assertEqual(params["poll_interval_sec"], 5.0)
                        self.assertEqual(
                            params["poll_duration_budget_sec"],
                            DEFAULT_SCALE_RECOVERY_POLL_DURATION_BUDGET_SEC,
                        )
                    else:
                        self.assertTrue(params["require_final_exact"])

                observation_steps = [
                    step
                    for step in _steps(ramp)
                    if step.name == taac_types.StepName.LONGEVITY_STEP
                    and "exact 60s stable tail" in (step.description or "")
                ]
                self.assertEqual(len(observation_steps), 2)
                expected_observation = int(
                    module.SCALE_RECOVERY_SLA_SEC
                    + module.SCALE_RECOVERY_STABILITY_SEC
                    + 2 * module.COLLECTOR_POLL_INTERVAL_SEC
                    + DEFAULT_SCALE_RECOVERY_POLL_DURATION_BUDGET_SEC
                )
                self.assertEqual(module.SCALE_OBSERVATION_SEC, expected_observation)
                self.assertTrue(
                    all(
                        _step_params(step)["duration"] == expected_observation
                        for step in observation_steps
                    )
                )
                collector = next(
                    task
                    for task in module.TEST_CONFIG.setup_tasks
                    if task.task_name == "fpf_start_collectors"
                )
                self.assertEqual(
                    _params(collector)["poll_interval_sec"],
                    module.COLLECTOR_POLL_INTERVAL_SEC,
                )

    def test_recovered_disruption_longevity_qualifies_before_soak(self):
        recovered = (
            fpf_tc33_gtsw_stsw_links_down,
            fpf_tc35_stsw_undrain_reinject,
            fpf_tc40_cont_interface_flaps,
            fpf_tc42_cont_flaps_wedge_restart,
            fpf_tc43_cont_flaps_bgp_restart,
            fpf_tc44_cont_flaps_fsdb_restart,
        )
        for module in recovered:
            with self.subTest(config=module.TEST_CONFIG.name):
                longevity = module.TEST_CONFIG.playbooks[-1]
                prechecks = {
                    check.check_id: check
                    for check in longevity.prechecks or []
                    if check.check_id
                }
                for check_id in (
                    "fpf_prod_hrt_prefix_stability_precheck",
                    "fpf_hrt_system_memory_precheck",
                    "fpf_hrt_driver_disconnect_precheck",
                ):
                    self.assertNotIn(check_id, prechecks)

                steps = _steps(longevity)
                gate = next(
                    index
                    for index, step in enumerate(steps)
                    if _step_params(step).get("custom_step_name")
                    == "fpf_verify_recovered_state"
                )
                anchor = next(
                    index
                    for index, step in enumerate(steps)
                    if _step_params(step).get("custom_step_name")
                    == "record_fpf_recovered_baseline_time"
                )
                self.assertLess(gate, anchor)
                self.assertEqual(_step_params(steps[anchor + 1])["duration"], 120)
                self.assertEqual(_step_params(steps[anchor + 2])["duration"], 300)
                gate_params = _step_params(steps[gate])
                self.assertEqual(gate_params["future_timestamp_grace_sec"], 1.0)
                self.assertEqual(
                    gate_params["device_planes_by_host"],
                    {
                        host: {str(device_id): [0, 1, 2, 3] for device_id in range(8)}
                        for host in (SERVER, CLIENT)
                    },
                )
                for expectations in gate_params[
                    "prod_prefix_expectations_by_host"
                ].values():
                    for state in expectations.values():
                        self.assertEqual(state["device_ids"], [0])
                        self.assertEqual(state["reachable_planes"], [0, 1, 2, 3])
                        self.assertEqual(state["unreachable_planes"], [])
                        self.assertEqual(state["plane_up"], [0, 1, 2, 3])

                collector = next(
                    task
                    for task in module.TEST_CONFIG.setup_tasks
                    if task.task_name == "fpf_start_collectors"
                )
                self.assertEqual(
                    _params(collector)["fsdb_session_hosts"], [SERVER, CLIENT]
                )
                collector_params = _params(collector)
                expected_prod_hosts = set(
                    collector_params.get("prod_prefixes_by_host", {})
                ) or {collector_params["prod_prefix_host"]}
                self.assertEqual(
                    set(gate_params["prod_prefix_expectations_by_host"]),
                    expected_prod_hosts,
                )

    def test_tc46_has_exact_8k_checkpoint_before_withdrawal(self):
        playbook = fpf_tc46_scale_down_8k_4k.TEST_CONFIG.playbooks[0]
        steps = _steps(playbook)
        descriptions = [step.description or "" for step in steps]
        checkpoint = next(
            step
            for step in steps
            if step.name == taac_types.StepName.VALIDATION_STEP
            and "exact 8K" in (step.description or "")
        )
        baseline_marker = descriptions.index(
            "Record TC46 8K scale-baseline mutation time"
        )
        checkpoint_index = steps.index(checkpoint)
        withdrawal_marker = descriptions.index("Record TC46 8K-to-4K mutation time")
        first_withdrawal = next(
            index
            for index, step in enumerate(steps)
            if step.name == taac_types.StepName.FPF_BGP_PREFIX_INJECTION_STEP
            and _step_params(step)["withdraw_only"]
        )
        self.assertLess(baseline_marker, checkpoint_index)
        self.assertLess(checkpoint_index, withdrawal_marker)
        self.assertEqual(withdrawal_marker + 1, first_withdrawal)

        rendered = json.loads(checkpoint.input_json)["point_in_time_checks"]
        by_id = {check["check_id"]: check for check in rendered}
        count_checks = [
            check
            for check_id, check in by_id.items()
            if check_id.startswith("fpf_tc46_8k_fsdb_")
            or check_id.startswith("fpf_tc46_8k_bgp_")
            or check_id.startswith("fpf_tc46_8k_hrt_lane")
        ]
        self.assertEqual(len(count_checks), 8)
        for check in count_checks:
            params = json.loads(check["check_params"]["json_params"])
            expected = params.get("expected_matched") or next(
                iter(params["expected_per_lane"].values())
            )
            self.assertEqual(expected, 8000)
            self.assertTrue(params["use_mutation_time"])
            self.assertTrue(params["require_final_exact"])
        rf_checks = [
            check
            for check_id, check in by_id.items()
            if check_id.startswith("fpf_tc46_8k_remote_failure_")
        ]
        self.assertEqual(len(rf_checks), 2)
        for check in rf_checks:
            params = json.loads(check["check_params"]["json_params"])
            self.assertEqual(params["direction"], "scale_recovery")
            self.assertEqual(params["max_convergence_sec"], 120)
            self.assertEqual(params["recovery_stability_sec"], 60.0)
            self.assertEqual(params["poll_grace_sec"], 10.0)
            self.assertEqual(params["poll_interval_sec"], 5.0)
            self.assertEqual(
                params["poll_duration_budget_sec"],
                DEFAULT_SCALE_RECOVERY_POLL_DURATION_BUDGET_SEC,
            )
        session_params = json.loads(
            by_id["fpf_tc46_8k_hrt_sessions"]["check_params"]["json_params"]
        )
        self.assertEqual(session_params["expected_session_count"], 32)
        self.assertEqual(session_params["device_ids"], list(range(8)))
        traffic_params = json.loads(
            by_id["fpf_tc46_8k_traffic"]["check_params"]["json_params"]
        )
        self.assertEqual(traffic_params["hosts"], [SERVER, CLIENT])
        self.assertEqual(traffic_params["lookback_sec"], 60)

    def test_tc55_reboot_is_explicitly_dut_scoped(self):
        reboot = next(
            step
            for step in _steps(fpf_tc55_gtsw_device_reboot.TEST_CONFIG.playbooks[0])
            if step.name == taac_types.StepName.SYSTEM_REBOOT_STEP
        )
        self.assertEqual(
            list(reboot.device_regexes or []),
            [fpf_tc55_gtsw_device_reboot.OBSERVER_GTSWS[0]],
        )


class TestNamedHostPairProfile(unittest.TestCase):
    PROFILE = "mwg2_twshared_1354_1379"
    SERVER = "twshared1354.03.mwg2"
    CLIENT = "twshared1379.03.mwg2"
    PROFILE_ENV = {
        "TAAC_FPF_HOST_PROFILE": PROFILE,
        # A selected profile supplies these host-derived values. Empty legacy
        # overrides must not be required to instantiate the suite.
        "FPF_GPU_HOSTS": "",
        "FPF_HRT_DEVICE_IDS": "",
        "FPF_HRT_LANES": "",
        "FPF_HRT_VF1_DEVICE_IDS": "",
        "FPF_HRT_VF2_DEVICE_IDS": "",
        "TAAC_FPF_IB_DEVICE": "",
        "TAAC_FPF_LINK_DRAIN_INTERFACE": "",
    }

    def tearDown(self) -> None:
        # Leave module globals in their default state for tests that share this
        # process, regardless of an assertion or import-time failure above.
        os.environ.pop("TAAC_FPF_HOST_PROFILE", None)
        for name in self.PROFILE_ENV:
            if name != "TAAC_FPF_HOST_PROFILE" and os.environ.get(name) == "":
                os.environ.pop(name, None)
        importlib.reload(fpf_prod_prefix_map)
        importlib.reload(fpf_hardening_common)
        importlib.reload(fpf_shared_injection_suite)

    def test_one_profile_instantiates_new_pair_and_all_host_artifacts(self) -> None:
        with patch.dict(os.environ, self.PROFILE_ENV, clear=False):
            importlib.reload(fpf_prod_prefix_map)
            importlib.reload(fpf_hardening_common)
            importlib.reload(fpf_tc32_downlink_flaps)
            for module in MODULES:
                importlib.reload(module)
            importlib.reload(fpf_shared_injection_suite)

            self.assertEqual(
                fpf_hardening_common.HOST_PROFILE_NAME,
                self.PROFILE,
            )
            self.assertEqual(
                fpf_hardening_common.GPU_HOSTS,
                [self.SERVER, self.CLIENT],
            )
            self.assertEqual(
                fpf_hardening_common.fpf_link_drain_interface(),
                "eth1/37/1",
            )
            self.assertEqual(
                fpf_hardening_common.fpf_gpu_downlink_interfaces(),
                ["eth1/37/1", "eth1/37/2", "eth1/37/3", "eth1/37/4"],
            )
            self.assertEqual(
                fpf_hardening_common.fpf_hrt_device_ids(),
                list(range(8)),
            )
            self.assertEqual(fpf_hardening_common.fpf_hrt_lanes(), [0, 1, 2, 3])
            self.assertEqual(
                fpf_hardening_common.fpf_hrt_vf_device_ids(list(range(8))),
                ([0, 2, 4, 6], [1, 3, 5, 7]),
            )
            traffic = fpf_hardening_common.fpf_ib_traffic_config()
            self.assertEqual(traffic["server"], self.SERVER)
            self.assertEqual(traffic["clients"], [self.CLIENT])
            self.assertEqual(traffic["device"], "mlx5_bveth0")
            self.assertEqual(traffic["gid_iface"], "bveth0")
            self.assertEqual(traffic["gid_prefix"], "2401")

            self.assertEqual(
                fpf_prod_prefix_map.get_hrt_device_prefixes(self.SERVER),
                {
                    0: "2401:db00:292a:a270::/64",
                    1: "2401:db00:292a:a570::/64",
                    2: "2401:db00:292a:a271::/64",
                    3: "2401:db00:292a:a571::/64",
                    4: "2401:db00:292a:a272::/64",
                    5: "2401:db00:292a:a572::/64",
                    6: "2401:db00:292a:a273::/64",
                    7: "2401:db00:292a:a573::/64",
                },
            )
            self.assertEqual(
                fpf_prod_prefix_map.get_hrt_device_prefixes(self.CLIENT),
                {
                    0: "2401:db00:292a:a15c::/64",
                    1: "2401:db00:292a:a45c::/64",
                    2: "2401:db00:292a:a15d::/64",
                    3: "2401:db00:292a:a45d::/64",
                    4: "2401:db00:292a:a15e::/64",
                    5: "2401:db00:292a:a45e::/64",
                    6: "2401:db00:292a:a15f::/64",
                    7: "2401:db00:292a:a45f::/64",
                },
            )

            suite = fpf_shared_injection_suite.TEST_CONFIG
            collector = next(
                task
                for task in suite.setup_tasks or []
                if task.task_name == "fpf_start_collectors"
            )
            collector_params = _params(collector)
            self.assertEqual(collector_params["hosts"], [self.SERVER, self.CLIENT])
            self.assertEqual(
                collector_params["hrt_device_ids"],
                list(range(8)),
            )
            self.assertEqual(collector_params["hrt_plane_ids"], [0, 1, 2, 3])
            self.assertEqual(
                fpf_shared_injection_suite.PROD_TARGET_PREFIX,
                "2401:db00:292a:a270::/64",
            )
            self.assertEqual(
                fpf_shared_injection_suite._link_drain_circuits()[0].a_end_interface,
                "eth1/37/1",
            )

            tc32_flap = next(
                step
                for step in _steps(fpf_tc32_downlink_flaps.TEST_CONFIG.playbooks[0])
                if _step_params(step).get("custom_step_name") == "fpf_rapid_flap_lldp"
            )
            self.assertEqual(
                _step_params(tc32_flap)["expected_interfaces"],
                ["eth1/37/1", "eth1/37/2", "eth1/37/3", "eth1/37/4"],
            )
            self.assertEqual(_step_params(tc32_flap)["neighbor_hosts"], [self.SERVER])

            tc37_circuit = fpf_tc37_nic_side_link_flap.CIRCUITS[0]
            self.assertEqual(tc37_circuit.a_end_interface, "eth1/37/1")
            self.assertEqual(tc37_circuit.z_end_device, self.SERVER)

            tc40_flap = next(
                step
                for step in _steps(
                    fpf_tc40_cont_interface_flaps.TEST_CONFIG.playbooks[0]
                )
                if _step_params(step).get("custom_step_name")
                == "fpf_multi_gtsw_rapid_flap"
            )
            tc40_params = _step_params(tc40_flap)
            self.assertEqual(tc40_params["neighbor_hosts"], [self.SERVER])
            self.assertEqual(
                tc40_params["expected_interfaces"],
                ["eth1/37/1", "eth1/37/2", "eth1/37/3", "eth1/37/4"],
            )
            for gtsw in fpf_tc40_cont_interface_flaps.ALL_GTSWS:
                self.assertEqual(
                    tc40_params["nic_recovery_by_gtsw_interface"][gtsw]["eth1/37/1"],
                    {
                        "host": self.SERVER,
                        "dev": 0,
                        "lane": fpf_hardening_common.gtsw_to_lane(gtsw),
                    },
                )

    def test_selected_profile_preserves_gpu_ids_and_separates_hrt_ids(self) -> None:
        with patch.dict(os.environ, self.PROFILE_ENV, clear=False):
            original = {
                host: dict(prefixes)
                for host, prefixes in fpf_prod_prefix_map.HOST_DEVICE_PREFIX.items()
            }
            importlib.reload(fpf_prod_prefix_map)
            self.assertEqual(
                fpf_prod_prefix_map.get_prefix(self.SERVER, 1),
                "2401:db00:292a:a271::/64",
            )
            self.assertEqual(
                fpf_prod_prefix_map.get_host_prefixes(self.SERVER),
                original[self.SERVER],
            )
            self.assertEqual(
                fpf_prod_prefix_map.get_hrt_device_prefixes(self.SERVER)[1],
                "2401:db00:292a:a570::/64",
            )
            self.assertEqual(fpf_prod_prefix_map.HOST_DEVICE_PREFIX, original)

    def test_selected_profile_rejects_conflicting_generated_vf1_prefix(self) -> None:
        with patch.dict(os.environ, self.PROFILE_ENV, clear=False):
            with patch.object(
                type(MWG2_TWSHARED_1354_1379.server),
                "prefixes_by_device",
                new_callable=PropertyMock,
                return_value={
                    **MWG2_TWSHARED_1354_1379.server.prefixes_by_device,
                    0: "2401:db00:292a:ffff::/64",
                },
            ):
                with self.assertRaisesRegex(ValueError, "VF1 prefixes disagree"):
                    fpf_prod_prefix_map.get_host_prefixes(self.SERVER)

    def test_selected_profile_rejects_conflicting_legacy_host_override(self) -> None:
        env = {
            **self.PROFILE_ENV,
            "FPF_GPU_HOSTS": "twshared1352.03.mwg2,twshared1388.03.mwg2",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaisesRegex(ValueError, "conflicts with host profile"):
                importlib.reload(fpf_hardening_common)


if __name__ == "__main__":
    unittest.main()
