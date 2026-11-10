# Copyright (c) Meta Platforms, Inc. and affiliates.

import json

from taac.health_checks.healthcheck_definitions import (
    create_core_dumps_snapshot_check,
    create_device_core_dumps_check,
    create_ixia_packet_loss_check,
)
from taac.playbooks.playbook_definitions import (
    create_bgp_longevity_ndp_device_group_toggle_playbook,
    get_longevity_playbooks,
)
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_ixia_api_step,
    create_longevity_step,
    create_service_convergence_step,
    create_validation_step,
)
from taac.testconfigs.fboss_solution_tests.fboss_bgp_and_platform_hardening_conveyor import (
    test_config_for_bgp_and_fboss_platform_hardening_in_conveyor,
)
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config.types import (
    Playbook,
    PointInTimeHealthCheck,
    Service,
    TestConfig,
    ValidationStage,
)


_MP3BA_FADU_PARAMS: dict[str, str | int | bool | list[str]] = {
    "device_name": "fa002-du001.qza1",
    "local_mac_address": "5e:40:97:19:90:73",
    "ixia_downlink_interface": "eth1/14/1",
    "ixia_uplink_interface": "eth1/15/1",
    "peergroup_uplink_mimic_v6": "PEERGROUP_FADU_FAUU_V6",
    "peergroup_uplink_mimic_v4": "PEERGROUP_FADU_FAUU_V4",
    "peergroup_downlink_mimic_v6": "PEERGROUP_FADU_SSW_V6",
    "peergroup_downlink_mimic_v4": "PEERGROUP_FADU_SSW_V4",
    "peergroup_rogue_mimic_v6": "PEERGROUP_FADU_FAUU_V6",
    "peergroup_rogue_mimic_v4": "PEERGROUP_FADU_FAUU_V4",
    "route_map_uplink_ingress": "PROPAGATE_FADU_FAUU_IN",
    "route_map_uplink_egress": "PROPAGATE_FADU_FAUU_OUT",
    "route_map_downlink_ingress": "PROPAGATE_FADU_SSW_IN",
    "route_map_downlink_egress": "PROPAGATE_FADU_SSW_OUT",
    "route_map_rogue_ingress": "PROPAGATE_FADU_FAUU_IN",
    "route_map_rogue_egress": "PROPAGATE_FADU_SSW_OUT",
    "ixia_downlink_ic_parent_network_v6": "2401:db00:e50d:10:8",
    "ixia_uplink_ic_parent_network_v6": "2401:db00:e50d:10:9",
    "ixia_rogue_ic_parent_network_v6": "2401:db00:e50d:10:10",
    "ixia_downlink_ic_parent_network_v4": "10.153.28",
    "ixia_uplink_ic_parent_network_v4": "10.154.28",
    "ixia_rogue_ic_parent_network_v4": "10.155.28",
    "good_ndp_entry_network_v6": "2401:db00:e50d:10:9",
    "rogue_ndp_entry_network_v6": "2401:db00:e50d:10:8",
    "good_arp_entry_network_v4": "192.168",
    "rogue_arp_entry_network_v4": "193.168",
    "prefix_limit": "75000",
    "per_peer_max_route_limit": "25000",
    "downlink_peer_count": 18,
    "uplink_peer_count": 4,
    "rogue_peer_count": 25,
    "remote_downlink_as_4byte": 64901,
    "remote_uplink_as_4byte": 7010,
    "remote_rogue_as_4byte": 64901,
    "is_uplink_peer_confed": "True",
    "is_downlink_peer_confed": "False",
    "is_rogue_peer_confed": "True",
    "ixia_downlink_prefix_count_v6": 2500,
    "ixia_uplink_prefix_count_v6": 7500,
    "ixia_rogue_prefix_count_v6": 3750,
    "ixia_downlink_prefix_count_v4": 3500,
    "ixia_uplink_prefix_count_v4": 7500,
    "ixia_rogue_prefix_count_v4": 3750,
    "ixia_uplink_good_ndp_network": "2401:db00:e50d:1001:9",
    "ixia_downlink_good_ndp_network": "2401:db00:e50d:1001:8",
    "ixia_downlink_communities": ["65441:132", "65442:133", "65529:26730"],
    "ixia_uplink_communities": ["65526:35724", "65441:134", "65442:135"],
    "downlink_peer_tag": "SSW",
    "uplink_peer_tag": "FAUU",
    "ecmp_group_limit": 1520,
    "ecmp_member_limit": 11500,
    "good_ndp_entries_uplink": 200,
    "good_ndp_entries_downlink": 200,
    "rogue_ndp_entries": 6000,
    "good_arp_entries": 200,
    "rogue_arp_entries": 1500,
    "good_mac_entry_count": 100,
    "rogue_mac_entry_count": 200,
    "bgp_induced_ecmp_group_count": 50,
    "bgpd_restart_no_of_interations": 5,
    "wedge_agent_restart_no_of_interations": 5,
    "basset_pool": "dne.test",
    "v6_uplink_prefix": "6100",
}

MP3BA_BGP_PLAYBOOK_NAMES: tuple[str, ...] = (
    "test_longevity_prefix_flap_all_prefixes",
    "test_longevity_activate_deactivate_all_prefixes",
    "test_bgp_longevity_local_pref_churn",
    "test_longevity_session_flap_all_prefixes",
    "test_longevity_prefix_flap_all_prefixes_plus_bgp_restart",
    "test_longevity_session_flap_all_prefixes_plus_bgp_restart",
    "test_longevity_rogue_prefix_session_enable",
    "test_longevity_no_prefix_no_session_flap",
    "test_longevity_continuous_toggle_device_group",
    "test_longevity_frequent_best_path_computation",
    "test_longevity_cold_start_with_prefix_and_session_oscillations",
    "test_bgp_longevity_bgpd_crash",
    "test_bgp_longevity_ndp_device_group_toggle",
)

MP3BA_BGP_SKIPPED_PLAYBOOKS: tuple[str, ...] = (
    "test_cgroup_system_slice_oom_kill_policy",
    "test_hardening_of_ndp_overload_entries",
    "test_hardening_of_arp_overload_entries",
    "test_hardening_of_mac_overload_entries",
    "test_hardening_of_ndp_overload_with_agent_churn",
    "test_hardening_of_ndp_overload_10x_with_table_clear",
    "test_hardening_of_arp_overload_with_agent_churn",
    "test_hardening_of_arp_overload_10x_with_table_clear",
    "test_hardening_of_mac_overload_with_agent_churn",
    "test_agent_warmboot",
    "test_bgpd_restart",
    "test_bgp_malformed_packet_test",
    "test_ecmp_member_overload_limit",
    "test_ecmp_group_overload_limit",
    "test_cpu_high_priority_queue_overload",
    "test_qsfp_service_restart",
    "test_fsdb_restart",
    "test_openr_restart",
    "test_agent_coldboot",
    "test_agent_crash",
    "test_bgpd_crash",
    "test_openr_crash",
    "test_qsfp_service_crash",
    "test_fsdb_crash",
    "test_fboss_sw_agent_warmboot",
    "test_fboss_sw_agent_crash",
    "test_fboss_hw_agent_0_restart",
    "test_fboss_hw_agent_0_crash",
    "test_fboss_sw_agent_and_hw_agent_0_restart",
    "test_fboss_sw_agent_and_hw_agent_0_crash",
    "test_bgpd_and_fsdb_restart",
    "test_agent_and_bgpd_restart",
    "test_agent_and_fsdb_restart",
    "test_agent_and_qsfp_service_restart",
    "test_fsdb_and_qsfp_service_restart",
    "test_sw_agent_and_wedge_agent_restart",
    "test_qsfp_service_warmboot_and_reset",
    "test_qsfp_service_warmboot_and_agent_coldboot",
    "test_qsfp_service_warmboot_and_tx_flap",
    "test_agent_warmboot_wedge_and_sw_agent",
    "test_fboss_hw_agent_0_coldboot",
)

_MP3BA_NDP_GROUP_REGEX: str = (
    r"^DEVICE_GROUP_D2_FA002-DU001\.QZA1:ETH1/14/1_DOWNLINK_NDP_STRESSOR$"
)


_MP3BA_DIRECTIONAL_TRAFFIC: list[str] = [
    "FA002-DU001.QZA1_V6_DIRECTIONAL_TRAFFIC_BETWEEN_DOWNLINK_AND_UPLINK",
    "FA002-DU001.QZA1_V4_DIRECTIONAL_TRAFFIC_BETWEEN_DOWNLINK_AND_UPLINK",
]
_MP3BA_L3_TRAFFIC: str = "FA002-DU001.QZA1_V6_LAYER3_TRAFFIC_DOWNLINK_AND_UPLINK"
_MP3BA_FAULTED_TRAFFIC: dict[str, list[str]] = {
    **{
        name: _MP3BA_DIRECTIONAL_TRAFFIC
        for name in (
            "test_longevity_prefix_flap_all_prefixes",
            "test_longevity_activate_deactivate_all_prefixes",
            "test_longevity_session_flap_all_prefixes",
            "test_longevity_prefix_flap_all_prefixes_plus_bgp_restart",
            "test_longevity_session_flap_all_prefixes_plus_bgp_restart",
        )
    },
    "test_longevity_continuous_toggle_device_group": [
        "FA002-DU001.QZA1_V4_DIRECTIONAL_TRAFFIC_BETWEEN_DOWNLINK_AND_UPLINK",
        _MP3BA_L3_TRAFFIC,
    ],
    "test_longevity_cold_start_with_prefix_and_session_oscillations": [
        *_MP3BA_DIRECTIONAL_TRAFFIC,
        _MP3BA_L3_TRAFFIC,
    ],
    "test_bgp_longevity_ndp_device_group_toggle": [_MP3BA_L3_TRAFFIC],
}


def _create_fault_window_check(affected: list[str]) -> PointInTimeHealthCheck:
    unaffected = [
        name
        for name in [*_MP3BA_DIRECTIONAL_TRAFFIC, _MP3BA_L3_TRAFFIC]
        if name not in affected
    ]
    return create_ixia_packet_loss_check(
        thresholds=[
            hc_types.PacketLossThreshold(
                names=affected,
                metric=hc_types.PacketLossMetric.PERCENTAGE,
                str_value="100",
                expect_packet_loss=False,
            ),
            *(
                [
                    hc_types.PacketLossThreshold(
                        names=unaffected,
                        metric=hc_types.PacketLossMetric.DURATION,
                        str_value="0.1",
                        expect_packet_loss=False,
                    )
                ]
                if unaffected
                else []
            ),
            hc_types.PacketLossThreshold(
                names=[
                    "FA002-DU001.QZA1_GOOD_BUT_LOSSY_NDP_TRAFFIC",
                    "FA002-DU001.QZA1_LOSSY_ROGUE_NDP_TRAFFIC",
                ],
                expect_packet_loss=True,
            ),
        ],
        clear_traffic_stats=False,
        check_id="intentional_churn_window",
    )


def _with_recovered_traffic_check(pb: Playbook) -> Playbook:
    affected = _MP3BA_FAULTED_TRAFFIC.get(pb.name)
    if affected is None:
        return pb
    fault_check = _create_fault_window_check(affected)
    steps = [
        create_validation_step(
            point_in_time_checks=[fault_check], stage=ValidationStage.POST_TEST
        )
    ]
    if pb.name == "test_longevity_continuous_toggle_device_group":
        assert pb.cleanup_steps
        steps.append(pb.cleanup_steps[-1])
    steps.extend(
        [
            create_service_convergence_step(services=[Service.AGENT, Service.BGP]),
            create_ixia_api_step(api_name="clear_traffic_stats", args_dict={}),
            create_longevity_step(duration=30),
        ]
    )
    return pb(stages=[*(pb.stages or []), create_steps_stage(steps=steps)])


def _create_mp3ba_bgp_playbooks() -> list[Playbook]:
    playbooks = get_longevity_playbooks(
        device_name="fa002-du001.qza1",
        include_extended_bgp_hardening_playbooks=True,
        bgp_longevity_ndp_device_group_regex=_MP3BA_NDP_GROUP_REGEX,
    )
    if tuple(pb.name for pb in playbooks) != MP3BA_BGP_PLAYBOOK_NAMES:
        raise ValueError(
            "MP3BA qualification requires exactly the requested 13 BGP playbooks"
        )
    ndp = create_bgp_longevity_ndp_device_group_toggle_playbook(
        device_group_name_regex=_MP3BA_NDP_GROUP_REGEX,
        expected_device_group_matches=1,
        uptime_s=900,
        downtime_s=120,
        cycles=3,
    )
    playbooks[-1] = ndp(
        description="BGP longevity: toggle 3500 IPv6 neighbors for 60 minutes (15m up / 2m down, then 9m up)",
        stages=[
            *(ndp.stages or []),
            create_steps_stage(
                steps=[
                    *(ndp.cleanup_steps or []),
                    create_longevity_step(duration=540),
                ],
            ),
        ],
    )
    return [
        _with_recovered_traffic_check(pb)(
            prechecks=[
                check
                for check in pb.prechecks or []
                if check.name != hc_types.CheckName.BGP_SESSION_ESTABLISH_CHECK
            ],
            postchecks=[
                check
                for check in pb.postchecks or []
                if check.name != hc_types.CheckName.BGP_SESSION_ESTABLISH_CHECK
            ],
        )
        for pb in playbooks
    ]


def _allow_expected_bgp_crash_cores(config: TestConfig) -> TestConfig:
    playbooks = []
    for pb in config.playbooks:
        if pb.name == "test_bgp_longevity_bgpd_crash":
            pb = pb(
                postchecks=[
                    create_device_core_dumps_check(
                        core_dump_processes_to_ignore=["bgpd_cpp", "bgpd_main"]
                    )
                    if check.name == hc_types.CheckName.DEVICE_CORE_DUMPS_CHECK
                    else check
                    for check in pb.postchecks or []
                ],
                snapshot_checks=[
                    create_core_dumps_snapshot_check(
                        core_dump_processes_to_ignore=["bgpd_cpp", "bgpd_main"]
                    )
                    if check.name == hc_types.CheckName.CORE_DUMPS_CHECK
                    else check
                    for check in pb.snapshot_checks or []
                ],
            )
        playbooks.append(pb)
    return config(playbooks=playbooks)


FBOSS_BGP_HARDENING_MP3BA_FA002_DU001_QZA1_TEST_CONFIG: TestConfig = (
    _allow_expected_bgp_crash_cores(
        test_config_for_bgp_and_fboss_platform_hardening_in_conveyor(
            test_config_name="FBOSS_BGP_HARDENING_MP3BA_FA002_DU001_QZA1",
            **{**_MP3BA_FADU_PARAMS, "good_ndp_entries_downlink": 3500},
            playbooks=_create_mp3ba_bgp_playbooks(),
            playbooks_selected=list(MP3BA_BGP_PLAYBOOK_NAMES),
            skip_playbooks=list(MP3BA_BGP_SKIPPED_PLAYBOOKS),
            include_cgroup_memory_setup=False,
            stress_static_routes=False,
            validate_test_bgp_sessions=True,
            fsdb_memory_threshold_bytes=5 * (1024**3),
        )
    )
)

FBOSS_BGP_RESTART_MP3BA_FA002_DU001_QZA1_TEST_CONFIG: TestConfig = (
    test_config_for_bgp_and_fboss_platform_hardening_in_conveyor(
        test_config_name="FBOSS_BGP_RESTART_MP3BA_FA002_DU001_QZA1",
        **_MP3BA_FADU_PARAMS,
        validate_test_bgp_sessions=True,
        fsdb_memory_threshold_bytes=5 * (1024**3),
        playbooks_selected=["test_bgpd_restart"],
        include_cgroup_memory_setup=False,
        include_bgp_peer_route_snapshot_check=True,
        fail_on_bgp_route_collection_error=True,
    )
)
