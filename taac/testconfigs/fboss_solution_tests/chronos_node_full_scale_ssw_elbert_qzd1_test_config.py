# Copyright (c) Meta Platforms, Inc. and affiliates.

"""CHRONOS_NODE_FULL_SCALE_SSW_ELBERT_QZD1 — `ssw_bgp_hardening` conveyor TestConfig.

Runs the 13 BGP hardening playbooks with the compact CI/CD timing profile on
`test_config_for_bgp_and_fboss_platform_hardening_in_conveyor`, so every
playbook carries that factory's IXIA traffic items and packet-loss checks.

Playbooks that churn routes on purpose get a churn window: the affected
traffic may lose up to 100% while the churn runs, then BGP and the agent must
converge and all traffic must stay loss-free over a 30 s soak.
"""

import re
from collections.abc import Sequence

from taac.abstractions.physical_inventory import SSW_ELBERT_QZD1
from taac.health_checks.healthcheck_definitions import (
    create_ixia_packet_loss_check,
)
from taac.playbooks.playbook_definitions import (
    BGP_HARDENING_TIMING_PROFILES,
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

_DEVICE: str = SSW_ELBERT_QZD1.device_name
_PREFIX: str = _DEVICE.upper()

SSW_BGP_PLAYBOOK_NAMES: tuple[str, ...] = (
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

_V6_DIRECTIONAL: str = f"{_PREFIX}_V6_DIRECTIONAL_TRAFFIC_BETWEEN_DOWNLINK_AND_UPLINK"
_V4_DIRECTIONAL: str = f"{_PREFIX}_V4_DIRECTIONAL_TRAFFIC_BETWEEN_DOWNLINK_AND_UPLINK"
_DIRECTIONAL: list[str] = [_V6_DIRECTIONAL, _V4_DIRECTIONAL]
_L3: str = f"{_PREFIX}_V6_LAYER3_TRAFFIC_DOWNLINK_AND_UPLINK"
_LOSSY_NDP: list[str] = [
    f"{_PREFIX}_GOOD_BUT_LOSSY_NDP_TRAFFIC",
    f"{_PREFIX}_LOSSY_ROGUE_NDP_TRAFFIC",
]

# IXIA re-advertises a whole prefix pool (MP_UNREACH, then MP_REACH) on every
# LOCAL_PREF change, so best-path churn also drops the routed traffic.
_CHURN_AFFECTED_TRAFFIC: dict[str, list[str]] = {
    **{
        name: _DIRECTIONAL
        for name in (
            "test_longevity_prefix_flap_all_prefixes",
            "test_longevity_activate_deactivate_all_prefixes",
            "test_bgp_longevity_local_pref_churn",
            "test_longevity_session_flap_all_prefixes",
            "test_longevity_prefix_flap_all_prefixes_plus_bgp_restart",
            "test_longevity_session_flap_all_prefixes_plus_bgp_restart",
            "test_longevity_frequent_best_path_computation",
        )
    },
    "test_longevity_continuous_toggle_device_group": [_V4_DIRECTIONAL, _L3],
    "test_longevity_cold_start_with_prefix_and_session_oscillations": [
        *_DIRECTIONAL,
        _L3,
    ],
    "test_bgp_longevity_ndp_device_group_toggle": [_L3],
}

_NDP_GROUP_REGEX: str = (
    f"^DEVICE_GROUP_D2_{re.escape(_PREFIX)}:"
    f"{re.escape(SSW_ELBERT_QZD1.extras['ixia_downlink_interface'].upper())}"
    "_DOWNLINK_NDP_STRESSOR$"
)


def _churn_window_check(affected: list[str]) -> PointInTimeHealthCheck:
    unaffected = [name for name in [*_DIRECTIONAL, _L3] if name not in affected]
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
            hc_types.PacketLossThreshold(names=_LOSSY_NDP, expect_packet_loss=True),
        ],
        clear_traffic_stats=False,
        check_id="intentional_churn_window",
    )


def _with_churn_window(pb: Playbook) -> Playbook:
    affected = _CHURN_AFFECTED_TRAFFIC.get(pb.name)
    if affected is None:
        return pb
    steps = [
        create_validation_step(
            point_in_time_checks=[_churn_window_check(affected)],
            stage=ValidationStage.POST_TEST,
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


def _without_session_establish_check(
    checks: Sequence[PointInTimeHealthCheck] | None,
) -> list[PointInTimeHealthCheck]:
    return [
        check
        for check in checks or []
        if check.name != hc_types.CheckName.BGP_SESSION_ESTABLISH_CHECK
    ]


def _create_ssw_bgp_playbooks() -> list[Playbook]:
    playbooks = get_longevity_playbooks(
        device_name=_DEVICE,
        bgp_hardening_timing_profile=BGP_HARDENING_TIMING_PROFILES["cicd"],
        include_extended_bgp_hardening_playbooks=True,
        bgp_longevity_ndp_device_group_regex=_NDP_GROUP_REGEX,
    )
    if tuple(pb.name for pb in playbooks) != SSW_BGP_PLAYBOOK_NAMES:
        raise ValueError("SSW BGP hardening requires exactly the 13 BGP playbooks")
    return [
        _with_churn_window(pb)(
            prechecks=_without_session_establish_check(pb.prechecks),
            postchecks=_without_session_establish_check(pb.postchecks),
        )
        for pb in playbooks
    ]


CHRONOS_NODE_FULL_SCALE_SSW_ELBERT_QZD1_TEST_CONFIG: TestConfig = (
    test_config_for_bgp_and_fboss_platform_hardening_in_conveyor(
        test_config_name="CHRONOS_NODE_FULL_SCALE_SSW_ELBERT_QZD1",
        device_name=_DEVICE,
        local_mac_address=SSW_ELBERT_QZD1.mac_address,
        **{
            key: value
            for key, value in SSW_ELBERT_QZD1.extras.items()
            if key != "ixia_rogue_interface"
        },
        prefix_limit="75000",
        per_peer_max_route_limit="25000",
        downlink_peer_count=20,
        uplink_peer_count=20,
        rogue_peer_count=20,
        ixia_downlink_prefix_count_v6=10000,
        ixia_uplink_prefix_count_v6=10000,
        ixia_rogue_prefix_count_v6=17500,
        ixia_downlink_prefix_count_v4=7500,
        ixia_uplink_prefix_count_v4=7500,
        ixia_rogue_prefix_count_v4=17500,
        downlink_peer_tag="RSW",
        uplink_peer_tag="SSW",
        ecmp_group_limit=1400,
        good_ndp_entries_uplink=250,
        good_ndp_entries_downlink=200,
        rogue_ndp_entries=10000,
        good_arp_entries=500,
        rogue_arp_entries=1500,
        good_mac_entry_count=100,
        rogue_mac_entry_count=200,
        bgp_induced_ecmp_group_count=50,
        basset_pool="dne.regression",
        playbooks=_create_ssw_bgp_playbooks(),
        playbooks_selected=list(SSW_BGP_PLAYBOOK_NAMES),
        include_cgroup_memory_setup=False,
        allow_all_v4_policies=True,
        validate_test_bgp_sessions=True,
        configure_induced_ecmp_2_peers=False,
    )
)
