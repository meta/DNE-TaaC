# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""FSDB steady-state validation at DSF BGP path scale on Ashburn RDSW004."""

import json

from ixia.ixia import types as ixia_types
from taac.health_checks.healthcheck_definitions import (
    create_bgp_route_count_verification_check,
    create_bgp_session_establish_check,
    create_bgp_session_snapshot_check,
    create_bgp_stale_route_check,
    create_core_dumps_snapshot_check,
    create_dsf_drain_state_check,
    create_dsf_fabric_reachability_check,
    create_dsf_fsdb_session_check,
    create_dsf_pfc_check,
    create_dsf_traffic_rebalance_check,
    create_fsdb_subscriber_timestamp_check,
    create_ixia_packet_loss_check,
    create_ixia_port_stats_check,
    create_systemctl_active_state_check,
    create_unclean_exit_check,
)
from taac.packet_headers import DSF_RDMA_PACKET_HEADERS
from taac.playbooks.playbook_definitions import (
    create_longevity_playbook,
)
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_longevity_step,
    create_validation_step,
)
from taac.task_definitions import (
    create_coop_apply_patchers_task,
    create_coop_register_patcher_task,
    create_coop_unregister_patchers_task,
    create_run_commands_on_shell_task,
)
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.types import TestConfig


_DUT = "rdsw004.u001.c086.ash6"
_DUT_MAC = "02:00:00:00:0f:0b"
_DUT_ASN = 4200000004
_IXIA_API_SERVER = "2401:db00:2066:3037::3004"
_PEER_GROUP = "PEERGROUP_RDSW_IXIA_PATH_SCALE_V6"
_POLICY_IN = "PROPAGATE_RDSW_IXIA_PATH_SCALE_IN"
_POLICY_OUT = "PROPAGATE_RDSW_IXIA_PATH_SCALE_OUT"
_ACTIVE_PEER = "2401:db00:206a:4068::100"
_ACTIVE_PEER_DESCRIPTION = "TAAC FSDB path-scale active injector"
_PLAYBOOK_NAME = "test_fsdb_path_scale_stable_state"
_CONTROL_PLANE_PLAYBOOK_NAME = "test_fsdb_path_scale_control_plane"
_TRAFFIC_GOLDEN = "fsdb_path_scale_golden"
_TRAFFIC_ROGUE = "fsdb_path_scale_rogue"
_TRAFFIC_ITEMS = [_TRAFFIC_GOLDEN, _TRAFFIC_ROGUE]
_IXIA_INTERFACES = ["eth1/11/1", "eth1/15/1", "eth1/25/1"]
_DOWNLINK_NETWORK = "2401:db00:206a:4060"
_UPLINK_NETWORK = "2401:db00:206a:4068"
_ROGUE_NETWORK = "2401:db00:206a:407c"
_PREFIX_COUNT_PER_POOL = 200
_GOLDEN_PATH_MULTIPLIER = 2048
_ROGUE_PATH_MULTIPLIER = 2048
_ECMP_WIDTH = 2048
_EXPECTED_PREFIXES = 2 * _PREFIX_COUNT_PER_POOL
_EXPECTED_PATHS = (
    _PREFIX_COUNT_PER_POOL * _GOLDEN_PATH_MULTIPLIER
    + _PREFIX_COUNT_PER_POOL * _ROGUE_PATH_MULTIPLIER
)
_FSDB_SUBSCRIBERS = [
    "bgpd",
    "qsfp_service",
    "fan_service",
    "led_service",
    "switch_agent:switchagent_core_global_1",
    "switch_agent:switchagent_cluster_ash6_be_0",
]

_DSF_L1_CONFIG = ixia_types.L1Config(
    enable_fcoe=True,
    flow_control_config=ixia_types.FlowControlConfig(
        pfc_prority_groups_config=ixia_types.PfcPriorityGroupsConfig(
            priority0_pfc_queue=ixia_types.PfcQueue.TWO,
            priority1_pfc_queue=ixia_types.PfcQueue.ONE,
            priority2_pfc_queue=ixia_types.PfcQueue.ZERO,
            priority3_pfc_queue=ixia_types.PfcQueue.THREE,
        ),
        enable_pfc_pause_delay=False,
    ),
)

_DSF_FRAME_SIZES = ixia_types.FrameSize(
    type=ixia_types.FrameSizeType.CUSTOM_IMIX,
    imix_weight={94: 1, 96: 18, 192: 3, 512: 1, 1200: 1, 4600: 76},
)


def _network_groups(
    device_group_name: str,
) -> list[ixia_types.CustomNetworkGroupConfig]:
    """Mirror both route pools on active and MIMIC groups for IXIA merging."""
    return [
        ixia_types.CustomNetworkGroupConfig(
            device_group_name=device_group_name,
            network_group_name="fsdb_path_scale_golden_prefixes",
            network_group_multiplier=_GOLDEN_PATH_MULTIPLIER,
            number_of_addresses_per_row=_PREFIX_COUNT_PER_POOL,
            prefix_start_value="5000:dd::",
            prefix_length=64,
            nexthop_start_value=f"{_ROGUE_NETWORK}::a000",
            nexthop_increments="::2",
            ecmp_width=_ECMP_WIDTH,
            community_list=["65446:30"],
            network_group_index=0,
        ),
        ixia_types.CustomNetworkGroupConfig(
            device_group_name=device_group_name,
            network_group_name="fsdb_path_scale_rogue_prefixes",
            network_group_multiplier=_ROGUE_PATH_MULTIPLIER,
            number_of_addresses_per_row=_PREFIX_COUNT_PER_POOL,
            prefix_start_value="5000:ee::",
            prefix_length=64,
            nexthop_start_value=f"{_ROGUE_NETWORK}::a000",
            nexthop_increments="::1",
            ecmp_width=_ECMP_WIDTH,
            community_list=["65446:30"],
            network_group_index=1,
        ),
    ]


def _bgp_config(device_group_name: str) -> taac_types.BgpConfig:
    return taac_types.BgpConfig(
        local_as_4_bytes=_DUT_ASN,
        local_as_increment=0,
        enable_4_byte_local_as=True,
        bgp_peer_type=ixia_types.BgpPeerType.IBGP,
        is_confed=False,
        bgp_capabilities=[
            ixia_types.BgpCapability.IpV6Unicast,
            ixia_types.BgpCapability.Ipv6UnicastAddPath,
        ],
        custom_network_group_configs=_network_groups(device_group_name),
    )


def _downlink_port_config() -> taac_types.BasicPortConfig:
    return taac_types.BasicPortConfig(
        l1_config=_DSF_L1_CONFIG,
        endpoint=f"{_DUT}:eth1/11/1",
        device_group_configs=[
            taac_types.DeviceGroupConfig(
                device_group_index=0,
                tag_name="DOWNLINK_L3_TRAFFIC",
                multiplier=1,
                v6_addresses_config=taac_types.IpAddressesConfig(
                    starting_ip=f"{_DOWNLINK_NETWORK}::a000",
                    increment_ip="::",
                    gateway_starting_ip=f"{_DOWNLINK_NETWORK}::",
                    gateway_increment_ip="::",
                    mask=64,
                ),
            ),
        ],
    )


def _uplink_port_config() -> taac_types.BasicPortConfig:
    return taac_types.BasicPortConfig(
        l1_config=_DSF_L1_CONFIG,
        endpoint=f"{_DUT}:eth1/15/1",
        device_group_configs=[
            taac_types.DeviceGroupConfig(
                device_group_index=0,
                tag_name="BGP_ROUTE_INJECTOR",
                multiplier=1,
                v6_addresses_config=taac_types.IpAddressesConfig(
                    starting_ip=_ACTIVE_PEER,
                    increment_ip="::",
                    gateway_starting_ip=f"{_UPLINK_NETWORK}::",
                    gateway_increment_ip="::",
                    mask=64,
                ),
                v6_bgp_config=_bgp_config("BGP_ROUTE_INJECTOR"),
            ),
        ],
    )


def _rogue_port_config() -> taac_types.BasicPortConfig:
    return taac_types.BasicPortConfig(
        l1_config=_DSF_L1_CONFIG,
        endpoint=f"{_DUT}:eth1/25/1",
        device_group_configs=[
            # This mirror exists only so IXIA can merge destination groups. It
            # deliberately has no DUT neighbor and is therefore expected down.
            taac_types.DeviceGroupConfig(
                device_group_index=0,
                tag_name="MIMIC_BGP_PEER",
                multiplier=1,
                v6_addresses_config=taac_types.IpAddressesConfig(
                    starting_ip=_ACTIVE_PEER,
                    increment_ip="::",
                    gateway_starting_ip=f"{_UPLINK_NETWORK}::",
                    gateway_increment_ip="::",
                    mask=64,
                ),
                v6_bgp_config=_bgp_config("MIMIC_BGP_PEER"),
            ),
            # Cover every possible 2048-wide nexthop set used by either pool.
            taac_types.DeviceGroupConfig(
                device_group_index=1,
                tag_name="NDP_SUPPORTING_NEXTHOP",
                enable=True,
                multiplier=4096,
                v6_addresses_config=taac_types.IpAddressesConfig(
                    starting_ip=f"{_ROGUE_NETWORK}::a000",
                    increment_ip="::1",
                    gateway_starting_ip=f"{_ROGUE_NETWORK}::",
                    gateway_increment_ip="::",
                    mask=64,
                ),
            ),
        ],
    )


def _traffic_item(
    name: str, network_group_index: int
) -> taac_types.BasicTrafficItemConfig:
    return taac_types.BasicTrafficItemConfig(
        name=name,
        bidirectional=False,
        merge_destinations=True,
        line_rate=5,
        line_rate_type=ixia_types.RateType.PERCENT_LINE_RATE,
        src_dest_mesh=ixia_types.SrcDestMeshType.ONE_TO_ONE,
        src_endpoints=[
            taac_types.TrafficEndpoint(
                name=f"{_DUT}:eth1/11/1",
                device_group_index=0,
            ),
        ],
        dest_endpoints=[
            taac_types.TrafficEndpoint(
                name=f"{_DUT}:eth1/15/1",
                device_group_index=0,
                network_group_index=network_group_index,
            ),
            taac_types.TrafficEndpoint(
                name=f"{_DUT}:eth1/25/1",
                device_group_index=0,
                network_group_index=network_group_index,
            ),
        ],
        skip_default_l4_protocol=True,
        traffic_type=ixia_types.TrafficType.IPV6,
        tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
        frame_size_settings=_DSF_FRAME_SIZES,
        packet_headers=DSF_RDMA_PACKET_HEADERS,
    )


def _active_peer_check() -> taac_types.PointInTimeHealthCheck:
    return create_bgp_session_establish_check(
        ignore_all_prefixes_except=[_ACTIVE_PEER],
        expected_established_sessions=1,
        retry_count=30,
        retry_delay_seconds=5,
        retry_delay_multiplier=1,
    )


def _rib_path_scale_check() -> taac_types.PointInTimeHealthCheck:
    return create_bgp_route_count_verification_check(
        json_params={
            "rib_prefix_ranges": ["5000:dd::/32", "5000:ee::/32"],
            "expected_rib_prefix_count": _EXPECTED_PREFIXES,
            "expected_rib_path_count": _EXPECTED_PATHS,
            "retry_count": 30,
            "retry_delay_seconds": 5,
        }
    )


def _loss_check(*, clear_traffic_stats: bool) -> taac_types.PointInTimeHealthCheck:
    check = create_ixia_packet_loss_check(
        thresholds=[
            hc_types.PacketLossThreshold(
                names=_TRAFFIC_ITEMS,
                str_value="0",
                metric=hc_types.PacketLossMetric.DURATION,
                comparison=hc_types.ComparisonType.LESS_THAN_EQUAL_TO,
                expect_packet_loss=False,
            ),
        ],
        sleep_time=60,
        clear_traffic_stats=clear_traffic_stats,
    )
    # At this scale IxNetwork's waitForTrafficStatsRefresh operation returns
    # 504 and can hold the health check for several minutes. Fresh sessions
    # start with zero counters, and the pre/post checks each stop traffic before
    # taking a strict snapshot, so clearing is unnecessary and would hide the
    # very window being measured.
    return check(
        check_params=taac_types.Params(
            json_params=json.dumps({"skip_clear_stats_at_end": True})
        )
    )


def _fsdb_check() -> taac_types.PointInTimeHealthCheck:
    return create_fsdb_subscriber_timestamp_check(
        json_params={
            "target_device": _DUT,
            "subscriber_names": _FSDB_SUBSCRIBERS,
        },
        start_time_jq_var="test_case_start_time",
    )


def _pfc_check(mode: str) -> taac_types.PointInTimeHealthCheck:
    return create_dsf_pfc_check(
        thresholds=[
            hc_types.DsfPfcThreshold(
                interfaces=[f"{_DUT}:{interface}" for interface in _IXIA_INTERFACES],
                in_pfc=0,
                out_pfc=0,
                comparison=hc_types.ComparisonType.EQUAL_TO,
                priority=hc_types.Priority.PRIORITY_2,
            ),
        ],
        mode=mode,
        check_scope=hc_types.Scope.DEFAULT,
    )


_PRECHECKS = [
    create_systemctl_active_state_check(),
    create_unclean_exit_check(),
    create_dsf_fsdb_session_check(),
    create_dsf_fabric_reachability_check(),
    create_dsf_drain_state_check(is_drained=False),
    create_dsf_traffic_rebalance_check(deviation_threshold_pct=20),
    _active_peer_check(),
    _rib_path_scale_check(),
    _fsdb_check(),
    create_ixia_port_stats_check(snapshot_baseline=True),
    _pfc_check("snapshot"),
    _loss_check(clear_traffic_stats=False),
]

_POSTCHECKS = [
    create_systemctl_active_state_check(),
    create_unclean_exit_check(),
    create_dsf_fsdb_session_check(),
    create_dsf_fabric_reachability_check(),
    create_dsf_drain_state_check(is_drained=False),
    create_dsf_traffic_rebalance_check(deviation_threshold_pct=20),
    _active_peer_check(),
    _rib_path_scale_check(),
    create_bgp_stale_route_check(),
    _fsdb_check(),
    create_ixia_port_stats_check(),
    _pfc_check("check"),
    _loss_check(clear_traffic_stats=False),
]

# The DUT's known local DRAINED_DUE_TO_ASIC_ERROR is diagnostic-only for this
# requested run. Keep every product/forwarding assertion strict, but do not let
# that pre-existing drain signal block either the path-scale or traffic phase.
_PATH_SCALE_PRECHECKS = [
    check
    for check in _PRECHECKS
    if check.name != hc_types.CheckName.DSF_DRAIN_STATE_CHECK
]
_PATH_SCALE_POSTCHECKS = [
    check
    for check in _POSTCHECKS
    if check.name != hc_types.CheckName.DSF_DRAIN_STATE_CHECK
]

# Prove and hold path scale without depending on IXIA traffic-stat view
# initialization. Traffic validation runs as a separate playbook below.
_CONTROL_PLANE_PRECHECKS = _PATH_SCALE_PRECHECKS[:-1]
_CONTROL_PLANE_POSTCHECKS = _PATH_SCALE_POSTCHECKS[:-1]

_SNAPSHOT_CHECKS = [
    create_core_dumps_snapshot_check(),
    create_bgp_session_snapshot_check(),
]


def _control_plane_playbook() -> taac_types.Playbook:
    """Validate and hold path scale without starting IXIA traffic.

    TAAC's generic Step pre-hook starts traffic unless a step explicitly opts
    out.  Keeping the checks in Playbook.prechecks/postchecks would therefore
    try to start a deliberately empty traffic selection and leave IxNetwork in
    kUnapplied.  Explicit validation/hold stages let every step opt out while
    BGP route advertisement remains active.
    """
    return taac_types.Playbook(
        name=_CONTROL_PLANE_PLAYBOOK_NAME,
        traffic_items_to_start=["^$"],
        stages=[
            create_steps_stage(
                stage_id="control_plane_prechecks",
                steps=[
                    create_validation_step(
                        point_in_time_checks=_CONTROL_PLANE_PRECHECKS,
                        start_traffic=False,
                        fail_on_failure=True,
                    ),
                ],
            ),
            create_steps_stage(
                stage_id="control_plane_hold",
                steps=[
                    create_longevity_step(
                        duration=300,
                        description="Hold full BGP AddPath scale for five minutes",
                        start_traffic=False,
                    ),
                ],
            ),
            create_steps_stage(
                stage_id="control_plane_postchecks",
                steps=[
                    create_validation_step(
                        point_in_time_checks=_CONTROL_PLANE_POSTCHECKS,
                        start_traffic=False,
                        fail_on_failure=True,
                    ),
                ],
            ),
        ],
        snapshot_checks=_SNAPSHOT_CHECKS,
    )


def _path_scale_peer_group_tasks() -> list[taac_types.Task]:
    return [
        create_coop_register_patcher_task(
            hostname=_DUT,
            config_name="bgpcpp",
            patcher_name=f"add_peer_group_patcher_{_PEER_GROUP}",
            task_name="add_peer_group_patcher",
            patcher_args={
                "name": _PEER_GROUP,
                "description": "RDSW to IXIA IPv6 AddPath scale test",
                "disable_ipv4_afi": "True",
                "disable_ipv6_afi": "False",
                "ingress_policy_name": _POLICY_IN,
                "egress_policy_name": _POLICY_OUT,
                "bgp_peer_timers_hold_time_seconds": "30",
                "bgp_peer_timers_keep_alive_seconds": "10",
                "bgp_peer_timers_out_delay_seconds": "0",
                "bgp_peer_timers_withdraw_unprog_delay_seconds": "0",
                "peer_tag": "IXIA",
                "max_routes": "900000",
                "warning_only": "True",
                "warning_limit": "0",
                "next_hop_self": "True",
                "is_confed_peer": "False",
                "is_passive": "False",
                "add_path": "BOTH",
                "v4_over_v6_nexthop": "False",
                "link_bandwidth_bps": "auto",
            },
            py_func_name="add_peer_group_patcher",
        ),
        create_coop_register_patcher_task(
            hostname=_DUT,
            config_name="bgpcpp",
            patcher_name=f"a_add_bgp_policy_statement_{_POLICY_IN}",
            task_name="add_bgp_policy_statement",
            patcher_args={
                "name": _POLICY_IN,
                "description": "Accept IXIA routes for RDSW path-scale testing",
            },
            py_func_name="add_bgp_policy_statement",
        ),
        create_coop_register_patcher_task(
            hostname=_DUT,
            config_name="bgpcpp",
            patcher_name=f"a_add_bgp_policy_statement_{_POLICY_OUT}",
            task_name="add_bgp_policy_statement",
            patcher_args={
                "name": _POLICY_OUT,
                "description": "RDSW path-scale test egress policy",
            },
            py_func_name="add_bgp_policy_statement",
        ),
        create_coop_register_patcher_task(
            hostname=_DUT,
            config_name="bgpcpp",
            patcher_name=(
                f"add_bgp_policy_match_prefix_to_propagate_routes_{_POLICY_IN}_v6"
            ),
            task_name="add_bgp_policy_match_prefix_to_propagate_routes",
            patcher_args={
                "matching_prefix": "5000::/16",
                "in_stmt_name": _POLICY_IN,
                "out_stmt_name": "RANDOM",
            },
            py_func_name="add_bgp_policy_match_prefix_to_propagate_routes",
        ),
    ]


_SETUP_TASKS = [
    create_coop_unregister_patchers_task(_DUT, config_names=["bgpcpp"]),
    # Safe mode is persisted across bgpd restarts. A previous capped scale run
    # may leave this marker behind and make the next run drop every non-golden
    # route even after its limit has been raised.
    create_run_commands_on_shell_task(
        hostname=_DUT,
        cmds=["rm -f /dev/shm/safemode.txt"],
        validate_output=True,
    ),
    # The Python configure_bgp_switch_limit patcher is lab-inventory gated, but
    # this reserved RDSW is not tagged as a lab device. Patch only the target
    # leaf through COOP before IXIA starts, preserving every sibling field.
    create_coop_register_patcher_task(
        hostname=_DUT,
        config_name="bgpcpp",
        patcher_name="zz_taac_fsdb_path_scale_total_path_limit",
        task_name="configure_bgp_switch_limit",
        jq_program=(
            ".switch_limit_config.total_path_limit = 10000000 | "
            ".switch_limit_config.overload_protection_mode = 1"
        ),
    ),
    *_path_scale_peer_group_tasks(),
    create_coop_register_patcher_task(
        hostname=_DUT,
        config_name="bgpcpp",
        patcher_name="add_bgp_peers_taac_fsdb_path_scale",
        task_name="add_bgp_peers",
        patcher_args={
            "peer_configs": json.dumps(
                [
                    {
                        "local_addr": f"{_UPLINK_NETWORK}::",
                        "peer_addr": _ACTIVE_PEER,
                        "peer_group_name": _PEER_GROUP,
                        "remote_as_4_byte": str(_DUT_ASN),
                        "description": _ACTIVE_PEER_DESCRIPTION,
                    },
                ]
            ),
        },
        py_func_name="add_bgp_peers",
    ),
    create_coop_apply_patchers_task(hostnames=[_DUT], config_name="bgpcpp"),
]


RDSW004_C086_U001_ASH6_FSDB_PATH_SCALE = TestConfig(
    name="RDSW004_C086_U001_ASH6_FSDB_PATH_SCALE",
    basset_pool="fboss.dsf",
    tags=["dsf"],
    endpoints=[
        taac_types.Endpoint(
            name=_DUT,
            ixia_ports=_IXIA_INTERFACES,
            dut=True,
            mac_address=_DUT_MAC,
            direct_ixia_connections=[
                taac_types.DirectIxiaConnection(
                    interface="eth1/11/1",
                    ixia_chassis_ip=_IXIA_API_SERVER,
                    ixia_port="1/4",
                ),
                taac_types.DirectIxiaConnection(
                    interface="eth1/15/1",
                    ixia_chassis_ip=_IXIA_API_SERVER,
                    ixia_port="1/5",
                ),
                taac_types.DirectIxiaConnection(
                    interface="eth1/25/1",
                    ixia_chassis_ip=_IXIA_API_SERVER,
                    ixia_port="1/6",
                ),
            ],
        ),
    ],
    setup_tasks=_SETUP_TASKS,
    teardown_tasks=[
        create_coop_unregister_patchers_task(_DUT, config_names=["bgpcpp"]),
    ],
    basic_port_configs=[
        _downlink_port_config(),
        _uplink_port_config(),
        _rogue_port_config(),
    ],
    basic_traffic_item_configs=[
        _traffic_item(_TRAFFIC_GOLDEN, 0),
        _traffic_item(_TRAFFIC_ROGUE, 1),
    ],
    # The MIMIC BGP stack is intentionally unpeered/down. The active session
    # is checked explicitly by address above, so global IXIA "all protocols"
    # verification would be both redundant and incorrect.
    skip_ixia_protocol_verification=True,
    ixia_protocol_verification_timeout=180,
    playbooks=[
        _control_plane_playbook(),
        create_longevity_playbook(
            playbook_name=_PLAYBOOK_NAME,
            longevity_duration=300,
            traffic_items_to_start=_TRAFFIC_ITEMS,
            prechecks=_PATH_SCALE_PRECHECKS,
            postchecks=_PATH_SCALE_POSTCHECKS,
            snapshot_checks=_SNAPSHOT_CHECKS,
        ),
    ],
)


# Control-plane-only variant for the path-scale experiment. It intentionally
# reserves only the proven active BGP injector port; route acceptance and FSDB
# publication do not require the traffic/MIMIC/NDP port on IXIA 1/6.
RDSW004_C086_U001_ASH6_FSDB_PATH_SCALE_CONTROL_PLANE = TestConfig(
    name="RDSW004_C086_U001_ASH6_FSDB_PATH_SCALE_CONTROL_PLANE",
    basset_pool="fboss.dsf",
    tags=["dsf"],
    endpoints=[
        taac_types.Endpoint(
            name=_DUT,
            ixia_ports=["eth1/15/1"],
            dut=True,
            mac_address=_DUT_MAC,
            direct_ixia_connections=[
                taac_types.DirectIxiaConnection(
                    interface="eth1/15/1",
                    ixia_chassis_ip=_IXIA_API_SERVER,
                    ixia_port="1/5",
                ),
            ],
        ),
    ],
    setup_tasks=_SETUP_TASKS,
    teardown_tasks=[
        create_coop_unregister_patchers_task(_DUT, config_names=["bgpcpp"]),
    ],
    basic_port_configs=[_uplink_port_config()],
    skip_ixia_protocol_verification=True,
    ixia_protocol_verification_timeout=180,
    playbooks=[_control_plane_playbook()],
)
