# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Short FSDB stable-state baseline for rdsw004.u001.c086.ash6."""

from ixia.ixia import types as ixia_types
from taac.health_checks.healthcheck_definitions import (
    create_core_dumps_snapshot_check,
    create_dsf_drain_state_check,
    create_dsf_fabric_reachability_check,
    create_dsf_pfc_check,
    create_fsdb_subscriber_timestamp_check,
    create_ixia_packet_loss_check,
    create_systemctl_active_state_check,
)
from taac.packet_headers import DSF_RDMA_PACKET_HEADERS
from taac.playbooks.playbook_definitions import (
    create_longevity_playbook,
)
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.types import TestConfig


_DUT = "rdsw004.u001.c086.ash6"
_DUT_MAC = "02:00:00:00:0f:0b"
_IXIA_API_SERVER = "2401:db00:2066:3037::3004"
_PLAYBOOK_NAME = "test_fsdb_stable_state"
_TRAFFIC_TO_ETH1_15 = "fsdb_stable_state_to_eth1_15"
_TRAFFIC_TO_ETH1_25 = "fsdb_stable_state_to_eth1_25"
_TRAFFIC_ITEMS = [_TRAFFIC_TO_ETH1_15, _TRAFFIC_TO_ETH1_25]
_IXIA_INTERFACES = ["eth1/11/1", "eth1/15/1", "eth1/25/1"]
_INTERFACE_NETWORKS = {
    "eth1/11/1": "2401:db00:206a:4060",
    "eth1/15/1": "2401:db00:206a:4068",
    "eth1/25/1": "2401:db00:206a:407c",
}
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


def _port_config(interface: str) -> taac_types.BasicPortConfig:
    device_group_name = interface.replace("/", "_")
    network = _INTERFACE_NETWORKS[interface]
    return taac_types.BasicPortConfig(
        l1_config=_DSF_L1_CONFIG,
        endpoint=f"{_DUT}:{interface}",
        device_group_configs=[
            taac_types.DeviceGroupConfig(
                device_group_index=0,
                tag_name=device_group_name,
                multiplier=1,
                v6_addresses_config=taac_types.IpAddressesConfig(
                    starting_ip=f"{network}::100",
                    increment_ip="::",
                    gateway_starting_ip=f"{network}::",
                    gateway_increment_ip="::",
                    mask=64,
                ),
            ),
        ],
    )


def _loss_check(*, clear_traffic_stats: bool) -> taac_types.PointInTimeHealthCheck:
    return create_ixia_packet_loss_check(
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


def _traffic_item(
    name: str,
    destination_interface: str,
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
                name=f"{_DUT}:{destination_interface}",
                device_group_index=0,
            ),
        ],
        traffic_type=ixia_types.TrafficType.IPV6,
        tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
        frame_size_settings=_DSF_FRAME_SIZES,
        packet_headers=DSF_RDMA_PACKET_HEADERS,
    )


_PRECHECKS = [
    create_systemctl_active_state_check(),
    create_dsf_drain_state_check(is_drained=False),
    create_dsf_fabric_reachability_check(),
    _fsdb_check(),
    _pfc_check("snapshot"),
    _loss_check(clear_traffic_stats=True),
]

_POSTCHECKS = [
    create_systemctl_active_state_check(),
    create_dsf_drain_state_check(is_drained=False),
    create_dsf_fabric_reachability_check(),
    _fsdb_check(),
    _pfc_check("check"),
    _loss_check(clear_traffic_stats=False),
]

_SNAPSHOT_CHECKS = [create_core_dumps_snapshot_check()]


RDSW004_C086_U001_ASH6_FSDB_STABLE_STATE = TestConfig(
    name="RDSW004_C086_U001_ASH6_FSDB_STABLE_STATE",
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
    setup_tasks=[],
    teardown_tasks=[],
    basic_port_configs=[
        _port_config("eth1/11/1"),
        _port_config("eth1/15/1"),
        _port_config("eth1/25/1"),
    ],
    basic_traffic_item_configs=[
        _traffic_item(_TRAFFIC_TO_ETH1_15, "eth1/15/1"),
        _traffic_item(_TRAFFIC_TO_ETH1_25, "eth1/25/1"),
    ],
    skip_ixia_protocol_verification=False,
    ixia_protocol_verification_timeout=120,
    playbooks=[
        create_longevity_playbook(
            playbook_name=_PLAYBOOK_NAME,
            longevity_duration=180,
            traffic_items_to_start=_TRAFFIC_ITEMS,
            prechecks=_PRECHECKS,
            postchecks=_POSTCHECKS,
            snapshot_checks=_SNAPSHOT_CHECKS,
        ),
    ],
)
