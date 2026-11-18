# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Minipack3N (NVIDIA Spectrum-4) NPI CPU queue TestConfig.

IPv6-only variant of `create_npi_cpu_queue_test_config` for MP3N, where IPv4
is not a use case. Spectrum ASICs accept neighbors from only one MAC per
physical port, so each IXIA port carries its V6 peers behind one MAC: an
`NDP_HANDLER` device group owns the peer addresses and a `CHAINED_0` device
group runs the BGP sessions on top of it (same pattern as
`ai_bb/mp3n_bgp_path_scale_test_config.py`).

Playbooks and traffic match the original minus everything IPv4 (ARP, DHCPv4,
ICMPv4, IPv4 TTL, martian SIP, V4 BGP control plane) and npi_cpu_041, whose
low-queue burst is IPv4.
"""

import json
from dataclasses import dataclass

from ixia.ixia import types as ixia_types
from taac.health_checks.healthcheck_definitions import (
    create_cpu_queue_snapshot_check,
)
from taac.packet_headers import (
    BGP_CP_TRAFFIC_PACKET_HEADERS,
    BGP_CP_V6_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
    BGP_CP_V6_LINK_LOCAL_DSCP0_TRAFFIC_PACKET_HEADERS,
    BGP_CP_V6_LINK_LOCAL_DSCP48_TRAFFIC_PACKET_HEADERS,
    DHCP_V6_GLOBAL_DSCP0_TRAFFIC_PACKET_HEADERS,
    DHCP_V6_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
    DHCP_V6_LL_DSCP48_TRAFFIC_PACKET_HEADERS,
    DHCP_V6_TRAFFIC_PACKET_HEADERS,
    DSCP_48_TO_SWITCH_GLOBAL_IPV6_TRAFFIC_PACKET_HEADERS,
    DSCP_48_TO_SWITCH_LINK_LOCAL_IPV6_TRAFFIC_PACKET_HEADERS,
    HOP_LIMIT_0_IPV6_TRAFFIC_PACKET_HEADERS,
    HOP_LIMIT_1_IPV6_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_DEST_UNREACHABLE_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_DEST_UNREACHABLE_LINK_LOCAL_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_ECHO_REPLY_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_ECHO_REPLY_LINK_LOCAL_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_ECHO_REQUEST_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_ECHO_REQUEST_LINK_LOCAL_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_PACKET_TOO_BIG_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_PACKET_TOO_BIG_LINK_LOCAL_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_REQUEST_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_TIME_EXCEEDED_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
    ICMP_V6_TIME_EXCEEDED_LINK_LOCAL_TRAFFIC_PACKET_HEADERS,
    LACP_SLOW_TIMER_TRAFFIC_PACKET_HEADERS,
    LLDP_TRAFFIC_PACKET_HEADERS,
    MTU_EXCEED_IPV6_TRAFFIC_PACKET_HEADERS,
    NDP_NA_MULTICAST_TRAFFIC_PACKET_HEADERS,
    NDP_NA_UNICAST_TRAFFIC_PACKET_HEADERS,
    NDP_NS_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
    NDP_NS_MULTICAST_TRAFFIC_PACKET_HEADERS,
    NDP_NS_UNICAST_TRAFFIC_PACKET_HEADERS,
    NDP_RA_MULTICAST_TRAFFIC_PACKET_HEADERS,
    NDP_RA_UNICAST_TRAFFIC_PACKET_HEADERS,
    NDP_RS_MULTICAST_TRAFFIC_PACKET_HEADERS,
    NDP_RS_UNICAST_TRAFFIC_PACKET_HEADERS,
    UNH_DIRECT_CONNECTED_HOST_IPV6_TRAFFIC_PACKET_HEADERS,
    UNH_REMOTE_SUBNET_128_IPV6_TRAFFIC_PACKET_HEADERS,
    UNH_REMOTE_SUBNET_IPV6_TRAFFIC_PACKET_HEADERS,
)
from taac.playbooks.playbook_definitions import (
    add_common_checks_to_cpu_queue_playbooks,
    create_cpu_queue_playbooks,
)
from taac.task_definitions import (
    create_coop_apply_patchers_task,
    create_coop_register_patcher_task,
    create_coop_unregister_patchers_task,
    create_enable_ixia_ports_patcher_task,
)
from taac.testconfigs.npi.cpu_queue_test_config import (
    _select_playbooks,
)
from taac.testconfigs.npi.minipack_cpu_queue_constants import (
    MINIPACK_CPU_QUEUE_PLAYBOOKS,
)
from taac.utils.common import get_default_bgp_configs
from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.types import TestConfig


_BGP_CONFIG_NAMES = ("bgpcpp", "bgpcpp_softdrain")
_NDP_HANDLER_DEVICE_GROUP_INDEX = 0
_V6_BGP_DEVICE_GROUP_INDEX = 1
# DUT side of every IXIA port: the `::a` address already on its /64.
_V6_DUT_HOST = "a"
_V6_IXIA_FIRST_HOST = 0x100
# CPU queue playbooks that need IPv4 traffic.
_IPV4_PLAYBOOKS = frozenset(
    {
        "npi_cpu_005_bgp_cp_v4_def_gw_dscp48_to_high_queue",
        "npi_cpu_006_bgp_cp_v4_def_gw_dscp0_to_high_queue",
        "npi_cpu_010_dhcp_v4_discover_bcast_to_mid_queue",
        "npi_cpu_011_dhcp_v4_discover_ucast_to_mid_queue",
        "npi_cpu_012_icmp_v4_echo_req_to_mid_queue",
        "npi_cpu_013_icmp_v4_echo_reply_to_mid_queue",
        "npi_cpu_014_icmp_v4_dest_unreach_to_mid_queue",
        "npi_cpu_015_icmp_v4_time_exceeded_to_mid_queue",
        "npi_cpu_017_arp_request_bcast_to_high_queue",
        "npi_cpu_018_arp_response_to_high_queue",
        "npi_cpu_019_arp_response_bcast_to_high_queue",
        "npi_cpu_041_queue_prioritization_high_no_drops",
        "npi_cpu_044_ttl_1_ipv4_to_low_queue",
        "npi_cpu_045_ttl_0_ipv4_not_punted",
        "npi_cpu_046_martian_sip_not_punted",
    }
)
# Only the Spectrum-4 CoPP config has a post-lookup ACL table, where DSCP 48 to
# the switch's global IP hits `cpuPolicing-high-myip-network-control-acl-v6`
# (HIGH). Platforms without it trap that traffic as IP2ME (MID). DHCPv6 keeps
# its DHCPV6 trap queue (MID) on Spectrum-4 too.
_SP4_ACTIVE_QUEUE_OVERRIDES: dict[str, str] = {
    "npi_cpu_047_dscp_48_to_switch_global_to_mid_queue": "high",
}


@dataclass(frozen=True)
class Mp3nIxiaPort:
    """IXIA port carrying V6 peers, all behind one IXIA MAC.

    Attributes:
        interface: DUT port.
        network: The /64 already on the DUT port, without the host part
            (`2401:db00:209e:2` for `2401:db00:209e:2::a/64`). The DUT keeps
            `::a`; IXIA peers take `::100`, `::101`, ...
        ixia_chassis_ip / ixia_port: Direct IXIA connection.
    """

    interface: str
    network: str
    ixia_chassis_ip: str
    ixia_port: str


# MP3NM has a single hardware agent; on native NetOS the systemctl check raises
# on the absent `fboss_hw_agent@1` unit instead of skipping it.
_SYSTEMCTL_SERVICES: list[hc_types.Service] = [
    service
    for service in hc_types.Service
    if service != hc_types.Service.FBOSS_HW_AGENT_1
]


def _apply_sp4_queue_overrides(
    playbooks: list[taac_types.Playbook],
    queues: dict[str, int],
    bgp_peer_count: int,
) -> list[taac_types.Playbook]:
    """Swap the CPU-queue snapshot check of `_SP4_ACTIVE_QUEUE_OVERRIDES` playbooks.

    Noise tolerances match `create_cpu_queue_playbooks`.
    """
    noise = {
        queues["low"]: 100 + bgp_peer_count * 20,
        queues["mid"]: 100 + bgp_peer_count * 5,
        queues["high"]: 100 + bgp_peer_count * 50,
    }
    result = []
    for playbook in playbooks:
        override = _SP4_ACTIVE_QUEUE_OVERRIDES.get(playbook.name)
        if override is None:
            result.append(playbook)
            continue
        active = queues[override]
        inactive = [q for q in queues.values() if q != active]
        check = create_cpu_queue_snapshot_check(
            active_queues=[active],
            inactive_queues=inactive,
            inactive_max_pps_per_queue={q: noise[q] for q in inactive},
            no_discard_queues=[queues["high"]],
            active_min_out_pps_per_queue={active: 10},
        )
        result.append(playbook(snapshot_checks=[check]))
    return result


def _ixia_address(network: str, index: int) -> str:
    return f"{network}::{_V6_IXIA_FIRST_HOST + index:x}"


def _device_group_configs(
    *,
    port: Mp3nIxiaPort,
    peer_count: int,
    remote_as_4byte: int,
    remote_as_4_byte_step: int,
    prefix_count: int,
    starting_prefix: str,
    communities: list[str],
) -> list[taac_types.DeviceGroupConfig]:
    addresses = taac_types.IpAddressesConfig(
        starting_ip=_ixia_address(port.network, 0),
        increment_ip="::1",
        gateway_starting_ip=f"{port.network}::{_V6_DUT_HOST}",
        gateway_increment_ip="::",
        mask=64,
    )
    return [
        taac_types.DeviceGroupConfig(
            device_group_index=_NDP_HANDLER_DEVICE_GROUP_INDEX,
            tag_name="NDP_HANDLER",
            multiplier=peer_count,
            v6_addresses_config=addresses,
        ),
        taac_types.DeviceGroupConfig(
            device_group_index=_V6_BGP_DEVICE_GROUP_INDEX,
            tag_name=f"CHAINED_{_NDP_HANDLER_DEVICE_GROUP_INDEX}:BGP_MULTI_PEER",
            multiplier=peer_count,
            v6_addresses_config=addresses,
            v6_bgp_config=taac_types.BgpConfig(
                local_as_4_bytes=remote_as_4byte,
                local_as_increment=remote_as_4_byte_step,
                enable_4_byte_local_as=True,
                is_confed=False,
                bgp_capabilities=[ixia_types.BgpCapability.IpV6Unicast],
                route_scales=[
                    taac_types.RouteScaleSpec(
                        network_group_index=0,
                        v6_route_scale=taac_types.RouteScale(
                            multiplier=1,
                            prefix_count=prefix_count,
                            prefix_length=64,
                            starting_prefixes=starting_prefix,
                            prefix_step="0:0:0:0::0",
                            bgp_communities=communities,
                            ip_address_family=ixia_types.IpAddressFamily.IPV6,
                        ),
                    ),
                ],
            ),
        ),
    ]


def _peer_configs(
    *,
    port: Mp3nIxiaPort,
    peer_count: int,
    peer_group_name: str,
    remote_as_4byte: int,
    remote_as_4_byte_step: int,
    description: str,
) -> list[dict[str, str]]:
    return [
        {
            "local_addr": f"{port.network}::{_V6_DUT_HOST}",
            "peer_addr": _ixia_address(port.network, i),
            "peer_group_name": peer_group_name,
            "remote_as_4_byte": str(remote_as_4byte + i * remote_as_4_byte_step),
            "description": f"{description} {i}",
        }
        for i in range(peer_count)
    ]


def _peer_group_update_task(
    *, hostname: str, config_names: list[str], name: str, max_routes: str
) -> taac_types.Task:
    return create_coop_register_patcher_task(
        hostname=hostname,
        config_names=config_names,
        patcher_name=f"update_peer_group_patcher_{name}",
        task_name="coop_register_patcher",
        patcher_args={
            "name": name,
            "attributes_to_update_json": json.dumps(
                {
                    "disable_ipv4_afi": "True",
                    "v4_over_v6_nexthop": "False",
                    "is_passive": "False",
                    "max_routes": max_routes,
                    "is_confed_peer": "False",
                }
            ),
        },
        py_func_name="configure_bgp_peer_group",
    )


def _create_mp3n_cpu_queue_traffic_items(
    device_name: str,
    ixia_downlink_interface: str,
    ixia_uplink_interface: str,
) -> list[taac_types.BasicTrafficItemConfig]:
    """`create_npi_cpu_queue_test_config`'s IPv6 traffic items.

    Raw items resolve their IPv6 references from the NDP handler group; the
    BGP items use the chained BGP group's network group.
    """
    return [
        taac_types.BasicTrafficItemConfig(
            name="V6_DIRECTIONAL_TRAFFIC_BETWEEN_DOWNLINK_AND_UPLINK",
            bidirectional=True,
            merge_destinations=True,
            line_rate=10,
            src_dest_mesh=ixia_types.SrcDestMeshType.MANY_TO_MANY,
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    network_group_index=0,
                    device_group_index=_V6_BGP_DEVICE_GROUP_INDEX,
                )
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    network_group_index=0,
                    device_group_index=_V6_BGP_DEVICE_GROUP_INDEX,
                )
            ],
            traffic_type=ixia_types.TrafficType.IPV6,
            tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    network_group_index=0,
                    device_group_index=0,
                )
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    network_group_index=0,
                    device_group_index=0,
                )
            ],
            name="TEST_RAW_BGP_CP_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=BGP_CP_TRAFFIC_PACKET_HEADERS,
        ),
        # CPU_002: BGPv6 global + DSCP=48 → HIGH queue
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    network_group_index=0,
                    device_group_index=0,
                )
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    network_group_index=0,
                    device_group_index=0,
                )
            ],
            name="TEST_RAW_BGP_CP_V6_GLOBAL_DSCP48_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=BGP_CP_V6_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
        ),
        # CPU_003: BGPv6 link-local + DSCP=48 → HIGH queue
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    network_group_index=0,
                    device_group_index=0,
                )
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    network_group_index=0,
                    device_group_index=0,
                )
            ],
            name="TEST_RAW_BGP_CP_V6_LINK_LOCAL_DSCP48_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=BGP_CP_V6_LINK_LOCAL_DSCP48_TRAFFIC_PACKET_HEADERS,
        ),
        # CPU_004: BGPv6 link-local + DSCP=0 → HIGH queue
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    network_group_index=0,
                    device_group_index=0,
                )
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    network_group_index=0,
                    device_group_index=0,
                )
            ],
            name="TEST_RAW_BGP_CP_V6_LINK_LOCAL_DSCP0_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=BGP_CP_V6_LINK_LOCAL_DSCP0_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    network_group_index=0,
                    device_group_index=0,
                )
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    network_group_index=0,
                    device_group_index=0,
                )
            ],
            name="TEST_RAW_LLDP_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=LLDP_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            name="BGP_PREFIX_TRAFFIC",
            bidirectional=False,
            merge_destinations=True,
            line_rate=10,
            src_dest_mesh=ixia_types.SrcDestMeshType.MANY_TO_MANY,
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    network_group_index=0,
                    device_group_index=_V6_BGP_DEVICE_GROUP_INDEX,
                )
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    network_group_index=0,
                    device_group_index=_V6_BGP_DEVICE_GROUP_INDEX,
                )
            ],
            traffic_type=ixia_types.TrafficType.IPV6,
            frame_size_settings=ixia_types.FrameSize(
                type=ixia_types.FrameSizeType.CUSTOM_IMIX
            ),
        ),
        taac_types.BasicTrafficItemConfig(
            name="IPV6_TRAFFIC",
            bidirectional=False,
            merge_destinations=True,
            line_rate=10,
            src_dest_mesh=ixia_types.SrcDestMeshType.MANY_TO_MANY,
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    network_group_index=0,
                    device_group_index=_V6_BGP_DEVICE_GROUP_INDEX,
                )
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    network_group_index=0,
                    device_group_index=_V6_BGP_DEVICE_GROUP_INDEX,
                )
            ],
            traffic_type=ixia_types.TrafficType.IPV6,
            frame_size_settings=ixia_types.FrameSize(
                type=ixia_types.FrameSizeType.CUSTOM_IMIX
            ),
        ),
        # CPU_007: DHCPv6 global + DSCP=48 → MID queue
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_RAW_DHCP_V6_GLOBAL_DSCP48_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=DHCP_V6_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
        ),
        # CPU_008: DHCPv6 global + DSCP=0 → MID queue
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_RAW_DHCP_V6_GLOBAL_DSCP0_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=DHCP_V6_GLOBAL_DSCP0_TRAFFIC_PACKET_HEADERS,
        ),
        # CPU_009: DHCPv6 link-local + DSCP=48 → MID queue
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=1,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=1,
                ),
            ],
            name="TEST_RAW_DHCP_V6_LL_DSCP48_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=DHCP_V6_LL_DSCP48_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_RAW_ICMP_V6_REQUEST_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_REQUEST_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_NEXTHOP_LIMIT_1_IPV6_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=HOP_LIMIT_1_IPV6_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_NEXTHOP_LIMIT_0_IPV6_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=HOP_LIMIT_0_IPV6_TRAFFIC_PACKET_HEADERS,
        ),
        # CPU_039: MTU exceed — routed IPv6 packet larger than DUT MTU
        # (1500). DUT must punt to LOW queue for ICMPv6 "Packet Too Big"
        # generation. NOTE: frame size > MTU must be configured on this
        # traffic item by IXIA (default frame size ~64B will not trigger
        # MTU exceed); follow-up tuning may be required if the framework's
        # default frame-size policy doesn't already produce oversize
        # frames for RAW traffic items.
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_MTU_EXCEED_IPV6_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=MTU_EXCEED_IPV6_TRAFFIC_PACKET_HEADERS,
            # 9100 byte fixed frame size exceeds the DUT interface MTU
            # (confirmed 9000 jumbo on gtsw001.l1001.c085.ash6 eth1/13/1
            # via `fboss2 show interface`, 2026-06-08) so the routed
            # packet triggers the MTU-exceed exception and is punted to
            # the LOW CPU queue (with the DUT emitting ICMPv6 "Packet
            # Too Big" back).
            #
            # The test-case spec ("Change MTU on interface to be 1500
            # and send data plane traffic for remote subnet with MTU
            # > 1500, exp: q0") expects the playbook to shrink the
            # DUT egress interface MTU to 1500 (see the matching
            # `change_interface_mtu_patcher` step in the npi_cpu_039
            # playbook in `playbook_definitions.py`). Once that
            # patcher applies, **any** frame > 1500 triggers the
            # silicon's MTU-exceed exception → CPU low queue.
            #
            # Use 1700 — just barely above the 1500 DUT MTU so the
            # punt fires deterministically — and well below any
            # plausible IXIA-side port limit so the tx never gets
            # silently dropped at the chassis. Past attempts at
            # fixed_size=9100 (Run 4.3+4.4 2026-06-08) failed
            # because the DUT was still at its provisioned jumbo
            # MTU (~9000) — without the new patcher step, 9100 was
            # only marginally over MTU and the silicon didn't
            # punt. 1700 + DUT MTU=1500 is the correct pairing.
            frame_size_settings=ixia_types.FrameSize(
                type=ixia_types.FrameSizeType.FIXED,
                fixed_size=1700,
            ),
            # RAW traffic items get NO tracking by default: ixia.py's
            # default_tracking_types_raw is deliberately empty when
            # traffic_type is RAW, so TrackBy ends up [] and the traffic-item
            # statistics view is never initialised. That makes npi_cpu_039
            # undiagnosable -- when it fails with "No output packet increase
            # detected on queue 0" there is no way to tell whether IXIA
            # transmitted at all or whether the DUT declined to punt, because
            # get_latest_stats_traffic() raises "IXIA traffic-item statistics
            # view is not initialized" (taac_ixia.py gates the view on
            # TRAFFIC_ITEM being present in TrackBy).
            # Asking for TRAFFIC_ITEM explicitly bypasses the RAW default and
            # gives the tx/rx frame counts needed to tell those two apart.
            tracking_types=[
                ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM,
            ],
        ),
        # CPU_047: DSCP=48 to-switch global IPv6 — host-bound, DSCP=48
        # → MID queue. No L4/ICMP layer; pure IPv6 to switch's own global IP.
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_DSCP_48_TO_SWITCH_GLOBAL_IPV6_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=DSCP_48_TO_SWITCH_GLOBAL_IPV6_TRAFFIC_PACKET_HEADERS,
        ),
        # CPU_048: DSCP=48 to-switch link-local IPv6 — host-bound,
        # SIP=Ixia LL, DIP=switch LL, DSCP=48 → MID queue.
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_DSCP_48_TO_SWITCH_LINK_LOCAL_IPV6_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=DSCP_48_TO_SWITCH_LINK_LOCAL_IPV6_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_LACP_SLOW_TIMER_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=LACP_SLOW_TIMER_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_NDP_NS_MULTICAST_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=NDP_NS_MULTICAST_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_NDP_NA_MULTICAST_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=NDP_NA_MULTICAST_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_NDP_RS_MULTICAST_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=NDP_RS_MULTICAST_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_NDP_RA_MULTICAST_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=NDP_RA_MULTICAST_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_NDP_NS_UNICAST_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            # 14 (eth) + 40 (ipv6) + 24 (NS body) + 8 (NDP source-LL
            # option) = 86 B; pin frame size so we don't inherit IXIA's
            # 400 B RAW default and pollute the test with oversized
            # frames.
            frame_size_settings=ixia_types.FrameSize(
                type=ixia_types.FrameSizeType.FIXED, fixed_size=86
            ),
            bidirectional=False,
            packet_headers=NDP_NS_UNICAST_TRAFFIC_PACKET_HEADERS,
        ),
        # CPU_020: NDP NS global + DSCP=48 → HIGH queue
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_RAW_NDP_NS_GLOBAL_DSCP48_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            # Pin NDP NS frame size; see TEST_NDP_NS_UNICAST_TRAFFIC.
            frame_size_settings=ixia_types.FrameSize(
                type=ixia_types.FrameSizeType.FIXED, fixed_size=86
            ),
            bidirectional=False,
            packet_headers=NDP_NS_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_NDP_NA_UNICAST_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            # NDP NA also 86 B; see TEST_NDP_NS_UNICAST_TRAFFIC.
            frame_size_settings=ixia_types.FrameSize(
                type=ixia_types.FrameSizeType.FIXED, fixed_size=86
            ),
            bidirectional=False,
            packet_headers=NDP_NA_UNICAST_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_NDP_RS_UNICAST_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            # NDP RS at 86 B; see TEST_NDP_NS_UNICAST_TRAFFIC.
            frame_size_settings=ixia_types.FrameSize(
                type=ixia_types.FrameSizeType.FIXED, fixed_size=86
            ),
            bidirectional=False,
            packet_headers=NDP_RS_UNICAST_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_NDP_RA_UNICAST_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            # NDP RA at 86 B; see TEST_NDP_NS_UNICAST_TRAFFIC.
            frame_size_settings=ixia_types.FrameSize(
                type=ixia_types.FrameSizeType.FIXED, fixed_size=86
            ),
            bidirectional=False,
            packet_headers=NDP_RA_UNICAST_TRAFFIC_PACKET_HEADERS,
        ),
        # ICMPv6 Non-NDP with Link-Local Addresses
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_ICMPV6_ECHO_REQUEST_LINK_LOCAL_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_ECHO_REQUEST_LINK_LOCAL_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_ICMPV6_ECHO_REPLY_LINK_LOCAL_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_ECHO_REPLY_LINK_LOCAL_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_ICMPV6_DEST_UNREACHABLE_LINK_LOCAL_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_DEST_UNREACHABLE_LINK_LOCAL_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_ICMPV6_PACKET_TOO_BIG_LINK_LOCAL_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_PACKET_TOO_BIG_LINK_LOCAL_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_ICMPV6_TIME_EXCEEDED_LINK_LOCAL_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_TIME_EXCEEDED_LINK_LOCAL_TRAFFIC_PACKET_HEADERS,
        ),
        # ICMPv6 Non-NDP with Global Addresses and DSCP 48
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_ICMPV6_ECHO_REQUEST_GLOBAL_DSCP48_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_ECHO_REQUEST_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_ICMPV6_ECHO_REPLY_GLOBAL_DSCP48_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_ECHO_REPLY_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_ICMPV6_DEST_UNREACHABLE_GLOBAL_DSCP48_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_DEST_UNREACHABLE_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_ICMPV6_PACKET_TOO_BIG_GLOBAL_DSCP48_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_PACKET_TOO_BIG_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_ICMPV6_TIME_EXCEEDED_GLOBAL_DSCP48_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=ICMP_V6_TIME_EXCEEDED_GLOBAL_DSCP48_TRAFFIC_PACKET_HEADERS,
        ),
        # High rate traffic to MID queue (DHCPv6) to create drops
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="BURST_MID_QUEUE_DHCPV6_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=100000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=DHCP_V6_TRAFFIC_PACKET_HEADERS,
        ),
        # UNH (Unreachable Next Hop) traffic items — RAW IPv6 traffic
        # keeps entering the switch after the downlink BGP session drops
        # (which stops BGP_PREFIX_TRAFFIC / IPV6_TRAFFIC). CPU_036 targets
        # the directly connected downlink host; CPU_037 and CPU_038 target
        # prefixes installed by register_cpu_queue_static_route_patcher.
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_RAW_UNH_DIRECT_CONNECTED_HOST_IPV6_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=UNH_DIRECT_CONNECTED_HOST_IPV6_TRAFFIC_PACKET_HEADERS,
            tracking_types=[
                ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM,
            ],
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_RAW_UNH_REMOTE_SUBNET_IPV6_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=UNH_REMOTE_SUBNET_IPV6_TRAFFIC_PACKET_HEADERS,
        ),
        taac_types.BasicTrafficItemConfig(
            src_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_uplink_interface}",
                    device_group_index=0,
                ),
            ],
            dest_endpoints=[
                taac_types.TrafficEndpoint(
                    name=f"{device_name}:{ixia_downlink_interface}",
                    device_group_index=0,
                ),
            ],
            name="TEST_RAW_UNH_REMOTE_SUBNET_128_IPV6_TRAFFIC",
            line_rate_type=ixia_types.RateType.FRAMES_PER_SECOND,
            line_rate=2000,
            traffic_type=ixia_types.TrafficType.RAW,
            bidirectional=False,
            packet_headers=UNH_REMOTE_SUBNET_128_IPV6_TRAFFIC_PACKET_HEADERS,
        ),
    ]


def create_mp3n_npi_cpu_queue_test_config(
    *,
    test_config_name: str,
    device_name: str,
    local_mac_address: str,
    ixia_downlink_port: Mp3nIxiaPort,
    ixia_uplink_port: Mp3nIxiaPort,
    peergroup_downlink_v6: str,
    peergroup_uplink_v6: str,
    remote_downlink_as_4byte: int,
    remote_uplink_as_4byte: int,
    downlink_prefix_count: int,
    uplink_prefix_count: int,
    downlink_communities: list[str],
    uplink_communities: list[str],
    unique_prefix_limit: str,
    per_peer_max_route_limit: str,
    low_queue: int,
    mid_queue: int,
    high_queue: int,
    downlink_peer_count: int = 1,
    uplink_peer_count: int = 1,
    remote_as_4_byte_step: int = 1,
    basset_pool: str = "dne.test",
    ixia_packet_loss_threshold: str = "0.1",
    service_restart_services: list[str] | None = None,
    playbooks_selected: list[str] | None = None,
    skip_ixia_protocol_verification: bool = False,
) -> TestConfig:
    """Build the IPv6-only CPU queue TestConfig for a Minipack3N DUT.

    Args:
        ixia_downlink_port: Traffic sink and flap target.
        ixia_uplink_port: CPU-queue traffic source.
        peergroup_downlink_v6 / peergroup_uplink_v6: Existing V6 peer groups;
            they are updated, not created.
        downlink_peer_count / uplink_peer_count: V6 peers per port.
        remote_as_4_byte_step: Remote-AS increment between peers on a port.
        low_queue / mid_queue / high_queue: CPU queue indices.
        playbooks_selected: Optional ordered subset of CPU queue playbook names.
        skip_ixia_protocol_verification: Run playbooks without waiting for the
            IXIA BGP sessions to establish.
    """
    bgp_config_names = [
        c for c in get_default_bgp_configs(device_name) if c in _BGP_CONFIG_NAMES
    ]
    peer_configs = [
        *_peer_configs(
            port=ixia_downlink_port,
            peer_count=downlink_peer_count,
            peer_group_name=peergroup_downlink_v6,
            remote_as_4byte=remote_downlink_as_4byte,
            remote_as_4_byte_step=remote_as_4_byte_step,
            description="IXIA downlink IPv6 peer",
        ),
        *_peer_configs(
            port=ixia_uplink_port,
            peer_count=uplink_peer_count,
            peer_group_name=peergroup_uplink_v6,
            remote_as_4byte=remote_uplink_as_4byte,
            remote_as_4_byte_step=remote_as_4_byte_step,
            description="IXIA uplink IPv6 peer",
        ),
    ]
    ports = [ixia_downlink_port, ixia_uplink_port]
    ixia_interfaces = [port.interface for port in ports]
    bgp_peer_count = downlink_peer_count + uplink_peer_count
    playbooks = _apply_sp4_queue_overrides(
        [
            playbook
            for playbook in create_cpu_queue_playbooks(
                low_queue=low_queue,
                mid_queue=mid_queue,
                high_queue=high_queue,
                ixia_downlink_interface=ixia_downlink_port.interface,
                bgp_peer_count=bgp_peer_count,
                # The NDP_HANDLER group has no network group.
                static_route_device_group_index=_V6_BGP_DEVICE_GROUP_INDEX,
            )
            if playbook.name not in _IPV4_PLAYBOOKS
        ],
        queues={"low": low_queue, "mid": mid_queue, "high": high_queue},
        bgp_peer_count=bgp_peer_count,
    )
    return TestConfig(
        name=test_config_name,
        ixia_protocol_verification_timeout=600,
        skip_ixia_protocol_verification=skip_ixia_protocol_verification,
        basset_pool=basset_pool,
        ixia_config_cache=taac_types.IxiaConfigCache(enabled=False),
        endpoints=[
            taac_types.Endpoint(
                name=device_name,
                ixia_ports=ixia_interfaces,
                dut=True,
                mac_address=local_mac_address,
                direct_ixia_connections=[
                    taac_types.DirectIxiaConnection(
                        interface=port.interface,
                        ixia_chassis_ip=port.ixia_chassis_ip,
                        ixia_port=port.ixia_port,
                    )
                    for port in ports
                ],
            ),
        ],
        setup_tasks=[
            create_coop_unregister_patchers_task(device_name),
            create_enable_ixia_ports_patcher_task(device_name, ixia_interfaces),
            create_coop_register_patcher_task(
                hostname=device_name,
                config_names=bgp_config_names,
                patcher_name="a_remove_bgp_peers",
                task_name="coop_register_patcher",
                patcher_args={"delete_all": "True"},
                py_func_name="remove_bgp_peers",
            ),
            create_coop_register_patcher_task(
                hostname=device_name,
                config_names=bgp_config_names,
                patcher_name="configure_bgp_switch_limit",
                task_name="coop_register_patcher",
                patcher_args={"prefix_limit": unique_prefix_limit},
                py_func_name="configure_bgp_switch_limit",
            ),
            *[
                _peer_group_update_task(
                    hostname=device_name,
                    config_names=bgp_config_names,
                    name=name,
                    max_routes=per_peer_max_route_limit,
                )
                for name in dict.fromkeys([peergroup_downlink_v6, peergroup_uplink_v6])
            ],
            create_coop_register_patcher_task(
                hostname=device_name,
                config_names=bgp_config_names,
                patcher_name="add_bgp_peers_ixia",
                task_name="coop_register_patcher",
                patcher_args={"peer_configs": json.dumps(peer_configs)},
                py_func_name="add_bgp_peers",
            ),
            create_coop_apply_patchers_task(
                hostnames=[device_name], fail_on_agent_reload_error=True
            ),
        ],
        teardown_tasks=[
            create_coop_unregister_patchers_task(device_name),
            create_coop_apply_patchers_task(
                hostnames=[device_name],
                config_name="agent",
                fail_on_agent_reload_error=True,
            ),
        ],
        basic_port_configs=[
            taac_types.BasicPortConfig(
                endpoint=f"{device_name}:{ixia_downlink_port.interface}",
                device_group_configs=_device_group_configs(
                    port=ixia_downlink_port,
                    peer_count=downlink_peer_count,
                    remote_as_4byte=remote_downlink_as_4byte,
                    remote_as_4_byte_step=remote_as_4_byte_step,
                    prefix_count=downlink_prefix_count,
                    starting_prefix="9000:1::",
                    communities=downlink_communities,
                ),
            ),
            taac_types.BasicPortConfig(
                endpoint=f"{device_name}:{ixia_uplink_port.interface}",
                device_group_configs=_device_group_configs(
                    port=ixia_uplink_port,
                    peer_count=uplink_peer_count,
                    remote_as_4byte=remote_uplink_as_4byte,
                    remote_as_4_byte_step=remote_as_4_byte_step,
                    prefix_count=uplink_prefix_count,
                    starting_prefix="8000:1::",
                    communities=uplink_communities,
                ),
            ),
        ],
        basic_traffic_item_configs=_create_mp3n_cpu_queue_traffic_items(
            device_name, ixia_downlink_port.interface, ixia_uplink_port.interface
        ),
        playbooks=add_common_checks_to_cpu_queue_playbooks(
            _select_playbooks(playbooks, playbooks_selected),
            unique_prefix_limit=int(unique_prefix_limit),
            ixia_packet_loss_threshold=ixia_packet_loss_threshold,
            service_restart_services=service_restart_services,
            systemctl_services=_SYSTEMCTL_SERVICES,
        ),
    )


_IXIA16_CHASSIS_IP = "2401:db00:2066:304b::3004"

# rtsw001.l1003.c084.ash6: MINIPACK3NM, CPU queues low=0 / mid=2 / high=3
# (agent `cpuQueues` / `rxReasonToQueue`). IXIA ports are ixia16 links (LLDP).
# The RTSW has only the FTSW V6 group, so both directions attach to it (as on
# the IcePack GTSW). RTSW is non-drainable: only `bgpcpp` is patched.
MP3N_RTSW001_L1003_C084_CPU_QUEUE_TEST_CONFIG = create_mp3n_npi_cpu_queue_test_config(
    test_config_name="MP3N_RTSW001_L1003_C084_CPU_QUEUE_TEST_CONFIG",
    device_name="rtsw001.l1003.c084.ash6",
    local_mac_address="5e:40:97:19:90:83",
    ixia_downlink_port=Mp3nIxiaPort(
        interface="eth1/1/1",
        network="2401:db00:209e:0",
        ixia_chassis_ip=_IXIA16_CHASSIS_IP,
        ixia_port="1/13",
    ),
    ixia_uplink_port=Mp3nIxiaPort(
        interface="eth1/2/1",
        network="2401:db00:209e:2",
        ixia_chassis_ip=_IXIA16_CHASSIS_IP,
        ixia_port="1/15",
    ),
    peergroup_downlink_v6="PEERGROUP_RTSW_FTSW_V6",
    peergroup_uplink_v6="PEERGROUP_RTSW_FTSW_V6",
    # eBGP mimics; both differ from the DUT's local AS 4200000143.
    remote_downlink_as_4byte=7001,
    remote_uplink_as_4byte=65272,
    downlink_prefix_count=500,
    uplink_prefix_count=500,
    # PROPAGATE_RTSW_FTSW_IN denies (rule 470) without a path community
    # 65441:{67,133,196,259}. This set takes the D_HOP3 branch and installs at
    # LP 90, like real FTSW-learned RTSW loopbacks:
    #   65446:30 LIVE, 65441:259 D_HOP3 path, 65456:259 LP=90.
    downlink_communities=["65446:30", "65441:259", "65456:259"],
    uplink_communities=["65446:30", "65441:259", "65456:259"],
    unique_prefix_limit="5000",
    per_peer_max_route_limit="20000",
    low_queue=0,
    mid_queue=2,
    high_queue=3,
    basset_pool="taac_netcastle_ash6",
    # openr and fboss_hw_agent@0 are not running on this DUT.
    service_restart_services=[
        "bgpd",
        "fboss_sw_agent",
        "fsdb",
        "qsfp_service",
        "wedge_agent",
    ],
    playbooks_selected=[
        name for name in MINIPACK_CPU_QUEUE_PLAYBOOKS if name not in _IPV4_PLAYBOOKS
    ],
)
