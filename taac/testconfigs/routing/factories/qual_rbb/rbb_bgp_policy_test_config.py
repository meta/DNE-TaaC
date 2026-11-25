# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Two-DUT/IXIA TestConfig for Phase-2 TC-65--68."""

from __future__ import annotations

import typing as t

from ixia.ixia import types as ixia_types
from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.types import (
    BasicPortConfig,
    BasicTrafficItemConfig,
    BgpConfig,
    DeviceGroupConfig,
    Endpoint,
    IpAddressesConfig,
    RouteScale,
    RouteScaleSpec,
    TestConfig,
    TrafficEndpoint,
)
from taac.playbooks.routing.factories.qual_rbb.rbb_bgp_policy_playbook import (
    create_rbb_bgp_policy_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _direct_ixia_connections,
    _dut_bootstrap_setup_tasks,
    _dut_bootstrap_teardown_tasks,
    _edge_ebgp_setup_tasks,
    _edge_ebgp_teardown_tasks,
    _resolve_topology,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import (
    build_rbb_inventories,
    rbb_oss_mock_device_data,
)
from taac.testconfigs.routing.util.bgp_rbb_policy_profiles import (
    TC65_PREFIX,
    TC65_UNDRAIN_COMMUNITY,
    TC68_DEFAULT_PREFIX,
    TC68_OVERSPECIFIC_PREFIX,
    TC68_SAFE_PREFIX,
    select_rbb_bgp_policy_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


def _scale(
    index: int,
    name: str,
    prefix: str,
    communities: list[str] | None = None,
) -> RouteScaleSpec:
    network, length = prefix.split("/")
    return RouteScaleSpec(
        network_group_index=index,
        multiplier=1,
        v6_route_scale=RouteScale(
            prefix_name=name,
            starting_prefixes=network,
            prefix_length=int(length),
            prefix_step="::",
            multiplier=1,
            prefix_count=1,
            ip_address_family=ixia_types.IpAddressFamily.IPV6,
            bgp_communities=communities or [],
        ),
    )


def _edge_port_config(
    inventory: t.Any,
    interface: str,
    *,
    edge_ip: str,
    gateway_ip: str,
    local_as: int,
    scales: list[RouteScaleSpec] | None = None,
) -> BasicPortConfig:
    return BasicPortConfig(
        endpoint=f"{inventory.device_name}:{interface}",
        device_group_configs=[DeviceGroupConfig(
            device_group_index=0, multiplier=1,
            v6_addresses_config=IpAddressesConfig(
                starting_ip=edge_ip,
                gateway_starting_ip=gateway_ip,
                mask=C.IXIA_EDGE_PREFIX_MASK,
            ),
            v6_bgp_config=BgpConfig(
                local_as_4_bytes=local_as, enable_4_byte_local_as=True,
                bgp_capabilities=[ixia_types.BgpCapability.IpV6Unicast],
                bgp_peer_type=ixia_types.BgpPeerType.EBGP,
                enable_graceful_restart=True, graceful_restart_timer=120,
                advertise_end_of_rib=True, route_scales=scales or [],
            ),
        )],
    )


def create_rbb_bgp_policy_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_BGP_POLICY_LIFECYCLE_TEST",
    testplan_ids: t.Iterable[str] | None = None,
) -> TestConfig:
    topology = _resolve_topology(topology, include_traffic=True)
    selected = select_rbb_bgp_policy_profiles(testplan_ids)
    if not selected:
        raise ValueError("BGP policy profile selection is empty")
    r1, r2 = build_rbb_inventories(topology)
    r1_port = _edge_port_config(
        r1,
        topology.r1.primary_ixia_interface,
        edge_ip=C.IXIA_R1_EDGE_V6,
        gateway_ip=C.IXIA_R1_EDGE_GW_V6,
        local_as=C.IXIA_R1_EDGE_AS,
    )
    r2_port = _edge_port_config(
        r2,
        topology.r2.primary_ixia_interface,
        edge_ip=C.IXIA_R2_EDGE_V6,
        gateway_ip=C.IXIA_R2_EDGE_GW_V6,
        local_as=C.IXIA_R2_EDGE_AS,
        scales=[
            _scale(0, "TC65_UNDRAIN", TC65_PREFIX, [TC65_UNDRAIN_COMMUNITY]),
            _scale(1, "TC68_DEFAULT", TC68_DEFAULT_PREFIX),
            _scale(2, "TC68_SAFE", TC68_SAFE_PREFIX),
            _scale(3, "TC68_OVERSPECIFIC", TC68_OVERSPECIFIC_PREFIX),
        ],
    )
    traffic = BasicTrafficItemConfig(
        name="RBB_P2_TC65_UNDRAIN",
        src_endpoints=[
            TrafficEndpoint(
                name=f"{r1.device_name}:{topology.r1.primary_ixia_interface}",
                device_group_index=0,
            )
        ],
        dest_endpoints=[
            TrafficEndpoint(
                name=f"{r2.device_name}:{topology.r2.primary_ixia_interface}",
                device_group_index=0,
                network_group_index=0,
            )
        ],
        traffic_type=ixia_types.TrafficType.IPV6,
        line_rate=C.TRAFFIC_LINE_RATE_PCT,
        line_rate_type=ixia_types.RateType.PERCENT_LINE_RATE,
        frame_size_settings=ixia_types.FrameSize(
            type=ixia_types.FrameSizeType.FIXED,
            fixed_size=C.TRAFFIC_FRAME_SIZE,
        ),
        bidirectional=False,
        merge_destinations=True,
        src_dest_mesh=ixia_types.SrcDestMeshType.MANY_TO_MANY,
        tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
    )
    chassis = topology.ixia_chassis or C.IXIA_CHASSIS
    return TestConfig(
        name=name,
        basset_pool="",
        skip_ixia_protocol_verification=False,
        skip_advertised_prefixes_check=C.SKIP_ADVERTISED_PREFIXES_CHECK,
        skip_default_oss_setup_tasks=True,
        endpoints=[
            Endpoint(
                name=inv.device_name,
                dut=True,
                ixia_needed=True,
                ixia_ports=[interface for interface, _ in inv.ixia_ports],
                direct_ixia_connections=_direct_ixia_connections(
                    inv, topology.node(role), chassis
                ),
            )
            for role, inv in (("r1", r1), ("r2", r2))
        ],
        host_os_type_map={
            r1.device_name: taac_types.DeviceOsType.FBOSS,
            r2.device_name: taac_types.DeviceOsType.FBOSS,
        },
        oss_mock_device_data=rbb_oss_mock_device_data((r1, r2)),
        startup_checks=[],
        setup_tasks=(
            _dut_bootstrap_setup_tasks(r1, r2, topology, include_traffic=True)
            + _edge_ebgp_setup_tasks(r1, r2, topology, include_traffic=True)
        ),
        teardown_tasks=(
            _edge_ebgp_teardown_tasks(r1, r2, include_traffic=True)
            + _dut_bootstrap_teardown_tasks(r1, r2)
        ),
        basic_port_configs=[r1_port, r2_port],
        basic_traffic_item_configs=[traffic],
        playbooks=[
            create_rbb_bgp_policy_playbook(
                profile,
                r2_hostname=r2.device_name,
                r2_ixia_interface=topology.r2.primary_ixia_interface,
            )
            for profile in selected
        ],
    )


__all__ = ["create_rbb_bgp_policy_test_config"]
