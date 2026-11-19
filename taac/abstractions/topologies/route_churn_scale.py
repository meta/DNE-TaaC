# Copyright (c) Meta Platforms, Inc. and affiliates.

from taac.abstractions.compatibility.eos_bgpcpp_compatibility import (
    PEERGROUP_EBGP_V6,
    PEERGROUP_IBGP_V6,
)
from taac.abstractions.compatibility.legacy_ebb_binding import (
    IXIA_EBGP_IC_PARENT_NETWORK_V6,
    IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE1,
)
from taac.abstractions.compatibility.legacy_ebb_topology import (
    EBGP_REMOTE_AS,
    IBGP_REMOTE_AS,
)
from taac.abstractions.routing_semantics import PeerRelationship
from taac.abstractions.topology import (
    AddressPlan,
    BgpPeerGroup,
    DeviceGroupSpec,
    EndpointSpec,
    FormulaicPrefixSource,
    IxiaBgpCapability,
    IxiaBgpSessionIntent,
    IxiaPortAssignment,
    LogicalTopology,
    OpenRMode,
    PeerPrefixDistribution,
    PrefixAdvertisement,
    PrefixAllocation,
    PrefixMembership,
    PrefixSet,
    RouteAttributeDistribution,
    RouteAttributePool,
    RouteSender,
    RoutingDeviceConfig,
    StandardCommunity,
    TaskCompatibilityProfile,
)


ROUTE_CHURN_SCALE_EBGP_PEER_COUNT = 100
ROUTE_CHURN_SCALE_IBGP_PEER_COUNT = 100
ROUTE_CHURN_SCALE_CHURN_PREFIX_COUNT = 100
ROUTE_CHURN_SCALE_MAX_PREFIX_COUNT = 50_000

ROUTE_CHURN_SCALE_PORT_MAP = {"ebgp": 0, "ibgp": 1}
ROUTE_CHURN_SCALE_PARENT_NETWORKS = {
    "ebgp_v6": IXIA_EBGP_IC_PARENT_NETWORK_V6,
    "ibgp_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE1,
}
ROUTE_CHURN_SCALE_AS_NUMBERS = {"ebgp": EBGP_REMOTE_AS, "ibgp": IBGP_REMOTE_AS}

_IXIA_BGP_SESSION = IxiaBgpSessionIntent(
    capabilities=(IxiaBgpCapability.IPV6_UNICAST,),
)
_EBGP_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_EBGP_V6,
    remote_asn="ebgp",
    ixia_session=_IXIA_BGP_SESSION,
)
_IBGP_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_IBGP_V6,
    local_asn="ibgp",
    remote_asn="ibgp",
    enable_graceful_restart=False,
    ixia_session=_IXIA_BGP_SESSION,
)
ROUTE_CHURN_SCALE_PEER_GROUPS = {
    _EBGP_PEER_GROUP.name: _EBGP_PEER_GROUP,
    _IBGP_PEER_GROUP.name: _IBGP_PEER_GROUP,
}

_ROUTE_ATTRIBUTES = RouteAttributePool(
    community_rows=((StandardCommunity(asn=65529, value=39744),),),
    distribution=RouteAttributeDistribution.ROUND_ROBIN,
)
_CHURNED_PREFIX_SET = PrefixSet(
    name="route_churn_scale_ibgp_peer_1_churned",
    afi="v6",
    source=FormulaicPrefixSource(
        start_prefix="5001:db8:1000::",
        prefix_step=1 << 64,
        prefix_length=64,
        count=ROUTE_CHURN_SCALE_CHURN_PREFIX_COUNT,
        parent_network="5001:db8::/32",
    ),
)
_CONTROL_PREFIX_SET = PrefixSet(
    name="route_churn_scale_ibgp_peer_1_control",
    afi="v6",
    source=FormulaicPrefixSource(
        start_prefix="5001:db8:1000:64::",
        prefix_step=1 << 64,
        prefix_length=64,
        count=(
            ROUTE_CHURN_SCALE_MAX_PREFIX_COUNT - ROUTE_CHURN_SCALE_CHURN_PREFIX_COUNT
        ),
        parent_network="5001:db8::/32",
    ),
)
_REST_PREFIX_SET = PrefixSet(
    name="route_churn_scale_ibgp_peers_rest",
    afi="v6",
    source=FormulaicPrefixSource(
        start_prefix="5001:db8:1000::",
        prefix_step=1 << 64,
        prefix_length=64,
        count=ROUTE_CHURN_SCALE_MAX_PREFIX_COUNT,
        parent_network="5001:db8::/32",
    ),
)


def _advertisement(
    *,
    name: str,
    prefix_set: PrefixSet,
    network_group_index: int,
    legacy_ixia_name: str,
) -> PrefixAdvertisement:
    return PrefixAdvertisement(
        name=name,
        prefix_set=prefix_set.name,
        allocation=PrefixAllocation(
            prefixes_per_peer=prefix_set.source.count,
            peer_distribution=PeerPrefixDistribution.SHARED,
            network_group_index=network_group_index,
        ),
        membership=PrefixMembership(
            start_index=0,
            prefix_count=prefix_set.source.count,
        ),
        route_attributes=_ROUTE_ATTRIBUTES,
        legacy_ixia_name=legacy_ixia_name,
    )


_CHURNED_ADVERTISEMENT = _advertisement(
    name="route_churn_scale_ibgp_peer_1_churned_routes",
    prefix_set=_CHURNED_PREFIX_SET,
    network_group_index=0,
    legacy_ixia_name="PREFIX_POOL_IPV6_IBGP_PEER_1_CHURNED",
)
_CONTROL_ADVERTISEMENT = _advertisement(
    name="route_churn_scale_ibgp_peer_1_control_routes",
    prefix_set=_CONTROL_PREFIX_SET,
    network_group_index=1,
    legacy_ixia_name="PREFIX_POOL_IPV6_IBGP_PEER_1_CONTROL",
)
_REST_ADVERTISEMENT = _advertisement(
    name="route_churn_scale_ibgp_peers_rest_routes",
    prefix_set=_REST_PREFIX_SET,
    network_group_index=0,
    legacy_ixia_name="PREFIX_POOL_IPV6_IBGP_PEERS_REST",
)

_EBGP_PORT_ASSIGNMENT = IxiaPortAssignment(logical_role="ebgp")
_IBGP_PORT_ASSIGNMENT = IxiaPortAssignment(
    logical_role="ibgp",
    reuse_group="route_churn_scale_ibgp",
)

ROUTE_CHURN_SCALE = LogicalTopology(
    name="route_churn_scale",
    legacy_profile=None,
    task_compatibility_profile=TaskCompatibilityProfile.ROUTE_CHURN_SCALE,
    endpoints=(
        EndpointSpec(name="dut0", role="dut", kind="dut", setup_mode="full"),
        EndpointSpec(name="ixia", role="trafficgen", kind="ixia", setup_mode="full"),
    ),
    device_groups=(
        DeviceGroupSpec(
            name="dg_route_churn_scale_ebgp_v6",
            role="ebgp",
            peer_relationship=PeerRelationship.EXTERNAL,
            afi="v6",
            peer_count=ROUTE_CHURN_SCALE_EBGP_PEER_COUNT,
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ebgp_v6",
                stride=2,
                prefix_length=127,
                start_index=0,
            ),
            peer_group=_EBGP_PEER_GROUP,
            legacy_ixia_bgp_peer_name="BGP_PEER_IPV6_EBGP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_EBGP",
            port_assignment=_EBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=0,
        ),
        DeviceGroupSpec(
            name="dg_route_churn_scale_ibgp_peer_1_v6",
            role="ibgp",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=1,
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_v6",
                stride=2,
                prefix_length=127,
                start_index=0,
            ),
            peer_group=_IBGP_PEER_GROUP,
            prefix_advertisements=(
                _CHURNED_ADVERTISEMENT,
                _CONTROL_ADVERTISEMENT,
            ),
            legacy_ixia_bgp_peer_name="BGP_PEER_IPV6_IBGP_PEER_1",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP_PEER_1",
            port_assignment=_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=0,
        ),
        DeviceGroupSpec(
            name="dg_route_churn_scale_ibgp_peers_rest_v6",
            role="ibgp",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=ROUTE_CHURN_SCALE_IBGP_PEER_COUNT - 1,
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_v6",
                stride=2,
                prefix_length=127,
                start_index=1,
            ),
            peer_group=_IBGP_PEER_GROUP,
            prefix_advertisements=(_REST_ADVERTISEMENT,),
            legacy_ixia_bgp_peer_name="BGP_PEER_IPV6_IBGP_PEERS_REST",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP_PEERS_REST",
            port_assignment=_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=1,
        ),
    ),
    device_config=RoutingDeviceConfig(
        update_group_enable=False,
        bgpcpp_logging_config_override="INFO;default:async=true",
        bgpcpp_agent_thrift_recv_timeout_ms=600_000,
        fibagent_bgp_thrift_queue_timeout_ms=60_000,
        openr_mode=OpenRMode.NONE,
    ),
    peer_groups=tuple(ROUTE_CHURN_SCALE_PEER_GROUPS.values()),
    prefix_sets=(
        _CHURNED_PREFIX_SET,
        _CONTROL_PREFIX_SET,
        _REST_PREFIX_SET,
    ),
    route_senders=(
        RouteSender(
            device_group="dg_route_churn_scale_ibgp_peer_1_v6",
            prefix_advertisement=_CHURNED_ADVERTISEMENT.name,
        ),
        RouteSender(
            device_group="dg_route_churn_scale_ibgp_peer_1_v6",
            prefix_advertisement=_CONTROL_ADVERTISEMENT.name,
        ),
        RouteSender(
            device_group="dg_route_churn_scale_ibgp_peers_rest_v6",
            prefix_advertisement=_REST_ADVERTISEMENT.name,
        ),
    ),
)


__all__ = (
    "ROUTE_CHURN_SCALE",
    "ROUTE_CHURN_SCALE_AS_NUMBERS",
    "ROUTE_CHURN_SCALE_CHURN_PREFIX_COUNT",
    "ROUTE_CHURN_SCALE_EBGP_PEER_COUNT",
    "ROUTE_CHURN_SCALE_IBGP_PEER_COUNT",
    "ROUTE_CHURN_SCALE_MAX_PREFIX_COUNT",
    "ROUTE_CHURN_SCALE_PARENT_NETWORKS",
    "ROUTE_CHURN_SCALE_PEER_GROUPS",
    "ROUTE_CHURN_SCALE_PORT_MAP",
)
