# Copyright (c) Meta Platforms, Inc. and affiliates.

from taac.abstractions.compatibility.eos_bgpcpp_compatibility import (
    EBB_BGPCPP_LOGGING_CONFIG,
    PEERGROUP_EBGP_V4,
    PEERGROUP_EBGP_V6,
    PEERGROUP_IBGP_V4,
    PEERGROUP_IBGP_V6,
)
from taac.abstractions.compatibility.legacy_ebb_binding import (
    IXIA_EBGP_IC_PARENT_NETWORK_V4,
    IXIA_EBGP_IC_PARENT_NETWORK_V6,
    IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE1,
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
    IxiaBgpSessionIntent,
    IxiaPortAssignment,
    LogicalTopology,
    OpenRMode,
    PeerPrefixDistribution,
    PrefixAdvertisement,
    PrefixAllocation,
    PrefixMembership,
    PrefixSet,
    RouteSender,
    RoutingDeviceConfig,
    TaskCompatibilityProfile,
)


TRANSIENT_MEMORY_ROUTE_SCALE_EBGP_PEERS_PER_AFI = 1
TRANSIENT_MEMORY_ROUTE_SCALE_IBGP_PEERS_PER_AFI = 250

TRANSIENT_MEMORY_ROUTE_SCALE_PORT_MAP = {"ebgp": 0, "ibgp": 1}
TRANSIENT_MEMORY_ROUTE_SCALE_PARENT_NETWORKS = {
    "ebgp_v6": IXIA_EBGP_IC_PARENT_NETWORK_V6,
    "ebgp_v4": IXIA_EBGP_IC_PARENT_NETWORK_V4,
    "ibgp_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE1,
    "ibgp_v4": IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE1,
}
TRANSIENT_MEMORY_ROUTE_SCALE_AS_NUMBERS = {
    "ebgp": EBGP_REMOTE_AS,
    "ibgp": IBGP_REMOTE_AS,
}

_IXIA_BGP_SESSION = IxiaBgpSessionIntent()

_EBGP_V6_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_EBGP_V6,
    remote_asn="ebgp",
    ixia_session=_IXIA_BGP_SESSION,
)
_EBGP_V4_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_EBGP_V4,
    remote_asn="ebgp",
    ixia_session=_IXIA_BGP_SESSION,
)
_IBGP_V6_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_IBGP_V6,
    local_asn="ibgp",
    remote_asn="ibgp",
    ixia_session=_IXIA_BGP_SESSION,
)
_IBGP_V4_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_IBGP_V4,
    local_asn="ibgp",
    remote_asn="ibgp",
    ixia_session=_IXIA_BGP_SESSION,
)
TRANSIENT_MEMORY_ROUTE_SCALE_PEER_GROUPS = {
    peer_group.name: peer_group
    for peer_group in (
        _EBGP_V6_PEER_GROUP,
        _EBGP_V4_PEER_GROUP,
        _IBGP_V6_PEER_GROUP,
        _IBGP_V4_PEER_GROUP,
    )
}

_EBGP_V6_PREFIX_SET = PrefixSet(
    name="transient_memory_route_scale_ebgp_v6",
    afi="v6",
    source=FormulaicPrefixSource(
        start_prefix="2001:db8:1000::",
        prefix_step=1 << 80,
        prefix_length=64,
        count=1,
        parent_network="2001:db8::/32",
    ),
)
_EBGP_V4_PREFIX_SET = PrefixSet(
    name="transient_memory_route_scale_ebgp_v4",
    afi="v4",
    source=FormulaicPrefixSource(
        start_prefix="10.100.0.0",
        prefix_step=1 << 8,
        prefix_length=24,
        count=1,
        parent_network="10.0.0.0/8",
    ),
)
_EBGP_V6_ADVERTISEMENT = PrefixAdvertisement(
    name="transient_memory_route_scale_ebgp_v6_routes",
    prefix_set=_EBGP_V6_PREFIX_SET.name,
    allocation=PrefixAllocation(
        prefixes_per_peer=1,
        peer_distribution=PeerPrefixDistribution.SHARED,
        network_group_index=0,
    ),
    membership=PrefixMembership(start_index=0, prefix_count=1),
    legacy_ixia_name="PREFIX_POOL_IPV6_EBGP",
)
_EBGP_V4_ADVERTISEMENT = PrefixAdvertisement(
    name="transient_memory_route_scale_ebgp_v4_routes",
    prefix_set=_EBGP_V4_PREFIX_SET.name,
    allocation=PrefixAllocation(
        prefixes_per_peer=1,
        peer_distribution=PeerPrefixDistribution.SHARED,
        network_group_index=0,
    ),
    membership=PrefixMembership(start_index=0, prefix_count=1),
    legacy_ixia_name="PREFIX_POOL_IPV4_EBGP",
)

_EBGP_PORT_ASSIGNMENT = IxiaPortAssignment(
    logical_role="ebgp",
    reuse_group="transient_memory_route_scale_ebgp",
)
_IBGP_PORT_ASSIGNMENT = IxiaPortAssignment(
    logical_role="ibgp",
    reuse_group="transient_memory_route_scale_ibgp",
)

TRANSIENT_MEMORY_ROUTE_SCALE = LogicalTopology(
    name="transient_memory_route_scale",
    legacy_profile=None,
    task_compatibility_profile=TaskCompatibilityProfile.TRANSIENT_MEMORY_ROUTE_SCALE,
    endpoints=(
        EndpointSpec(name="dut0", role="dut", kind="dut", setup_mode="full"),
        EndpointSpec(name="ixia", role="trafficgen", kind="ixia", setup_mode="full"),
    ),
    device_groups=(
        DeviceGroupSpec(
            name="dg_transient_memory_route_scale_ebgp_v6",
            role="ebgp",
            peer_relationship=PeerRelationship.EXTERNAL,
            afi="v6",
            peer_count=TRANSIENT_MEMORY_ROUTE_SCALE_EBGP_PEERS_PER_AFI,
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ebgp_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=_EBGP_V6_PEER_GROUP,
            prefix_advertisements=(_EBGP_V6_ADVERTISEMENT,),
            legacy_ixia_bgp_peer_name="BGP_PEER_IPV6_EBGP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_EBGP",
            port_assignment=_EBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=0,
        ),
        DeviceGroupSpec(
            name="dg_transient_memory_route_scale_ebgp_v4",
            role="ebgp",
            peer_relationship=PeerRelationship.EXTERNAL,
            afi="v4",
            peer_count=TRANSIENT_MEMORY_ROUTE_SCALE_EBGP_PEERS_PER_AFI,
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ebgp_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=_EBGP_V4_PEER_GROUP,
            prefix_advertisements=(_EBGP_V4_ADVERTISEMENT,),
            legacy_ixia_bgp_peer_name="BGP_PEER_IPV4_EBGP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_EBGP",
            port_assignment=_EBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=1,
        ),
        DeviceGroupSpec(
            name="dg_transient_memory_route_scale_ibgp_v6",
            role="ibgp",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=TRANSIENT_MEMORY_ROUTE_SCALE_IBGP_PEERS_PER_AFI,
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=_IBGP_V6_PEER_GROUP,
            legacy_ixia_bgp_peer_name="BGP_PEER_IPV6_IBGP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP",
            port_assignment=_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=0,
        ),
        DeviceGroupSpec(
            name="dg_transient_memory_route_scale_ibgp_v4",
            role="ibgp",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v4",
            peer_count=TRANSIENT_MEMORY_ROUTE_SCALE_IBGP_PEERS_PER_AFI,
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ibgp_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=_IBGP_V4_PEER_GROUP,
            legacy_ixia_bgp_peer_name="BGP_PEER_IPV4_IBGP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_IBGP",
            port_assignment=_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=1,
        ),
    ),
    device_config=RoutingDeviceConfig(
        update_group_enable=False,
        bgpcpp_logging_config_override=EBB_BGPCPP_LOGGING_CONFIG,
        openr_mode=OpenRMode.NONE,
    ),
    peer_groups=tuple(TRANSIENT_MEMORY_ROUTE_SCALE_PEER_GROUPS.values()),
    prefix_sets=(_EBGP_V6_PREFIX_SET, _EBGP_V4_PREFIX_SET),
    route_senders=(
        RouteSender(
            device_group="dg_transient_memory_route_scale_ebgp_v6",
            prefix_advertisement=_EBGP_V6_ADVERTISEMENT.name,
        ),
        RouteSender(
            device_group="dg_transient_memory_route_scale_ebgp_v4",
            prefix_advertisement=_EBGP_V4_ADVERTISEMENT.name,
        ),
    ),
)


__all__ = (
    "TRANSIENT_MEMORY_ROUTE_SCALE",
    "TRANSIENT_MEMORY_ROUTE_SCALE_AS_NUMBERS",
    "TRANSIENT_MEMORY_ROUTE_SCALE_EBGP_PEERS_PER_AFI",
    "TRANSIENT_MEMORY_ROUTE_SCALE_IBGP_PEERS_PER_AFI",
    "TRANSIENT_MEMORY_ROUTE_SCALE_PARENT_NETWORKS",
    "TRANSIENT_MEMORY_ROUTE_SCALE_PEER_GROUPS",
    "TRANSIENT_MEMORY_ROUTE_SCALE_PORT_MAP",
)
