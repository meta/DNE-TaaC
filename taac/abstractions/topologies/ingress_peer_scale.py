# Copyright (c) Meta Platforms, Inc. and affiliates.

from taac.abstractions.compatibility.eos_bgpcpp_compatibility import (
    EBB_BGPCPP_LOGGING_CONFIG,
    PEERGROUP_EBGP_V6,
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
    NextHopIntent,
    NextHopMode,
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
    SelfNextHopRealization,
    StandardCommunity,
    TaskCompatibilityProfile,
)


INGRESS_PEER_SCALE_EBGP_PEER_COUNT = 16
INGRESS_PEER_SCALE_IBGP_PEER_COUNT = 500
INGRESS_PEER_SCALE_PREFIXES_PER_SENDER = 3_125
INGRESS_PEER_SCALE_TOTAL_PREFIX_COUNT = 50_000

INGRESS_PEER_SCALE_PORT_MAP = {"ebgp": 0, "ibgp": 1}
INGRESS_PEER_SCALE_PARENT_NETWORKS = {
    "ebgp_v6": IXIA_EBGP_IC_PARENT_NETWORK_V6,
    "ebgp_v4": IXIA_EBGP_IC_PARENT_NETWORK_V4,
    "ibgp_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE1,
    "ibgp_v4": IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE1,
}
INGRESS_PEER_SCALE_AS_NUMBERS = {"ebgp": EBGP_REMOTE_AS, "ibgp": IBGP_REMOTE_AS}

_IXIA_BGP_SESSION = IxiaBgpSessionIntent()
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
INGRESS_PEER_SCALE_PEER_GROUPS = {
    _EBGP_PEER_GROUP.name: _EBGP_PEER_GROUP,
    _IBGP_PEER_GROUP.name: _IBGP_PEER_GROUP,
}

_PREFIX_SET = PrefixSet(
    name="ingress_peer_scale_ebgp_v6",
    afi="v6",
    source=FormulaicPrefixSource(
        start_prefix="2001:db8:1000::",
        prefix_step=1 << 64,
        prefix_length=64,
        count=INGRESS_PEER_SCALE_TOTAL_PREFIX_COUNT,
        parent_network="2001:db8::/32",
    ),
)
_ADVERTISEMENT = PrefixAdvertisement(
    name="ingress_peer_scale_ebgp_v6_routes",
    prefix_set=_PREFIX_SET.name,
    allocation=PrefixAllocation(
        prefixes_per_peer=INGRESS_PEER_SCALE_PREFIXES_PER_SENDER,
        peer_distribution=PeerPrefixDistribution.DISJOINT,
        network_group_index=0,
    ),
    membership=PrefixMembership(
        start_index=0,
        prefix_count=INGRESS_PEER_SCALE_TOTAL_PREFIX_COUNT,
    ),
    next_hop=NextHopIntent(
        mode=NextHopMode.SELF,
        self_realization=SelfNextHopRealization.ADVERTISING_SESSION_LOCAL_ADDRESS,
    ),
    route_attributes=RouteAttributePool(
        community_rows=((StandardCommunity(asn=65529, value=39744),),),
        distribution=RouteAttributeDistribution.ROUND_ROBIN,
    ),
    legacy_ixia_name="PREFIX_POOL_IPV6_EBGP",
)

INGRESS_PEER_SCALE = LogicalTopology(
    name="ingress_peer_scale",
    legacy_profile=None,
    task_compatibility_profile=TaskCompatibilityProfile.INGRESS_PEER_SCALE,
    endpoints=(
        EndpointSpec(name="dut0", role="dut", kind="dut", setup_mode="full"),
        EndpointSpec(name="ixia", role="trafficgen", kind="ixia", setup_mode="full"),
    ),
    device_groups=(
        DeviceGroupSpec(
            name="dg_ingress_peer_scale_ebgp_v6",
            role="ebgp",
            peer_relationship=PeerRelationship.EXTERNAL,
            afi="v6",
            peer_count=INGRESS_PEER_SCALE_EBGP_PEER_COUNT,
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ebgp_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=_EBGP_PEER_GROUP,
            prefix_advertisements=(_ADVERTISEMENT,),
            legacy_ixia_bgp_peer_name="BGP_PEER_IPV6_EBGP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_EBGP",
            port_assignment=IxiaPortAssignment(logical_role="ebgp"),
            legacy_ixia_device_group_index=0,
        ),
        DeviceGroupSpec(
            name="dg_ingress_peer_scale_ibgp_v6",
            role="ibgp",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=INGRESS_PEER_SCALE_IBGP_PEER_COUNT,
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=_IBGP_PEER_GROUP,
            legacy_ixia_bgp_peer_name="BGP_PEER_IPV6_IBGP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP",
            port_assignment=IxiaPortAssignment(logical_role="ibgp"),
            legacy_ixia_device_group_index=0,
        ),
    ),
    device_config=RoutingDeviceConfig(
        update_group_enable=False,
        bgpcpp_logging_config_override=EBB_BGPCPP_LOGGING_CONFIG,
        openr_mode=OpenRMode.NONE,
    ),
    peer_groups=tuple(INGRESS_PEER_SCALE_PEER_GROUPS.values()),
    prefix_sets=(_PREFIX_SET,),
    route_senders=(
        RouteSender(
            device_group="dg_ingress_peer_scale_ebgp_v6",
            prefix_advertisement=_ADVERTISEMENT.name,
        ),
    ),
)


__all__ = (
    "INGRESS_PEER_SCALE",
    "INGRESS_PEER_SCALE_AS_NUMBERS",
    "INGRESS_PEER_SCALE_EBGP_PEER_COUNT",
    "INGRESS_PEER_SCALE_IBGP_PEER_COUNT",
    "INGRESS_PEER_SCALE_PARENT_NETWORKS",
    "INGRESS_PEER_SCALE_PEER_GROUPS",
    "INGRESS_PEER_SCALE_PORT_MAP",
    "INGRESS_PEER_SCALE_PREFIXES_PER_SENDER",
    "INGRESS_PEER_SCALE_TOTAL_PREFIX_COUNT",
)
