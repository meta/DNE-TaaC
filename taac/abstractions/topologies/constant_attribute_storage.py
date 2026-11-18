# Copyright (c) Meta Platforms, Inc. and affiliates.

from taac.abstractions.compatibility.eos_bgpcpp_compatibility import (
    EBB_BGPCPP_LOGGING_CONFIG,
    PEERGROUP_EBGP_V6,
)
from taac.abstractions.compatibility.legacy_ebb_binding import (
    IXIA_EBGP_IC_PARENT_NETWORK_V6,
)
from taac.abstractions.compatibility.legacy_ebb_topology import (
    EBGP_REMOTE_AS,
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


CONSTANT_ATTRIBUTE_STORAGE_EBGP_PEER_COUNT = 8
CONSTANT_ATTRIBUTE_STORAGE_PREFIXES_PER_PEER = 100_000

CONSTANT_ATTRIBUTE_STORAGE_PORT_MAP = {"ebgp": 0}
CONSTANT_ATTRIBUTE_STORAGE_PARENT_NETWORKS = {
    "ebgp_v6": IXIA_EBGP_IC_PARENT_NETWORK_V6,
}
CONSTANT_ATTRIBUTE_STORAGE_AS_NUMBERS = {"ebgp": EBGP_REMOTE_AS}

CONSTANT_ATTRIBUTE_STORAGE_EBGP_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_EBGP_V6,
    remote_asn="ebgp",
    ixia_session=IxiaBgpSessionIntent(),
)
CONSTANT_ATTRIBUTE_STORAGE_PEER_GROUPS = {
    CONSTANT_ATTRIBUTE_STORAGE_EBGP_PEER_GROUP.name: (
        CONSTANT_ATTRIBUTE_STORAGE_EBGP_PEER_GROUP
    ),
}

CONSTANT_ATTRIBUTE_STORAGE_PREFIX_SET = PrefixSet(
    name="constant_attribute_storage_ebgp_v6",
    afi="v6",
    source=FormulaicPrefixSource(
        start_prefix="2001:db8:1000::",
        prefix_step=1 << 80,
        prefix_length=64,
        count=CONSTANT_ATTRIBUTE_STORAGE_PREFIXES_PER_PEER,
        parent_network="2001::/16",
    ),
)
CONSTANT_ATTRIBUTE_STORAGE_ADVERTISEMENT = PrefixAdvertisement(
    name="constant_attribute_storage_ebgp_v6_routes",
    prefix_set=CONSTANT_ATTRIBUTE_STORAGE_PREFIX_SET.name,
    allocation=PrefixAllocation(
        prefixes_per_peer=CONSTANT_ATTRIBUTE_STORAGE_PREFIXES_PER_PEER,
        peer_distribution=PeerPrefixDistribution.SHARED,
        network_group_index=0,
    ),
    membership=PrefixMembership(
        start_index=0,
        prefix_count=CONSTANT_ATTRIBUTE_STORAGE_PREFIXES_PER_PEER,
    ),
    legacy_ixia_name="PREFIX_POOL_IPV6_EBGP",
)

CONSTANT_ATTRIBUTE_STORAGE = LogicalTopology(
    name="constant_attribute_storage",
    legacy_profile=None,
    task_compatibility_profile=TaskCompatibilityProfile.CONSTANT_ATTRIBUTE_STORAGE,
    endpoints=(
        EndpointSpec(name="dut0", role="dut", kind="dut", setup_mode="full"),
        EndpointSpec(name="ixia", role="trafficgen", kind="ixia", setup_mode="full"),
    ),
    device_groups=(
        DeviceGroupSpec(
            name="dg_constant_attribute_storage_ebgp_v6",
            role="ebgp",
            peer_relationship=PeerRelationship.EXTERNAL,
            afi="v6",
            peer_count=CONSTANT_ATTRIBUTE_STORAGE_EBGP_PEER_COUNT,
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ebgp_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=CONSTANT_ATTRIBUTE_STORAGE_EBGP_PEER_GROUP,
            prefix_advertisements=(CONSTANT_ATTRIBUTE_STORAGE_ADVERTISEMENT,),
            legacy_ixia_bgp_peer_name="BGP_PEER_IPV6_EBGP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_EBGP",
            port_assignment=IxiaPortAssignment(logical_role="ebgp"),
            legacy_ixia_device_group_index=0,
        ),
    ),
    device_config=RoutingDeviceConfig(
        update_group_enable=False,
        bgpcpp_logging_config_override=EBB_BGPCPP_LOGGING_CONFIG,
        openr_mode=OpenRMode.NONE,
    ),
    peer_groups=(CONSTANT_ATTRIBUTE_STORAGE_EBGP_PEER_GROUP,),
    prefix_sets=(CONSTANT_ATTRIBUTE_STORAGE_PREFIX_SET,),
    route_senders=(
        RouteSender(
            device_group="dg_constant_attribute_storage_ebgp_v6",
            prefix_advertisement=CONSTANT_ATTRIBUTE_STORAGE_ADVERTISEMENT.name,
        ),
    ),
)


__all__ = (
    "CONSTANT_ATTRIBUTE_STORAGE",
    "CONSTANT_ATTRIBUTE_STORAGE_ADVERTISEMENT",
    "CONSTANT_ATTRIBUTE_STORAGE_AS_NUMBERS",
    "CONSTANT_ATTRIBUTE_STORAGE_EBGP_PEER_COUNT",
    "CONSTANT_ATTRIBUTE_STORAGE_EBGP_PEER_GROUP",
    "CONSTANT_ATTRIBUTE_STORAGE_PARENT_NETWORKS",
    "CONSTANT_ATTRIBUTE_STORAGE_PEER_GROUPS",
    "CONSTANT_ATTRIBUTE_STORAGE_PORT_MAP",
    "CONSTANT_ATTRIBUTE_STORAGE_PREFIX_SET",
    "CONSTANT_ATTRIBUTE_STORAGE_PREFIXES_PER_PEER",
)
