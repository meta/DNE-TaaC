# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-strict

from __future__ import annotations

import ipaddress
import re
import typing as t
from collections import Counter
from dataclasses import dataclass, replace

from taac.abstractions.compatibility.eos_bgpcpp_compatibility import (
    EBB_BGPCPP_LOGGING_CONFIG,
    PEERGROUP_BGP_MON,
    PEERGROUP_EBGP_V4,
    PEERGROUP_EBGP_V6,
    PEERGROUP_IBGP_V4,
    PEERGROUP_IBGP_V6,
)
from taac.abstractions.compatibility.legacy_ebb_binding import (
    IXIA03_BGP_MON_IC_PARENT_NETWORK,
    IXIA03_EBGP_IC_PARENT_NETWORK_V4,
    IXIA03_EBGP_IC_PARENT_NETWORK_V6,
    IXIA03_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE1,
    IXIA03_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE2,
    IXIA03_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE3,
    IXIA03_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE4,
    IXIA03_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE1,
    IXIA03_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE2,
    IXIA03_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE3,
    IXIA03_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE4,
    IXIA03_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE1,
    IXIA03_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE2,
    IXIA03_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE3,
    IXIA03_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE4,
    IXIA03_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE1,
    IXIA03_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE2,
    IXIA03_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE3,
    IXIA03_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE4,
    IXIA_BGP_MON_IC_PARENT_NETWORK,
    IXIA_EBGP_IC_PARENT_NETWORK_V4,
    IXIA_EBGP_IC_PARENT_NETWORK_V6,
    IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE1,
    IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE2,
    IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE3,
    IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE4,
    IXIA_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE1,
    IXIA_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE2,
    IXIA_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE3,
    IXIA_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE4,
    IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE1,
    IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE2,
    IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE3,
    IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE4,
    IXIA_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE1,
    IXIA_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE2,
    IXIA_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE3,
    IXIA_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE4,
)
from taac.abstractions.compatibility.legacy_ebb_topology import (
    BGP_MON_PEER_COUNT,
    BGP_MON_REMOTE_AS,
    EBB_BGP_HOLD_TIMER_S,
    EBB_BGP_KEEPALIVE_TIMER_S,
    EBB_DEVICE_PER_PEER_MAX_ROUTE_LIMIT,
    EBB_DEVICE_PREFIX_LIMIT,
    EBB_DEVICE_ROUTE_LIMIT,
    EBGP_PEER_COUNT_V4,
    EBGP_PEER_COUNT_V6,
    EBGP_REMOTE_AS,
    IBGP_PEER_SCALE_PER_PLANE,
    IBGP_REMOTE_AS,
)
from taac.abstractions.routing_semantics import PeerRelationship
from taac.abstractions.topologies.ebb_prefix_inventory import (
    EBB_IBGP_V4_EXCLUDED_PREFIX_INDICES,
    EBB_IBGP_V6_EXCLUDED_PREFIX_INDICES,
    EBB_IBGP_VETTED_CANDIDATE_SPAN,
)
from taac.abstractions.topology import (
    AddressPlan,
    BgpPeerGroup,
    BgpPolicy,
    BoundTopology,
    DeviceGroupSpec,
    EndpointSpec,
    ExplicitNextHopSource,
    FormulaicNextHopSource,
    FormulaicPrefixSource,
    IxiaDeviceGroupChild,
    IxiaPortAssignment,
    LogicalTopology,
    NextHopDistribution,
    NextHopIntent,
    NextHopMode,
    OpenRInjectionScale,
    OpenRMode,
    PeerPrefixActivation,
    PeerPrefixDistribution,
    PeerPrefixExclusionBlock,
    PrefixAdvertisement,
    PrefixAllocation,
    PrefixMembership,
    PrefixSet,
    RouteAttributePool,
    RouteScaleMode,
    RoutingDeviceConfig,
    StandardCommunity,
    TaskCompatibilityProfile,
)
from taac.abstractions.validation import (
    TopologyValidationError,
    ValidationIssue,
)


def _require_count(name: str, value: object, *, minimum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(
            f"EBB scale {name} must be an integer >= {minimum}; got {value!r}"
        )


@dataclass(frozen=True, kw_only=True)
class EbbScaleProfile:
    """The EBB fleet scale one topology instance emulates.

    A scale is a fiscal-year fleet target, not a chassis or a testbed: it says
    how many HE sites each DC plane stands in for, how many emulated peers
    stand in for them, and how many routes each of those peers carries. It
    carries no addresses -- those come from the bound topology -- so the same
    profile is correct on every chassis.

    Every dimension is an explicit field, because each one is set by a
    different owner decision and drives a different consumer. The dimensions
    are not independent, though: the Open/R injection exists to make the
    advertised route next hops resolvable, and each emulated HE peer row
    advertises exactly one of them. ``__post_init__`` therefore binds the
    injection, the advertised population and the peer fleet together, so a
    profile that moves one without the others is rejected here rather than
    compiling into a topology that injects headroom nothing uses, or leaves
    advertised next hops unresolved.

    Attributes:
        name: Stable identifier for the profile, used in diagnostics.
        he_sites_per_range: HE sites emulated per DC plane, which is also the
            synthetic nodes and host routes injected per range, per AFI.
        ibgp_peers_per_group: Emulated peers in every AF-specific HE and MP
            iBGP device group.
        advertised_pnh_count: Leading rows of each injected range that the HE
            peers advertise as route next hops. One per HE peer row.
        routes_per_he_peer: Routes each HE peer advertises. The four HE planes
            advertise the same per-peer windows, so this times the peer count
            is the unique HE route demand per AFI.
        fa_routes_per_peer: Baseline routes each eBGP (FA) peer advertises.
        openr_injection_headroom: Injected rows per range beyond the advertised
            population. Explicit so that zero headroom is an enforced
            equality, not two numbers that happen to match.
        allows_bgp_monitor: Whether a topology at this scale may carry the
            BGP-monitor session group.
        allows_dense_unvetted_route_tail: Whether the HE route demand may
            extend past the candidate span the migration exclusion inventory
            vetted, into dense synthetic prefixes nothing vetted. Topology
            construction fails when the demand needs that tail and this is
            false.
        next_hop_step: Address stride between consecutive HE sites. Must match
            the stride the plane's advertised route next hops use.
        bgp_total_path_limit: BGP++ ``switch_limit_config.total_path_limit``
            to configure before BGP++ starts, or None to keep the limit the
            deployed EBB BGP++ config carries. BGP++ counts received and
            advertised paths against it and drops prefixes past it.
    """

    name: str
    he_sites_per_range: int
    ibgp_peers_per_group: int
    advertised_pnh_count: int
    routes_per_he_peer: int
    fa_routes_per_peer: int
    openr_injection_headroom: int
    allows_bgp_monitor: bool
    allows_dense_unvetted_route_tail: bool
    next_hop_step: int = 2
    bgp_total_path_limit: int | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("EBB scale profile requires a name")
        # Resolve once at construction so an invalid site count or stride is
        # rejected here rather than at the first bind. Discarding the result
        # is the point: OpenRInjectionScale owns the validation.
        _ = self.openr_injection_scale
        if self.bgp_total_path_limit is not None:
            _require_count("bgp_total_path_limit", self.bgp_total_path_limit, minimum=1)
        for field_name in (
            "ibgp_peers_per_group",
            "advertised_pnh_count",
            "routes_per_he_peer",
            "fa_routes_per_peer",
        ):
            _require_count(field_name, getattr(self, field_name), minimum=1)
        _require_count(
            "openr_injection_headroom", self.openr_injection_headroom, minimum=0
        )
        for field_name in ("allows_bgp_monitor", "allows_dense_unvetted_route_tail"):
            value = getattr(self, field_name)
            if not isinstance(value, bool):
                raise ValueError(
                    f"EBB scale {field_name} must be a bool; got {value!r}"
                )
        if self.advertised_pnh_count != self.ibgp_peers_per_group:
            raise ValueError(
                f"{self.name}: advertised_pnh_count {self.advertised_pnh_count} "
                f"must equal ibgp_peers_per_group {self.ibgp_peers_per_group}; "
                "each HE peer row advertises exactly one route next hop"
            )
        injected = self.advertised_pnh_count + self.openr_injection_headroom
        if self.he_sites_per_range != injected:
            raise ValueError(
                f"{self.name}: he_sites_per_range {self.he_sites_per_range} must "
                f"equal advertised_pnh_count {self.advertised_pnh_count} plus "
                f"openr_injection_headroom {self.openr_injection_headroom}"
            )

    @property
    def openr_injection_scale(self) -> OpenRInjectionScale:
        return OpenRInjectionScale(
            count=self.he_sites_per_range,
            step=self.next_hop_step,
        )

    @property
    def he_routes_per_afi(self) -> int:
        """Unique HE routes per AFI, shared by all four HE planes."""
        return self.ibgp_peers_per_group * self.routes_per_he_peer


# Scheduled: every EBB CICD binding runs this. 4 DC planes x 63 HE sites gives
# 252 synthetic nodes and 504 injected host routes, one row of headroom over
# the 62 advertised next hops; 62 peers x 750 routes is 46,500 HE routes/AFI.
EBB_FY26_SCALE = EbbScaleProfile(
    name="EBB_FY26",
    he_sites_per_range=63,
    ibgp_peers_per_group=IBGP_PEER_SCALE_PER_PLANE,
    advertised_pnh_count=IBGP_PEER_SCALE_PER_PLANE,
    routes_per_he_peer=750,
    fa_routes_per_peer=750,
    openr_injection_headroom=1,
    allows_bgp_monitor=True,
    allows_dense_unvetted_route_tail=False,
)

# FY27 Scenario 1, from the owner's authoritative scale sheet. Not scheduled
# anywhere: 100 peers per AF-specific HE/MP group, an injection of exactly the
# 100 advertised next hops per range, 1,000 routes per HE peer (100,000 unique
# HE routes/AFI) and per FA peer, and no BGP monitor. 100,000 retained routes
# need 100,750 candidates; the first 47,250 keep the vetted FY26 exclusions,
# and the remaining 53,500 are declared dense synthetic prefixes.
EBB_FY27_SCALE = EbbScaleProfile(
    name="EBB_FY27",
    he_sites_per_range=100,
    ibgp_peers_per_group=100,
    advertised_pnh_count=100,
    routes_per_he_peer=1000,
    fa_routes_per_peer=1000,
    openr_injection_headroom=0,
    # The sheet's 1.08M received plus 29.6M advertised paths exceed the
    # 30,000,000 total-path limit the EBB BGP++ config deploys.
    bgp_total_path_limit=32_000_000,
    allows_bgp_monitor=False,
    allows_dense_unvetted_route_tail=True,
)


EBB_PARENT_NETWORKS: dict[str, str] = {
    "ebgp_v6": IXIA_EBGP_IC_PARENT_NETWORK_V6,
    "ebgp_v4": IXIA_EBGP_IC_PARENT_NETWORK_V4,
    "ibgp_dc_p1_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE1,
    "ibgp_dc_p2_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE2,
    "ibgp_dc_p3_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE3,
    "ibgp_dc_p4_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE4,
    "ibgp_mp_p1_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE1,
    "ibgp_mp_p2_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE2,
    "ibgp_mp_p3_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE3,
    "ibgp_mp_p4_v6": IXIA_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE4,
    "ibgp_dc_p1_v4": IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE1,
    "ibgp_dc_p2_v4": IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE2,
    "ibgp_dc_p3_v4": IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE3,
    "ibgp_dc_p4_v4": IXIA_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE4,
    "ibgp_mp_p1_v4": IXIA_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE1,
    "ibgp_mp_p2_v4": IXIA_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE2,
    "ibgp_mp_p3_v4": IXIA_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE3,
    "ibgp_mp_p4_v4": IXIA_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE4,
    "bgpmon_v6": IXIA_BGP_MON_IC_PARENT_NETWORK,
}

# Same topology against the secondary chassis (ixia03) instead of ixia11. The
# addressing has to be swapped alongside the ports: PhysicalInventory
# .for_secondary_ixia() moves which DUT interfaces are driven, but the parent
# networks are what TAAC programs onto the IXIA side, so leaving them at the
# ixia11 defaults would emulate peers the DUT has no gateway for and fail
# looking like a link fault. Keys must mirror EBB_PARENT_NETWORKS exactly.
EBB_PARENT_NETWORKS_IXIA03: dict[str, str] = {
    "ebgp_v6": IXIA03_EBGP_IC_PARENT_NETWORK_V6,
    "ebgp_v4": IXIA03_EBGP_IC_PARENT_NETWORK_V4,
    "ibgp_dc_p1_v6": IXIA03_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE1,
    "ibgp_dc_p2_v6": IXIA03_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE2,
    "ibgp_dc_p3_v6": IXIA03_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE3,
    "ibgp_dc_p4_v6": IXIA03_IBGP_IC_PARENT_NETWORK_V6_DC_PLANE4,
    "ibgp_mp_p1_v6": IXIA03_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE1,
    "ibgp_mp_p2_v6": IXIA03_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE2,
    "ibgp_mp_p3_v6": IXIA03_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE3,
    "ibgp_mp_p4_v6": IXIA03_IBGP_IC_PARENT_NETWORK_V6_MP_PLANE4,
    "ibgp_dc_p1_v4": IXIA03_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE1,
    "ibgp_dc_p2_v4": IXIA03_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE2,
    "ibgp_dc_p3_v4": IXIA03_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE3,
    "ibgp_dc_p4_v4": IXIA03_IBGP_IC_PARENT_NETWORK_V4_DC_PLANE4,
    "ibgp_mp_p1_v4": IXIA03_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE1,
    "ibgp_mp_p2_v4": IXIA03_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE2,
    "ibgp_mp_p3_v4": IXIA03_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE3,
    "ibgp_mp_p4_v4": IXIA03_IBGP_IC_PARENT_NETWORK_V4_MP_PLANE4,
    "bgpmon_v6": IXIA03_BGP_MON_IC_PARENT_NETWORK,
}

EBB_AS_NUMBERS: dict[str, int] = {
    "ebgp": EBGP_REMOTE_AS,
    "ibgp": IBGP_REMOTE_AS,
    "bgpmon": BGP_MON_REMOTE_AS,
}

_EBB_ACCEPTANCE_COMMUNITY = StandardCommunity(asn=65529, value=39744)
_EBB_IBGP_ROUTE_ATTRIBUTES = RouteAttributePool(
    community_rows=tuple(
        (
            _EBB_ACCEPTANCE_COMMUNITY,
            StandardCommunity(asn=asn, value=value),
        )
        for asn, value in (
            (65060, 10012),
            (65140, 65529),
            (65520, 503),
            (65529, 11610),
            (65529, 39744),
            (65530, 50300),
            (65530, 50320),
            (65530, 50800),
        )
    ),
)
EBB_LONGEVITY_COMMUNITY_BASELINE_COUNT = len(
    _EBB_IBGP_ROUTE_ATTRIBUTES.community_rows[0]
)
# Every Playbook in a shared EBB TestConfig starts from these route attributes.
# Playbook-specific changes must use runtime mutation and restore this state.
EBB_BASELINE_ATTRIBUTES = (
    ("med", None),
    ("local_pref", 100),
    ("origin", "igp"),
)

EBB_FIBAGENT_BGP_NHG_WATERMARK_HIGH = 1000
EBB_FIBAGENT_BGP_NHG_WATERMARK_LOW = 1000

_EBB_ROUTE_STORM_SHARD_COUNT = 3


def ebb_route_storm_shard_peer_counts(peer_count: int) -> tuple[int, ...]:
    """Split one plane's peers into the route-storm IXIA shards, largest first.

    The shards are peer-aligned and as even as possible, so the heaviest shard
    -- the unit IXIA programs at once -- is as small as the peer count allows.
    """
    _require_count("route-storm peer count", peer_count, minimum=1)
    base, extra = divmod(peer_count, _EBB_ROUTE_STORM_SHARD_COUNT)
    if base == 0:
        raise ValueError(
            f"route storm needs at least {_EBB_ROUTE_STORM_SHARD_COUNT} peers per "
            f"plane to shard; got {peer_count}"
        )
    return tuple(
        base + (ordinal < extra) for ordinal in range(_EBB_ROUTE_STORM_SHARD_COUNT)
    )


def ebb_route_storm_shard_route_counts(scale: EbbScaleProfile) -> tuple[int, ...]:
    return tuple(
        peer_count * scale.routes_per_he_peer
        for peer_count in ebb_route_storm_shard_peer_counts(scale.ibgp_peers_per_group)
    )


EBB_ROUTE_STORM_SHARD_PEER_COUNTS = ebb_route_storm_shard_peer_counts(
    EBB_FY26_SCALE.ibgp_peers_per_group
)
EBB_ROUTE_STORM_SHARD_ROUTE_COUNTS = ebb_route_storm_shard_route_counts(EBB_FY26_SCALE)

EBB_DIVERSE_NHG_GROUP_COUNT = 25
EBB_DIVERSE_NHG_PREFIXES_PER_GROUP = 30
EBB_DIVERSE_NHG_EXCLUDED_PEERS_PER_GROUP = 2
_EBB_DIVERSE_NHG_FIRST_EXCLUDED_PEER = 90
_EBB_DIVERSE_NHG_REQUIRED_PEER_COUNT = (
    _EBB_DIVERSE_NHG_FIRST_EXCLUDED_PEER
    + EBB_DIVERSE_NHG_GROUP_COUNT * EBB_DIVERSE_NHG_EXCLUDED_PEERS_PER_GROUP
)

EBGP_V6_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_EBGP_V6,
    remote_asn="ebgp",
    enable_graceful_restart=True,
)
EBGP_V4_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_EBGP_V4,
    remote_asn="ebgp",
    enable_graceful_restart=True,
)
IBGP_V6_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_IBGP_V6,
    remote_asn="ibgp",
    enable_graceful_restart=False,
)
IBGP_V4_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_IBGP_V4,
    remote_asn="ibgp",
    enable_graceful_restart=False,
)
BGP_MON_PEER_GROUP = BgpPeerGroup(
    name=PEERGROUP_BGP_MON,
    remote_asn="bgpmon",
    enable_graceful_restart=False,
)

EBB_PEER_GROUPS: dict[str, BgpPeerGroup] = {
    PEERGROUP_EBGP_V6: EBGP_V6_PEER_GROUP,
    PEERGROUP_EBGP_V4: EBGP_V4_PEER_GROUP,
    PEERGROUP_IBGP_V6: IBGP_V6_PEER_GROUP,
    PEERGROUP_IBGP_V4: IBGP_V4_PEER_GROUP,
    PEERGROUP_BGP_MON: BGP_MON_PEER_GROUP,
}

EBB_PORT_MAP = {
    "uplink": 0,
    "ibgp": 1,
}
EBB_PORT_MAP_WITH_BGPMON = {
    **EBB_PORT_MAP,
    "bgpmon": 2,
}

_EBB_UPLINK_PORT_ASSIGNMENT = IxiaPortAssignment(
    logical_role="uplink",
    reuse_group="ebb_uplink",
)
_EBB_IBGP_PORT_ASSIGNMENT = IxiaPortAssignment(
    logical_role="ibgp",
    reuse_group="ebb_ibgp",
)
_EBB_BGPMON_PORT_ASSIGNMENT = IxiaPortAssignment(logical_role="bgpmon")

EBB_DEVICE_CONFIG = RoutingDeviceConfig(
    update_group_enable=False,
    bgpcpp_logging_config_override=EBB_BGPCPP_LOGGING_CONFIG,
    enable_next_hop_tracking=True,
    enable_dynamic_policy_evaluation=True,
    openr_mode=OpenRMode.NONE,
    prefix_limit=EBB_DEVICE_PREFIX_LIMIT,
    per_peer_max_route_limit=EBB_DEVICE_PER_PEER_MAX_ROUTE_LIMIT,
    route_limit=EBB_DEVICE_ROUTE_LIMIT,
    bgp_hold_timer_s=EBB_BGP_HOLD_TIMER_S,
    bgp_keepalive_timer_s=EBB_BGP_KEEPALIVE_TIMER_S,
    fibagent_bgp_nhg_watermark_high=EBB_FIBAGENT_BGP_NHG_WATERMARK_HIGH,
    fibagent_bgp_nhg_watermark_low=EBB_FIBAGENT_BGP_NHG_WATERMARK_LOW,
)

EBB_EBGP_V6_PREFIX_SET = PrefixSet(
    name="ebb_ebgp_v6",
    afi="v6",
    source=FormulaicPrefixSource(
        start_prefix="2402:db00::",
        prefix_step=1 << 64,
        prefix_length=64,
        count=750,
        parent_network="2402:db00::/48",
    ),
)
EBB_EBGP_V4_PREFIX_SET = PrefixSet(
    name="ebb_ebgp_v4",
    afi="v4",
    source=FormulaicPrefixSource(
        start_prefix="120.0.0.0",
        prefix_step=1 << 8,
        prefix_length=24,
        count=750,
        parent_network="120.0.0.0/14",
    ),
)
EBB_IBGP_V6_PREFIX_SET = PrefixSet(
    name="ebb_ibgp_v6",
    afi="v6",
    source=FormulaicPrefixSource(
        start_prefix="2001:db8::",
        prefix_step=1 << 64,
        prefix_length=64,
        count=46_500,
        parent_network="2001:db8::/48",
        excluded_indices=EBB_IBGP_V6_EXCLUDED_PREFIX_INDICES,
    ),
)
EBB_IBGP_V4_PREFIX_SET = PrefixSet(
    name="ebb_ibgp_v4",
    afi="v4",
    source=FormulaicPrefixSource(
        start_prefix="11.0.0.0",
        prefix_step=1 << 8,
        prefix_length=24,
        count=46_500,
        parent_network="11.0.0.0/8",
        excluded_indices=EBB_IBGP_V4_EXCLUDED_PREFIX_INDICES,
    ),
)

EBB_PREFIX_SETS = (
    EBB_EBGP_V6_PREFIX_SET,
    EBB_EBGP_V4_PREFIX_SET,
    EBB_IBGP_V6_PREFIX_SET,
    EBB_IBGP_V4_PREFIX_SET,
)


def _ebb_route_inventory_issues(
    sized_names: t.AbstractSet[str],
) -> list[ValidationIssue]:
    """Name every way ``EBB_PREFIX_SETS`` differs from the sets the scale sizes.

    A set nothing sizes would reach the topology at its checked-in count, and
    a missing one would leave its advertisements without an inventory. Ad-hoc
    inventories belong in ``extra_prefix_sets``, not here.
    """
    names = Counter(prefix_set.name for prefix_set in EBB_PREFIX_SETS)
    issues = []
    unsized = sorted(names.keys() - sized_names)
    if unsized:
        issues.append(
            ValidationIssue(
                path="prefix_sets",
                code="ebb_route_inventory_unsized",
                message=(
                    f"EBB_PREFIX_SETS holds {unsized}, which no scale dimension "
                    "sizes. Give each a scale-derived count, or pass it as "
                    "extra_prefix_sets."
                ),
            )
        )
    missing = sorted(sized_names - names.keys())
    if missing:
        issues.append(
            ValidationIssue(
                path="prefix_sets",
                code="ebb_route_inventory_missing",
                message=(
                    f"EBB_PREFIX_SETS lacks {missing}, which every EBB topology "
                    "sizes and advertises."
                ),
            )
        )
    duplicated = sorted(name for name, count in names.items() if count > 1)
    if duplicated:
        issues.append(
            ValidationIssue(
                path="prefix_sets",
                code="ebb_route_inventory_duplicated",
                message=f"EBB_PREFIX_SETS names {duplicated} more than once.",
            )
        )
    return issues


# Adjacent space an iBGP progression continues into once its demand outgrows
# the FY26 parent. Neither widens to a supernet: the only aligned /7 holding
# 11/8 is 10.0.0.0/7, which also holds the iBGP session networks.
_EBB_IBGP_EXTENSION_PARENT_NETWORKS: dict[str, str] = {
    EBB_IBGP_V4_PREFIX_SET.name: "12.0.0.0/8",
    EBB_IBGP_V6_PREFIX_SET.name: "2001:db8:1::/48",
}


def _exclusions_within(excluded: tuple[int, ...], count: int) -> tuple[int, ...]:
    """The excluded candidates that fall before the last of ``count`` retained."""
    retained = 0
    while retained < len(excluded) and excluded[retained] < count + retained:
        retained += 1
    return excluded[:retained]


def _formulaic_candidate_capacity(
    start_prefix: str,
    prefix_step: int,
    parent_networks: t.Sequence[str],
) -> int:
    """Candidates from ``start_prefix`` to the end of its contiguous parents."""
    start = int(ipaddress.ip_address(start_prefix))
    end: int | None = None
    for network in sorted(
        (ipaddress.ip_network(parent) for parent in parent_networks),
        key=lambda network: int(network.network_address),
    ):
        first, last = int(network.network_address), int(network.broadcast_address)
        if end is None and first <= start <= last:
            end = last
        elif end is not None and first == end + 1:
            end = last
    return 0 if end is None else (end - start) // prefix_step + 1


def _ebb_sized_prefix_set(
    prefix_set: PrefixSet,
    count: int,
    *,
    demand: str,
    vetted_span: int | None = None,
) -> tuple[PrefixSet, list[ValidationIssue]]:
    """Size one EBB route inventory to ``count`` retained prefixes.

    Every way the inventory can fall short is reported as a named issue
    rather than left to surface later as an out-of-range index.
    """
    source = prefix_set.source
    path = f"prefix_sets.{prefix_set.name}"
    excluded = _exclusions_within(source.excluded_indices, count)
    span = count + len(excluded)
    issues = []
    if vetted_span is not None and span > vetted_span:
        issues.append(
            ValidationIssue(
                path=path,
                code="ebb_route_window_unvetted",
                message=(
                    f"{demand} needs a {span:,}-candidate span from "
                    f"{prefix_set.name}, but its exclusion inventory vetted only "
                    f"the first {vetted_span:,} candidates against the migration "
                    f"route inventory, leaving {span - vetted_span:,} unvetted. "
                    "Regenerate the exclusion inventory for the larger span, or "
                    "declare allows_dense_unvetted_route_tail on the scale profile."
                ),
            )
        )
    parents = (source.parent_network,)
    step = int(source.prefix_step)
    extension = _EBB_IBGP_EXTENSION_PARENT_NETWORKS.get(prefix_set.name)
    if extension and span > _formulaic_candidate_capacity(
        source.start_prefix, step, parents
    ):
        parents = (*parents, extension)
    capacity = _formulaic_candidate_capacity(source.start_prefix, step, parents)
    if span > capacity:
        issues.append(
            ValidationIssue(
                path=path,
                code="ebb_route_prefix_capacity_exceeded",
                message=(
                    f"{demand} needs {count:,} prefixes from {prefix_set.name}, a "
                    f"{span:,}-candidate span with {len(excluded):,} exclusions, "
                    f"but {', '.join(parents)} hold {capacity:,} candidates from "
                    f"{source.start_prefix}. Reduce the demand or extend the "
                    "inventory with an adjacent parent network."
                ),
            )
        )
    sized = replace(
        prefix_set,
        source=replace(
            source,
            count=count,
            excluded_indices=excluded,
            extension_parent_networks=parents[1:],
        ),
    )
    return sized, issues


def _ebb_prefix_sets(
    topology_name: str,
    scale: EbbScaleProfile,
    ebgp_prefix_count: int,
) -> tuple[PrefixSet, ...]:
    he_demand = (
        f"{scale.name} ({scale.ibgp_peers_per_group} HE peers x "
        f"{scale.routes_per_he_peer} routes)"
    )
    fa_demand = f"{scale.name} ({ebgp_prefix_count} FA routes per peer)"
    vetted_span = (
        None
        if scale.allows_dense_unvetted_route_tail
        else EBB_IBGP_VETTED_CANDIDATE_SPAN
    )
    issues = _ebb_route_inventory_issues(
        {
            EBB_EBGP_V4_PREFIX_SET.name,
            EBB_EBGP_V6_PREFIX_SET.name,
            *_EBB_IBGP_EXTENSION_PARENT_NETWORKS,
        }
    )
    if issues:
        raise TopologyValidationError(topology_name, issues)
    # Past the check, a set that is not iBGP is one of the two eBGP sets.
    sized_sets = []
    for prefix_set in EBB_PREFIX_SETS:
        if prefix_set.name in _EBB_IBGP_EXTENSION_PARENT_NETWORKS:
            sized, set_issues = _ebb_sized_prefix_set(
                prefix_set,
                scale.he_routes_per_afi,
                demand=he_demand,
                vetted_span=vetted_span,
            )
        else:
            sized, set_issues = _ebb_sized_prefix_set(
                prefix_set, ebgp_prefix_count, demand=fa_demand
            )
        sized_sets.append(sized)
        issues.extend(set_issues)
    if issues:
        raise TopologyValidationError(topology_name, issues)
    return tuple(sized_sets)


EBB_ACCEPT_POLICY = BgpPolicy(
    name="ebb_accept",
    communities=("65529:39744",),
)


# IXIA pool name per EBB eBGP prefix set, mirroring the names
# bgp_ebb_ixia_config.py gives these pools. Needed because a drain selects pools
# by their IXIA name, while the drained window is defined by the prefix set.
_EBB_EBGP_IXIA_POOL_NAMES: dict[str, str] = {
    EBB_EBGP_V4_PREFIX_SET.name: "PREFIX_POOL_IPV4_EBGP",
    EBB_EBGP_V6_PREFIX_SET.name: "PREFIX_POOL_IPV6_EBGP",
}


def ebb_drained_prefix_descriptors(
    prefix_end_index: int,
    prefix_start_index: int = 0,
    prefix_pool_regex: str = ".*EBGP.*",
) -> list[dict[str, t.Any]]:
    """Descriptors for the eBGP prefixes a FAUU drain actually touches.

    Lives beside the pool definitions because it is derived entirely from them:
    both the playbook and the scale TestConfig build the same drain and must
    hand the capture steps the same window, or the pcap ORIGIN/LOCAL_PREF check
    has nothing to scope itself to.

    Scoped two ways, because the capture asserts full coverage of what it is
    given:

    - By index. A drain rewrites only ``[start, end)`` of each 750-prefix pool,
      so the untouched majority legitimately keeps the old ORIGIN and LOCAL_PREF.
    - By pool. ``prefix_pool_regex`` is configurable, so a caller can drain one
      address family. Describing both would demand capture coverage for a pool
      the drain never touched and fail a healthy run, so only matching pools are
      described. Matching mirrors IXIA's own pool selection: ``re.search``
      against the pool name, case-sensitive.

    Args:
        prefix_end_index: Exclusive end of the drained window. Clamped to the
            pool size, since a drain cannot touch more prefixes than exist.
        prefix_start_index: Inclusive start of the drained window.
        prefix_pool_regex: The same regex the drain uses to select IXIA pools.
            Defaults to both eBGP address families.

    Returns:
        One descriptor per matching address family.

    Raises:
        ValueError: The regex matches no EBB eBGP pool, so the drain would have
            nothing to verify and the caller has almost certainly mistyped it.
    """
    descriptors = [
        {
            "start_prefix": prefix_set.source.start_prefix,
            "prefix_step": prefix_set.source.prefix_step,
            "prefix_length": prefix_set.source.prefix_length,
            "start_index": prefix_start_index,
            "end_index": min(prefix_end_index, prefix_set.source.count),
        }
        for prefix_set in (EBB_EBGP_V4_PREFIX_SET, EBB_EBGP_V6_PREFIX_SET)
        if re.search(prefix_pool_regex, _EBB_EBGP_IXIA_POOL_NAMES[prefix_set.name])
    ]
    if not descriptors:
        raise ValueError(
            f"prefix_pool_regex {prefix_pool_regex!r} matches none of the EBB "
            f"eBGP pools {sorted(_EBB_EBGP_IXIA_POOL_NAMES.values())}, so the "
            "drain has no prefixes whose attributes could be verified"
        )
    return descriptors


def _lexical_ip_range(start: str, count: int) -> tuple[str, ...]:
    first = ipaddress.ip_address(start)
    # IXIA's legacy EBB pools used string-lexical ordering; retain that observable
    # peer-to-next-hop association instead of silently normalizing numerically.
    return tuple(
        sorted(str(type(first)(int(first) + 2 * index)) for index in range(count))
    )


def _formulaic_next_hop(start: str, parent_network: str) -> NextHopIntent:
    return NextHopIntent(
        mode=NextHopMode.FORMULAIC,
        distribution=NextHopDistribution.PER_PEER,
        formulaic_source=FormulaicNextHopSource(
            start=start,
            step=2,
            parent_network=parent_network,
        ),
        description="externally resolved EBB next hops",
    )


def _explicit_next_hop(start: str, count: int, parent_network: str) -> NextHopIntent:
    return NextHopIntent(
        mode=NextHopMode.EXPLICIT,
        distribution=NextHopDistribution.PER_PEER,
        explicit_source=ExplicitNextHopSource(
            addresses=_lexical_ip_range(start, count),
            parent_network=parent_network,
        ),
        description="externally resolved EBB next hops",
    )


def _sequential_explicit_next_hop(
    start: str,
    count: int,
    parent_network: str,
) -> NextHopIntent:
    first = ipaddress.ip_address(start)
    return NextHopIntent(
        mode=NextHopMode.EXPLICIT,
        distribution=NextHopDistribution.PER_PEER,
        explicit_source=ExplicitNextHopSource(
            addresses=tuple(
                str(type(first)(int(first) + 2 * index)) for index in range(count)
            ),
            parent_network=parent_network,
        ),
        description="legacy per-peer EBB next hops",
    )


@dataclass(frozen=True)
class EbbNextHopScheme:
    """Chassis-specific bases for the next hops emulated peers advertise.

    These are built during topology construction, before ``bind_to_inventory``,
    so they cannot be read from ``parent_networks``. They also are not simply
    the peer subnets: the v6 iBGP next hops deliberately sit on different
    hextets from the peer parents, and the Open/R variants live in their own
    ``20.x`` / ``e80d`` space. What does move together across chassis is the
    numbering *structure*, so only the two bases that differ are captured here.

    Attributes:
        ebgp_v4_network: eBGP /23 base, e.g. ``"10.163.28"``.
        ebgp_v6_network: eBGP /80 base, e.g. ``"2401:db00:e50d:11:8"``.
        ibgp_v4_plane_base: Second octet that plane N counts from, so plane N
            is ``<first>.<base + N>.28.0/24``. Equals the eBGP second octet.
        ibgp_v6_group: Fourth hextet identifying the chassis, e.g. ``"11"``.
    """

    ebgp_v4_network: str
    ebgp_v6_network: str
    ibgp_v4_plane_base: int
    ibgp_v6_group: str


EBB_NEXT_HOPS: EbbNextHopScheme = EbbNextHopScheme(
    ebgp_v4_network=IXIA_EBGP_IC_PARENT_NETWORK_V4,
    ebgp_v6_network=IXIA_EBGP_IC_PARENT_NETWORK_V6,
    ibgp_v4_plane_base=163,
    ibgp_v6_group="11",
)

EBB_NEXT_HOPS_IXIA03: EbbNextHopScheme = EbbNextHopScheme(
    ebgp_v4_network=IXIA03_EBGP_IC_PARENT_NETWORK_V4,
    ebgp_v6_network=IXIA03_EBGP_IC_PARENT_NETWORK_V6,
    ibgp_v4_plane_base=180,
    ibgp_v6_group="33",
)


def _ebb_ibgp_next_hop_source(
    afi: str,
    plane: int,
    openr_mode: OpenRMode,
    next_hops: EbbNextHopScheme,
) -> tuple[str, str, bool]:
    if afi not in {"v4", "v6"}:
        raise ValueError(f"EBB iBGP next-hop AFI must be v4 or v6; got {afi!r}")
    if not 1 <= plane <= 4:
        raise ValueError(
            f"EBB iBGP next-hop plane must be between 1 and 4; got {plane}"
        )
    openr_enabled = openr_mode is OpenRMode.STANDALONE
    if afi == "v4":
        first_octet = 20 if openr_enabled else 10
        second_octet = next_hops.ibgp_v4_plane_base + plane
        return (
            f"{first_octet}.{second_octet}.28.10",
            f"{first_octet}.{second_octet}.28.0/24",
            True,
        )

    # Legacy OpenR CSVs and KV injection use the literal slots 9/10/11/12.
    # Non-OpenR DC planes use hexadecimal slots a/b/c/9.
    slot = str(plane + 8) if openr_enabled else f"{9 if plane == 4 else plane + 9:x}"
    fabric = "e80d" if openr_enabled else "e50d"
    start = f"2401:db00:{fabric}:{next_hops.ibgp_v6_group}:{slot}::10"
    return start, str(ipaddress.ip_network(f"{start}/80", strict=False)), False


def ebb_openr_injected_next_hops(
    next_hops: EbbNextHopScheme,
) -> tuple[list[str], list[str]]:
    """Return the (v4, v6) plane next hops Open/R must inject reachability for.

    The emulated peers advertise routes whose iBGP next hops come from
    ``_ebb_ibgp_next_hop_source``; those next hops only resolve because Open/R
    injects a route covering each one. Expressing the injection set separately
    from the advertised set lets the two drift, and on a chassis whose scheme
    differs the drift is silent: the routes still arrive and sit in the RIB,
    but none become installable, so the shadow RIB and everything advertised
    downstream collapse to whatever else happens to resolve. Deriving both from
    one scheme is what keeps them in step.

    Args:
        next_hops: Chassis scheme the emulated peers are wired to.

    Returns:
        Parallel lists of the four plane start addresses, v4 first.
    """
    v4_starts: list[str] = []
    v6_starts: list[str] = []
    for plane in range(1, 5):
        v4_starts.append(
            _ebb_ibgp_next_hop_source("v4", plane, OpenRMode.STANDALONE, next_hops)[0]
        )
        v6_starts.append(
            _ebb_ibgp_next_hop_source("v6", plane, OpenRMode.STANDALONE, next_hops)[0]
        )
    return v4_starts, v6_starts


(
    _EBB_OPENR_INJECTED_START_IPV4S,
    _EBB_OPENR_INJECTED_START_IPV6S,
) = ebb_openr_injected_next_hops(EBB_NEXT_HOPS)
EBB_OPENR_INJECTED_START_IPV4S: tuple[str, ...] = tuple(_EBB_OPENR_INJECTED_START_IPV4S)
EBB_OPENR_INJECTED_START_IPV6S: tuple[str, ...] = tuple(_EBB_OPENR_INJECTED_START_IPV6S)
(
    _EBB_OPENR_INJECTED_START_IPV4S_IXIA03,
    _EBB_OPENR_INJECTED_START_IPV6S_IXIA03,
) = ebb_openr_injected_next_hops(EBB_NEXT_HOPS_IXIA03)
EBB_OPENR_INJECTED_START_IPV4S_IXIA03: tuple[str, ...] = tuple(
    _EBB_OPENR_INJECTED_START_IPV4S_IXIA03
)
EBB_OPENR_INJECTED_START_IPV6S_IXIA03: tuple[str, ...] = tuple(
    _EBB_OPENR_INJECTED_START_IPV6S_IXIA03
)


def ebb_ibgp_route_next_hops(
    afi: str,
    plane: int,
    peer_count: int,
    openr_mode: OpenRMode,
    next_hops: EbbNextHopScheme,
) -> tuple[str, ...]:
    """Return the route next hop associated with each EBB iBGP peer row.

    Args:
        afi: ``"v4"`` or ``"v6"``.
        plane: iBGP plane, 1-4.
        peer_count: Number of peer rows to generate next hops for.
        openr_mode: Selects the Open/R next-hop space when STANDALONE.
        next_hops: Chassis scheme the emulated peers are wired to.
    """
    start, _parent, _lexical = _ebb_ibgp_next_hop_source(
        afi, plane, openr_mode, next_hops
    )
    return ebb_ibgp_route_next_hops_from_start(afi, start, peer_count)


def ebb_ibgp_route_next_hops_from_start(
    afi: str,
    start: str,
    peer_count: int,
) -> tuple[str, ...]:
    """Expand one plane's first route next hop into its per-peer-row next hops.

    Args:
        afi: ``"v4"`` or ``"v6"``.
        start: Route next hop of peer row 0, as bound for the run's chassis.
        peer_count: Number of peer rows to generate next hops for.
    """
    if afi not in {"v4", "v6"}:
        raise ValueError(f"EBB iBGP next-hop AFI must be v4 or v6; got {afi!r}")
    if peer_count < 1:
        raise ValueError(f"EBB iBGP peer count must be positive; got {peer_count}")
    if afi == "v4":
        return _lexical_ip_range(start, peer_count)
    first = ipaddress.ip_address(start)
    return tuple(
        str(type(first)(int(first) + 2 * index)) for index in range(peer_count)
    )


def ebb_ibgp_route_next_hop_starts(
    bound: BoundTopology,
) -> dict[str, dict[str, str]]:
    """Return each iBGP plane's first route next hop from a bound EBB topology.

    Consumers that reconstruct per-row next hops must start from the bound
    topology rather than a chassis default; every row is checked against the
    shared expansion so a consumer cannot silently disagree with the IXIA
    configuration.

    Args:
        bound: EBB full-scale topology bound to the run's physical inventory.

    Returns:
        ``{"ipv4": {"1": start, ...}, "ipv6": {...}}`` covering planes 1-4.

    Raises:
        ValueError: A plane is missing or duplicated, advertises next-hop-self,
            or its resolved next hops differ from the shared expansion.
    """
    starts: dict[str, dict[str, str]] = {"ipv4": {}, "ipv6": {}}
    for group in bound.device_groups:
        if not group.role.startswith("ibgp_dc_p"):
            continue
        afi_key = "ipv4" if group.spec.afi == "v4" else "ipv6"
        plane = str(_ebb_plane_number(group.spec))
        if plane in starts[afi_key]:
            raise ValueError(f"EBB iBGP {afi_key} plane {plane} is bound twice")
        if len(group.prefix_advertisements) != 1:
            raise ValueError(
                f"{group.name} must bind exactly one route advertisement; "
                f"got {len(group.prefix_advertisements)}"
            )
        (advertisement,) = group.prefix_advertisements
        if advertisement.spec.next_hop.mode is NextHopMode.SELF:
            raise ValueError(
                f"{group.name} advertises next-hop-self; route next hops are "
                "the session addresses"
            )
        resolved = tuple(
            str(advertisement.path_at(row, 0).next_hop)
            for row in range(group.peer_count)
        )
        # v4 rows sort lexically, so row 0 need not be the start; the start is
        # always the numeric minimum of the expansion.
        start = str(min(resolved, key=lambda value: int(ipaddress.ip_address(value))))
        expected = ebb_ibgp_route_next_hops_from_start(
            group.spec.afi, start, group.peer_count
        )
        if resolved != expected:
            raise ValueError(
                f"{group.name} resolved route next hops do not follow the EBB "
                f"per-row expansion from {start}"
            )
        starts[afi_key][plane] = start
    for afi_key, planes in starts.items():
        if set(planes) != {"1", "2", "3", "4"}:
            raise ValueError(
                f"bound EBB topology must define {afi_key} iBGP planes 1-4; "
                f"got {sorted(planes)}"
            )
    return starts


def _ebb_next_hop(
    device_group: DeviceGroupSpec,
    openr_mode: OpenRMode,
    next_hops: EbbNextHopScheme,
) -> NextHopIntent:
    """Build next hops aligned with legacy route assets and OpenR injection."""
    openr_enabled = openr_mode is OpenRMode.STANDALONE
    if device_group.name == "dg_ebgp_v4":
        ebgp_v4_parent = f"{next_hops.ebgp_v4_network}.0/23"
        return (
            _sequential_explicit_next_hop(
                f"{next_hops.ebgp_v4_network}.11",
                device_group.peer_count,
                ebgp_v4_parent,
            )
            if openr_enabled
            else _explicit_next_hop(
                f"{next_hops.ebgp_v4_network}.10",
                device_group.peer_count,
                ebgp_v4_parent,
            )
        )
    if device_group.name == "dg_ebgp_v6":
        ebgp_v6_parent = f"{next_hops.ebgp_v6_network}::/80"
        return (
            _sequential_explicit_next_hop(
                f"{next_hops.ebgp_v6_network}::11",
                device_group.peer_count,
                ebgp_v6_parent,
            )
            if openr_enabled
            else _explicit_next_hop(
                f"{next_hops.ebgp_v6_network}::10",
                device_group.peer_count,
                ebgp_v6_parent,
            )
        )

    plane = _ebb_plane_number(device_group)
    start, parent, lexical = _ebb_ibgp_next_hop_source(
        device_group.afi, plane, openr_mode, next_hops
    )
    return (
        _explicit_next_hop(start, device_group.peer_count, parent)
        if lexical
        else _formulaic_next_hop(start, parent)
    )


def _ebb_plane_number(device_group: DeviceGroupSpec) -> int:
    _, separator, plane_suffix = device_group.role.rpartition("_p")
    if not separator or not plane_suffix.isdigit():
        raise ValueError(
            "EBB iBGP device-group roles must end in a numeric plane suffix; "
            f"got role={device_group.role!r} for {device_group.name!r}"
        )
    plane = int(plane_suffix)
    if not 1 <= plane <= 4:
        raise ValueError(
            "EBB iBGP device-group plane must be between 1 and 4; "
            f"got role={device_group.role!r} for {device_group.name!r}"
        )
    return plane


def _ebb_diverse_nhg_activation(
    prefix_count: int,
    *,
    peer_count: int,
) -> PeerPrefixActivation:
    if peer_count != _EBB_DIVERSE_NHG_REQUIRED_PEER_COUNT:
        raise ValueError(
            "EBB diverse-NHG activation requires exactly "
            f"{_EBB_DIVERSE_NHG_REQUIRED_PEER_COUNT} peers; got {peer_count}"
        )
    canonical_prefix_count = min(
        prefix_count,
        EBB_DIVERSE_NHG_GROUP_COUNT * EBB_DIVERSE_NHG_PREFIXES_PER_GROUP,
    )
    segments = (
        (0, canonical_prefix_count),
        (canonical_prefix_count, prefix_count - canonical_prefix_count),
    )
    blocks = []
    for segment_start, segment_count in segments:
        prefixes_per_group, extra_prefixes = divmod(
            segment_count,
            EBB_DIVERSE_NHG_GROUP_COUNT,
        )
        prefix_start = segment_start
        for group in range(EBB_DIVERSE_NHG_GROUP_COUNT):
            group_prefix_count = prefixes_per_group + (group < extra_prefixes)
            if group_prefix_count == 0:
                continue
            first_excluded_peer = (
                _EBB_DIVERSE_NHG_FIRST_EXCLUDED_PEER
                + group * EBB_DIVERSE_NHG_EXCLUDED_PEERS_PER_GROUP
            )
            blocks.append(
                PeerPrefixExclusionBlock(
                    prefix_start_index=prefix_start,
                    prefix_count=group_prefix_count,
                    peer_indices=tuple(
                        range(
                            first_excluded_peer,
                            first_excluded_peer
                            + EBB_DIVERSE_NHG_EXCLUDED_PEERS_PER_GROUP,
                        )
                    ),
                )
            )
            prefix_start += group_prefix_count
    return PeerPrefixActivation(exclusion_blocks=tuple(blocks))


def _ebb_advertisement(
    device_group: DeviceGroupSpec,
    openr_mode: OpenRMode,
    *,
    prefix_sets_by_name: t.Mapping[str, PrefixSet],
    ebgp_static_prefix_count: int,
    routes_per_he_peer: int,
    next_hop_self: bool = False,
    include_legacy_community_rows: bool = False,
    next_hops: EbbNextHopScheme,
) -> PrefixAdvertisement | None:
    if device_group.name == "dg_ebgp_v4":
        prefix_set = prefix_sets_by_name[EBB_EBGP_V4_PREFIX_SET.name]
        distribution = PeerPrefixDistribution.SHARED
        legacy_name = "PREFIX_POOL_IPV4_EBGP"
    elif device_group.name == "dg_ebgp_v6":
        prefix_set = prefix_sets_by_name[EBB_EBGP_V6_PREFIX_SET.name]
        distribution = PeerPrefixDistribution.SHARED
        legacy_name = "PREFIX_POOL_IPV6_EBGP"
    elif device_group.role.startswith("ibgp_dc_p"):
        prefix_set = prefix_sets_by_name[
            (
                EBB_IBGP_V4_PREFIX_SET.name
                if device_group.afi == "v4"
                else EBB_IBGP_V6_PREFIX_SET.name
            )
        ]
        distribution = PeerPrefixDistribution.DISJOINT
        plane = _ebb_plane_number(device_group)
        legacy_name = (
            f"PREFIX_POOL_IBGP_IPV{4 if device_group.afi == 'v4' else 6}_"
            f"PLANE_{plane}_REMOTE_EB"
        )
    else:
        return None
    advertised_prefix_count = (
        ebgp_static_prefix_count
        if device_group.role == "uplink"
        else prefix_set.source.count
    )
    return PrefixAdvertisement(
        name=f"{device_group.name}_routes",
        prefix_set=prefix_set.name,
        allocation=PrefixAllocation(
            prefixes_per_peer=(
                advertised_prefix_count
                if device_group.role == "uplink"
                else routes_per_he_peer
            ),
            peer_distribution=distribution,
            route_scale_mode=RouteScaleMode.FLAT,
        ),
        membership=PrefixMembership(
            start_index=0,
            prefix_count=advertised_prefix_count,
        ),
        next_hop=(
            NextHopIntent(mode=NextHopMode.SELF)
            if next_hop_self
            else _ebb_next_hop(device_group, openr_mode, next_hops)
        ),
        policy=EBB_ACCEPT_POLICY if device_group.role == "uplink" else None,
        attributes=EBB_BASELINE_ATTRIBUTES,
        peer_prefix_activation=(
            _ebb_diverse_nhg_activation(
                advertised_prefix_count,
                peer_count=device_group.peer_count,
            )
            if device_group.role == "uplink"
            else None
        ),
        route_attributes=(
            _EBB_IBGP_ROUTE_ATTRIBUTES
            if include_legacy_community_rows
            and device_group.role.startswith("ibgp_dc_p")
            else None
        ),
        legacy_ixia_name=legacy_name,
    )


def _ebb_route_storm_ixia_children(
    device_group: DeviceGroupSpec,
) -> tuple[IxiaDeviceGroupChild, ...]:
    if device_group.name not in {"dg_ibgp_v4_dc_p1", "dg_ibgp_v6_dc_p1"}:
        return ()
    if len(device_group.prefix_advertisements) != 1:
        raise ValueError(
            f"{device_group.name!r} route sharding requires one advertisement"
        )
    device_group_name = device_group.legacy_ixia_device_group_name
    bgp_peer_name = (
        device_group.legacy_ixia_bgp_peer_name or device_group.legacy_ixia_tag_name
    )
    device_group_index = device_group.legacy_ixia_device_group_index
    prefix_pool_name = device_group.prefix_advertisements[0].legacy_ixia_name
    if (
        device_group_name is None
        or bgp_peer_name is None
        or device_group_index is None
        or prefix_pool_name is None
    ):
        raise ValueError(
            f"{device_group.name!r} route sharding requires legacy IXIA identity"
        )

    children = []
    start_index = 0
    shard_peer_counts = ebb_route_storm_shard_peer_counts(device_group.peer_count)
    additional_shard_count = len(shard_peer_counts) - 1
    extra_index_start = (
        16 if device_group.name == "dg_ibgp_v6_dc_p1" else 16 + additional_shard_count
    )
    for ordinal, peer_count in enumerate(shard_peer_counts):
        suffix = "" if ordinal == 0 else f"_SHARD_{ordinal + 1}"
        children.append(
            IxiaDeviceGroupChild(
                name=f"{device_group.name}_route_shard_{ordinal + 1}",
                ordinal=ordinal,
                start_index=start_index,
                peer_count=peer_count,
                legacy_ixia_device_group_name=f"{device_group_name}{suffix}",
                legacy_ixia_bgp_peer_name=f"{bgp_peer_name}{suffix}",
                legacy_ixia_prefix_pool_name=f"{prefix_pool_name}{suffix}",
                legacy_ixia_device_group_index=(
                    device_group_index
                    if ordinal == 0
                    else extra_index_start + ordinal - 1
                ),
            )
        )
        start_index += peer_count
    return tuple(children)


def _with_ebb_route_storm_shards(
    device_group: DeviceGroupSpec,
) -> DeviceGroupSpec:
    children = _ebb_route_storm_ixia_children(device_group)
    if not children:
        return device_group
    return replace(
        device_group,
        legacy_ixia_tag_name=None,
        legacy_ixia_bgp_peer_name=None,
        legacy_ixia_device_group_name=None,
        legacy_ixia_device_group_index=None,
        ixia_children=children,
    )


# Variant A: with bgpmon - 3 physical interfaces, 19 DeviceGroups total.
# Keep this first topology instance explicit so it can be reviewed against
# Appendix 1 without following helper loops or generated DG lists.
_EBB_FY26_TOPOLOGY_WITH_BGPMON_BASE = LogicalTopology(
    name="ebb_full_scale_with_bgpmon",
    legacy_profile="ebb_full_scale",
    endpoints=(
        EndpointSpec(name="dut0", role="dut", kind="dut", setup_mode="full"),
        EndpointSpec(name="ixia", role="trafficgen", kind="ixia", setup_mode="full"),
    ),
    device_groups=(
        # eBGP uplink: 2 DGs sharing the uplink physical interface.
        DeviceGroupSpec(
            name="dg_ebgp_v6",
            role="uplink",
            peer_relationship=PeerRelationship.EXTERNAL,
            afi="v6",
            peer_count=EBGP_PEER_COUNT_V6,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ebgp_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=EBGP_V6_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV6_EBGP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_EBGP",
            port_assignment=_EBB_UPLINK_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=0,
        ),
        DeviceGroupSpec(
            name="dg_ebgp_v4",
            role="uplink",
            peer_relationship=PeerRelationship.EXTERNAL,
            afi="v4",
            peer_count=EBGP_PEER_COUNT_V4,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ebgp_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=EBGP_V4_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV4_EBGP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_EBGP",
            port_assignment=_EBB_UPLINK_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=1,
        ),
        # iBGP DC planes 1-4: v6 DGs sharing the iBGP physical interface.
        DeviceGroupSpec(
            name="dg_ibgp_v6_dc_p1",
            role="ibgp_dc_p1",
            openr_injection_range_ordinal=1,
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_dc_p1_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=IBGP_V6_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV6_IBGP_PLANE_1_REMOTE_EB",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP_PLANE_1_REMOTE_EB",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=0,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v6_dc_p2",
            role="ibgp_dc_p2",
            openr_injection_range_ordinal=2,
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_dc_p2_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=IBGP_V6_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV6_IBGP_PLANE_2_REMOTE_EB",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP_PLANE_2_REMOTE_EB",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=4,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v6_dc_p3",
            role="ibgp_dc_p3",
            openr_injection_range_ordinal=3,
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_dc_p3_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=IBGP_V6_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV6_IBGP_PLANE_3_REMOTE_EB",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP_PLANE_3_REMOTE_EB",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=8,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v6_dc_p4",
            role="ibgp_dc_p4",
            openr_injection_range_ordinal=4,
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_dc_p4_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=IBGP_V6_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV6_IBGP_PLANE_4_REMOTE_EB",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP_PLANE_4_REMOTE_EB",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=12,
        ),
        # iBGP DC planes 1-4: v4 DGs.
        DeviceGroupSpec(
            name="dg_ibgp_v4_dc_p1",
            role="ibgp_dc_p1",
            openr_injection_range_ordinal=1,
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v4",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ibgp_dc_p1_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=IBGP_V4_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV4_IBGP_PLANE_1_REMOTE_EB",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_IBGP_PLANE_1_REMOTE_EB",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=2,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v4_dc_p2",
            role="ibgp_dc_p2",
            openr_injection_range_ordinal=2,
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v4",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ibgp_dc_p2_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=IBGP_V4_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV4_IBGP_PLANE_2_REMOTE_EB",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_IBGP_PLANE_2_REMOTE_EB",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=6,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v4_dc_p3",
            role="ibgp_dc_p3",
            openr_injection_range_ordinal=3,
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v4",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ibgp_dc_p3_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=IBGP_V4_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV4_IBGP_PLANE_3_REMOTE_EB",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_IBGP_PLANE_3_REMOTE_EB",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=10,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v4_dc_p4",
            role="ibgp_dc_p4",
            openr_injection_range_ordinal=4,
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v4",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ibgp_dc_p4_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=IBGP_V4_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV4_IBGP_PLANE_4_REMOTE_EB",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_IBGP_PLANE_4_REMOTE_EB",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=14,
        ),
        # iBGP MP planes 1-4: v6 DGs sharing the iBGP physical interface.
        DeviceGroupSpec(
            name="dg_ibgp_v6_mp_p1",
            role="ibgp_mp_p1",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_mp_p1_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=IBGP_V6_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV6_IBGP_PLANE_1_REMOTE_MP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP_PLANE_1_REMOTE_MP",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=1,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v6_mp_p2",
            role="ibgp_mp_p2",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_mp_p2_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=IBGP_V6_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV6_IBGP_PLANE_2_REMOTE_MP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP_PLANE_2_REMOTE_MP",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=5,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v6_mp_p3",
            role="ibgp_mp_p3",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_mp_p3_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=IBGP_V6_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV6_IBGP_PLANE_3_REMOTE_MP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP_PLANE_3_REMOTE_MP",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=9,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v6_mp_p4",
            role="ibgp_mp_p4",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v6",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="ibgp_mp_p4_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=IBGP_V6_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV6_IBGP_PLANE_4_REMOTE_MP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV6_IBGP_PLANE_4_REMOTE_MP",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=13,
        ),
        # iBGP MP planes 1-4: v4 DGs.
        DeviceGroupSpec(
            name="dg_ibgp_v4_mp_p1",
            role="ibgp_mp_p1",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v4",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ibgp_mp_p1_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=IBGP_V4_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV4_IBGP_PLANE_1_REMOTE_MP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_IBGP_PLANE_1_REMOTE_MP",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=3,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v4_mp_p2",
            role="ibgp_mp_p2",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v4",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ibgp_mp_p2_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=IBGP_V4_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV4_IBGP_PLANE_2_REMOTE_MP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_IBGP_PLANE_2_REMOTE_MP",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=7,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v4_mp_p3",
            role="ibgp_mp_p3",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v4",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ibgp_mp_p3_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=IBGP_V4_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV4_IBGP_PLANE_3_REMOTE_MP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_IBGP_PLANE_3_REMOTE_MP",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=11,
        ),
        DeviceGroupSpec(
            name="dg_ibgp_v4_mp_p4",
            role="ibgp_mp_p4",
            peer_relationship=PeerRelationship.INTERNAL,
            afi="v4",
            peer_count=IBGP_PEER_SCALE_PER_PLANE,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v4",
                parent_network_key="ibgp_mp_p4_v4",
                stride=2,
                prefix_length=31,
            ),
            peer_group=IBGP_V4_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV4_IBGP_PLANE_4_REMOTE_MP",
            legacy_ixia_device_group_name="DEVICE_GROUP_IPV4_IBGP_PLANE_4_REMOTE_MP",
            port_assignment=_EBB_IBGP_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=15,
        ),
        # BGP MON: 1 DG on the bgpmon physical interface.
        DeviceGroupSpec(
            name="dg_bgp_mon_v6",
            role="bgpmon",
            peer_relationship=PeerRelationship.MONITOR,
            afi="v6",
            peer_count=BGP_MON_PEER_COUNT,
            a_endpoint="dut0",
            z_endpoint="ixia",
            address_plan=AddressPlan(
                afi="v6",
                parent_network_key="bgpmon_v6",
                stride=2,
                prefix_length=127,
            ),
            peer_group=BGP_MON_PEER_GROUP,
            legacy_ixia_tag_name="BGP_PEER_IPV6_BGP_MON",
            legacy_ixia_device_group_name="DEVICE_GROUP_BGP_MON",
            port_assignment=_EBB_BGPMON_PORT_ASSIGNMENT,
            legacy_ixia_device_group_index=0,
        ),
    ),
    device_config=EBB_DEVICE_CONFIG,
    peer_groups=tuple(EBB_PEER_GROUPS.values()),
)


def _with_ebb_route_intent(
    topology: LogicalTopology,
    openr_mode: OpenRMode,
    *,
    ebgp_graceful_restart: bool = True,
    next_hop_self: bool = False,
    include_legacy_community_rows: bool = True,
    ebgp_prefix_count: int | None = None,
    ebgp_static_prefix_count: int | None = None,
    extra_prefix_sets: tuple[PrefixSet, ...] = (),
    extra_advertisements: t.Mapping[str, tuple[PrefixAdvertisement, ...]] | None = None,
    next_hops: EbbNextHopScheme,
    route_storm_shards: bool = False,
    scale: EbbScaleProfile,
) -> LogicalTopology:
    if not scale.allows_bgp_monitor and any(
        device_group.role == "bgpmon" for device_group in topology.device_groups
    ):
        raise ValueError(f"{scale.name} models no BGP monitor; drop the bgpmon group")
    if ebgp_prefix_count is None:
        ebgp_prefix_count = scale.fa_routes_per_peer
    if ebgp_prefix_count < scale.fa_routes_per_peer:
        raise ValueError(
            f"ebgp_prefix_count must be at least {scale.fa_routes_per_peer}, "
            f"{scale.name}'s FA routes per peer"
        )
    static_prefix_count = (
        ebgp_prefix_count
        if ebgp_static_prefix_count is None
        else ebgp_static_prefix_count
    )
    # Equality is the default full-static topology. A smaller explicit value
    # reserves the suffix for runtime route operations such as TC7.
    if static_prefix_count <= 0 or static_prefix_count > ebgp_prefix_count:
        raise ValueError(
            "ebgp_static_prefix_count must be positive and no greater than "
            "ebgp_prefix_count"
        )
    prefix_sets = _ebb_prefix_sets(topology.name, scale, ebgp_prefix_count)
    prefix_sets_by_name = {prefix_set.name: prefix_set for prefix_set in prefix_sets}
    extra_advertisements = extra_advertisements or {}
    device_groups = []
    for device_group in topology.device_groups:
        if device_group.role.startswith("ibgp_"):
            device_group = replace(device_group, peer_count=scale.ibgp_peers_per_group)
        peer_group = device_group.peer_group
        if (
            device_group.role == "uplink"
            and isinstance(peer_group, BgpPeerGroup)
            and peer_group.enable_graceful_restart != ebgp_graceful_restart
        ):
            peer_group = replace(
                peer_group,
                enable_graceful_restart=ebgp_graceful_restart,
            )
        advertisement = _ebb_advertisement(
            device_group,
            openr_mode,
            prefix_sets_by_name=prefix_sets_by_name,
            ebgp_static_prefix_count=static_prefix_count,
            routes_per_he_peer=scale.routes_per_he_peer,
            next_hop_self=next_hop_self,
            include_legacy_community_rows=include_legacy_community_rows,
            next_hops=next_hops,
        )
        additional_advertisements = tuple(
            replace(extra, route_attributes=_EBB_IBGP_ROUTE_ATTRIBUTES)
            if include_legacy_community_rows
            and device_group.role.startswith("ibgp_dc_p")
            and extra.route_attributes is None
            else extra
            for extra in extra_advertisements.get(device_group.name, ())
        )
        resolved_group = replace(
            device_group,
            peer_group=peer_group,
            prefix_advertisements=(
                ((advertisement,) if advertisement else ()) + additional_advertisements
            ),
        )
        device_groups.append(
            _with_ebb_route_storm_shards(resolved_group)
            if route_storm_shards
            else resolved_group
        )
    # Only STANDALONE injects. Leaving the scale unset in the other modes keeps
    # the NONE-mode module topologies byte-identical to what they were before
    # this field, and the injected addresses are resolved from the bound route
    # advertisements at lowering time rather than recorded here.
    return replace(
        topology,
        device_groups=tuple(device_groups),
        device_config=replace(
            topology.device_config,
            openr_mode=openr_mode,
            openr_injection_scale=(
                scale.openr_injection_scale
                if openr_mode is OpenRMode.STANDALONE
                else None
            ),
        ),
        policies=(EBB_ACCEPT_POLICY,),
        prefix_sets=(*prefix_sets, *extra_prefix_sets),
    )


EBB_FY26_TOPOLOGY_WITH_BGPMON = replace(
    _with_ebb_route_intent(
        _EBB_FY26_TOPOLOGY_WITH_BGPMON_BASE,
        openr_mode=OpenRMode.NONE,
        next_hops=EBB_NEXT_HOPS,
        scale=EBB_FY26_SCALE,
    ),
    legacy_profile=None,
    task_compatibility_profile=TaskCompatibilityProfile.EBB_FULL_SCALE_WITH_BGPMON,
)

# Variant B: without bgpmon - 2 physical interfaces, 18 DeviceGroups total.
# This small derived filter keeps the two variants consistent without hiding
# the full Appendix-style listing above.
_EBB_FY26_TOPOLOGY_NO_BGPMON_BASE = LogicalTopology(
    name="ebb_full_scale_no_bgpmon",
    legacy_profile="ebb_full_scale",
    endpoints=_EBB_FY26_TOPOLOGY_WITH_BGPMON_BASE.endpoints,
    device_groups=tuple(
        dg
        for dg in _EBB_FY26_TOPOLOGY_WITH_BGPMON_BASE.device_groups
        if dg.role != "bgpmon" and dg.name != "dg_bgp_mon_v6"
    ),
    device_config=EBB_DEVICE_CONFIG,
    peer_groups=tuple(
        peer_group
        for peer_group in EBB_PEER_GROUPS.values()
        if peer_group.name != PEERGROUP_BGP_MON
    ),
)

EBB_FY26_TOPOLOGY_NO_BGPMON = replace(
    _with_ebb_route_intent(
        _EBB_FY26_TOPOLOGY_NO_BGPMON_BASE,
        openr_mode=OpenRMode.NONE,
        next_hops=EBB_NEXT_HOPS,
        scale=EBB_FY26_SCALE,
    ),
    legacy_profile=None,
    task_compatibility_profile=TaskCompatibilityProfile.EBB_FULL_SCALE_NO_BGPMON,
)


def ebb_topology(
    *,
    openr_mode: OpenRMode,
    include_bgpmon: bool | None = None,
    ebgp_graceful_restart: bool = True,
    next_hop_self: bool = False,
    include_legacy_community_rows: bool = True,
    ebgp_prefix_count: int | None = None,
    ebgp_static_prefix_count: int | None = None,
    extra_prefix_sets: tuple[PrefixSet, ...] = (),
    extra_advertisements: t.Mapping[str, tuple[PrefixAdvertisement, ...]] | None = None,
    next_hops: EbbNextHopScheme = EBB_NEXT_HOPS,
    route_storm_shards: bool = False,
    scale: EbbScaleProfile,
) -> LogicalTopology:
    """Build the EBB topology at ``scale``.

    ``include_bgpmon`` defaults to whether the scale allows a BGP monitor, and
    ``ebgp_prefix_count`` to the scale's FA routes per peer.
    """
    if include_bgpmon is None:
        include_bgpmon = scale.allows_bgp_monitor
    base = (
        _EBB_FY26_TOPOLOGY_WITH_BGPMON_BASE
        if include_bgpmon
        else _EBB_FY26_TOPOLOGY_NO_BGPMON_BASE
    )
    topology = _with_ebb_route_intent(
        base,
        openr_mode,
        ebgp_graceful_restart=ebgp_graceful_restart,
        next_hop_self=next_hop_self,
        include_legacy_community_rows=include_legacy_community_rows,
        ebgp_prefix_count=ebgp_prefix_count,
        ebgp_static_prefix_count=ebgp_static_prefix_count,
        extra_prefix_sets=extra_prefix_sets,
        extra_advertisements=extra_advertisements,
        next_hops=next_hops,
        route_storm_shards=route_storm_shards,
        scale=scale,
    )
    if not route_storm_shards:
        return topology
    return replace(
        topology,
        name=f"{topology.name}_route_sharded",
        legacy_profile=None,
        task_compatibility_profile=(
            TaskCompatibilityProfile.EBB_FULL_SCALE_WITH_BGPMON
            if include_bgpmon
            else TaskCompatibilityProfile.EBB_FULL_SCALE_NO_BGPMON
        ),
    )


__all__ = (
    "BGP_MON_PEER_GROUP",
    "EBB_AS_NUMBERS",
    "EBB_BASELINE_ATTRIBUTES",
    "EBB_DEVICE_CONFIG",
    "EBB_DIVERSE_NHG_EXCLUDED_PEERS_PER_GROUP",
    "EBB_DIVERSE_NHG_GROUP_COUNT",
    "EBB_DIVERSE_NHG_PREFIXES_PER_GROUP",
    "EBB_EBGP_V4_PREFIX_SET",
    "EBB_EBGP_V6_PREFIX_SET",
    "EBB_FY26_SCALE",
    "EBB_FY26_TOPOLOGY_NO_BGPMON",
    "EBB_FY26_TOPOLOGY_WITH_BGPMON",
    "EBB_FY27_SCALE",
    "ebb_ibgp_route_next_hop_starts",
    "ebb_ibgp_route_next_hops",
    "ebb_ibgp_route_next_hops_from_start",
    "EBB_IBGP_V4_PREFIX_SET",
    "EBB_IBGP_V6_PREFIX_SET",
    "EBB_LONGEVITY_COMMUNITY_BASELINE_COUNT",
    "EBB_NEXT_HOPS",
    "EBB_NEXT_HOPS_IXIA03",
    "ebb_openr_injected_next_hops",
    "EBB_OPENR_INJECTED_START_IPV4S",
    "EBB_OPENR_INJECTED_START_IPV4S_IXIA03",
    "EBB_OPENR_INJECTED_START_IPV6S",
    "EBB_OPENR_INJECTED_START_IPV6S_IXIA03",
    "EBB_PARENT_NETWORKS",
    "EBB_PARENT_NETWORKS_IXIA03",
    "EBB_PEER_GROUPS",
    "EBB_PORT_MAP",
    "EBB_PORT_MAP_WITH_BGPMON",
    "EBB_PREFIX_SETS",
    "EBB_ROUTE_STORM_SHARD_PEER_COUNTS",
    "EBB_ROUTE_STORM_SHARD_ROUTE_COUNTS",
    "ebb_route_storm_shard_peer_counts",
    "ebb_route_storm_shard_route_counts",
    "ebb_topology",
    "EbbNextHopScheme",
    "EbbScaleProfile",
    "EBGP_V4_PEER_GROUP",
    "EBGP_V6_PEER_GROUP",
    "IBGP_V4_PEER_GROUP",
    "IBGP_V6_PEER_GROUP",
)
