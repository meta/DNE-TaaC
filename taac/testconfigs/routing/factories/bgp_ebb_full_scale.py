# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.
# pyre-unsafe
"""Factory for the EBB full-scale topology."""

import ipaddress
import json
import re
import typing as t
import uuid
from collections import Counter

from taac.abstractions.eos_bgpcpp_setup_tasks import (
    DEFAULT_OPENR_STANDALONE_INJECTION,
)
from taac.abstractions.physical_inventory import PhysicalInventory
from taac.abstractions.topologies.ebb_full_scale import (
    EBB_ACCEPT_POLICY,
    EBB_AS_NUMBERS,
    EBB_EBGP_V4_PREFIX_SET,
    EBB_EBGP_V6_PREFIX_SET,
    EBB_FIBAGENT_BGP_NHG_WATERMARK_HIGH,
    EBB_FIBAGENT_BGP_NHG_WATERMARK_LOW,
    EBB_FY26_SCALE,
    ebb_ibgp_route_next_hop_starts,
    EBB_IBGP_V4_PREFIX_SET,
    EBB_IBGP_V6_PREFIX_SET,
    EBB_NEXT_HOPS,
    EBB_PARENT_NETWORKS,
    EBB_PEER_GROUPS,
    ebb_port_map,
    ebb_topology,
    EbbNextHopScheme,
    EbbScaleProfile,
)
from taac.abstractions.topology import (
    BgpPeerGroup,
    BoundDeviceGroup,
    BoundTopology,
    DeviceGroupSpec,
    FormulaicPrefixSource,
    LogicalTopology,
    NextHopIntent,
    NextHopMode,
    OpenRMode,
    PeerPrefixDistribution,
    PeerRelationship,
    PrefixAdvertisement,
    PrefixAllocation,
    PrefixMembership,
    PrefixSet,
    RoutingDeviceConfig,
)
from taac.abstractions.validation import (
    resolve_validated_openr_injection_plan,
)
from taac.constants import (
    BgpPlusPlusProfile,
    TESTBED_ISOLATION_BYPASS_TAG,
)
from taac.playbooks.routing.bgp_ebb_playbooks import (
    get_bgp_ebb_attribute_churn_playbook,
    get_bgp_ebb_cold_start_playbook,
    get_bgp_ebb_daemon_restart_playbook,
    get_bgp_ebb_ebgp_route_oscillation_playbook,
    get_bgp_ebb_ebgp_session_oscillation_playbook,
    get_bgp_ebb_fauu_drain_undrain_playbook,
    get_bgp_ebb_ibgp_plane_session_oscillation_playbook,
    get_bgp_ebb_ibgp_route_oscillation_playbook,
    get_bgp_ebb_igp_pnh_metric_oscillation_playbook,
    get_bgp_ebb_igp_unresolvable_pnh_playbook,
    get_bgp_ebb_longevity_playbook,
    get_bgp_ebb_multipath_group_oscillation_playbook,
    get_bgp_ebb_nexthop_group_count_threshold_playbook,
    get_bgp_ebb_plane_drain_undrain_playbook,
    get_bgp_ebb_route_registry_runtime_update_playbook,
    get_bgp_ebb_route_storm_playbook,
)
from taac.playbooks.routing.factories.qual_bgp_update_group.tc7_cases.link_flap_recovery import (
    create_bgp_ug_link_flap_recovery_playbook,
)
from taac.playbooks.routing.factories.qual_bgp_update_group.tc7_cases.sustained_link_flap import (
    create_bgp_ug_sustained_link_flap_playbook,
)
from taac.steps.step_definitions import (
    create_bgp_ixia_session_recovery_step,
)
from taac.task_definitions import (
    create_configure_bgpcpp_startup_task,
)
from taac.testconfigs.routing.factories.bgp_ug_2_7_suite import (
    build_bgp_ug_2_7_playbook,
)
from taac.testconfigs.routing.util.bgp_ebb_check_profiles import (
    CharacterizationGates,
    NO_CHARACTERIZATION_GATES,
)
from taac.testconfigs.routing.util.bgp_ebb_constants import (
    DEFAULT_PROFILE,
    EBB_BGPCPP_LOGGING_CONFIG,
    EBGP_PEER_COUNT_V4,
    EBGP_PEER_COUNT_V6,
    IBGP_PEER_SCALE_PER_PLANE,
    PEERGROUP_EBGP_V4,
    PEERGROUP_EBGP_V6,
    PEERGROUP_IBGP_V4,
    PEERGROUP_IBGP_V6,
)
from taac.testconfigs.routing.util.bgp_ebb_health_checks import (
    BgpMonScope,
    create_standard_postchecks,
    create_standard_prechecks,
    create_standard_snapshot_checks,
)
from taac.testconfigs.routing.util.bgp_ebb_setup_tasks import (
    build_expected_peer_identity,
    insert_gateway_resolution_gate,
)
from taac.utils.characterization import (
    DISABLED,
    OBSERVE_ONLY_ON_DEVICE,
)
from taac.utils.hardware_capacity_utils import (
    get_precheck_thresholds,
)
from taac.test_as_a_config.types import (
    BasicPortConfig,
    Params,
    Playbook,
    PointInTimeHealthCheck,
    SnapshotHealthCheck,
    StepName,
    TestConfig,
)


_LONGEVITY_DURATION_SECONDS = 14400
_FULL_SCALE_FEC_PRECHECK_THRESHOLD = 15_000
_NEXTHOP_GROUP_AGGREGATE_GUARDRAIL = 8192
_NHG_STORM_PLAYBOOK_NAME = "bgp_ebb_nexthop_group_count_threshold_playbook"
# Five 30-prefix blocks per AFI per stage keep the restoration transient under
# the 104,856-entry Jericho2 FecLevel2 table; a one-shot restore overflowed it.
_NHG_STORM_RESTORATION_STAGE_PREFIX_COUNT = 150
# CICD-EBB-12 advertises this many FA prefixes past the scale's baseline.
_RUNTIME_UPDATE_EBGP_PREFIX_DELTA = 100
_TC7_STATIC_EBGP_PREFIX_COUNT = 650
_TC7_EXPECTED_SESSION_COUNT = 1272
_TC7_PLAYBOOK_NAMES = (
    "bgp_ug_link_flap_recovery",
    "update_group_sustained_link_flap",
    "bgp_ug_bgp_peer_flapping",
    "bgp_ug_bgp_daemon_restart",
    "bgp_ug_cold_start",
    "bgp_ug_fibagent_restart",
)
_TC7_LINK_FLAP_NAME = _TC7_PLAYBOOK_NAMES[0]
_TC7_SHARED_IBGP_RUNTIME_POOL_V4 = "PREFIX_POOL_IBGP_IPV4_UG_2_7_RUNTIME"
_TC7_SHARED_IBGP_RUNTIME_POOL_V6 = "PREFIX_POOL_IBGP_IPV6_UG_2_7_RUNTIME"
_TC7_SHARED_EBGP_RUNTIME_POOL_V4 = "PREFIX_POOL_IPV4_EBGP_UG_2_7_RUNTIME"
_TC7_SHARED_EBGP_RUNTIME_POOL_V6 = "PREFIX_POOL_IPV6_EBGP_UG_2_7_RUNTIME"
_RuntimeRouteSpec = tuple[str, str, str, str, str, int, int]
_UG_2_7_2_IBGP_POOLS = (
    rf"^{_TC7_SHARED_IBGP_RUNTIME_POOL_V4}$",
    rf"^{_TC7_SHARED_IBGP_RUNTIME_POOL_V6}$",
)
_UG_2_7_2_EBGP_POOLS = (
    rf"^{_TC7_SHARED_EBGP_RUNTIME_POOL_V4}$",
    rf"^{_TC7_SHARED_EBGP_RUNTIME_POOL_V6}$",
)
_FY26_DRAIN_PNH_REASON = (
    "its Open/R PNH readiness check is passed no range inventory, so it runs on "
    "the runtime's FY26 defaults rather than the resolved injection"
)
# Playbooks whose contract still pins FY26 geometry outside this factory. They
# build only at EBB_FY26_SCALE until that pin moves; selecting one at another
# scale fails with the reason rather than emitting FY26 numbers.
_FY26_ONLY_PLAYBOOKS: t.Mapping[str, str] = {
    "bgp_ebb_route_storm_playbook": (
        "RouteStorm requires exactly 10,500 storm paths, and RouteStormRuntime "
        "62 peers, 750 routes, rows 0-61 and 21/21/20 shards"
    ),
    "bgp_ebb_plane_drain_undrain_playbook": _FY26_DRAIN_PNH_REASON,
    "bgp_ebb_nexthop_group_count_threshold_playbook": (
        "its NHG storm and restoration staging are calibrated to the FY26 FEC baseline"
    ),
    **dict.fromkeys(
        _TC7_PLAYBOOK_NAMES,
        "the UG 2.7 runtime steps pin the FY26 two-port 1,272-session contract",
    ),
}


class _EbbAutomationContract(t.NamedTuple):
    """Runtime selectors derived from one bound full-scale topology."""

    non_monitor_established_session_count: int
    has_bgp_monitor: bool
    internal_peer_group_names_by_afi: t.Mapping[str, str]
    ebgp_peer_group_names_by_afi: t.Mapping[str, str]
    ebgp_peer_item_names_by_afi: t.Mapping[str, str]
    ebgp_peer_counts_by_afi: t.Mapping[str, int]
    ebgp_route_item_names_by_afi: t.Mapping[str, str]

    def exact_ebgp_peer_regex(self, afi: str) -> str:
        return rf"^{re.escape(self.ebgp_peer_item_names_by_afi[afi])}$"

    def exact_ebgp_route_regex(self) -> str:
        names = (
            self.ebgp_route_item_names_by_afi["ipv4"],
            self.ebgp_route_item_names_by_afi["ipv6"],
        )
        return rf"^(?:{'|'.join(re.escape(name) for name in names)})$"


def _is_bgp_monitor(group: BoundDeviceGroup | DeviceGroupSpec) -> bool:
    return group.peer_relationship is PeerRelationship.MONITOR


def _ebb_session_groups(bound: BoundTopology) -> tuple[BoundDeviceGroup, ...]:
    return tuple(
        group
        for group in bound.device_groups
        if not _is_bgp_monitor(group) and not group.dut_neighbor_absent
    )


def _bound_peer_group_name(group: BoundDeviceGroup) -> str:
    peer_group = group.peer_group
    name = peer_group.name if isinstance(peer_group, BgpPeerGroup) else peer_group
    if not isinstance(name, str) or not name:
        raise ValueError(f"BGP EBB group {group.name!r} has no bound peer-group name")
    return name


def _unique_peer_group_names_by_afi(
    groups: t.Iterable[BoundDeviceGroup],
    *,
    relationship: PeerRelationship,
) -> dict[str, str]:
    result: dict[str, str] = {}
    for topology_afi, automation_afi in (("v4", "ipv4"), ("v6", "ipv6")):
        names = {
            _bound_peer_group_name(group)
            for group in groups
            if group.peer_relationship is relationship and group.afi == topology_afi
        }
        if len(names) != 1:
            raise ValueError(
                "BGP EBB full-scale topology requires one unique "
                f"{relationship.value} {automation_afi} peer-group name; "
                f"got {sorted(names)}"
            )
        result[automation_afi] = names.pop()
    if len(set(result.values())) != len(result):
        raise ValueError(
            "BGP EBB full-scale topology requires distinct "
            f"{relationship.value} peer-group names by AFI; got {result}"
        )
    return result


def _ebb_automation_contract(bound: BoundTopology) -> _EbbAutomationContract:
    """Resolve every shared BGP/IXIA runtime handle from ``bound``."""
    groups = tuple(bound.device_groups)
    session_count = sum(group.peer_count for group in _ebb_session_groups(bound))
    if session_count <= 0:
        raise ValueError("BGP EBB full-scale topology has no non-monitor sessions")

    external_groups = tuple(
        group
        for group in groups
        if group.peer_relationship is PeerRelationship.EXTERNAL
    )
    external_by_afi: dict[str, BoundDeviceGroup] = {}
    for topology_afi, automation_afi in (("v4", "ipv4"), ("v6", "ipv6")):
        matches = tuple(group for group in external_groups if group.afi == topology_afi)
        if len(matches) != 1:
            raise ValueError(
                "BGP EBB full-scale topology requires exactly one external "
                f"{automation_afi} device group; got {[group.name for group in matches]}"
            )
        external_by_afi[automation_afi] = matches[0]

    peer_item_names: dict[str, str] = {}
    peer_counts: dict[str, int] = {}
    route_item_names: dict[str, str] = {}
    for afi, group in external_by_afi.items():
        if len(group.prefix_advertisements) != 1:
            raise ValueError(
                f"BGP EBB external {afi} group {group.name!r} must expose one "
                "route advertisement"
            )
        peer_item = group.legacy_ixia_bgp_peer_name or group.legacy_ixia_tag_name
        route_item = group.prefix_advertisements[0].spec.legacy_ixia_name
        if not peer_item or not route_item:
            raise ValueError(
                f"BGP EBB external {afi} group {group.name!r} is missing exact "
                "IXIA peer or route-item identity"
            )
        peer_item_names[afi] = peer_item
        peer_counts[afi] = group.peer_count
        route_item_names[afi] = route_item

    for label, names in (
        ("eBGP peer-item", peer_item_names),
        ("eBGP route-item", route_item_names),
    ):
        if len(set(names.values())) != len(names):
            raise ValueError(
                f"BGP EBB full-scale topology requires distinct {label} "
                f"names by AFI; got {names}"
            )

    return _EbbAutomationContract(
        non_monitor_established_session_count=session_count,
        has_bgp_monitor=any(_is_bgp_monitor(group) for group in groups),
        internal_peer_group_names_by_afi=_unique_peer_group_names_by_afi(
            groups,
            relationship=PeerRelationship.INTERNAL,
        ),
        ebgp_peer_group_names_by_afi=_unique_peer_group_names_by_afi(
            groups,
            relationship=PeerRelationship.EXTERNAL,
        ),
        ebgp_peer_item_names_by_afi=peer_item_names,
        ebgp_peer_counts_by_afi=peer_counts,
        ebgp_route_item_names_by_afi=route_item_names,
    )


def _attribute_prefix_sources(
    bound: BoundTopology,
) -> dict[str, dict[str, object]]:
    names = {
        "ipv4": EBB_IBGP_V4_PREFIX_SET.name,
        "ipv6": EBB_IBGP_V6_PREFIX_SET.name,
    }
    prefix_sets = {
        prefix_set.name: prefix_set for prefix_set in bound.logical_topology.prefix_sets
    }
    missing = sorted(set(names.values()) - prefix_sets.keys())
    if missing:
        raise ValueError(f"bound EBB topology is missing prefix sets: {missing}")
    return {
        afi: {
            "start_prefix": prefix_sets[name].source.start_prefix,
            "prefix_step": prefix_sets[name].source.prefix_step,
            "count": prefix_sets[name].source.count,
            "prefix_length": prefix_sets[name].source.prefix_length,
            "excluded_indices": list(prefix_sets[name].source.excluded_indices),
        }
        for afi, name in names.items()
    }


def _route_filter_prefix_sources(
    bound: BoundTopology,
    count: int,
) -> dict[str, dict[str, object]]:
    names = {
        "EB-FA-V4": EBB_EBGP_V4_PREFIX_SET.name,
        "EB-FA-V6": EBB_EBGP_V6_PREFIX_SET.name,
    }
    prefix_sets = {
        prefix_set.name: prefix_set for prefix_set in bound.logical_topology.prefix_sets
    }
    missing = sorted(set(names.values()) - prefix_sets.keys())
    if missing:
        raise ValueError(f"bound EBB topology is missing prefix sets: {missing}")
    sources: dict[str, dict[str, object]] = {}
    for statement, name in names.items():
        source = prefix_sets[name].source
        if count > source.count:
            raise ValueError(
                f"route-filter policy needs {count} prefixes from {name}, but the "
                f"bound source has {source.count}"
            )
        sources[statement] = {
            "start_prefix": source.start_prefix,
            "prefix_step": source.prefix_step,
            "count": count,
            "prefix_length": source.prefix_length,
            "parent_networks": [
                source.parent_network,
                *source.extension_parent_networks,
            ],
        }
    return sources


def _ebb_route_count_histogram_by_afi(
    bound: BoundTopology,
    prefix_count: int,
) -> dict[str, dict[int, int]]:
    """Derive the exact per-AFI peer route counts from topology activation."""
    result: dict[str, dict[int, int]] = {}
    groups = [group for group in bound.device_groups if group.role == "uplink"]
    for group in groups:
        if len(group.prefix_advertisements) != 1:
            raise ValueError(
                f"eBGP group {group.name!r} must expose one route advertisement"
            )
        advertisement = group.prefix_advertisements[0]
        if prefix_count > advertisement.spec.allocation.prefixes_per_peer:
            raise ValueError(
                f"eBGP route-count window {prefix_count} exceeds "
                f"{advertisement.spec.allocation.prefixes_per_peer} prefixes for "
                f"{group.name!r}"
            )
        activation = advertisement.spec.peer_prefix_activation
        exclusion_blocks = activation.exclusion_blocks if activation else ()
        invalid_peer_indices = sorted(
            {
                peer_index
                for block in exclusion_blocks
                for peer_index in block.peer_indices
                if peer_index < 0 or peer_index >= group.peer_count
            }
        )
        if invalid_peer_indices:
            raise ValueError(
                f"eBGP group {group.name!r} exclusion blocks reference peer "
                f"indices outside [0, {group.peer_count}): {invalid_peer_indices}"
            )
        peer_route_counts = []
        for peer_index in range(group.peer_count):
            clipped_exclusion_intervals = sorted(
                (
                    max(0, block.prefix_start_index),
                    min(
                        prefix_count,
                        block.prefix_start_index + block.prefix_count,
                    ),
                )
                for block in exclusion_blocks
                if peer_index in block.peer_indices
            )
            excluded_prefixes = 0
            covered_until = 0
            for block_start, block_end in clipped_exclusion_intervals:
                if block_end <= covered_until or block_start >= block_end:
                    continue
                excluded_prefixes += block_end - max(block_start, covered_until)
                covered_until = block_end
            peer_route_counts.append(prefix_count - excluded_prefixes)
        afi = "ipv4" if group.afi == "v4" else "ipv6"
        if afi in result:
            raise ValueError(f"duplicate eBGP uplink group for {afi}")
        result[afi] = dict(sorted(Counter(peer_route_counts).items()))
    if set(result) != {"ipv4", "ipv6"}:
        raise ValueError("expected exactly one IPv4 and one IPv6 eBGP uplink group")
    return result


def _ebb_peer_prefix_exclusion_blocks_by_pool(
    bound: BoundTopology,
) -> dict[str, list[dict[str, object]]]:
    """Serialize topology-authored sparse cells for deterministic IXIA replay."""
    result: dict[str, list[dict[str, object]]] = {}
    for group in (group for group in bound.device_groups if group.role == "uplink"):
        if len(group.prefix_advertisements) != 1:
            raise ValueError(
                f"eBGP group {group.name!r} must expose one route advertisement"
            )
        advertisement = group.prefix_advertisements[0]
        pool_name = advertisement.spec.legacy_ixia_name
        if not pool_name:
            raise ValueError(f"eBGP group {group.name!r} has no IXIA prefix-pool name")
        if pool_name in result:
            raise ValueError(f"duplicate eBGP IXIA prefix-pool name {pool_name!r}")
        activation = advertisement.spec.peer_prefix_activation
        result[pool_name] = [
            {
                "prefix_start_index": block.prefix_start_index,
                "prefix_count": block.prefix_count,
                "peer_indices": list(block.peer_indices),
            }
            for block in (activation.exclusion_blocks if activation else ())
        ]
    return result


def _validate_ebb12_automation_oracles(
    automation: _EbbAutomationContract,
    baseline_route_count_histogram_by_afi: t.Mapping[str, t.Mapping[int, int]],
    expanded_route_count_histogram_by_afi: t.Mapping[str, t.Mapping[int, int]],
    peer_prefix_exclusion_blocks_by_pool: t.Mapping[
        str, t.Sequence[t.Mapping[str, object]]
    ],
) -> None:
    """Keep EBB12's derived oracles keyed to the same bound automation view."""
    expected_route_afis = set(automation.ebgp_route_item_names_by_afi)
    for label, histogram in (
        ("baseline", baseline_route_count_histogram_by_afi),
        ("expanded", expanded_route_count_histogram_by_afi),
    ):
        if set(histogram) != expected_route_afis:
            raise ValueError(
                f"CICD-EBB-12 {label} route-count AFIs do not match the "
                f"bound automation contract: {sorted(histogram)} vs "
                f"{sorted(expected_route_afis)}"
            )
    expected_pool_names = set(automation.ebgp_route_item_names_by_afi.values())
    if set(peer_prefix_exclusion_blocks_by_pool) != expected_pool_names:
        raise ValueError(
            "CICD-EBB-12 exclusion-block pools do not match the bound "
            "automation contract"
        )


def _nhg_storm_ixia_items(
    bound: BoundTopology,
    automation: _EbbAutomationContract | None = None,
    *,
    target_prefix_count: int,
) -> dict[str, dict[str, t.Any]]:
    """Lower every topology-authored eBGP IXIA item into the C16 contract."""
    groups = [group for group in bound.device_groups if group.role == "uplink"]
    if {group.afi for group in groups} != {"v4", "v6"} or len(groups) != 2:
        raise ValueError(
            "CICD-EBB-16 requires exactly the topology's v4 and v6 uplink groups"
        )

    items: dict[str, dict[str, t.Any]] = {}
    for group in groups:
        if len(group.prefix_advertisements) != 1:
            raise ValueError(
                f"CICD-EBB-16 group {group.name!r} must expose one route item"
            )
        advertisement = group.prefix_advertisements[0]
        afi = "ipv4" if group.afi == "v4" else "ipv6"
        peer_item = (
            automation.ebgp_peer_item_names_by_afi[afi]
            if automation is not None
            else group.legacy_ixia_bgp_peer_name or group.legacy_ixia_tag_name
        )
        device_group_item = group.legacy_ixia_device_group_name
        route_item = (
            automation.ebgp_route_item_names_by_afi[afi]
            if automation is not None
            else advertisement.spec.legacy_ixia_name
        )
        missing = [
            label
            for label, value in (
                ("device-group", device_group_item),
                ("peer", peer_item),
                ("route", route_item),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                f"CICD-EBB-16 group {group.name!r} is missing topology-authored "
                f"IXIA items: {missing}"
            )
        route_counts = {len(paths) for paths in advertisement.paths_by_peer}
        if (
            len(advertisement.paths_by_peer) != group.peer_count
            or len(route_counts) != 1
        ):
            raise ValueError(
                f"CICD-EBB-16 group {group.name!r} has inconsistent peer/route rows"
            )
        routes_per_peer = route_counts.pop()
        if routes_per_peer < target_prefix_count:
            raise ValueError(
                f"CICD-EBB-16 group {group.name!r} exposes {routes_per_peer} "
                f"prefixes per peer; requires at least {target_prefix_count}"
            )
        items[afi] = {
            "logical_device_group": group.name,
            "logical_route_advertisement": advertisement.spec.name,
            "device_group_item": device_group_item,
            "peer_item": peer_item,
            "route_item": route_item,
            "expected_peer_count": (
                automation.ebgp_peer_counts_by_afi[afi]
                if automation is not None
                else group.peer_count
            ),
            "expected_routes_per_peer": routes_per_peer,
            "target_prefix_count": target_prefix_count,
        }
    return items


_UG_CHARACTERIZATION_GATES: t.Mapping[str, CharacterizationGates] = {
    "bgp_ebb_attribute_churn_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 5.0), (95, 60.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_route_storm_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 35.0), (95, 100.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_route_registry_runtime_update_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 30.0), (95, 60.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_multipath_group_oscillation_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 6.0), (95, 70.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_igp_pnh_metric_oscillation_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 30.0), (95, 100.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_fauu_drain_undrain_playbook": CharacterizationGates(
        rss_max_growth_pct=30.0
    ),
    "bgp_ebb_plane_drain_undrain_playbook": CharacterizationGates(
        rss_max_growth_pct=30.0
    ),
    "bgp_ebb_longevity_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 150.0), (95, 180.0)), rss_max_growth_pct=35.0
    ),
    # The UG baseline settles anywhere from ~1.26 to ~1.57 GiB while the end
    # state stays ~1.55-1.78 GiB, so a low baseline alone reads as 23-28%.
    "bgp_ebb_ebgp_session_oscillation_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 150.0), (95, 180.0)), rss_max_growth_pct=35.0
    ),
    "bgp_ebb_ebgp_route_oscillation_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 60.0), (95, 160.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_ibgp_plane_session_oscillation_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 10.0), (95, 20.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_ibgp_route_oscillation_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 90.0), (95, 160.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_igp_unresolvable_pnh_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 4.0), (95, 5.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_nexthop_group_count_threshold_playbook": CharacterizationGates(
        rss_max_growth_pct=20.0
    ),
}

_NON_UG_CHARACTERIZATION_GATES: t.Mapping[str, CharacterizationGates] = {
    "bgp_ebb_attribute_churn_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 140.0), (95, 150.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_route_registry_runtime_update_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 40.0), (95, 70.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_fauu_drain_undrain_playbook": CharacterizationGates(
        rss_max_growth_pct=10.0
    ),
    "bgp_ebb_ebgp_session_oscillation_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 150.0), (95, 200.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_ebgp_route_oscillation_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 140.0), (95, 190.0)), rss_max_growth_pct=10.0
    ),
    "bgp_ebb_igp_unresolvable_pnh_playbook": CharacterizationGates(
        cpu_thresholds_pct=((80, 7.0), (95, 140.0)), rss_max_growth_pct=10.0
    ),
}


class _Ug272PeerCohorts(t.NamedTuple):
    ibgp_v4: tuple[str, ...]
    ibgp_v6: tuple[str, ...]
    ebgp_v4: tuple[str, ...]
    ebgp_v6: tuple[str, ...]


class _Ug272PortTrack(t.TypedDict):
    role: str
    interface: str | None
    target_peer_subnets: list[str]


class _Ug272RouteLeg(t.TypedDict):
    source_prefix_pool_regexes: list[str]
    receiver_parent_prefixes: list[str]
    expected_receiver_count: int
    expected_route_delta: int


class _Ug272HeartbeatScenario(t.TypedDict, total=False):
    down_roles: list[str]
    verification_mode: str
    legs: list[_Ug272RouteLeg]
    structural_reason: str


def _prefix_at_index(prefix_set: PrefixSet, index: int) -> str:
    source = prefix_set.source
    if (
        isinstance(index, bool)
        or not isinstance(index, int)
        or not 0 <= index < source.count
    ):
        raise ValueError(
            f"Prefix index {index!r} is outside {prefix_set.name!r} inventory "
            f"[0, {source.count})"
        )
    return str(
        ipaddress.ip_address(source.start_prefix) + int(source.prefix_step) * index
    )


def _runtime_route_intent(
    *,
    pool_name: str,
    afi: str,
    start_prefix: str,
    parent_network: str,
    count: int,
    network_group_index: int,
) -> tuple[PrefixSet, PrefixAdvertisement]:
    intent_name = pool_name.lower()
    prefix_set = PrefixSet(
        name=intent_name,
        afi=afi,
        source=FormulaicPrefixSource(
            start_prefix=start_prefix,
            prefix_step=1 << (64 if afi == "v6" else 8),
            prefix_length=64 if afi == "v6" else 24,
            count=count,
            parent_network=parent_network,
        ),
    )
    advertisement = PrefixAdvertisement(
        name=f"{intent_name}_advertisement",
        prefix_set=prefix_set.name,
        allocation=PrefixAllocation(
            prefixes_per_peer=count,
            peer_distribution=PeerPrefixDistribution.SHARED,
            network_group_index=network_group_index,
        ),
        membership=PrefixMembership(
            start_index=0,
            prefix_count=count,
        ),
        next_hop=NextHopIntent(mode=NextHopMode.SELF),
        policy=EBB_ACCEPT_POLICY,
        attributes=(("med", None), ("local_pref", 100), ("origin", "igp")),
        legacy_ixia_name=pool_name,
    )
    return prefix_set, advertisement


def _shared_runtime_route_specs() -> tuple[_RuntimeRouteSpec, ...]:
    return (
        (
            "dg_ibgp_v4_dc_p1",
            _TC7_SHARED_IBGP_RUNTIME_POOL_V4,
            "v4",
            "11.200.0.0",
            "11.0.0.0/8",
            100,
            1,
        ),
        (
            "dg_ibgp_v6_dc_p1",
            _TC7_SHARED_IBGP_RUNTIME_POOL_V6,
            "v6",
            "2001:db8:0:c000::",
            "2001:db8::/48",
            100,
            1,
        ),
        (
            "dg_ebgp_v4",
            _TC7_SHARED_EBGP_RUNTIME_POOL_V4,
            "v4",
            _prefix_at_index(EBB_EBGP_V4_PREFIX_SET, _TC7_STATIC_EBGP_PREFIX_COUNT),
            EBB_EBGP_V4_PREFIX_SET.source.parent_network,
            100,
            1,
        ),
        (
            "dg_ebgp_v6",
            _TC7_SHARED_EBGP_RUNTIME_POOL_V6,
            "v6",
            _prefix_at_index(EBB_EBGP_V6_PREFIX_SET, _TC7_STATIC_EBGP_PREFIX_COUNT),
            EBB_EBGP_V6_PREFIX_SET.source.parent_network,
            100,
            1,
        ),
    )


def _tc7_runtime_intents(
    selected_playbooks: set[str],
) -> tuple[tuple[PrefixSet, ...], dict[str, tuple[PrefixAdvertisement, ...]]]:
    if not selected_playbooks:
        return (), {}
    prefix_sets = []
    advertisements: dict[str, list[PrefixAdvertisement]] = {}
    for (
        group_name,
        pool_name,
        afi,
        start,
        parent,
        count,
        index,
    ) in _shared_runtime_route_specs():
        prefix_set, advertisement = _runtime_route_intent(
            pool_name=pool_name,
            afi=afi,
            start_prefix=start,
            parent_network=parent,
            count=count,
            network_group_index=index,
        )
        prefix_sets.append(prefix_set)
        advertisements.setdefault(group_name, []).append(advertisement)
    return tuple(prefix_sets), {
        name: tuple(group_advertisements)
        for name, group_advertisements in advertisements.items()
    }


def _required_bound_group(bound: BoundTopology, name: str) -> BoundDeviceGroup:
    groups = [group for group in bound.device_groups if group.name == name]
    if len(groups) != 1:
        raise ValueError(
            f"EBB full-scale topology requires one {name!r} device group; "
            f"found {[group.name for group in groups]}"
        )
    return groups[0]


def _required_peer_addresses(
    groups: list[BoundDeviceGroup], expected_count: int
) -> list[str]:
    addresses = [address for group in groups for address in group.z_ips]
    if len(addresses) != expected_count or len(set(addresses)) != expected_count:
        raise ValueError(
            "EBB full-scale peer cohort cardinality mismatch: "
            f"expected {expected_count} unique peers, got {len(addresses)} total "
            f"and {len(set(addresses))} unique"
        )
    return addresses


def _tc7_group_contract() -> tuple[list[str], dict[str, int], dict[str, str]]:
    peer_groups = [
        PEERGROUP_EBGP_V4,
        PEERGROUP_EBGP_V6,
        PEERGROUP_IBGP_V4,
        PEERGROUP_IBGP_V6,
    ]
    member_counts = {
        PEERGROUP_EBGP_V4: EBGP_PEER_COUNT_V4,
        PEERGROUP_EBGP_V6: EBGP_PEER_COUNT_V6,
        PEERGROUP_IBGP_V4: IBGP_PEER_SCALE_PER_PLANE * 8,
        PEERGROUP_IBGP_V6: IBGP_PEER_SCALE_PER_PLANE * 8,
    }
    afis = {
        PEERGROUP_EBGP_V4: "ipv4",
        PEERGROUP_EBGP_V6: "ipv6",
        PEERGROUP_IBGP_V4: "ipv4",
        PEERGROUP_IBGP_V6: "ipv6",
    }
    return peer_groups, member_counts, afis


def _validate_tc7_bound_topology(bound: BoundTopology) -> None:
    _, expected_counts, _ = _tc7_group_contract()
    actual_counts: Counter[str] = Counter()
    graceful_restart_groups = []
    for group in bound.device_groups:
        peer_group = group.peer_group
        if not isinstance(peer_group, BgpPeerGroup):
            raise ValueError(f"TC7 group {group.name!r} has no resolved peer group")
        actual_counts[peer_group.name] += group.peer_count
        if peer_group.enable_graceful_restart:
            graceful_restart_groups.append(group.name)
    if len(bound.device_groups) != 18 or dict(actual_counts) != expected_counts:
        raise ValueError(
            "TC7 requires the exact two-interface 18-DG/1272-session EBB topology; "
            f"got {len(bound.device_groups)} DGs and {dict(actual_counts)}"
        )
    if graceful_restart_groups:
        raise ValueError(
            "TC7 requires graceful restart disabled on every peer group; "
            f"enabled on {graceful_restart_groups}"
        )
    device_config = bound.device_config
    if device_config is None or not device_config.update_group_enable:
        raise ValueError("TC7 requires Update Group enabled in resolved intent")
    if device_config.openr_mode is not OpenRMode.STANDALONE:
        raise ValueError("TC7 requires standalone OpenR in resolved intent")


def _tc7_health_checks() -> tuple[
    list[PointInTimeHealthCheck],
    list[PointInTimeHealthCheck],
    list[SnapshotHealthCheck],
]:
    prechecks = create_standard_prechecks(
        peergroup_ibgp_v6=PEERGROUP_IBGP_V6,
        peergroup_ibgp_v4=PEERGROUP_IBGP_V4,
        expected_established_sessions=_TC7_EXPECTED_SESSION_COUNT,
        cpu_baseline=12.0,
        check_ibgp_pnh=True,
        check_hardware_capacity=False,
        bgp_mon=BgpMonScope(exclude=True),
    )
    postchecks = create_standard_postchecks(
        expected_established_session_count=_TC7_EXPECTED_SESSION_COUNT,
        bgp_mon=BgpMonScope(exclude=True),
    )
    return (
        prechecks,
        postchecks,
        create_standard_snapshot_checks(
            skip_flap_check=True,
            skip_uptime_check=True,
            bgp_mon=BgpMonScope(exclude=True),
        ),
    )


def _bound_groups(
    bound: BoundTopology, names: t.Iterable[str]
) -> list[BoundDeviceGroup]:
    return [_required_bound_group(bound, name) for name in names]


def _ibgp_group_names(afi: str) -> list[str]:
    return [
        f"dg_ibgp_{afi}_{fabric}_p{plane}"
        for fabric in ("dc", "mp")
        for plane in range(1, 5)
    ]


def _host_prefixes(addresses: t.Iterable[str]) -> list[str]:
    return [f"{address}/{'128' if ':' in address else '32'}" for address in addresses]


def _ug_2_7_2_peer_cohorts(bound: BoundTopology) -> _Ug272PeerCohorts:
    def peers(group_names: list[str], expected_count: int) -> tuple[str, ...]:
        return tuple(
            sorted(
                _required_peer_addresses(
                    _bound_groups(bound, group_names), expected_count
                )
            )
        )

    return _Ug272PeerCohorts(
        ibgp_v4=peers(_ibgp_group_names("v4"), 496),
        ibgp_v6=peers(_ibgp_group_names("v6"), 496),
        ebgp_v4=peers(["dg_ebgp_v4"], 140),
        ebgp_v6=peers(["dg_ebgp_v6"], 140),
    )


def _ug_2_7_2_port_tracks(
    bound: BoundTopology, peers: _Ug272PeerCohorts
) -> list[_Ug272PortTrack]:
    tracks: list[_Ug272PortTrack] = [
        {
            "role": "ebgp",
            "interface": _required_bound_group(bound, "dg_ebgp_v6").a_interface,
            "target_peer_subnets": _host_prefixes([*peers.ebgp_v4, *peers.ebgp_v6]),
        },
        {
            "role": "ibgp",
            "interface": _required_bound_group(bound, "dg_ibgp_v6_dc_p1").a_interface,
            "target_peer_subnets": _host_prefixes([*peers.ibgp_v4, *peers.ibgp_v6]),
        },
    ]
    if any(not track["interface"] for track in tracks):
        raise ValueError("2.7.2 requires both resolved BAG012 interfaces")
    return tracks


def _ug_2_7_2_route_leg(
    source_pools: t.Sequence[str],
    receivers: t.Iterable[str],
    receiver_count: int,
    route_delta: int,
) -> _Ug272RouteLeg:
    return {
        "source_prefix_pool_regexes": list(source_pools),
        "receiver_parent_prefixes": _host_prefixes(receivers),
        "expected_receiver_count": receiver_count,
        "expected_route_delta": route_delta,
    }


def _ug_2_7_2_route_scenarios(
    peers: _Ug272PeerCohorts,
) -> list[_Ug272HeartbeatScenario]:
    return [
        {
            "down_roles": [],
            "verification_mode": "route",
            "legs": [
                _ug_2_7_2_route_leg(
                    [_UG_2_7_2_EBGP_POOLS[0]],
                    peers.ibgp_v4,
                    496,
                    1,
                ),
                _ug_2_7_2_route_leg(
                    [_UG_2_7_2_EBGP_POOLS[1]],
                    peers.ibgp_v6,
                    496,
                    1,
                ),
                _ug_2_7_2_route_leg(
                    [_UG_2_7_2_IBGP_POOLS[0]],
                    peers.ebgp_v4,
                    140,
                    1,
                ),
                _ug_2_7_2_route_leg(
                    [_UG_2_7_2_IBGP_POOLS[1]],
                    peers.ebgp_v6,
                    140,
                    1,
                ),
            ],
        },
    ]


def _ug_2_7_2_structural_scenario(
    down_roles: list[str], reason: str
) -> _Ug272HeartbeatScenario:
    return {
        "down_roles": down_roles,
        "verification_mode": "structural",
        "structural_reason": reason,
    }


def _ug_2_7_2_heartbeat_scenarios(
    peers: _Ug272PeerCohorts,
) -> list[_Ug272HeartbeatScenario]:
    structural = _ug_2_7_2_structural_scenario
    return [
        *_ug_2_7_2_route_scenarios(peers),
        structural(
            ["ebgp"],
            "only-iBGP-active:iBGP-split-horizon-has-no-independent-pair",
        ),
        structural(
            ["ibgp"],
            "only-eBGP-active:same-AS-loop-prevention-has-no-independent-pair",
        ),
        structural(
            ["ebgp", "ibgp"],
            "all-links-down:no-active-source-or-receiver",
        ),
    ]


def _ug_2_7_2_playbook(
    physical_inventory: PhysicalInventory,
    bound: BoundTopology,
) -> Playbook:
    peers = _ug_2_7_2_peer_cohorts(bound)
    port_tracks = _ug_2_7_2_port_tracks(bound, peers)
    heartbeats = _ug_2_7_2_heartbeat_scenarios(peers)
    peer_groups, member_counts, afis = _tc7_group_contract()
    prechecks, postchecks, snapshot_checks = _tc7_health_checks()
    return create_bgp_ug_sustained_link_flap_playbook(
        device_name=physical_inventory.device_name,
        port_tracks=port_tracks,
        heartbeat_scenarios=heartbeats,
        state_key=str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{physical_inventory.device_name}:update_group_sustained_link_flap",
            )
        ),
        peer_group_substrings=peer_groups,
        expected_member_counts=member_counts,
        expected_afi_by_substring=afis,
        prechecks=prechecks,
        postchecks=postchecks,
        snapshot_checks=snapshot_checks,
    )


def _ug_2_7_1_playbook(
    physical_inventory: PhysicalInventory,
    bound: BoundTopology,
) -> Playbook:
    ebgp_v6_peers = _required_peer_addresses(
        [_required_bound_group(bound, "dg_ebgp_v6")],
        EBGP_PEER_COUNT_V6,
    )
    ebgp_v4_peers = _required_peer_addresses(
        [_required_bound_group(bound, "dg_ebgp_v4")],
        EBGP_PEER_COUNT_V4,
    )
    ebgp_interface = _required_bound_group(bound, "dg_ebgp_v6").a_interface
    if ebgp_interface is None:
        raise ValueError("2.7.1 requires a resolved eBGP DUT interface")
    peer_groups, member_counts, afis = _tc7_group_contract()
    prechecks, postchecks, snapshot_checks = _tc7_health_checks()
    return create_bgp_ug_link_flap_recovery_playbook(
        device_name=physical_inventory.device_name,
        interface=ebgp_interface,
        target_peer_subnets=[
            *(f"{address}/32" for address in ebgp_v4_peers),
            *(f"{address}/128" for address in ebgp_v6_peers),
        ],
        route_pool_regexes=[rf"{_TC7_SHARED_IBGP_RUNTIME_POOL_V6}$"],
        recovered_ebgp_peer_addrs=ebgp_v6_peers,
        state_key=str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{physical_inventory.device_name}:{_TC7_LINK_FLAP_NAME}",
            )
        ),
        peer_group_substrings=peer_groups,
        expected_member_counts=member_counts,
        expected_afi_by_substring=afis,
        prechecks=prechecks,
        postchecks=postchecks,
        snapshot_checks=snapshot_checks,
    )


def _openr_owner_kv_link(physical_inventory: PhysicalInventory) -> dict:
    link = physical_inventory.openr_standalone_link
    if link is None:
        raise ValueError("OpenR playbook requires a standalone link")
    return link.kv_link(link.owner)


def _openr_helper_kv_link(physical_inventory: PhysicalInventory) -> dict:
    link = physical_inventory.openr_standalone_link
    if link is None:
        raise ValueError("OpenR playbook requires a standalone link")
    return link.kv_link(link.helper)


def _ebb_ibgp_capture_interfaces(bound: BoundTopology) -> tuple[str, ...]:
    """Return every bound internal link's physical capture interface in port order."""
    interfaces_by_port: dict[int, str] = {}
    for group in bound.device_groups:
        if group.peer_relationship is not PeerRelationship.INTERNAL:
            continue
        assignment = group.port_assignment
        if assignment is None or not assignment.dut_interface.strip():
            raise ValueError(
                f"bound iBGP link {group.name!r} has no physical capture interface"
            )
        port_index = bound.port_map.get(assignment.logical_role)
        if port_index is None or port_index != assignment.physical_inventory_index:
            raise ValueError(f"bound iBGP link {group.name!r} contradicts its port map")
        interface = assignment.dut_interface
        previous = interfaces_by_port.setdefault(port_index, interface)
        if previous != interface:
            raise ValueError(
                f"bound iBGP port {port_index} has contradictory capture interfaces"
            )
    interfaces = tuple(
        interfaces_by_port[index] for index in sorted(interfaces_by_port)
    )
    if not interfaces:
        raise ValueError("bound topology has no iBGP capture interfaces")
    if len(set(interfaces)) != len(interfaces):
        raise ValueError("distinct bound iBGP links have duplicate capture interfaces")
    return interfaces


def _ebb_fauu_capture_kwargs(
    bound: BoundTopology, scale: EbbScaleProfile
) -> dict[str, t.Any]:
    interfaces = _ebb_ibgp_capture_interfaces(bound)
    if scale != EBB_FY26_SCALE:
        return {"tcp_dump_capture_interfaces_ibgp": interfaces}
    if len(interfaces) != 1:
        raise ValueError("FY26 FAUU capture requires exactly one bound iBGP link")
    return {"tcp_dump_capture_interface_ibgp": interfaces[0]}


def _observe_only_cpu_rss_periodic_tasks(playbook: Playbook) -> Playbook:
    periodic_tasks = []
    for periodic_task in playbook.periodic_tasks or []:
        task = periodic_task.task
        if task is None or task.task_name != "counter_utilization":
            periodic_tasks.append(periodic_task)
            continue
        params = json.loads(task.params.json_params or "{}")
        if params.get("key") not in {
            "bgpd.process.cpu.percent",
            "bgpd.process.memory.rss.bytes",
        }:
            periodic_tasks.append(periodic_task)
            continue
        params["observe_only"] = True
        periodic_tasks.append(
            periodic_task(task=task(params=Params(json_params=json.dumps(params))))
        )
    return playbook(periodic_tasks=periodic_tasks)


def _characterization_gates(
    playbook_name: str,
    enable_update_group: bool,
    scale: EbbScaleProfile,
) -> CharacterizationGates:
    if scale != EBB_FY26_SCALE:
        return NO_CHARACTERIZATION_GATES
    gates_by_playbook = (
        _UG_CHARACTERIZATION_GATES
        if enable_update_group
        else _NON_UG_CHARACTERIZATION_GATES
    )
    return gates_by_playbook.get(playbook_name, NO_CHARACTERIZATION_GATES)


def _get_bgp_ebb_full_scale_playbooks(  # noqa: C901
    physical_inventory: PhysicalInventory,
    profile: BgpPlusPlusProfile,
    *,
    bound: BoundTopology,
    ebgp_prefix_count: int,
    selected_tc7_playbooks: set[str],
    playbooks_selected: t.Sequence[str] | None = None,
    scale: EbbScaleProfile = EBB_FY26_SCALE,
    port_map: t.Mapping[str, int] | None = None,
    enable_update_group: bool = True,
    multipath_test_duration_seconds: int = 1800,
    multipath_oscillation_interval_seconds: int = 280,
    multipath_cycle_count: int | None = None,
    multipath_min_peers_to_stop: int = 1,
    multipath_max_peers_to_stop: int = 11,
    route_storm_cycles: int = 60,
    route_storm_quiet_window_seconds: int = 120,
    route_storm_bounded_validation: bool = False,
    nhg_storm_epoch_count: int = 48,
    nhg_storm_epoch_interval_seconds: int = 25,
    nhg_storm_soak_seconds: int = 300,
    nhg_storm_poll_interval_seconds: int = 60,
    nhg_storm_min_eos_samples: int = 6,
    nhg_storm_min_eos_consecutive_samples: int = 3,
    nhg_storm_target_membership_width: int | None = 25,
    nhg_storm_min_observed_bgp_multiway_memberships: int = (
        EBB_FIBAGENT_BGP_NHG_WATERMARK_HIGH + 1
    ),
    nhg_storm_min_paused_fibagent_samples: int = 1,
    nhg_storm_min_confirmed_pause_fap_samples: int = 3,
    nhg_storm_control_plane_sample_interval_seconds: int = 5,
    nhg_storm_control_plane_read_timeout_seconds: int = 180,
    gateway_device_group_names: t.Sequence[str] = (),
) -> list[Playbook]:
    device_config = bound.device_config
    if device_config is None:
        raise ValueError("CICD-EBB-16 requires a bound routing device config")
    fibagent_bgp_nhg_watermark_high = device_config.fibagent_bgp_nhg_watermark_high
    fibagent_bgp_nhg_watermark_low = device_config.fibagent_bgp_nhg_watermark_low
    if (
        fibagent_bgp_nhg_watermark_high is None
        or fibagent_bgp_nhg_watermark_low is None
    ):
        raise ValueError("CICD-EBB-16 requires finite FibAgentBgp NHG watermarks")
    if selected_tc7_playbooks:
        playbooks = []
        if _TC7_LINK_FLAP_NAME in selected_tc7_playbooks:
            playbooks.append(_ug_2_7_1_playbook(physical_inventory, bound))
        if "bgp_ug_bgp_daemon_restart" in selected_tc7_playbooks:
            playbooks.append(
                build_bgp_ug_2_7_playbook(
                    "bgp_ug_bgp_daemon_restart", physical_inventory, bound
                )
            )
        if "bgp_ug_fibagent_restart" in selected_tc7_playbooks:
            playbooks.append(
                build_bgp_ug_2_7_playbook(
                    "bgp_ug_fibagent_restart", physical_inventory, bound
                )
            )
        if "update_group_sustained_link_flap" in selected_tc7_playbooks:
            playbooks.append(_ug_2_7_2_playbook(physical_inventory, bound))
        if "bgp_ug_bgp_peer_flapping" in selected_tc7_playbooks:
            playbooks.append(
                build_bgp_ug_2_7_playbook(
                    "bgp_ug_bgp_peer_flapping", physical_inventory, bound
                )
            )
        if "bgp_ug_cold_start" in selected_tc7_playbooks:
            playbooks.append(
                build_bgp_ug_2_7_playbook(
                    "bgp_ug_cold_start", physical_inventory, bound
                )
            )
        return playbooks

    device_name = physical_inventory.device_name
    required_port_map = ebb_port_map(scale, include_bgpmon=False)
    resolved_port_map = required_port_map if port_map is None else port_map
    missing_port_roles = sorted(required_port_map.keys() - resolved_port_map.keys())
    if missing_port_roles:
        raise ValueError(
            "BGP EBB full-scale port_map is missing required roles: "
            f"{missing_port_roles}"
        )
    port_count = len(physical_inventory.ixia_ports)
    invalid_port_roles = {
        role: port_index
        for role, port_index in resolved_port_map.items()
        if not 0 <= port_index < port_count
    }
    if invalid_port_roles:
        raise ValueError(
            "BGP EBB full-scale port_map has out-of-range indices for "
            f"{port_count} IXIA ports: {invalid_port_roles}"
        )
    ixia_interface_mimic_ebgp = physical_inventory.ixia_ports[
        resolved_port_map["uplink"]
    ][0]
    ixia_interface_mimic_ibgp = physical_inventory.ixia_ports[
        resolved_port_map["ibgp"]
    ][0]
    automation = _ebb_automation_contract(bound)
    session_count = automation.non_monitor_established_session_count
    peergroup_ibgp_v4 = automation.internal_peer_group_names_by_afi["ipv4"]
    peergroup_ibgp_v6 = automation.internal_peer_group_names_by_afi["ipv6"]
    # Derive from the bound topology rather than the module constants, so the
    # checks describe the chassis the run is actually wired to. A config using
    # for_secondary_ixia() peers on the secondary chassis' subnets, and the
    # ixia11 defaults would mark every one of those sessions unexpected.
    bound_parent_networks = dict(bound.parent_networks)
    try:
        bound_bgp_mon_network = bound_parent_networks["bgpmon_v6"]
    except KeyError as error:
        raise ValueError(
            "BGP EBB full-scale topology is missing required bgpmon_v6 network"
        ) from error
    bgp_mon_parent_prefix = f"{bound_bgp_mon_network}::/80"
    expected_peer_identity = build_expected_peer_identity(
        bound_parent_networks,
        ibgp_peers_per_plane=scale.ibgp_peers_per_group,
        include_bgp_mon=automation.has_bgp_monitor,
    )
    # One resolved plan feeds setup, the health checks, the churn steps, and
    # teardown. Reading it back from the bound topology -- rather than from a
    # chassis constant -- is what keeps the PNH inventory the checks assert
    # identical to the reachability the compiler actually injects. A topology
    # that declares no injection, or is not in standalone Open/R mode (every
    # non-Open/R profile), keeps passing None so the playbooks stay on their
    # own defaults, and the count/step come from the renderer's single
    # compatibility default rather than from numbers restated here. Only
    # standalone Open/R resolves the plan, exactly as the compiler does.
    openr_injection = (
        resolve_validated_openr_injection_plan(bound)
        if device_config.openr_mode is OpenRMode.STANDALONE
        else None
    )
    compatibility_injection = openr_injection or DEFAULT_OPENR_STANDALONE_INJECTION
    # Readiness describes the injection setup renders. Standalone Open/R
    # renders the compatibility default when no plan resolves, so readiness
    # checks that rather than falling back to the runtime's own defaults.
    rendered_injection = openr_injection
    if rendered_injection is None and device_config.openr_mode is OpenRMode.STANDALONE:
        rendered_injection = DEFAULT_OPENR_STANDALONE_INJECTION
    ibgp_pnh_start_ipv4s = (
        tuple(rendered_injection.start_ipv4s)
        if rendered_injection is not None
        else None
    )
    ibgp_pnh_start_ipv6s = (
        tuple(rendered_injection.start_ipv6s)
        if rendered_injection is not None
        else None
    )
    openr_route_count = compatibility_injection.count
    openr_route_step = compatibility_injection.step
    openr_pnh_count = (
        rendered_injection.count if rendered_injection is not None else None
    )
    openr_pnh_step = rendered_injection.step if rendered_injection is not None else None
    local_link = _openr_owner_kv_link(physical_inventory)
    other_link = _openr_helper_kv_link(physical_inventory)
    # The canonical 50-NHG topology consumes about 12.4K FEC entries before
    # stimulus, so keep regression headroom without relaxing unrelated suites.
    full_scale_precheck_thresholds = get_precheck_thresholds()
    full_scale_precheck_thresholds.fec_threshold = _FULL_SCALE_FEC_PRECHECK_THRESHOLD
    baseline_route_count_histogram_by_afi = _ebb_route_count_histogram_by_afi(
        bound, scale.fa_routes_per_peer
    )
    full_route_count_histogram_by_afi = _ebb_route_count_histogram_by_afi(
        bound, ebgp_prefix_count
    )
    peer_prefix_exclusion_blocks_by_pool = _ebb_peer_prefix_exclusion_blocks_by_pool(
        bound
    )
    _validate_ebb12_automation_oracles(
        automation,
        baseline_route_count_histogram_by_afi,
        full_route_count_histogram_by_afi,
        peer_prefix_exclusion_blocks_by_pool,
    )
    exact_ebgp_route_pool_names = (
        automation.ebgp_route_item_names_by_afi["ipv4"],
        automation.ebgp_route_item_names_by_afi["ipv6"],
    )
    exact_ebgp_peer_group_names = (
        automation.ebgp_peer_group_names_by_afi["ipv6"],
        automation.ebgp_peer_group_names_by_afi["ipv4"],
    )
    # Built lazily so a playbook pinned to FY26 geometry is never constructed
    # with another scale's numbers.
    builders: dict[str, t.Callable[[], Playbook]] = {
        "bgp_ebb_attribute_churn_playbook": lambda: get_bgp_ebb_attribute_churn_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            total_session_count=session_count,
            profile=profile,
            ibgp_route_next_hop_starts=ebb_ibgp_route_next_hop_starts(bound),
            precheck_thresholds=full_scale_precheck_thresholds,
            bgp_mon_parent_network=bound_bgp_mon_network,
            ibgp_pnh_start_ipv4s=ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            scale=scale,
            ibgp_prefix_sources=(
                None if scale == EBB_FY26_SCALE else _attribute_prefix_sources(bound)
            ),
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_attribute_churn_playbook", enable_update_group, scale
            ),
        ),
        "bgp_ebb_route_storm_playbook": lambda: get_bgp_ebb_route_storm_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            total_session_count=session_count,
            ixia_interface_mimic_ibgp=ixia_interface_mimic_ibgp,
            observer_peer_parent_prefix=bgp_mon_parent_prefix,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            bgp_mon_parent_network=bound_bgp_mon_network,
            ibgp_pnh_start_ipv4s=ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            cycles=route_storm_cycles,
            quiet_window_seconds=route_storm_quiet_window_seconds,
            bounded_validation=route_storm_bounded_validation,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_route_storm_playbook", enable_update_group, scale
            ),
        ),
        "bgp_ebb_route_registry_runtime_update_playbook": lambda: get_bgp_ebb_route_registry_runtime_update_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            expected_established_sessions=session_count,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            prefix_pool_regex=automation.exact_ebgp_route_regex(),
            expected_prefix_pool_names=exact_ebgp_route_pool_names,
            exact_ebgp_peer_group_names=exact_ebgp_peer_group_names,
            expected_route_count=scale.fa_routes_per_peer,
            runtime_prefix_start_index=scale.fa_routes_per_peer,
            runtime_prefix_end_index=(
                scale.fa_routes_per_peer + _RUNTIME_UPDATE_EBGP_PREFIX_DELTA
            ),
            baseline_policy_prefix_sources=(
                None
                if scale == EBB_FY26_SCALE
                else _route_filter_prefix_sources(bound, scale.fa_routes_per_peer)
            ),
            expanded_policy_prefix_sources=(
                None
                if scale == EBB_FY26_SCALE
                else _route_filter_prefix_sources(
                    bound,
                    scale.fa_routes_per_peer + _RUNTIME_UPDATE_EBGP_PREFIX_DELTA,
                )
            ),
            expected_route_count_histogram_by_afi=(
                baseline_route_count_histogram_by_afi
            ),
            expanded_route_count_histogram_by_afi=(full_route_count_histogram_by_afi),
            peer_prefix_exclusion_blocks_by_pool=(peer_prefix_exclusion_blocks_by_pool),
            bgp_mon_parent_network=bound_bgp_mon_network,
            ibgp_pnh_start_ipv4s=ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_route_registry_runtime_update_playbook",
                enable_update_group,
                scale,
            ),
        ),
        "bgp_ebb_multipath_group_oscillation_playbook": lambda: get_bgp_ebb_multipath_group_oscillation_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            expected_established_sessions=session_count,
            ipv4_peer_regex=automation.exact_ebgp_peer_regex("ipv4"),
            ipv6_peer_regex=automation.exact_ebgp_peer_regex("ipv6"),
            ipv4_session_count=automation.ebgp_peer_counts_by_afi["ipv4"],
            ipv6_session_count=automation.ebgp_peer_counts_by_afi["ipv6"],
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            exclude_bgp_mon=automation.has_bgp_monitor,
            bgp_mon_parent_network=(
                bound_bgp_mon_network if automation.has_bgp_monitor else None
            ),
            ibgp_pnh_start_ipv4s=ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            test_duration_seconds=multipath_test_duration_seconds,
            oscillation_interval_seconds=multipath_oscillation_interval_seconds,
            cycle_count=multipath_cycle_count,
            min_peers_to_stop=multipath_min_peers_to_stop,
            max_peers_to_stop=multipath_max_peers_to_stop,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_multipath_group_oscillation_playbook",
                enable_update_group,
                scale,
            ),
        ),
        "bgp_ebb_igp_pnh_metric_oscillation_playbook": lambda: get_bgp_ebb_igp_pnh_metric_oscillation_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            local_link=local_link,
            other_link=other_link,
            expected_established_sessions=session_count,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            expected_peer_identity=expected_peer_identity,
            bgp_mon_parent_network=bound_bgp_mon_network,
            start_ipv4s=(
                list(ibgp_pnh_start_ipv4s) if ibgp_pnh_start_ipv4s is not None else None
            ),
            start_ipv6s=(
                list(ibgp_pnh_start_ipv6s) if ibgp_pnh_start_ipv6s is not None else None
            ),
            count=openr_route_count,
            step_size=openr_route_step,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_igp_pnh_metric_oscillation_playbook",
                enable_update_group,
                scale,
            ),
        ),
        "bgp_ebb_fauu_drain_undrain_playbook": lambda: get_bgp_ebb_fauu_drain_undrain_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            expected_established_sessions=session_count,
            expected_peer_identity=expected_peer_identity,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            tcp_dump_capture_interface_ebgp=ixia_interface_mimic_ebgp,
            **_ebb_fauu_capture_kwargs(bound, scale),
            # FY26's frozen readiness payload omits the optional range fields.
            ibgp_pnh_start_ipv4s=None
            if scale == EBB_FY26_SCALE
            else ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=None
            if scale == EBB_FY26_SCALE
            else ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=None if scale == EBB_FY26_SCALE else openr_pnh_count,
            ibgp_pnh_step=None if scale == EBB_FY26_SCALE else openr_pnh_step,
            require_stable_restoration_baseline=scale != EBB_FY26_SCALE,
            bgp_mon_parent_network=bound_bgp_mon_network,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_fauu_drain_undrain_playbook", enable_update_group, scale
            ),
        ),
        "bgp_ebb_plane_drain_undrain_playbook": lambda: get_bgp_ebb_plane_drain_undrain_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            expected_established_sessions=session_count,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            tcp_dump_capture_interface_ebgp=ixia_interface_mimic_ebgp,
            tcp_dump_capture_interface_ibgp=ixia_interface_mimic_ibgp,
            bgp_mon_parent_network=bound_bgp_mon_network,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_plane_drain_undrain_playbook", enable_update_group, scale
            ),
        ),
        "bgp_ebb_longevity_playbook": lambda: get_bgp_ebb_longevity_playbook(
            device_name=device_name,
            duration=_LONGEVITY_DURATION_SECONDS,
            bgp_mon_parent_network=bound_bgp_mon_network,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_longevity_playbook", enable_update_group, scale
            ),
        ),
        "bgp_ebb_daemon_restart_playbook": lambda: get_bgp_ebb_daemon_restart_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            expected_established_sessions=session_count,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            expected_peer_identity=expected_peer_identity,
            bgp_mon_parent_network=bound_bgp_mon_network,
            ibgp_pnh_start_ipv4s=ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            reactivate_device_groups=scale.restart_reactivate_device_groups,
            cycle_device_groups_before_restart=scale.restart_cycle_device_groups,
            # Deliberately unmeasured. Restarting bgpcpp replaces the PID
            # mid-bracket, and both collectors resolve the PID once at START:
            # CPU then reads a dead /proc entry and silently drops every
            # sample, and RSS fails outright because `restarted` invalidates a
            # steady-state comparison by construction. Beyond the mechanism,
            # the numbers would not be worth having: this is a lifecycle
            # recovery test, not a sustained-load test, so a CPU percentile or
            # an RSS delta measured across a process boundary describes two
            # different processes rather than one workload.
            characterization=DISABLED,
        ),
        "bgp_ebb_cold_start_playbook": lambda: get_bgp_ebb_cold_start_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            expected_established_sessions=session_count,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            expected_peer_identity=expected_peer_identity,
            bgp_mon_parent_network=bound_bgp_mon_network,
            ibgp_pnh_start_ipv4s=ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            gateway_resolution_device_group_names=gateway_device_group_names,
        ),
        "bgp_ebb_ebgp_session_oscillation_playbook": lambda: get_bgp_ebb_ebgp_session_oscillation_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            ipv4_session_count=automation.ebgp_peer_counts_by_afi["ipv4"],
            ipv6_session_count=automation.ebgp_peer_counts_by_afi["ipv6"],
            expected_established_sessions=session_count,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            expected_peer_identity=expected_peer_identity,
            bgp_mon_parent_network=bound_bgp_mon_network,
            ibgp_pnh_start_ipv4s=ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_ebgp_session_oscillation_playbook", enable_update_group, scale
            ),
        ),
        "bgp_ebb_ebgp_route_oscillation_playbook": lambda: get_bgp_ebb_ebgp_route_oscillation_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            expected_established_sessions=session_count,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            prefix_pool_regex=automation.exact_ebgp_route_regex(),
            expected_prefix_pool_names=(
                automation.ebgp_route_item_names_by_afi["ipv4"],
                automation.ebgp_route_item_names_by_afi["ipv6"],
            ),
            prefix_pool_names_by_afi=automation.ebgp_route_item_names_by_afi,
            prefix_end_index=scale.fa_routes_per_peer,
            advertise_transition_soft_threshold_seconds=(
                scale.route_oscillation_advertise_threshold_seconds
            ),
            bgp_mon_parent_network=bound_bgp_mon_network,
            ibgp_pnh_start_ipv4s=ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_ebgp_route_oscillation_playbook", enable_update_group, scale
            ),
        ),
        "bgp_ebb_ibgp_plane_session_oscillation_playbook": lambda: get_bgp_ebb_ibgp_plane_session_oscillation_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            ipv4_sessions_per_plane=scale.ibgp_peers_per_group,
            ipv6_sessions_per_plane=scale.ibgp_peers_per_group,
            expected_established_sessions=session_count,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            expected_peer_identity=expected_peer_identity,
            bgp_mon_parent_network=bound_bgp_mon_network,
            ibgp_pnh_start_ipv4s=ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_ibgp_plane_session_oscillation_playbook",
                enable_update_group,
                scale,
            ),
        ),
        "bgp_ebb_ibgp_route_oscillation_playbook": lambda: get_bgp_ebb_ibgp_route_oscillation_playbook(
            device_name=device_name,
            prefix_end_index=scale.routes_per_he_peer,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            expected_established_sessions=session_count,
            profile=profile,
            advertise_transition_soft_threshold_seconds=(
                scale.route_oscillation_advertise_threshold_seconds
            ),
            precheck_thresholds=full_scale_precheck_thresholds,
            expected_peer_identity=expected_peer_identity,
            bgp_mon_parent_network=bound_bgp_mon_network,
            ibgp_pnh_start_ipv4s=ibgp_pnh_start_ipv4s,
            ibgp_pnh_start_ipv6s=ibgp_pnh_start_ipv6s,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_ibgp_route_oscillation_playbook", enable_update_group, scale
            ),
        ),
        "bgp_ebb_igp_unresolvable_pnh_playbook": lambda: get_bgp_ebb_igp_unresolvable_pnh_playbook(
            device_name=device_name,
            peergroup_ibgp_v6=peergroup_ibgp_v6,
            peergroup_ibgp_v4=peergroup_ibgp_v4,
            local_link=local_link,
            other_link=other_link,
            expected_in_scope_sessions=session_count,
            profile=profile,
            precheck_thresholds=full_scale_precheck_thresholds,
            expected_peer_identity=expected_peer_identity,
            bgp_mon_parent_network=bound_bgp_mon_network,
            start_ipv4s=(
                list(ibgp_pnh_start_ipv4s[:1])
                if ibgp_pnh_start_ipv4s is not None
                else None
            ),
            start_ipv6s=(
                list(ibgp_pnh_start_ipv6s[:1])
                if ibgp_pnh_start_ipv6s is not None
                else None
            ),
            restore_start_ipv4s=(
                list(ibgp_pnh_start_ipv4s) if ibgp_pnh_start_ipv4s is not None else None
            ),
            restore_start_ipv6s=(
                list(ibgp_pnh_start_ipv6s) if ibgp_pnh_start_ipv6s is not None else None
            ),
            count=openr_route_count,
            step_size=openr_route_step,
            ibgp_pnh_count=openr_pnh_count,
            ibgp_pnh_step=openr_pnh_step,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                "bgp_ebb_igp_unresolvable_pnh_playbook", enable_update_group, scale
            ),
        ),
        "bgp_ebb_nexthop_group_count_threshold_playbook": lambda: get_bgp_ebb_nexthop_group_count_threshold_playbook(
            device_name=device_name,
            expected_established_sessions=session_count,
            route_count_expected=ebgp_prefix_count,
            exact_ebgp_peer_group_names=(
                automation.ebgp_peer_group_names_by_afi["ipv6"],
                automation.ebgp_peer_group_names_by_afi["ipv4"],
            ),
            route_count_histogram_by_afi=full_route_count_histogram_by_afi,
            ixia_items_by_afi=_nhg_storm_ixia_items(
                bound, automation, target_prefix_count=scale.fa_routes_per_peer
            ),
            prefix_pool_scope_regex=automation.exact_ebgp_route_regex(),
            nexthop_group_threshold=_NEXTHOP_GROUP_AGGREGATE_GUARDRAIL,
            epoch_count=nhg_storm_epoch_count,
            epoch_interval_seconds=nhg_storm_epoch_interval_seconds,
            soak_duration=nhg_storm_soak_seconds,
            restoration_stage_prefix_count=_NHG_STORM_RESTORATION_STAGE_PREFIX_COUNT,
            nexthop_group_poll_interval_seconds=(nhg_storm_poll_interval_seconds),
            nexthop_group_min_samples=nhg_storm_min_eos_samples,
            nexthop_group_min_consecutive_samples=(
                nhg_storm_min_eos_consecutive_samples
            ),
            target_membership_width=nhg_storm_target_membership_width,
            minimum_observed_bgp_multiway_memberships=(
                nhg_storm_min_observed_bgp_multiway_memberships
            ),
            minimum_paused_fibagent_samples=(nhg_storm_min_paused_fibagent_samples),
            minimum_confirmed_pause_fap_samples=(
                nhg_storm_min_confirmed_pause_fap_samples
            ),
            fibagent_nhg_watermark_high=fibagent_bgp_nhg_watermark_high,
            fibagent_nhg_watermark_low=fibagent_bgp_nhg_watermark_low,
            control_plane_sample_interval_seconds=(
                nhg_storm_control_plane_sample_interval_seconds
            ),
            control_plane_read_timeout_seconds=(
                nhg_storm_control_plane_read_timeout_seconds
            ),
            enable_update_group=enable_update_group,
            bgp_mon_parent_network=bound_bgp_mon_network,
            characterization=OBSERVE_ONLY_ON_DEVICE,
            characterization_gates=_characterization_gates(
                _NHG_STORM_PLAYBOOK_NAME,
                enable_update_group,
                scale,
            ),
        ),
    }
    unknown = sorted(set(playbooks_selected or ()) - builders.keys())
    if unknown:
        raise ValueError(f"Unrecognized BGP EBB playbook selections: {unknown}")
    skipped = set() if scale == EBB_FY26_SCALE else set(_FY26_ONLY_PLAYBOOKS)
    names = (
        tuple(builders)
        if playbooks_selected is None
        else tuple(
            name for name in playbooks_selected if name not in _TC7_PLAYBOOK_NAMES
        )
    )
    return [builders[name]() for name in names if name not in skipped]


_EBB_IXIA_BGP_PEER_REGEX = r"^BGP_PEER_"


def _validate_non_fy26_selection(
    scale: EbbScaleProfile,
    profile: BgpPlusPlusProfile,
    playbooks_selected: list[str] | None,
    setup_only: bool,
) -> None:
    if profile != BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R:
        raise ValueError(
            f"{scale.name} couples its HE peers to an Open/R injection of "
            f"{scale.he_sites_per_range} sites per range; build it with "
            "BGP_PLUS_PLUS_WITH_OPEN_R"
        )
    if setup_only:
        return
    blocked = (
        list(_FY26_ONLY_PLAYBOOKS)
        if not playbooks_selected
        else [name for name in playbooks_selected if name in _FY26_ONLY_PLAYBOOKS]
    )
    if blocked:
        reasons = "; ".join(f"{name}: {_FY26_ONLY_PLAYBOOKS[name]}" for name in blocked)
        raise ValueError(
            f"{scale.name} cannot build playbooks still pinned to FY26 geometry, "
            f"so it needs an explicit selection without them. {reasons}"
        )


def _setup_enables_all_ixia_device_groups(playbook: Playbook) -> bool:
    """True when the last all-group IXIA toggle in setup enables them. Setup
    that disables them (cold start) or never toggles them (UG suite cases)
    does not guarantee every IXIA BGP peer is up."""
    enabled = False
    for step in playbook.setup_steps or []:
        if step.name != StepName.INVOKE_IXIA_API_STEP or step.step_params is None:
            continue
        params = json.loads(step.step_params.json_params or "{}")
        if params.get("api_name") != "toggle_device_groups":
            continue
        args = json.loads(params.get("args_json") or "{}")
        if args.get("device_group_name_regex") == ".*":
            enabled = args.get("enable", True)
    return enabled


def _enabled_ixia_device_group_names(
    port_configs: t.Sequence[BasicPortConfig],
) -> list[str]:
    """Name every IXIA device group the compiled setup creates enabled."""
    names = []
    for port_config in port_configs:
        for device_group in port_config.device_group_configs or []:
            if not device_group.enable:
                continue
            if not device_group.device_group_name:
                raise ValueError(
                    f"IXIA device group {device_group.device_group_index} on "
                    f"{port_config.endpoint!r} has no name to gate its gateway on"
                )
            names.append(device_group.device_group_name)
    return names


def create_bgp_ebb_full_scale_test_config(  # noqa: C901
    physical_inventory: PhysicalInventory,
    *,
    name: str,
    playbooks_selected: list[str] | None = None,
    profile: BgpPlusPlusProfile = DEFAULT_PROFILE,
    enable_update_group: bool = True,
    bgpcpp_logging_config_override: str | None = EBB_BGPCPP_LOGGING_CONFIG,
    parent_networks: dict[str, str] | None = None,
    next_hops: EbbNextHopScheme = EBB_NEXT_HOPS,
    port_map: t.Mapping[str, int] | None = None,
    multipath_test_duration_seconds: int = 1800,
    multipath_oscillation_interval_seconds: int = 280,
    multipath_cycle_count: int | None = None,
    multipath_min_peers_to_stop: int = 1,
    multipath_max_peers_to_stop: int = 11,
    route_storm_cycles: int = 60,
    route_storm_quiet_window_seconds: int = 120,
    route_storm_bounded_validation: bool = False,
    nhg_storm_epoch_count: int = 48,
    nhg_storm_epoch_interval_seconds: int = 25,
    nhg_storm_soak_seconds: int = 300,
    nhg_storm_poll_interval_seconds: int = 60,
    nhg_storm_min_eos_samples: int = 6,
    nhg_storm_min_eos_consecutive_samples: int = 3,
    nhg_storm_target_membership_width: int | None = 25,
    nhg_storm_min_confirmed_pause_fap_samples: int = 3,
    nhg_storm_control_plane_sample_interval_seconds: int = 5,
    nhg_storm_control_plane_read_timeout_seconds: int = 180,
    fibagent_bgp_nhg_watermark_high: int = EBB_FIBAGENT_BGP_NHG_WATERMARK_HIGH,
    fibagent_bgp_nhg_watermark_low: int = EBB_FIBAGENT_BGP_NHG_WATERMARK_LOW,
    setup_only: bool = False,
    topology_override: LogicalTopology | None = None,
    scale: EbbScaleProfile = EBB_FY26_SCALE,
) -> TestConfig:
    """Build one selectable test suite on the canonical EBB full-scale topology.

    Args:
        physical_inventory: DUT and IXIA port bindings for the run.
        name: Test config name, used to resolve it from the catalog.
        playbooks_selected: Subset of the suite's playbooks to run; all if None.
        profile: BGP++ profile, which also decides the Open/R mode.
        enable_update_group: Whether to enable BGP Update Group on the device.
        bgpcpp_logging_config_override: Exact BGP++ logging configuration to
            apply to the launcher, defaulting to the production DBG1 level so
            a run never inherits the previous run's level. Pass ``None`` to
            preserve the launcher without a logging override.
        parent_networks: IXIA-side parent networks, defaulting to
            ``EBB_PARENT_NETWORKS`` (ixia11). Pass ``EBB_PARENT_NETWORKS_IXIA03``
            when the inventory has been swapped with
            ``PhysicalInventory.for_secondary_ixia()``: that helper moves the
            ports but not the addressing, and the two have to agree or the
            emulated peers land on subnets the DUT has no address in.
        next_hops: Chassis scheme for the next hops the emulated peers
            advertise. Built during topology construction, before binding, so
            it cannot be derived from ``parent_networks``; pass
            ``EBB_NEXT_HOPS_IXIA03`` alongside
            ``EBB_PARENT_NETWORKS_IXIA03``. Mismatched pairs are rejected,
            because peers on one chassis' subnets advertising next hops on
            another's produce routes the DUT cannot resolve.
        port_map: Optional mapping from logical IXIA roles to ordered physical
            inventory entries. Use this for a testbed-specific role assignment.
        setup_only: Compile setup and teardown for the selected topology without
            adding Playbooks. This explicit mode leaves the existing empty-list
            selector behavior unchanged.
        topology_override: Optional already-authored topology for an ad-hoc
            lifecycle binding. The standard EBB topology remains the default.
        scale: Fleet profile the topology, port map, prefix windows, session
            counts and playbook geometry are derived from. Every scheduled
            binding uses ``EBB_FY26_SCALE``. Any other scale must use the
            Open/R profile and name its playbooks, none of which may be one
            still pinned to FY26 geometry.
    """
    if setup_only and playbooks_selected is not None:
        raise ValueError("setup_only requires playbooks_selected=None")
    resolved_parent_networks = parent_networks or EBB_PARENT_NETWORKS
    if resolved_parent_networks.get("ebgp_v4") != next_hops.ebgp_v4_network:
        raise ValueError(
            "parent_networks and next_hops describe different chassis: "
            f"eBGP v4 parent {resolved_parent_networks.get('ebgp_v4')!r} vs "
            f"next-hop base {next_hops.ebgp_v4_network!r}"
        )
    duplicate_names = sorted(
        selected_name
        for selected_name, count in Counter(playbooks_selected or ()).items()
        if count > 1
    )
    if duplicate_names:
        raise ValueError(f"Duplicate BGP EBB playbook selections: {duplicate_names}")

    selected_tc7_playbooks = set(playbooks_selected or ()) & set(_TC7_PLAYBOOK_NAMES)
    if selected_tc7_playbooks and (
        profile != BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R
    ):
        raise ValueError("BGP Update Group 2.7 requires the WITH_OPEN_R profile")
    if selected_tc7_playbooks and not enable_update_group:
        raise ValueError("BGP Update Group 2.7 requires Update Group enabled")
    if scale != EBB_FY26_SCALE:
        _validate_non_fy26_selection(scale, profile, playbooks_selected, setup_only)

    openr_mode = (
        OpenRMode.STANDALONE
        if profile == BgpPlusPlusProfile.BGP_PLUS_PLUS_WITH_OPEN_R
        else OpenRMode.NONE
    )
    enable_runtime_update = not setup_only and (
        not playbooks_selected
        or "bgp_ebb_route_registry_runtime_update_playbook" in playbooks_selected
    )
    enable_route_storm_shards = not setup_only and (
        not playbooks_selected or "bgp_ebb_route_storm_playbook" in playbooks_selected
    )
    runtime_prefix_sets, runtime_advertisements = _tc7_runtime_intents(
        selected_tc7_playbooks
    )
    # Whether the run carries a BGP monitor is decided once: the port map and
    # topology follow it here, and the session counts and peer identity read
    # it back from the bound topology. An authored topology decides for
    # itself. Otherwise the monitor rides a spare port only where the scale
    # allows one, so a scale without a monitor never gains it from an
    # inventory with extra ports.
    include_auxiliary_observers = (
        any(_is_bgp_monitor(group) for group in topology_override.device_groups)
        if topology_override is not None
        else scale.allows_bgp_monitor
        and not selected_tc7_playbooks
        and len(physical_inventory.ixia_ports)
        > len(ebb_port_map(scale, include_bgpmon=False))
    )
    if include_auxiliary_observers and not scale.allows_bgp_monitor:
        raise ValueError(
            f"{scale.name} models no BGP monitor, but topology_override carries "
            "one; drop its monitor group"
        )
    default_port_map = ebb_port_map(scale, include_bgpmon=include_auxiliary_observers)
    resolved_port_map = dict(default_port_map if port_map is None else port_map)
    ebgp_prefix_count = scale.fa_routes_per_peer + (
        _RUNTIME_UPDATE_EBGP_PREFIX_DELTA if enable_runtime_update else 0
    )
    topology = topology_override or ebb_topology(
        scale=scale,
        next_hops=next_hops,
        openr_mode=openr_mode,
        include_bgpmon=include_auxiliary_observers,
        ebgp_graceful_restart=not selected_tc7_playbooks,
        ebgp_prefix_count=ebgp_prefix_count,
        ebgp_static_prefix_count=(
            _TC7_STATIC_EBGP_PREFIX_COUNT if selected_tc7_playbooks else None
        ),
        extra_prefix_sets=runtime_prefix_sets,
        extra_advertisements=runtime_advertisements,
        route_storm_shards=enable_route_storm_shards,
    )
    bound = topology.bind_to_inventory(
        physical_inventory=physical_inventory,
        port_map=resolved_port_map,
        parent_networks=resolved_parent_networks,
        peer_groups=EBB_PEER_GROUPS,
        as_numbers=EBB_AS_NUMBERS,
        device_config_override=RoutingDeviceConfig(
            openr_mode=openr_mode,
            update_group_enable=enable_update_group,
            bgpcpp_logging_config_override=bgpcpp_logging_config_override,
            fibagent_bgp_nhg_watermark_high=fibagent_bgp_nhg_watermark_high,
            fibagent_bgp_nhg_watermark_low=fibagent_bgp_nhg_watermark_low,
        ),
    )
    if selected_tc7_playbooks:
        _validate_tc7_bound_topology(bound)
    compiled = bound.compile()
    gateway_device_group_names = _enabled_ixia_device_group_names(
        compiled.basic_port_configs or []
    )
    compiled_setup_tasks = (
        insert_gateway_resolution_gate(
            list(compiled.setup_tasks), gateway_device_group_names
        )
        if gateway_device_group_names
        else list(compiled.setup_tasks)
    )
    if scale != EBB_FY26_SCALE:
        bgpcpp_enable_indices = [
            index
            for index, task in enumerate(compiled_setup_tasks)
            if task.task_name == "arista_daemon_control"
            and json.loads(task.params.json_params or "{}").get("daemon_name")
            == "Bgpcpp"
            and json.loads(task.params.json_params or "{}").get("action") == "enable"
        ]
        if len(bgpcpp_enable_indices) != 1:
            raise ValueError(
                f"{scale.name} requires exactly one Bgpcpp enable task, found "
                f"{len(bgpcpp_enable_indices)}"
            )
        compiled_setup_tasks.insert(
            bgpcpp_enable_indices[0],
            create_configure_bgpcpp_startup_task(
                hostname=physical_inventory.device_name,
                flags={"platform": "ebb"},
                use_managed_shell=True,
                set_outer_hostname=True,
                ixia_needed=True,
            ),
        )
    # Auxiliary observation peers stay out of testcase triggers and verdicts.
    monitor_device_group_names = {
        group.legacy_ixia_device_group_name or group.name
        for group in bound.device_groups
        if group.peer_relationship is PeerRelationship.MONITOR
    }
    testcase_gateway_device_group_names = [
        device_group_name
        for device_group_name in gateway_device_group_names
        if device_group_name not in monitor_device_group_names
    ]
    playbooks = []
    if not setup_only:
        playbooks = _get_bgp_ebb_full_scale_playbooks(
            physical_inventory,
            profile=profile,
            bound=bound,
            ebgp_prefix_count=ebgp_prefix_count,
            selected_tc7_playbooks=selected_tc7_playbooks,
            playbooks_selected=(playbooks_selected or None),
            scale=scale,
            port_map=resolved_port_map,
            enable_update_group=enable_update_group,
            multipath_test_duration_seconds=multipath_test_duration_seconds,
            multipath_oscillation_interval_seconds=(
                multipath_oscillation_interval_seconds
            ),
            multipath_cycle_count=multipath_cycle_count,
            multipath_min_peers_to_stop=multipath_min_peers_to_stop,
            multipath_max_peers_to_stop=multipath_max_peers_to_stop,
            route_storm_cycles=route_storm_cycles,
            route_storm_quiet_window_seconds=route_storm_quiet_window_seconds,
            route_storm_bounded_validation=route_storm_bounded_validation,
            nhg_storm_epoch_count=nhg_storm_epoch_count,
            nhg_storm_epoch_interval_seconds=nhg_storm_epoch_interval_seconds,
            nhg_storm_soak_seconds=nhg_storm_soak_seconds,
            nhg_storm_poll_interval_seconds=nhg_storm_poll_interval_seconds,
            nhg_storm_min_eos_samples=nhg_storm_min_eos_samples,
            nhg_storm_min_eos_consecutive_samples=(
                nhg_storm_min_eos_consecutive_samples
            ),
            nhg_storm_target_membership_width=(nhg_storm_target_membership_width),
            nhg_storm_min_observed_bgp_multiway_memberships=(
                fibagent_bgp_nhg_watermark_high + 1
            ),
            nhg_storm_min_confirmed_pause_fap_samples=(
                nhg_storm_min_confirmed_pause_fap_samples
            ),
            nhg_storm_control_plane_sample_interval_seconds=(
                nhg_storm_control_plane_sample_interval_seconds
            ),
            nhg_storm_control_plane_read_timeout_seconds=(
                nhg_storm_control_plane_read_timeout_seconds
            ),
            gateway_device_group_names=testcase_gateway_device_group_names,
        )
    if playbooks_selected:
        playbooks_by_name = {playbook.name: playbook for playbook in playbooks}
        unknown_names = [
            playbook_name
            for playbook_name in playbooks_selected
            if playbook_name not in playbooks_by_name
            and playbook_name not in _TC7_PLAYBOOK_NAMES
        ]
        if unknown_names:
            raise ValueError(
                "Unknown BGP EBB playbook selections: "
                f"{unknown_names}; available: "
                f"{sorted(set(playbooks_by_name) | set(_TC7_PLAYBOOK_NAMES))}"
            )
        unavailable_names = [
            playbook_name
            for playbook_name in playbooks_selected
            if playbook_name not in playbooks_by_name
        ]
        if unavailable_names:
            raise NotImplementedError(
                "BGP Update Group 2.7 playbook factories are not wired yet: "
                f"{unavailable_names}"
            )
        playbooks = [playbooks_by_name[name] for name in playbooks_selected]

    if scale != EBB_FY26_SCALE:
        playbooks = [
            _observe_only_cpu_rss_periodic_tasks(playbook) for playbook in playbooks
        ]

    # ixia03 peers intermittently stall after OPEN and never retry; one stuck
    # static peer (BGP-MON included) holds back End-of-RIB until the EoR timer
    # fires and fails convergence, so recover or name them before each case.
    session_recovery = create_bgp_ixia_session_recovery_step(
        device_name=physical_inventory.device_name,
        ixia_bgp_peer_regex=_EBB_IXIA_BGP_PEER_REGEX,
    )
    playbooks = [
        playbook(setup_steps=[*(playbook.setup_steps or []), session_recovery])
        if _setup_enables_all_ixia_device_groups(playbook)
        else playbook
        for playbook in playbooks
    ]

    return TestConfig(
        name=name,
        skip_ixia_protocol_verification=True,
        log_collection_timeout=600,
        basset_pool=physical_inventory.basset_pool,
        tags=(
            [TESTBED_ISOLATION_BYPASS_TAG]
            if openr_mode is OpenRMode.STANDALONE
            else None
        ),
        endpoints=compiled.endpoints,
        host_os_type_map=compiled.host_os_type_map,
        startup_checks=[],
        # A compile without an enabled IXIA device group has no gateway to check.
        setup_tasks=compiled_setup_tasks,
        teardown_tasks=compiled.teardown_tasks,
        basic_port_configs=compiled.basic_port_configs,
        basic_traffic_item_configs=(
            compiled.basic_traffic_item_configs
            if compiled.basic_traffic_item_configs
            else None
        ),
        playbooks=playbooks,
    )
