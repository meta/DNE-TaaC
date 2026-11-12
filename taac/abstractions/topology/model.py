# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-strict

from __future__ import annotations

import ipaddress
import typing as t
from dataclasses import dataclass, field, fields, MISSING, replace
from enum import Enum
from functools import cached_property

from taac.abstractions.config_artifact_semantics import (
    ConfigArtifactRef,
)
from taac.abstractions.ixia_semantics import (
    IxiaBgpCapability,
    IxiaEndpointPortLabelStyle,
    validate_ixia_bgp_tcp_window_size_bytes,
)
from taac.abstractions.physical_interface_semantics import (
    PhysicalInterfaceProfile,
)
from taac.abstractions.routing_semantics import (
    NetworkRole,
    PeerRelationship,
)
from taac.abstractions.topology.address import AddressPlan
from taac.abstractions.topology.attributes import (
    RouteAttributePool,
)
from taac.abstractions.topology.prefix import (
    NextHopDistribution,
    NextHopIntent,
    NextHopMode,
    PeerPrefixActivation,
    PrefixAllocation,
    PrefixMembership,
    PrefixSet,
)

AsnReference = int | str
_ROUTING_DEVICE_CONFIG_UNSET = object()


class CompiledTaacArtifactsLike(t.Protocol):
    """Structural compile result to keep topology primitives dependency-light.

    The concrete CompiledTaacArtifacts dataclass lives outside topology/model.py.
    Keeping this as a protocol lets BoundTopology.compile() expose the artifact
    shape without making primitive topology data import compiler/artifact code.
    """

    endpoints: list[t.Any]
    host_os_type_map: dict[str, t.Any]
    setup_tasks: list[t.Any]
    teardown_tasks: list[t.Any]
    basic_port_configs: list[t.Any]
    basic_traffic_item_configs: list[t.Any]


class ResolvedPrefixSetLike(t.Protocol):
    @property
    def spec(self) -> PrefixSet: ...

    @property
    def prefixes(self) -> t.Sequence[str]: ...


class ResolvedPrefixAdvertisementLike(t.Protocol):
    @property
    def spec(self) -> PrefixAdvertisement: ...

    @property
    def prefix_set(self) -> ResolvedPrefixSetLike: ...

    @property
    def paths_by_peer(self) -> t.Sequence[t.Sequence[t.Any]]: ...

    def path_at(self, peer_index: int, prefix_index: int) -> t.Any: ...


@dataclass(frozen=True)
class EndpointSpec:
    """Logical endpoint declaration; backend OS comes from physical inventory."""

    name: str
    role: str
    kind: str = "dut"
    required_os: str | None = None
    setup_mode: str = "full"


@dataclass(frozen=True)
class IxiaPortAssignment:
    logical_role: str
    reuse_group: str | None = None
    endpoint_label_style: IxiaEndpointPortLabelStyle = (
        IxiaEndpointPortLabelStyle.DUT_INTERFACE
    )


@dataclass(frozen=True)
class ResolvedIxiaPortAssignment:
    logical_role: str
    dut_interface: str
    ixia_port: str
    physical_inventory_index: int
    reuse_group: str | None
    physical_interface_profile: PhysicalInterfaceProfile
    endpoint_label_style: IxiaEndpointPortLabelStyle = (
        IxiaEndpointPortLabelStyle.DUT_INTERFACE
    )

    def __post_init__(self) -> None:
        if not isinstance(self.physical_interface_profile, PhysicalInterfaceProfile):
            raise TypeError("resolved physical interface profile must be typed")


@dataclass(frozen=True)
class DeviceGroupPartition:
    family: str
    ordinal: int
    start_index: int
    total_peer_count: int


@dataclass(frozen=True)
class IxiaDeviceGroupChild:
    name: str
    ordinal: int
    start_index: int
    peer_count: int
    legacy_ixia_device_group_name: str | None = None
    legacy_ixia_bgp_peer_name: str | None = None
    legacy_ixia_device_group_index: int | None = None
    legacy_ixia_prefix_pool_name: str | None = None


@dataclass(frozen=True)
class RouteSender:
    device_group: str
    prefix_advertisement: str


@dataclass(frozen=True)
class BgpPolicy:
    name: str
    route_maps: tuple[str, ...] = ()
    communities: tuple[str, ...] = ()
    prefix_lists: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    attributes: tuple[tuple[str, t.Any], ...] = ()
    local_pref: int | None = None
    med: int | None = None
    as_path_prepend: str | None = None


def _validate_ixia_bgp_capabilities(
    capabilities: tuple[IxiaBgpCapability, ...] | None,
) -> None:
    if capabilities is None:
        return
    if not capabilities or any(
        not isinstance(capability, IxiaBgpCapability) for capability in capabilities
    ):
        raise ValueError("IXIA BGP capabilities must be nonempty typed capabilities")
    if len(frozenset(capabilities)) != len(capabilities):
        raise ValueError("IXIA BGP capabilities must be unique")


def _validate_ixia_bgp_integer(
    field_name: str,
    value: object,
    *,
    allow_none: bool,
    allow_zero: bool,
) -> None:
    if value is None and allow_none:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"IXIA BGP {field_name} must be an integer")
    if value < 0 or (not allow_zero and value == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"IXIA BGP {field_name} must be {qualifier}")


@dataclass(frozen=True)
class BgpSlowPeerConfig:
    """IXIA transport settings that make one device group a slow receiver."""

    tcp_window_size_bytes: int = 1500

    def __post_init__(self) -> None:
        validate_ixia_bgp_tcp_window_size_bytes(self.tcp_window_size_bytes)


@dataclass(frozen=True)
class IxiaBgpSessionIntent:
    capabilities: tuple[IxiaBgpCapability, ...] | None = None
    address_prefix_length: int | None = None
    address_step: int | None = None
    address_start_index: int | None = None
    hold_timer_s: int = 30
    keepalive_timer_s: int = 10
    enable_graceful_restart: bool | None = None

    def __post_init__(self) -> None:
        _validate_ixia_bgp_capabilities(self.capabilities)
        _validate_ixia_bgp_integer(
            "address prefix length",
            self.address_prefix_length,
            allow_none=True,
            allow_zero=True,
        )
        _validate_ixia_bgp_integer(
            "hold_timer_s",
            self.hold_timer_s,
            allow_none=False,
            allow_zero=False,
        )
        _validate_ixia_bgp_integer(
            "keepalive_timer_s",
            self.keepalive_timer_s,
            allow_none=False,
            allow_zero=False,
        )
        _validate_ixia_bgp_integer(
            "address_step",
            self.address_step,
            allow_none=True,
            allow_zero=False,
        )
        _validate_ixia_bgp_integer(
            "address_start_index",
            self.address_start_index,
            allow_none=True,
            allow_zero=True,
        )
        if self.enable_graceful_restart is not None and not isinstance(
            self.enable_graceful_restart,
            bool,
        ):
            raise TypeError("IXIA BGP graceful-restart intent must be a bool")


@dataclass(frozen=True)
class BgpPeerGroup:
    name: str
    local_asn: AsnReference | None = None
    remote_asn: AsnReference | None = None
    policy: BgpPolicy | str | None = None
    hold_timer_s: int = 180
    keepalive_timer_s: int = 60
    connect_retry_timer_s: int = 120
    route_limit: int | str | None = None
    enable_graceful_restart: bool | None = None
    ixia_session: IxiaBgpSessionIntent = field(default_factory=IxiaBgpSessionIntent)


@dataclass(frozen=True)
class PrefixPool:
    name: str
    afi: str = "v6"
    route_count: int = 0
    route_file: str | None = None
    prefixes: tuple[str, ...] = ()
    prefix_length: int | None = None
    policy: BgpPolicy | str | None = None
    legacy_ixia_name: str | None = None
    attributes: tuple[tuple[str, t.Any], ...] = ()


@dataclass(frozen=True)
class PrefixAdvertisement:
    name: str
    prefix_set: str
    allocation: PrefixAllocation
    membership: PrefixMembership
    next_hop: NextHopIntent = field(default_factory=NextHopIntent)
    policy: BgpPolicy | str | None = None
    attributes: tuple[tuple[str, t.Any], ...] = ()
    route_attributes: RouteAttributePool | None = None
    legacy_ixia_name: str | None = None
    requires_route_mutation: bool = False
    peer_prefix_activation: PeerPrefixActivation | None = None


@dataclass(frozen=True)
class TrafficFlowSpec:
    name: str
    src_dg: str
    dst_dg: str | None = None
    dst_prefix_pool: str | None = None
    traffic_profile: str | None = None
    rate_percent: float | None = None
    rate_bps: int | None = None
    frame_size_bytes: int | None = None
    bidirectional: bool = False
    enabled: bool = True


class OpenRMode(str, Enum):
    NONE = "none"
    STANDALONE = "standalone"
    PEER = "peer"


class TaskCompatibilityProfile(str, Enum):
    BOUNDED_ECMP = "bounded_ecmp"
    CONSTANT_ATTRIBUTE_STORAGE = "constant_attribute_storage"
    EBB_FULL_SCALE_NO_BGPMON = "ebb_full_scale_no_bgpmon"
    EBB_FULL_SCALE_WITH_BGPMON = "ebb_full_scale_with_bgpmon"
    EGRESS_PEER_SCALE = "egress_peer_scale"
    INGRESS_PEER_SCALE = "ingress_peer_scale"
    IPV6_UPDATE_PACKING = "ipv6_update_packing"
    ROUTE_CHURN_SCALE = "route_churn_scale"
    TRANSIENT_MEMORY_ROUTE_SCALE = "transient_memory_route_scale"
    UG_ADD_PEER_DYNAMIC = "ug_add_peer_dynamic"
    UG_BACKPRESSURE = "ug_backpressure"
    UG_NEW_PEER_JOIN = "ug_new_peer_join"


class OpenRSetupSequence(str, Enum):
    NONE = "none"
    STANDALONE_SYNTHETIC_INJECTION = "standalone_synthetic_injection"
    PEER_DAEMON = "peer_daemon"
    # Compatibility for the pre-PEER-lowering inspection API.
    PEER_UNSUPPORTED = "peer_daemon"

    @classmethod
    def _missing_(cls, value: object) -> OpenRSetupSequence | None:
        if value == "peer_unsupported":
            return cls.PEER_DAEMON
        return None


@dataclass(frozen=True)
class ResolvedOpenRIntent:
    mode: OpenRMode
    setup_sequence: OpenRSetupSequence


@dataclass(frozen=True)
class OpenRStandaloneEndpoint:
    hostname: str
    member_interface: str
    ipv4_cidr: str
    ipv6_cidr: str
    link_local_cidr: str

    def __post_init__(self) -> None:
        if not self.hostname or not self.member_interface:
            raise ValueError(
                "OpenR endpoint hostname and member interface are required"
            )
        ipv4 = ipaddress.ip_interface(self.ipv4_cidr)
        ipv6 = ipaddress.ip_interface(self.ipv6_cidr)
        link_local = ipaddress.ip_interface(self.link_local_cidr)
        if ipv4.version != 4 or ipv4.network.prefixlen != 31:
            raise ValueError("OpenR endpoint IPv4 address must use a /31")
        if ipv6.version != 6 or ipv6.network.prefixlen != 127:
            raise ValueError("OpenR endpoint global IPv6 address must use a /127")
        if (
            link_local.version != 6
            or not link_local.ip.is_link_local
            or link_local.network.prefixlen != 64
        ):
            raise ValueError("OpenR endpoint link-local IPv6 address must use a /64")

    @property
    def ipv4(self) -> str:
        return str(ipaddress.ip_interface(self.ipv4_cidr).ip)

    @property
    def link_local(self) -> str:
        return str(ipaddress.ip_interface(self.link_local_cidr).ip)


@dataclass(frozen=True)
class OpenRStandaloneLink:
    port_channel_id: int
    owner: OpenRStandaloneEndpoint
    helper: OpenRStandaloneEndpoint
    speed: str = "400g-8"
    metric: int = 10

    def __post_init__(self) -> None:
        if self.port_channel_id <= 0:
            raise ValueError("OpenR port-channel ID must be positive")
        if self.owner.hostname == self.helper.hostname:
            raise ValueError("OpenR owner and helper must be different devices")
        owner_v4 = ipaddress.ip_interface(self.owner.ipv4_cidr)
        helper_v4 = ipaddress.ip_interface(self.helper.ipv4_cidr)
        owner_v6 = ipaddress.ip_interface(self.owner.ipv6_cidr)
        helper_v6 = ipaddress.ip_interface(self.helper.ipv6_cidr)
        owner_link_local = ipaddress.ip_interface(self.owner.link_local_cidr)
        helper_link_local = ipaddress.ip_interface(self.helper.link_local_cidr)
        for family, owner_address, helper_address in (
            ("IPv4", owner_v4, helper_v4),
            ("global IPv6", owner_v6, helper_v6),
            ("link-local IPv6", owner_link_local, helper_link_local),
        ):
            if owner_address.network != helper_address.network:
                raise ValueError(f"OpenR {family} endpoints must share a network")
            if owner_address.ip == helper_address.ip:
                raise ValueError(f"OpenR {family} endpoint addresses must differ")

    @property
    def interface_name(self) -> str:
        return f"Port-Channel{self.port_channel_id}"

    @property
    def short_interface_name(self) -> str:
        return f"po{self.port_channel_id}"

    def kv_link(self, endpoint: OpenRStandaloneEndpoint) -> dict[str, t.Any]:
        if endpoint not in (self.owner, self.helper):
            raise ValueError("OpenR KV endpoint must belong to the standalone link")
        return {
            "ipv4": endpoint.ipv4,
            "ipv6": endpoint.link_local,
            "ifName": self.short_interface_name,
            "weight": 0,
            "metric": self.metric,
        }


@dataclass(frozen=True)
class OpenRInjectionScale:
    """How much synthetic reachability each Open/R injection range carries.

    Unresolved intent: it fixes the size and stride of every range without
    naming an address. The addresses come from the bound topology, so a scale
    is reusable across chassis and testbeds.

    Attributes:
        count: Synthetic nodes, and therefore host routes per address family,
            injected per range.
        step: Address stride between consecutive injected host routes. Must
            match the stride the emulated peers' advertised next hops use, or
            the advertised next hops land between injected routes and never
            resolve.
    """

    count: int
    step: int = 2

    def __post_init__(self) -> None:
        for name, value in (("count", self.count), ("step", self.step)):
            # bool is an int subclass, and a float count silently yields a
            # non-integer range, so both are rejected rather than coerced.
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(
                    f"Open/R injection {name} must be an int; got {value!r}"
                )
            if value < 1:
                raise ValueError(
                    f"Open/R injection {name} must be positive; got {value}"
                )


@dataclass(frozen=True)
class OpenRInjectionExpansion:
    """The exact KvStore content one resolved injection plan owns.

    Setup creates precisely these keys. Teardown does not delete them
    individually: the withdrawal task passes no explicit delete count and the
    Open/R daemon stop remains the cleanup boundary, which is pre-existing
    behavior this model does not change. Holding the inventory as data --
    rather than only as a side effect of the renderer -- is what lets a unit
    test assert the injected scale without a device.

    The key grammar mirrors ``internal/utils/openr_kvstore_utils.py``:
    ``adj:<owner>`` for the owner's own adjacency database, ``adj:<node>``
    for each synthetic node, and ``prefix:<node>:[<prefix>]`` for each
    advertised host route.
    """

    owner_hostname: str
    synthetic_node_names: tuple[str, ...]
    ipv4_prefixes: tuple[str, ...]
    ipv6_prefixes: tuple[str, ...]
    local_adjacency_key: str
    synthetic_adjacency_keys: tuple[str, ...]
    ipv4_prefix_keys: tuple[str, ...]
    ipv6_prefix_keys: tuple[str, ...]

    @property
    def synthetic_node_count(self) -> int:
        return len(self.synthetic_node_names)

    @property
    def keys(self) -> tuple[str, ...]:
        return (
            self.local_adjacency_key,
            *self.synthetic_adjacency_keys,
            *self.ipv4_prefix_keys,
            *self.ipv6_prefix_keys,
        )

    @property
    def key_count(self) -> int:
        return len(self.keys)

    @cached_property
    def injected_addresses(
        self,
    ) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Every address made reachable, parsed once.

        Cached because callers check whole advertised inventories against it,
        and rebuilding the set per address turns a linear check quadratic.
        """
        return frozenset(
            ipaddress.ip_address(prefix.split("/", 1)[0])
            for prefix in (*self.ipv4_prefixes, *self.ipv6_prefixes)
        )

    def covers(self, addresses: t.Iterable[str]) -> bool:
        """Whether every address is reachable through an injected host route."""
        injected = self.injected_addresses
        return all(ipaddress.ip_address(address) in injected for address in addresses)

    def uncovered(self, addresses: t.Iterable[str]) -> tuple[str, ...]:
        """The addresses no injected host route reaches, deduplicated and sorted."""
        injected = self.injected_addresses
        return tuple(
            sorted(
                {
                    address
                    for address in addresses
                    if ipaddress.ip_address(address) not in injected
                }
            )
        )


@dataclass(frozen=True)
class OpenRInjectionPlan:
    """A resolved synthetic Open/R injection: which ranges, how many, how far apart.

    One range per plane and address family. ``start_ipv4s[i]`` and
    ``start_ipv6s[i]`` describe the same plane, which is how the renderer
    pairs them, so the two sequences must stay the same length and in the
    same order.

    ``advertised_pnh_count`` is how many leading nodes of every range the
    emulated peers advertise as BGP next hops: rows ``0..N-1`` are advertised,
    and the remaining ``count - N`` are injected headroom no BGP path uses.
    It is read from the bound advertisements, never from ``count``, and is
    None for a plan not resolved from a topology.
    """

    start_ipv4s: tuple[str, ...]
    start_ipv6s: tuple[str, ...]
    count: int
    step: int
    advertised_pnh_count: int | None = None

    def __post_init__(self) -> None:
        if not self.start_ipv4s:
            raise ValueError("Open/R injection plan requires at least one range")
        if len(self.start_ipv4s) != len(self.start_ipv6s):
            raise ValueError(
                "Open/R injection plan needs one IPv6 start per IPv4 start; got "
                f"{len(self.start_ipv4s)} IPv4 and {len(self.start_ipv6s)} IPv6"
            )
        for starts, version in ((self.start_ipv4s, 4), (self.start_ipv6s, 6)):
            if len(set(starts)) != len(starts):
                raise ValueError(
                    f"Open/R injection IPv{version} starts must be distinct; "
                    f"got {list(starts)}"
                )
            for start in starts:
                if ipaddress.ip_address(start).version != version:
                    raise ValueError(
                        f"Open/R injection expected an IPv{version} start; got {start!r}"
                    )
        # Reuses the scale validation so an inline plan cannot bypass it.
        OpenRInjectionScale(count=self.count, step=self.step)
        advertised = self.advertised_pnh_count
        if advertised is not None:
            if isinstance(advertised, bool) or not isinstance(advertised, int):
                raise TypeError(
                    "Open/R injection advertised_pnh_count must be an int; "
                    f"got {advertised!r}"
                )
            if not 1 <= advertised <= self.count:
                raise ValueError(
                    "Open/R injection advertised_pnh_count must be within "
                    f"1..{self.count}, the injected nodes per range; got {advertised}"
                )
        self._reject_overlapping_ranges()

    def _reject_overlapping_ranges(self) -> None:
        """Reject ranges whose expansions collide.

        Distinct starts are not enough: two starts fewer than ``count * step``
        apart expand into each other, and the overlapping nodes would then
        carry the same prefix keys. The injected host count comes out silently
        short, so this fails at construction instead of on the DUT.
        """
        for starts in (self.start_ipv4s, self.start_ipv6s):
            owner_by_address: dict[int, str] = {}
            for start in starts:
                first = int(ipaddress.ip_address(start))
                for index in range(self.count):
                    address = first + self.step * index
                    collided = owner_by_address.setdefault(address, start)
                    if collided != start:
                        raise ValueError(
                            "Open/R injection ranges must not overlap; "
                            f"{start} and {collided} both expand through "
                            f"{ipaddress.ip_address(address)} at "
                            f"count={self.count} step={self.step}"
                        )

    @classmethod
    def from_scale(
        cls,
        scale: OpenRInjectionScale,
        start_ipv4s: t.Sequence[str],
        start_ipv6s: t.Sequence[str],
    ) -> OpenRInjectionPlan:
        return cls(
            start_ipv4s=tuple(start_ipv4s),
            start_ipv6s=tuple(start_ipv6s),
            count=scale.count,
            step=scale.step,
        )

    @property
    def scale(self) -> OpenRInjectionScale:
        return OpenRInjectionScale(count=self.count, step=self.step)

    @property
    def range_count(self) -> int:
        return len(self.start_ipv4s)

    @property
    def synthetic_node_count(self) -> int:
        return self.range_count * self.count

    def host_routes(self, start: str) -> tuple[str, ...]:
        """Expand one range start into the host routes injected for it."""
        first = ipaddress.ip_address(start)
        length = first.max_prefixlen
        return tuple(
            f"{type(first)(int(first) + self.step * index)}/{length}"
            for index in range(self.count)
        )

    def expand(self, owner_hostname: str) -> OpenRInjectionExpansion:
        """Resolve the plan into the KvStore content it owns on ``owner_hostname``.

        Pure: no device, no client, no I/O. Mirrors the per-plane, per-index
        iteration the runtime injector performs, including its synthetic node
        naming, so the content can be asserted directly.
        """
        if not owner_hostname:
            raise ValueError("Open/R injection expansion requires an owner hostname")
        node_names: list[str] = []
        ipv4_prefixes: list[str] = []
        ipv6_prefixes: list[str] = []
        ipv4_keys: list[str] = []
        ipv6_keys: list[str] = []
        for plane, (start_ipv4, start_ipv6) in enumerate(
            zip(self.start_ipv4s, self.start_ipv6s)
        ):
            plane_ipv4 = self.host_routes(start_ipv4)
            plane_ipv6 = self.host_routes(start_ipv6)
            for index in range(self.count):
                node_name = f"node.{owner_hostname}.{plane}.{index}"
                node_names.append(node_name)
                ipv4_prefixes.append(plane_ipv4[index])
                ipv6_prefixes.append(plane_ipv6[index])
                ipv4_keys.append(f"prefix:{node_name}:[{plane_ipv4[index]}]")
                ipv6_keys.append(f"prefix:{node_name}:[{plane_ipv6[index]}]")
        return OpenRInjectionExpansion(
            owner_hostname=owner_hostname,
            synthetic_node_names=tuple(node_names),
            ipv4_prefixes=tuple(ipv4_prefixes),
            ipv6_prefixes=tuple(ipv6_prefixes),
            local_adjacency_key=f"adj:{owner_hostname}",
            synthetic_adjacency_keys=tuple(f"adj:{name}" for name in node_names),
            ipv4_prefix_keys=tuple(ipv4_keys),
            ipv6_prefix_keys=tuple(ipv6_keys),
        )


@dataclass(frozen=True, init=False)
class RoutingDeviceConfig:
    update_group_enable: bool = False
    enable_next_hop_tracking: bool = False
    enable_dynamic_policy_evaluation: bool = False
    openr_mode: OpenRMode = OpenRMode.NONE
    openr_configerator_path: str | None = None
    openr_standalone_link: OpenRStandaloneLink | None = None
    # Size and stride of the synthetic reachability Open/R injects for the next
    # hops the emulated peers advertise. The addresses are NOT recorded here:
    # they are derived at lowering time from the bound route advertisements of
    # the device groups that declare an injection range, so the injected set
    # cannot drift from the advertised set. None means "use the renderer
    # default", which is the ixia11 set at the legacy 63/2 scale.
    openr_injection_scale: OpenRInjectionScale | None = None
    route_limit: int | str | None = None
    prefix_limit: int | str | None = None
    per_peer_max_route_limit: int | str | None = None
    bgp_hold_timer_s: int = 180
    bgp_keepalive_timer_s: int = 60
    bgp_connect_retry_timer_s: int = 120
    graceful_restart_timer_s: int | None = None
    bgpcpp_logging_config_override: str | None = None
    bgpcpp_agent_thrift_recv_timeout_ms: int | None = None
    fibagent_bgp_thrift_queue_timeout_ms: int | None = None
    fibagent_bgp_nhg_watermark_high: int | None = None
    fibagent_bgp_nhg_watermark_low: int | None = None
    _taac_overridden_fields: tuple[str, ...] = field(
        default=(),
        repr=False,
        compare=False,
        hash=False,
    )

    def __init__(self, *args: t.Any, **kwargs: t.Any) -> None:
        init_fields = tuple(
            config_field for config_field in fields(type(self)) if config_field.init
        )
        if len(args) > len(init_fields):
            raise TypeError(
                f"{type(self).__name__}.__init__() takes "
                f"{len(init_fields) + 1} positional arguments but "
                f"{len(args) + 1} were given"
            )
        for config_field, value in zip(init_fields, args):
            if config_field.name in kwargs:
                raise TypeError(
                    f"{type(self).__name__}.__init__() got multiple values "
                    f"for argument {config_field.name!r}"
                )
            kwargs[config_field.name] = value

        overridden_fields_arg = kwargs.pop(
            "_taac_overridden_fields",
            _ROUTING_DEVICE_CONFIG_UNSET,
        )
        config_fields = tuple(
            config_field
            for config_field in init_fields
            if not config_field.name.startswith("_")
        )
        config_field_names = {config_field.name for config_field in config_fields}
        unexpected_field_names = set(kwargs) - config_field_names
        if unexpected_field_names:
            unexpected_field_name = sorted(unexpected_field_names)[0]
            raise TypeError(
                f"{type(self).__name__}.__init__() got an unexpected "
                f"keyword argument {unexpected_field_name!r}"
            )

        overridden_fields = list(
            ()
            if overridden_fields_arg is _ROUTING_DEVICE_CONFIG_UNSET
            else overridden_fields_arg or ()
        )
        should_record_overrides = (
            overridden_fields_arg is _ROUTING_DEVICE_CONFIG_UNSET
            or overridden_fields_arg is None
        )
        for config_field in config_fields:
            field_name = config_field.name
            if field_name in kwargs:
                value = kwargs[field_name]
                if should_record_overrides:
                    overridden_fields.append(field_name)
            elif config_field.default is not MISSING:
                value = config_field.default
            elif config_field.default_factory is not MISSING:
                value = config_field.default_factory()
            else:
                raise TypeError(f"{field_name!r} is missing a default value")
            object.__setattr__(self, field_name, value)
        object.__setattr__(
            self,
            "_taac_overridden_fields",
            tuple(overridden_fields),
        )


@dataclass(frozen=True)
class DeviceGroupSpec:
    name: str
    role: str
    afi: str = "v6"
    peer_count: int = 1
    a_endpoint: str = "dut0"
    z_endpoint: str = "ixia"
    address_plan: AddressPlan = field(default_factory=AddressPlan)
    peer_group: BgpPeerGroup | str | None = None
    prefix_pools: tuple[PrefixPool, ...] = ()
    prefix_advertisements: tuple[PrefixAdvertisement, ...] = ()
    traffic_flows: tuple[TrafficFlowSpec, ...] = ()
    routing_driver: str | None = None
    legacy_ixia_tag_name: str | None = None
    legacy_ixia_bgp_peer_name: str | None = None
    legacy_ixia_device_group_name: str | None = None
    routing_device_config: RoutingDeviceConfig | None = None
    port_assignment: IxiaPortAssignment | None = None
    partition: DeviceGroupPartition | None = None
    legacy_ixia_device_group_index: int | None = None
    route_attributes: RouteAttributePool | None = None
    ixia_children: tuple[IxiaDeviceGroupChild, ...] = ()
    # When True, the group's IXIA session + DUT interface IP are still provisioned,
    # but NO DUT BGP neighbor is generated for it (it is skipped in the bgpcpp peer
    # plan). For runtime-added peers -- e.g. spec 2.4.4 (addPeers) -- where the peer
    # must be ABSENT from the DUT config at baseline so the test can add it live.
    dut_neighbor_absent: bool = False
    peer_relationship: PeerRelationship | None = None
    slow_peer: BgpSlowPeerConfig | None = None
    # 1-based ordinal of the Open/R injection range this group's advertised
    # route next hops belong to, or None when the group owns no range. Declared
    # per group rather than inferred from the role name, so the lowering never
    # branches on a topology or role string and a group that must stay out of
    # the injection -- an auxiliary, monitor, or MP plane -- is excluded simply
    # by saying nothing. The ordinals fix the order the ranges are injected in;
    # within one address family they must form 1..N exactly.
    openr_injection_range_ordinal: int | None = None


@dataclass(frozen=True)
class LogicalTopology:
    name: str
    endpoints: tuple[EndpointSpec, ...] = ()
    device_groups: tuple[DeviceGroupSpec, ...] = ()
    device_config: RoutingDeviceConfig = field(default_factory=RoutingDeviceConfig)
    peer_groups: tuple[BgpPeerGroup, ...] = ()
    policies: tuple[BgpPolicy, ...] = ()
    prefix_pools: tuple[PrefixPool, ...] = ()
    prefix_sets: tuple[PrefixSet, ...] = ()
    traffic_flows: tuple[TrafficFlowSpec, ...] = ()
    legacy_profile: str | None = None
    task_compatibility_profile: TaskCompatibilityProfile | None = None
    route_senders: tuple[RouteSender, ...] = ()

    @property
    def routing_device_config(self) -> RoutingDeviceConfig:
        return self.device_config

    def validate(self) -> None:
        import importlib

        validation = importlib.import_module(
            "neteng.test_infra.dne.taac.abstractions.validation"
        )
        validation.validate_logical_topology(self)

    def bind_to_inventory(
        self,
        physical_inventory: t.Any,
        port_map: t.Mapping[str, int],
        parent_networks: t.Mapping[str, str] | None = None,
        peer_groups: t.Mapping[str, BgpPeerGroup | str] | None = None,
        as_numbers: t.Mapping[str, int] | None = None,
        device_config_override: RoutingDeviceConfig | None = None,
    ) -> "BoundTopology":
        import importlib

        binding = importlib.import_module(
            "neteng.test_infra.dne.taac.abstractions.topology.binding"
        )

        return binding.bind_logical_topology_to_inventory(
            logical_topology=self,
            physical_inventory=physical_inventory,
            port_map=port_map,
            parent_networks=parent_networks,
            peer_groups=peer_groups,
            as_numbers=as_numbers,
            device_config_override=device_config_override,
        )


@dataclass(frozen=True)
class ResolvedEndpoint:
    name: str
    role: str
    kind: str
    backend: str
    physical_identifier: str | None
    network_role: NetworkRole | None = None


@dataclass(frozen=True)
class ResolvedPeer:
    a_ip: str
    z_ip: str
    peer_cidr: str | None


@dataclass(frozen=True)
class ResolvedIxiaDeviceGroupChild:
    name: str
    parent_name: str
    ordinal: int
    start_index: int
    role: str
    afi: str
    a_endpoint: str
    z_endpoint: str
    a_interface: str | None
    z_interface: str | None
    ixia_port: str | None
    routing_driver: str | None
    parent_network: str | None
    local_asn: int | None
    remote_asn: int | None
    peer_group: BgpPeerGroup | str | None
    legacy_ixia_device_group_name: str | None
    legacy_ixia_bgp_peer_name: str | None
    legacy_ixia_device_group_index: int | None
    legacy_ixia_prefix_pool_name: str | None
    peers: tuple[ResolvedPeer, ...]
    prefix_advertisements: tuple[ResolvedPrefixAdvertisementLike, ...]
    port_assignment: ResolvedIxiaPortAssignment | None
    route_attributes: RouteAttributePool | None
    provenance: "ResolvedDeviceGroupProvenance | None"

    @property
    def peer_count(self) -> int:
        return len(self.peers)


@dataclass(frozen=True)
class ResolvedDeviceGroup:
    name: str
    role: str
    afi: str
    a_endpoint: str
    z_endpoint: str
    a_interface: str | None
    z_interface: str | None
    ixia_port: str | None
    routing_driver: str | None
    parent_network: str | None
    local_asn: int | None
    remote_asn: int | None
    peer_group: BgpPeerGroup | str | None
    legacy_ixia_tag_name: str | None
    legacy_ixia_device_group_name: str | None
    peers: tuple[ResolvedPeer, ...]
    legacy_ixia_bgp_peer_name: str | None = None
    prefix_advertisements: tuple[ResolvedPrefixAdvertisementLike, ...] = ()
    port_assignment: ResolvedIxiaPortAssignment | None = None
    partition: DeviceGroupPartition | None = None
    legacy_ixia_device_group_index: int | None = None
    route_attributes: RouteAttributePool | None = None
    provenance: "ResolvedDeviceGroupProvenance | None" = None
    ixia_children: tuple[ResolvedIxiaDeviceGroupChild, ...] = ()
    peer_relationship: PeerRelationship | None = None
    slow_peer: BgpSlowPeerConfig | None = None

    @property
    def peer_count(self) -> int:
        return len(self.peers)

    @property
    def slow_peer_tcp_window_size_bytes(self) -> int | None:
        slow_peer = self.slow_peer
        return slow_peer.tcp_window_size_bytes if slow_peer is not None else None


@dataclass(frozen=True)
class ResolvedDeviceGroupProvenance:
    parent_network: str | None
    parent_network_source: str | None
    local_asn: int | None
    local_asn_source: str | None
    remote_asn: int | None
    remote_asn_source: str | None


@dataclass(frozen=True)
class ResolvedIntentReport:
    logical_topology_name: str
    endpoints: tuple[ResolvedEndpoint, ...]
    device_groups: tuple[ResolvedDeviceGroup, ...]
    openr: ResolvedOpenRIntent
    prefix_sets: tuple[ResolvedPrefixSetLike, ...] = ()
    route_senders: tuple[RouteSender, ...] = ()


@dataclass(frozen=True)
class BoundIxiaDeviceGroupChild:
    spec: IxiaDeviceGroupChild
    peers: tuple[ResolvedPeer, ...]
    prefix_advertisements: tuple[ResolvedPrefixAdvertisementLike, ...]

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def peer_count(self) -> int:
        return len(self.peers)


@dataclass(frozen=True)
class BoundDeviceGroup:
    spec: DeviceGroupSpec
    a_interface: str | None = None
    z_interface: str | None = None
    ixia_port: str | None = None
    a_ips: tuple[str, ...] = ()
    z_ips: tuple[str, ...] = ()
    a_os: str | None = None
    z_os: str | None = None
    routing_driver: str | None = None
    parent_network: str | None = None
    local_asn: int | None = None
    remote_asn: int | None = None
    peer_group: BgpPeerGroup | str | None = None
    legacy_ixia_tag_name: str | None = None
    legacy_ixia_bgp_peer_name: str | None = None
    legacy_ixia_device_group_name: str | None = None
    peer_cidrs: tuple[str | None, ...] = ()
    prefix_advertisements: tuple[ResolvedPrefixAdvertisementLike, ...] = ()
    port_assignment: ResolvedIxiaPortAssignment | None = None
    partition: DeviceGroupPartition | None = None
    legacy_ixia_device_group_index: int | None = None
    route_attributes: RouteAttributePool | None = None
    provenance: ResolvedDeviceGroupProvenance | None = None
    ixia_children: tuple[BoundIxiaDeviceGroupChild, ...] = ()
    peer_relationship: PeerRelationship | None = None

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def role(self) -> str:
        return self.spec.role

    @property
    def afi(self) -> str:
        return self.spec.afi

    @property
    def peer_count(self) -> int:
        return self.spec.peer_count

    @property
    def dut_neighbor_absent(self) -> bool:
        return self.spec.dut_neighbor_absent

    @property
    def slow_peer(self) -> BgpSlowPeerConfig | None:
        return self.spec.slow_peer

    @property
    def slow_peer_tcp_window_size_bytes(self) -> int | None:
        slow_peer = self.slow_peer
        return slow_peer.tcp_window_size_bytes if slow_peer is not None else None

    @property
    def peers(self) -> tuple[ResolvedPeer, ...]:
        peer_cidrs = self.peer_cidrs or (None,) * len(self.a_ips)
        return tuple(
            ResolvedPeer(a_ip=a_ip, z_ip=z_ip, peer_cidr=peer_cidr)
            for a_ip, z_ip, peer_cidr in zip(
                self.a_ips,
                self.z_ips,
                peer_cidrs,
                strict=True,
            )
        )


def resolve_endpoint_routing_drivers(
    endpoint_name: str,
    device_groups: t.Iterable[BoundDeviceGroup],
    routing_drivers: t.Mapping[str, str],
) -> tuple[str, ...]:
    drivers: list[str] = []
    for device_group in device_groups:
        if endpoint_name not in {
            device_group.spec.a_endpoint,
            device_group.spec.z_endpoint,
        }:
            continue
        driver = device_group.routing_driver or routing_drivers.get(device_group.name)
        if driver is not None and driver not in drivers:
            drivers.append(driver)
    return tuple(drivers)


@dataclass(frozen=True)
class BoundRoutingConfig:
    routing_driver: str
    source: ConfigArtifactRef | None
    variant: None = None

    def __post_init__(self) -> None:
        if not isinstance(self.routing_driver, str):
            raise TypeError("bound routing config driver must be a string")
        if not self.routing_driver:
            raise ValueError("bound routing config driver must be nonempty")
        if self.source is not None and not isinstance(self.source, ConfigArtifactRef):
            raise TypeError("bound routing config source must be typed")
        if self.variant is not None:
            raise ValueError("bound routing config variants are not implemented")


def _openr_injection_range_start(
    group: BoundDeviceGroup,
) -> tuple[str, tuple[str, ...]]:
    """Read one declared injection range's start out of a bound device group.

    A group may bind more than one advertisement: the TC7 runtime intents add
    a next-hop-self advertisement alongside the plane's real one. Only an
    advertisement whose next hops are externally resolved can anchor a range,
    so the auxiliary SELF ones are filtered out rather than counted. Exactly
    one eligible source must remain.

    Returns the range start -- the numerically lowest next hop that source
    advertises -- together with every next hop it advertises, which the caller
    checks against the resolved injection.
    """
    # A SELF advertisement's next hops are the session addresses, which no
    # injection covers; it is auxiliary here, not a candidate.
    candidates = [
        advertisement
        for advertisement in group.prefix_advertisements
        if advertisement.spec.next_hop.mode is not NextHopMode.SELF
    ]
    # Distribution is still enforced for every non-SELF candidate: an
    # unsupported one is a malformed source, not something to skip past.
    for candidate in candidates:
        distribution = candidate.spec.next_hop.distribution
        if distribution is not NextHopDistribution.PER_PEER:
            observed = "unset" if distribution is None else distribution.value
            raise ValueError(
                f"{group.name} declares an Open/R injection range but its "
                f"advertisement {candidate.spec.name!r} distributes next hops "
                f"{observed!r}; range anchoring supports only "
                f"{NextHopDistribution.PER_PEER.value!r}"
            )
    if len(candidates) != 1:
        described = ", ".join(
            f"{advertisement.spec.name!r}"
            f"(mode={advertisement.spec.next_hop.mode.value}, "
            f"distribution="
            f"{getattr(advertisement.spec.next_hop.distribution, 'value', 'unset')})"
            for advertisement in group.prefix_advertisements
        )
        reason = (
            "advertises next-hop-self on every one, so none can anchor a range"
            if not candidates
            else "binds several externally resolved advertisements, so the "
            "range anchor is ambiguous"
        )
        raise ValueError(
            f"{group.name} declares an Open/R injection range but "
            f"{reason}; {len(candidates)} eligible of "
            f"{len(group.prefix_advertisements)} bound advertisement(s): "
            f"{described}"
        )
    (advertisement,) = candidates
    resolved = tuple(
        str(advertisement.path_at(row, 0).next_hop) for row in range(group.peer_count)
    )
    if not resolved:
        raise ValueError(
            f"{group.name} declares an Open/R injection range but advertises "
            "no route next hops"
        )
    # v4 rows are ordered lexically, so row 0 is not necessarily the lowest
    # address; the range always starts at the numeric minimum.
    start = min(resolved, key=lambda value: int(ipaddress.ip_address(value)))
    return start, resolved


def _openr_advertised_pnh_count(
    advertised_by_group: t.Mapping[str, tuple[str, tuple[str, ...]]],
    step: int,
) -> int:
    """How many leading rows every injection range is known to advertise.

    Consumers address advertised next hops as injection rows ``0..N-1``. A
    disabled peer may leave a gap and the two AFIs may advertise different
    populations, so the safe shared bound is the shortest contiguous prefix
    starting at row zero across all ranges. Rows beyond a gap remain covered
    by the injection, but are deliberately outside this common consumer bound.
    """
    leading_counts: dict[str, int] = {}
    for name, (start, advertised) in advertised_by_group.items():
        first = int(ipaddress.ip_address(start))
        offsets = {int(ipaddress.ip_address(address)) - first for address in advertised}
        invalid_offsets = sorted(
            offset for offset in offsets if offset < 0 or offset % step != 0
        )
        if invalid_offsets:
            raise ValueError(
                f"{name} advertises next hops that are not injection rows at "
                f"step={step} from {start}; offsets: {invalid_offsets[:5]}..."
            )
        rows = {offset // step for offset in offsets}
        leading_count = 0
        while leading_count in rows:
            leading_count += 1
        leading_counts[name] = leading_count

    count = min(leading_counts.values())
    if count == 0:
        raise ValueError(
            "Open/R injection ranges have no common advertised prefix starting "
            f"at row zero: {dict(sorted(leading_counts.items()))}"
        )
    return count


@dataclass(frozen=True)
class BoundTopology:
    """Resolved logical intent bound to a physical inventory."""

    __hash__ = None

    logical_topology: LogicalTopology
    physical_inventory: t.Any | None = None
    device_groups: tuple[BoundDeviceGroup, ...] = ()
    device_config: RoutingDeviceConfig | None = None
    resolved_endpoints: t.Mapping[str, t.Mapping[str, t.Any]] = field(
        default_factory=dict
    )
    resolved_device_groups: t.Mapping[str, t.Mapping[str, t.Any]] = field(
        default_factory=dict
    )
    endpoint_os: t.Mapping[str, str] = field(default_factory=dict)
    endpoint_network_roles: t.Mapping[str, NetworkRole] = field(default_factory=dict)
    routing_configs: t.Mapping[str, BoundRoutingConfig] = field(default_factory=dict)
    routing_drivers: t.Mapping[str, str] = field(default_factory=dict)
    ixia_ports: t.Mapping[str, str] = field(default_factory=dict)
    interfaces: t.Mapping[str, str] = field(default_factory=dict)
    as_numbers: t.Mapping[str, int] = field(default_factory=dict)
    peer_groups_by_device_group: t.Mapping[str, BgpPeerGroup | str] = field(
        default_factory=dict
    )
    legacy_names: t.Mapping[str, str] = field(default_factory=dict)
    port_map: t.Mapping[str, int] = field(default_factory=dict)
    parent_networks: t.Mapping[str, str] = field(default_factory=dict)
    resolved_prefix_sets: t.Mapping[str, ResolvedPrefixSetLike] = field(
        default_factory=dict
    )
    resolved_route_senders: tuple[RouteSender, ...] = ()

    def validate_for_compile(self) -> None:
        import importlib

        binding = importlib.import_module(
            "neteng.test_infra.dne.taac.abstractions.topology.binding"
        )

        binding.validate_bound_topology_for_compile(self)

    def compile(self) -> CompiledTaacArtifactsLike:
        import importlib

        compiler = importlib.import_module(
            "neteng.test_infra.dne.taac.abstractions.compiler"
        )

        self.validate_for_compile()
        return compiler.select_topology_compiler(self).compile(self)

    def inspect_resolved_intent(self) -> ResolvedIntentReport:
        # inspection imports this primitive model, so keep the reverse BUCK edge runtime-only.
        import importlib

        inspection = importlib.import_module(
            "neteng.test_infra.dne.taac.abstractions.inspection"
        )
        return inspection.inspect_resolved_intent(self)

    def resolve_openr_injection_plan(self) -> OpenRInjectionPlan | None:
        """Resolve the synthetic Open/R injection this bound topology implies.

        The injected range starts are read back out of the bound route
        advertisements of the device groups that declare an injection range
        ordinal, never from a chassis constant and never from the IXIA session
        addresses. Emulated peers advertise those next hops and Open/R has to
        make them resolvable, so expressing the two sets separately lets them
        drift -- silently, because unresolved routes still arrive and sit in
        the RIB. Deriving one from the other removes the failure mode.

        Returns:
            The resolved plan, or None when the device config declares no
            injection scale, which leaves the renderer on its own defaults.

        Raises:
            ValueError: A declared range is unusable -- missing, duplicated,
                not numbered 1..N, carrying no single advertisement, resolving
                next-hop-self, or advertising a next hop the resolved
                injection would not make reachable.
        """
        scale = self.device_config.openr_injection_scale if self.device_config else None
        if scale is None:
            return None

        starts_by_afi: dict[str, dict[int, str]] = {"v4": {}, "v6": {}}
        advertised_by_afi: dict[str, set[str]] = {"v4": set(), "v6": set()}
        advertised_by_group: dict[str, tuple[str, tuple[str, ...]]] = {}
        for group in self.device_groups:
            ordinal = group.spec.openr_injection_range_ordinal
            if ordinal is None:
                continue
            afi = group.spec.afi
            if afi not in starts_by_afi:
                raise ValueError(
                    f"{group.name} declares an Open/R injection range for "
                    f"unsupported AFI {afi!r}"
                )
            if ordinal in starts_by_afi[afi]:
                raise ValueError(
                    f"Open/R injection range {ordinal} is declared twice for {afi}"
                )
            start, resolved = _openr_injection_range_start(group)
            advertised_by_afi[afi].update(resolved)
            advertised_by_group[group.name] = (start, resolved)
            starts_by_afi[afi][ordinal] = start

        if not starts_by_afi["v4"] and not starts_by_afi["v6"]:
            raise ValueError(
                f"{self.logical_topology.name} declares an Open/R injection "
                "scale but no device group declares an injection range"
            )
        for afi, other in (("v4", "v6"), ("v6", "v4")):
            if not starts_by_afi[afi]:
                raise ValueError(
                    f"{self.logical_topology.name} declares "
                    f"{len(starts_by_afi[other])} Open/R injection range(s) for "
                    f"{other} but none for {afi}; the injection is dual-stack "
                    "and needs one range per plane in each address family"
                )
        range_count = len(starts_by_afi["v4"])
        for afi, starts in starts_by_afi.items():
            if sorted(starts) != list(range(1, range_count + 1)):
                raise ValueError(
                    f"Open/R injection {afi} ranges must be numbered "
                    f"1..{range_count} with no gaps or duplicates; "
                    f"got {sorted(starts)}"
                )

        plan = OpenRInjectionPlan.from_scale(
            scale,
            start_ipv4s=[
                starts_by_afi["v4"][ordinal] for ordinal in range(1, range_count + 1)
            ],
            start_ipv6s=[
                starts_by_afi["v6"][ordinal] for ordinal in range(1, range_count + 1)
            ],
        )
        # Read-only evidence: the bound advertisements are the requirement, the
        # injection is the supply. A next hop outside the injected set would
        # arrive and never resolve.
        expansion = plan.expand("validation")
        unreachable = expansion.uncovered(
            address for addresses in advertised_by_afi.values() for address in addresses
        )
        if unreachable:
            raise ValueError(
                f"{self.logical_topology.name} advertises {len(unreachable)} route "
                f"next hop(s) the resolved Open/R injection would not make "
                f"reachable at count={plan.count} step={plan.step}; "
                f"sample: {unreachable[:5]}"
            )
        return replace(
            plan,
            advertised_pnh_count=_openr_advertised_pnh_count(
                advertised_by_group, plan.step
            ),
        )
