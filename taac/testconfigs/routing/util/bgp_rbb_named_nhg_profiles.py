# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Declarative Phase-2 named SRv6 next-hop-group lifecycle profiles.

The profiles share one structured control-plane contract; TC-03 and TC-04 add
mandatory IXIA forwarding and DUT counter evidence:

* TC-02 programs a named NHG, adds a route that references it, and verifies
  exact SRv6 NHE, RIB, and resolved agent-FIB state.
* TC-03 overlays the OpenR-learned remote loopback with a better-distance
  TE_AGENT route through the named NHG and verifies recursive service-prefix
  resolution through the new winner.
* TC-04 binds the load-bearing prefix directly to the named SRv6 NHG.
* TC-06 installs the route before its NHG and verifies the TE_AGENT candidate
  is retained in the client RIB without resolved per-client next hops.
* TC-07 independently recreates that forward reference, adds the missing NHG,
  and verifies that the same route becomes programmed.

Current FBOSS releases may reject a missing-NHG forward reference atomically.
The registered task reports TC-06/TC-07 as ``SKIP`` on those releases; the
profiles never relabel rejection/no-residue evidence as the original test.
"""

from __future__ import annotations

import enum
import ipaddress
import re
import typing as t
from dataclasses import dataclass

from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
    Srv6Profile,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    RbbTopology,
    validate_rbb_topology,
)


class RbbNamedNhgAction(enum.Enum):
    """The independently reported lifecycle exercised by one playbook."""

    PROGRAM_AND_VERIFY = "program_and_verify"
    ADMIN_DISTANCE_OVERRIDE = "admin_distance_override"
    BIND_SERVICE_PREFIX = "bind_service_prefix"
    FORWARD_REFERENCE = "forward_reference"
    RESOLVE_FORWARD_REFERENCE = "resolve_forward_reference"


class RbbNamedNhgCoverage(enum.Enum):
    """Coverage status against the original Phase-2 requirement."""

    PARTIAL = "partial"
    FULL = "full"


@dataclass(frozen=True)
class RbbNamedNhgMember:
    """One exact SRv6 NHE supplied to the FBOSS named-NHG API."""

    address: str
    weight: int
    srv6_segments: tuple[str, ...]
    tunnel_id: str
    interface: str | None = None

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.address)
        if address.version != 6:
            raise ValueError("named-NHG member address must be IPv6")
        object.__setattr__(self, "address", str(address))
        if type(self.weight) is not int or self.weight <= 0:
            raise ValueError("named-NHG member weight must be a positive integer")
        if not self.srv6_segments:
            raise ValueError("named-NHG member requires an SRv6 segment list")
        object.__setattr__(
            self,
            "srv6_segments",
            tuple(
                str(ipaddress.IPv6Address(segment)) for segment in self.srv6_segments
            ),
        )
        if not self.tunnel_id.strip():
            raise ValueError("named-NHG member requires an SRv6 tunnel ID")
        if address.is_link_local and not (self.interface and self.interface.strip()):
            raise ValueError("link-local named-NHG members require an interface")
        if self.interface is not None and not self.interface.strip():
            raise ValueError("named-NHG member interface must be nonempty")

    def to_params(self) -> dict[str, t.Any]:
        params: dict[str, t.Any] = {
            "address": self.address,
            "weight": self.weight,
            "srv6_segments": list(self.srv6_segments),
            "tunnel_id": self.tunnel_id,
        }
        if self.interface is not None:
            params["interface"] = self.interface
        return params


@dataclass(frozen=True)
class RbbNamedNhgProfile:
    """One original test-plan requirement and its exact task inputs."""

    testplan_id: str
    playbook_name: str
    title: str
    action: RbbNamedNhgAction
    coverage: RbbNamedNhgCoverage
    group_name: str
    route_prefix: str
    members: tuple[RbbNamedNhgMember, ...]
    underlay_anchor_prefix: str | None = None
    member_source_client: str | None = None
    member_source_prefix: str | None = None
    client: str = C.ROUTE_OWNER_TE_AGENT
    competing_client: str | None = None
    requires_forward_reference_support: bool = False
    unmet_requirements: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not re.fullmatch(r"phase2:TC-[0-9]+", self.testplan_id):
            raise ValueError(f"invalid Phase-2 testplan ID {self.testplan_id!r}")
        if not self.playbook_name.strip() or not self.title.strip():
            raise ValueError("named-NHG profile requires a name and title")
        if not isinstance(self.action, RbbNamedNhgAction):
            raise TypeError("named-NHG action must be an RbbNamedNhgAction")
        if not isinstance(self.coverage, RbbNamedNhgCoverage):
            raise TypeError("named-NHG coverage must be RbbNamedNhgCoverage")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,31}", self.group_name):
            raise ValueError(
                "named-NHG name must use 1..31 portable ASCII name characters"
            )
        network = ipaddress.ip_network(self.route_prefix, strict=True)
        if network.version != 6:
            raise ValueError("named-NHG lifecycle route must be IPv6")
        object.__setattr__(self, "route_prefix", str(network))
        if self.underlay_anchor_prefix is not None:
            anchor = ipaddress.ip_network(
                self.underlay_anchor_prefix, strict=True
            )
            if anchor.version != 6 or anchor.prefixlen != 128:
                raise ValueError("named-NHG underlay anchor must be an IPv6 /128")
            if anchor == network:
                raise ValueError(
                    "named-NHG underlay anchor must differ from the tested route"
                )
            object.__setattr__(self, "underlay_anchor_prefix", str(anchor))
        if (self.member_source_client is None) != (
            self.member_source_prefix is None
        ):
            raise ValueError(
                "named-NHG member source client and prefix must be supplied together"
            )
        if self.member_source_client is not None:
            if self.member_source_client not in {"OPENR", "BGPD"}:
                raise ValueError("named-NHG member source must be OPENR or BGPD")
            source_prefix = ipaddress.ip_network(
                t.cast(str, self.member_source_prefix), strict=True
            )
            if source_prefix.version != 6:
                raise ValueError("named-NHG member source prefix must be IPv6")
            object.__setattr__(self, "member_source_prefix", str(source_prefix))
        if not self.members:
            raise ValueError("named-NHG profile requires at least one NHE")
        member_keys = {
            (member.address, member.interface, member.srv6_segments, member.tunnel_id)
            for member in self.members
        }
        if len(member_keys) != len(self.members):
            raise ValueError("named-NHG profile contains duplicate NHEs")
        if self.client != C.ROUTE_OWNER_TE_AGENT:
            raise ValueError("named-NHG lifecycle is restricted to TE_AGENT")
        needs_competing_client = (
            self.action is RbbNamedNhgAction.ADMIN_DISTANCE_OVERRIDE
        )
        if needs_competing_client:
            if self.competing_client != "OPENR":
                raise ValueError(
                    "admin-distance override requires OPENR as competing_client"
                )
        elif self.competing_client is not None:
            raise ValueError(
                "competing_client is only valid for admin-distance override"
            )
        if self.coverage is RbbNamedNhgCoverage.PARTIAL:
            if not self.unmet_requirements:
                raise ValueError("partial named-NHG profiles must explain their gap")
        elif self.unmet_requirements:
            raise ValueError("non-partial profiles cannot have unmet requirements")
        needs_forward_reference = self.action in {
            RbbNamedNhgAction.FORWARD_REFERENCE,
            RbbNamedNhgAction.RESOLVE_FORWARD_REFERENCE,
        }
        if self.requires_forward_reference_support != needs_forward_reference:
            raise ValueError(
                "forward-reference support flag must match the selected action"
            )

    def task_params(self, *, include_members: bool) -> dict[str, t.Any]:
        params: dict[str, t.Any] = {
            "group_name": self.group_name,
            "route_prefix": self.route_prefix,
            "client": self.client,
        }
        if self.competing_client is not None:
            params["competing_client"] = self.competing_client
        if self.underlay_anchor_prefix is not None:
            params["underlay_anchor_prefix"] = self.underlay_anchor_prefix
        if self.member_source_client is not None:
            params["member_source_client"] = self.member_source_client
            params["member_source_prefix"] = self.member_source_prefix
        if include_members:
            params["members"] = [member.to_params() for member in self.members]
        return params


NAMED_NHG_SUITE_TESTPLAN_IDS: tuple[str, ...] = (
    "phase2:TC-02",
    "phase2:TC-03",
    "phase2:TC-04",
    "phase2:TC-06",
    "phase2:TC-07",
)

_TC02_GROUP = "taac-rbb-p2-tc02"
_TC03_GROUP = "taac-rbb-p2-tc03"
_TC04_GROUP = "taac-rbb-p2-tc04"
_FORWARD_REFERENCE_GROUP = "taac-rbb-p2-forward-ref"


def _members(
    topology: RbbTopology, srv6_profile: Srv6Profile
) -> tuple[RbbNamedNhgMember, ...]:
    """Build R1's NHEs from every declared R2-facing core path.

    Core RIF addresses are adopter inputs (``TAAC_RBB_R2_CORE<n>_V6``), not
    committed lab values. Global directly connected addresses intentionally do
    not carry an interface scope. Link-local inputs are rejected because the
    topology inventory does not expose the logical FBOSS RIF name required by
    ``BinaryAddress.ifName``.
    """
    segment = C.pack_usid_container(srv6_profile.locator, srv6_profile.encap_usids)
    members = []
    for index in range(len(topology.r1.core_pcs)):
        address = ipaddress.ip_interface(C.core_rif_cidr("r2", index, 6)).ip
        if address.is_link_local:
            raise ValueError(
                "named-NHG lifecycle requires global core peer addresses; "
                "the topology inventory does not expose the FBOSS RIF name "
                "required to scope a link-local NHE"
            )
        members.append(
            RbbNamedNhgMember(
                address=str(address),
                interface=None,
                weight=1,
                srv6_segments=(segment,),
                tunnel_id=C.SRV6_TUNNEL_ID,
            )
        )
    return tuple(members)


def _test_route_prefix(srv6_profile: Srv6Profile) -> ipaddress.IPv6Network:
    """Return an isolated lifecycle prefix that cannot alias live RBB state."""
    try:
        prefix = ipaddress.ip_network(C.NAMED_NHG_TEST_PREFIX, strict=True)
    except ValueError as exc:
        raise ValueError(
            "TAAC_RBB_NAMED_NHG_TEST_PREFIX must be a canonical IPv6 prefix"
        ) from exc
    if prefix.version != 6:
        raise ValueError("TAAC_RBB_NAMED_NHG_TEST_PREFIX must be IPv6")
    prefix = t.cast(ipaddress.IPv6Network, prefix)
    reserved = {
        "SRv6 locator": ipaddress.ip_network(srv6_profile.locator, strict=False),
        "active tail service prefix": ipaddress.ip_network(
            srv6_profile.tail_prefix, strict=True
        ),
    }
    for label, network in reserved.items():
        if prefix.overlaps(network):
            raise ValueError(
                "TAAC_RBB_NAMED_NHG_TEST_PREFIX must not overlap the "
                f"{label} ({network})"
            )
    return prefix


def build_rbb_named_nhg_profiles(
    topology: RbbTopology,
    srv6_profile: Srv6Profile = SRV6_3_USIDS_PROFILE,
) -> tuple[RbbNamedNhgProfile, ...]:
    """Build the dependency-ordered TC-02/03/04/06/07 catalog."""
    validate_rbb_topology(topology, require_ixia=False)
    members = _members(topology, srv6_profile)
    test_route_prefix = _test_route_prefix(srv6_profile)
    common = {"members": members}
    return (
        RbbNamedNhgProfile(
            testplan_id="phase2:TC-02",
            playbook_name="rbb_p2_tc02_program_named_srv6_nhg",
            title="Program and verify a named SRv6 NHG with SID-list NHEs",
            action=RbbNamedNhgAction.PROGRAM_AND_VERIFY,
            coverage=RbbNamedNhgCoverage.PARTIAL,
            group_name=_TC02_GROUP,
            route_prefix=str(test_route_prefix),
            unmet_requirements=(
                "the device-only suite does not generate data-plane traffic or "
                "independently query ASIC objects; it verifies exact NHG/NHE "
                "readback plus agent RIB/FIB state",
            ),
            **common,
        ),
        RbbNamedNhgProfile(
            testplan_id="phase2:TC-03",
            playbook_name="rbb_p2_tc03_loopback_admin_distance",
            title="Prefer a loopback-to-SRv6-NHG route by admin distance",
            action=RbbNamedNhgAction.ADMIN_DISTANCE_OVERRIDE,
            coverage=RbbNamedNhgCoverage.FULL,
            group_name=_TC03_GROUP,
            route_prefix=f"{C.R2_LOOPBACK_V6}/128",
            competing_client="OPENR",
            member_source_client="OPENR",
            member_source_prefix=f"{C.R2_LOOPBACK_V6}/128",
            **common,
        ),
        RbbNamedNhgProfile(
            testplan_id="phase2:TC-04",
            playbook_name="rbb_p2_tc04_service_prefix_srv6_nhg",
            title="Bind the load-bearing prefix to the named SRv6 NHG",
            action=RbbNamedNhgAction.BIND_SERVICE_PREFIX,
            coverage=RbbNamedNhgCoverage.FULL,
            group_name=_TC04_GROUP,
            route_prefix=C.TAIL_DEST_PREFIX,
            member_source_client="BGPD",
            member_source_prefix=C.TAIL_DEST_PREFIX,
            **common,
        ),
        RbbNamedNhgProfile(
            testplan_id="phase2:TC-06",
            playbook_name="rbb_p2_tc06_named_nhg_forward_reference",
            title="Retain an unresolved named-NHG route in RIB only",
            action=RbbNamedNhgAction.FORWARD_REFERENCE,
            coverage=RbbNamedNhgCoverage.PARTIAL,
            group_name=_FORWARD_REFERENCE_GROUP,
            route_prefix=str(test_route_prefix),
            requires_forward_reference_support=True,
            unmet_requirements=(
                "the lifecycle uses one isolated configured test prefix and does not "
                "require a lower-priority BGPD remote-loopback candidate; direct "
                "ASIC readback is not included, and current FBOSS releases reject "
                "missing-NHG forward references atomically",
            ),
            **common,
        ),
        RbbNamedNhgProfile(
            testplan_id="phase2:TC-07",
            playbook_name="rbb_p2_tc07_resolve_named_nhg_forward_reference",
            title="Resolve a forward-reference route into the agent FIB",
            action=RbbNamedNhgAction.RESOLVE_FORWARD_REFERENCE,
            coverage=RbbNamedNhgCoverage.PARTIAL,
            group_name=_FORWARD_REFERENCE_GROUP,
            route_prefix=str(test_route_prefix),
            requires_forward_reference_support=True,
            unmet_requirements=(
                "the lifecycle validates one isolated configured test prefix "
                "rather than both remote-loopback and load-bearing prefixes; "
                "direct ASIC readback is not included, and current FBOSS "
                "releases reject missing-NHG forward references atomically",
            ),
            **common,
        ),
    )


def select_rbb_named_nhg_profiles(
    profiles: t.Iterable[RbbNamedNhgProfile],
    testplan_ids: t.Iterable[str] | None = None,
) -> tuple[RbbNamedNhgProfile, ...]:
    """Select known IDs while retaining dependency-safe catalog order."""
    catalog = tuple(profiles)
    known = {profile.testplan_id for profile in catalog}
    if len(known) != len(catalog):
        raise ValueError("duplicate named-NHG testplan IDs")
    if testplan_ids is None:
        return catalog
    requested = tuple(testplan_ids)
    if len(requested) != len(set(requested)):
        raise ValueError("duplicate named-NHG testplan IDs in selection")
    unknown = sorted(set(requested) - known)
    if unknown:
        raise ValueError(f"unknown RBB named-NHG testplan IDs: {unknown}")
    selected = set(requested)
    return tuple(profile for profile in catalog if profile.testplan_id in selected)


__all__ = [
    "NAMED_NHG_SUITE_TESTPLAN_IDS",
    "RbbNamedNhgAction",
    "RbbNamedNhgCoverage",
    "RbbNamedNhgMember",
    "RbbNamedNhgProfile",
    "build_rbb_named_nhg_profiles",
    "select_rbb_named_nhg_profiles",
]
