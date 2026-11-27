# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Declarative, coverage-honest profiles for common RBB state audits.

The original RBB test plan contains requirements that overlap heavily.  These
profiles keep the device evidence reusable while preserving one playbook name
per original requirement.  A profile marked ``PARTIAL`` is never selected by
default and cannot be selected accidentally: callers must opt in explicitly.

Only topology/address-plan facts live here.  Device access remains in the
registered ``rbb_state_audit`` task and orchestration remains in the playbook
factory, keeping this module deterministic and unit-testable.
"""

from __future__ import annotations

import enum
import ipaddress
import re
import types
import typing as t
from dataclasses import dataclass

from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
    Srv6Profile,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology

_ROLES = frozenset(("r1", "r2"))


class RbbAuditCoverage(enum.Enum):
    """Whether a profile closes the mapped test-plan requirement."""

    FULL = "full"
    PARTIAL = "partial"


def _role(value: str) -> str:
    normalized = value.lower().strip()
    if normalized not in _ROLES:
        raise ValueError(f"RBB audit role must be 'r1' or 'r2': {value!r}")
    return normalized


def _prefix(value: str) -> str:
    return str(ipaddress.ip_network(value, strict=True))


def _address(value: str) -> str:
    return str(ipaddress.ip_address(value.split("/", 1)[0]))


@dataclass(frozen=True)
class RbbRouteExpectation:
    """One exact client route plus optional resolved-FIB evidence."""

    role: str
    prefix: str
    client: str
    require_fib: bool = True
    next_hops: tuple[str, ...] = ()
    interfaces: tuple[str, ...] = ()
    exact_next_hops: bool = True
    next_hop_count: int | None = None
    next_hop_interface_count: int | None = None
    next_hop_scope: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _role(self.role))
        object.__setattr__(self, "prefix", _prefix(self.prefix))
        if type(self.require_fib) is not bool or type(self.exact_next_hops) is not bool:
            raise TypeError("route boolean controls must be bool values")
        client = self.client.strip().upper()
        if not client:
            raise ValueError("route expectation requires a client")
        object.__setattr__(self, "client", client)
        object.__setattr__(
            self,
            "next_hops",
            tuple(_address(next_hop) for next_hop in self.next_hops),
        )
        if any(not interface.strip() for interface in self.interfaces):
            raise ValueError("route expectation interfaces must be non-empty")
        if self.next_hop_count is not None and self.next_hop_count < 1:
            raise ValueError("route next_hop_count must be positive")
        if self.next_hops and self.next_hop_count not in (
            None,
            len(self.next_hops),
        ):
            raise ValueError(
                "route next_hop_count must equal the number of exact next_hops"
            )
        if (
            self.next_hop_interface_count is not None
            and self.next_hop_interface_count < 1
        ):
            raise ValueError("route next_hop_interface_count must be positive")
        scope = self.next_hop_scope.lower() if self.next_hop_scope else None
        if scope not in (None, "link_local"):
            raise ValueError(f"unsupported route next_hop_scope {scope!r}")
        object.__setattr__(self, "next_hop_scope", scope)
        if not self.require_fib and any(
            (
                self.next_hops,
                self.interfaces,
                self.next_hop_count is not None,
                self.next_hop_interface_count is not None,
                self.next_hop_scope,
            )
        ):
            raise ValueError("resolved next-hop evidence requires require_fib=True")

    def to_params(self) -> dict[str, t.Any]:
        return {
            "prefix": self.prefix,
            "client": self.client,
            "require_fib": self.require_fib,
            "next_hops": list(self.next_hops),
            "interfaces": list(self.interfaces),
            "exact_next_hops": self.exact_next_hops,
            "next_hop_count": self.next_hop_count,
            "next_hop_interface_count": self.next_hop_interface_count,
            "next_hop_scope": self.next_hop_scope,
        }


@dataclass(frozen=True)
class RbbNdpExpectation:
    """An NDP entry on one topology-derived interface.

    The image owns the ingress VLAN and therefore the exact link-local address
    is not part of ``RbbTopology``.  ``address_scope='link_local'`` lets the
    task resolve the interface to its VLAN ID at runtime and match the exact
    NDP row by interface ID, address family/scope, and state.
    """

    role: str
    interface: str
    address: str | None = None
    address_scope: str | None = "link_local"
    allowed_states: tuple[str, ...] = ("REACHABLE",)

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _role(self.role))
        if not self.interface.strip():
            raise ValueError("NDP expectation requires an interface")
        if self.address is not None:
            object.__setattr__(self, "address", _address(self.address))
        scope = self.address_scope.lower() if self.address_scope else None
        if self.address is None and scope != "link_local":
            raise ValueError(
                "NDP expectation requires an address or link_local address scope"
            )
        if self.address is not None and scope is not None:
            raise ValueError("NDP address and address_scope are mutually exclusive")
        object.__setattr__(self, "address_scope", scope)
        states = tuple(state.strip().upper() for state in self.allowed_states)
        if not states or any(not state for state in states):
            raise ValueError("NDP expectation requires at least one allowed state")
        object.__setattr__(self, "allowed_states", states)

    def to_params(self) -> dict[str, t.Any]:
        params: dict[str, t.Any] = {
            "interface": self.interface,
            "states": list(self.allowed_states),
        }
        if self.address is not None:
            params["address"] = self.address
        else:
            params["address_scope"] = self.address_scope
        return params


@dataclass(frozen=True)
class RbbMySidExpectation:
    """One MySID entry whose fields must occur in the same CLI row/block."""

    role: str
    sid: str
    behavior: str
    require_resolved: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _role(self.role))
        object.__setattr__(self, "sid", _address(self.sid))
        if type(self.require_resolved) is not bool:
            raise TypeError("MySID require_resolved must be a bool value")
        if not self.behavior.strip():
            raise ValueError("MySID expectation requires a behavior")

    def to_params(self) -> dict[str, t.Any]:
        return {
            "sid": self.sid,
            "behavior": self.behavior,
            "require_resolved": self.require_resolved,
        }


@dataclass(frozen=True)
class RbbServiceExpectation:
    role: str
    service: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _role(self.role))
        if not self.service.strip():
            raise ValueError("service expectation requires a service")

    def to_params(self) -> dict[str, str]:
        return {"service": self.service}


@dataclass(frozen=True)
class RbbInterfaceExpectation:
    role: str
    interface: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _role(self.role))
        if not self.interface.strip():
            raise ValueError("interface expectation requires an interface")

    def to_params(self) -> dict[str, str]:
        return {"interface": self.interface}


@dataclass(frozen=True)
class RbbStateAuditProfile:
    """One independently reported original test-plan requirement."""

    testplan_id: str
    playbook_name: str
    title: str
    coverage: RbbAuditCoverage
    target_roles: tuple[str, ...] = ("r1", "r2")
    routes: tuple[RbbRouteExpectation, ...] = ()
    ndp: tuple[RbbNdpExpectation, ...] = ()
    mysids: tuple[RbbMySidExpectation, ...] = ()
    active_services: tuple[RbbServiceExpectation, ...] = ()
    interfaces_up: tuple[RbbInterfaceExpectation, ...] = ()
    unmet_requirements: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not re.fullmatch(r"phase[12]:TC-[0-9]+", self.testplan_id):
            raise ValueError(
                f"invalid RBB testplan ID {self.testplan_id!r}; "
                "expected phase1:TC-N or phase2:TC-N"
            )
        if not self.playbook_name.strip():
            raise ValueError("audit profile requires a testplan ID and playbook name")
        if not self.title.strip():
            raise ValueError("audit profile requires a title")
        if not isinstance(self.coverage, RbbAuditCoverage):
            raise TypeError("audit profile coverage must be an RbbAuditCoverage")
        if not isinstance(self.target_roles, tuple):
            raise TypeError("audit profile target_roles must be an immutable tuple")
        target_roles = tuple(_role(role) for role in self.target_roles)
        if not target_roles:
            raise ValueError("audit profile target_roles must not be empty")
        if len(set(target_roles)) != len(target_roles):
            raise ValueError("audit profile target_roles must not contain duplicates")
        object.__setattr__(self, "target_roles", target_roles)
        if not any(
            (
                self.routes,
                self.ndp,
                self.mysids,
                self.active_services,
                self.interfaces_up,
            )
        ):
            raise ValueError(f"{self.testplan_id} has no audit expectations")
        roles = {
            expectation.role
            for collection in (
                self.routes,
                self.ndp,
                self.mysids,
                self.active_services,
                self.interfaces_up,
            )
            for expectation in collection
        }
        if roles != set(target_roles):
            raise ValueError(
                f"{self.testplan_id} expectation roles must exactly match "
                f"target_roles; expected {sorted(target_roles)}, got "
                f"{sorted(roles)}"
            )
        if self.coverage is RbbAuditCoverage.FULL and self.unmet_requirements:
            raise ValueError("full audit profiles cannot have unmet requirements")
        if self.coverage is RbbAuditCoverage.PARTIAL and not self.unmet_requirements:
            raise ValueError("partial audit profiles must explain unmet requirements")

    def to_task_params(self, role: str) -> dict[str, t.Any]:
        role = _role(role)
        if role not in self.target_roles:
            raise ValueError(
                f"{self.testplan_id} does not target role {role!r}; "
                f"targets={list(self.target_roles)}"
            )
        return {
            "routes": [item.to_params() for item in self.routes if item.role == role],
            "ndp": [item.to_params() for item in self.ndp if item.role == role],
            "mysids": [item.to_params() for item in self.mysids if item.role == role],
            "active_services": [
                item.service for item in self.active_services if item.role == role
            ],
            "interfaces_up": [
                item.interface for item in self.interfaces_up if item.role == role
            ],
        }


TESTPLAN_ID_TO_PLAYBOOK: t.Mapping[str, str] = types.MappingProxyType(
    {
        "phase1:TC-01": "rbb_p1_tc01_openr_fib",
        "phase1:TC-04": "bgp_rbb_srv6_3_usids",
        "phase1:TC-07": "rbb_p1_tc07_current_prefix_rib_fib_partial",
        "phase2:TC-110": "rbb_p2_tc110_openr_reachability",
        "phase2:TC-111": "rbb_p2_tc111_ndp_resolution",
        "phase2:TC-112": "rbb_p2_tc112_current_srv6_state_partial",
        # Keep the final health audit last: later scenario families will reuse
        # it as their post-audit boundary.
        "phase1:TC-10": "rbb_p1_tc10_device_health_partial",
    }
)

EXISTING_PR46_TESTPLAN_IDS: frozenset[str] = frozenset(("phase1:TC-04",))


def _remote_loopback_routes(
    role: str,
    *,
    next_hop_count: int | None = None,
) -> tuple[RbbRouteExpectation, ...]:
    if role == "r1":
        remote_v4, remote_v6 = C.R2_ROUTER_ID, C.R2_LOOPBACK_V6
    else:
        remote_v4, remote_v6 = C.R1_ROUTER_ID, C.R1_LOOPBACK_V6
    return (
        RbbRouteExpectation(
            role,
            f"{remote_v4}/32",
            "OPENR",
            next_hop_count=next_hop_count,
            next_hop_interface_count=next_hop_count,
            next_hop_scope="link_local" if next_hop_count is not None else None,
        ),
        RbbRouteExpectation(
            role,
            f"{remote_v6}/128",
            "OPENR",
            next_hop_count=next_hop_count,
            next_hop_interface_count=next_hop_count,
            next_hop_scope="link_local" if next_hop_count is not None else None,
        ),
    )


def _openr_reachability_routes(
    topology: RbbTopology,
) -> tuple[RbbRouteExpectation, ...]:
    # The PR #46 bootstrap's OpenR redistribution regex exports only fboss4000,
    # whose complete expected inventory is the local IPv4 and IPv6 loopback.
    # Each remote route must resolve over every equal-cost core LAG.
    return _remote_loopback_routes(
        "r1", next_hop_count=len(topology.r1.core_pcs)
    ) + _remote_loopback_routes("r2", next_hop_count=len(topology.r2.core_pcs))


def _core_ndp(topology: RbbTopology) -> tuple[RbbNdpExpectation, ...]:
    expectations: list[RbbNdpExpectation] = []
    for role in ("r1", "r2"):
        node = topology.node(role)
        for pc in node.core_pcs:
            if not pc.members:
                raise ValueError(f"{node.hostname}:{pc.name} has no core member")
            # Core circuits are validated as exclusive R1<->R2 point-to-point
            # LAGs by the topology loader. The RIF/VLAN is image-owned, so one
            # physical member is sufficient to resolve that LAG's interface ID.
            # Wider member health is a separate gate.
            expectations.append(RbbNdpExpectation(role=role, interface=pc.members[0]))
    return tuple(expectations)


def _core_interfaces(topology: RbbTopology) -> tuple[RbbInterfaceExpectation, ...]:
    return tuple(
        RbbInterfaceExpectation(role, member)
        for role in ("r1", "r2")
        for pc in topology.node(role).core_pcs
        for member in pc.members
    )


def _critical_services() -> tuple[RbbServiceExpectation, ...]:
    names = ("FBOSS_HW_AGENT_0", "FBOSS_SW_AGENT", "BGP", "OPENR", "QSFP")
    return tuple(
        RbbServiceExpectation(role, service)
        for role in ("r1", "r2")
        for service in names
    )


def build_rbb_state_audit_profiles(
    topology: RbbTopology,
    srv6_profile: Srv6Profile = SRV6_3_USIDS_PROFILE,
) -> tuple[RbbStateAuditProfile, ...]:
    """Build the initial common-audit catalog from declared topology inputs."""
    openr_reachability_routes = _openr_reachability_routes(topology)
    return (
        RbbStateAuditProfile(
            testplan_id="phase1:TC-01",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-01"],
            title="OpenR route ownership and FIB programming",
            coverage=RbbAuditCoverage.FULL,
            routes=openr_reachability_routes,
        ),
        RbbStateAuditProfile(
            testplan_id="phase1:TC-07",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-07"],
            title="Current BGP prefix RIB/FIB programming",
            coverage=RbbAuditCoverage.PARTIAL,
            routes=(
                RbbRouteExpectation("r1", srv6_profile.tail_prefix, "BGPD"),
                RbbRouteExpectation(
                    "r2", srv6_profile.tail_prefix, "BGPD", require_fib=False
                ),
            ),
            unmet_requirements=(
                (
                    "PR #46 advertises only the tail pool; full TC-07 needs the "
                    "head pool, bidirectional IXIA route inventory, R2 FIB "
                    "validation, and exact resolved next hops"
                ),
            ),
        ),
        RbbStateAuditProfile(
            testplan_id="phase2:TC-110",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase2:TC-110"],
            title="Remote loopback reachability through OpenR",
            coverage=RbbAuditCoverage.FULL,
            routes=openr_reachability_routes,
        ),
        RbbStateAuditProfile(
            testplan_id="phase2:TC-111",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase2:TC-111"],
            title="Per-core link-local NDP resolution",
            coverage=RbbAuditCoverage.FULL,
            ndp=_core_ndp(topology),
        ),
        RbbStateAuditProfile(
            testplan_id="phase2:TC-112",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase2:TC-112"],
            title="Current SRv6 MySID programming",
            coverage=RbbAuditCoverage.PARTIAL,
            mysids=(
                RbbMySidExpectation(
                    "r1", srv6_profile.usid_head, C.SRV6_BEHAVIOR_ADJACENCY, True
                ),
                RbbMySidExpectation(
                    "r2", srv6_profile.usid_mid, C.SRV6_BEHAVIOR_ADJACENCY, True
                ),
                RbbMySidExpectation(
                    "r2", srv6_profile.decap_sid, C.SRV6_BEHAVIOR_DECAP, False
                ),
            ),
            unmet_requirements=(
                (
                    "PR #46 programs one adjacency MySID per DUT; full TC-112 "
                    "requires locator/controller-config validation and an "
                    "explicit adjacency SID for every core LAG"
                ),
            ),
        ),
        RbbStateAuditProfile(
            testplan_id="phase1:TC-10",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-10"],
            title="Device service and interface health subset",
            coverage=RbbAuditCoverage.PARTIAL,
            active_services=_critical_services(),
            interfaces_up=_core_interfaces(topology),
            unmet_requirements=(
                (
                    "full TC-10 also requires crash/core and log comparison, "
                    "session and route audits, edge-interface and counter checks, "
                    "traffic KPIs, and agreed CPU/memory thresholds"
                ),
            ),
        ),
    )


def select_rbb_state_audit_profiles(
    profiles: t.Iterable[RbbStateAuditProfile],
    testplan_ids: t.Iterable[str] | None = None,
    *,
    allow_partial: bool = False,
) -> tuple[RbbStateAuditProfile, ...]:
    """Select in catalog order and fail closed on gaps or partial coverage."""
    ordered = tuple(profiles)
    by_id = {profile.testplan_id: profile for profile in ordered}
    if len(by_id) != len(ordered):
        raise ValueError("duplicate test-plan IDs in RBB state-audit profiles")
    if testplan_ids is None:
        return tuple(
            profile for profile in ordered if profile.coverage is RbbAuditCoverage.FULL
        )

    requested = tuple(testplan_ids)
    if len(set(requested)) != len(requested):
        raise ValueError("duplicate test-plan IDs in state-audit selection")
    unknown = [testplan_id for testplan_id in requested if testplan_id not in by_id]
    existing = [
        testplan_id
        for testplan_id in unknown
        if testplan_id in EXISTING_PR46_TESTPLAN_IDS
    ]
    if existing:
        raise ValueError(
            f"{existing} are already covered by the PR #46 SRv6 playbook, not "
            "separate state-audit profiles"
        )
    if unknown:
        raise ValueError(f"unknown RBB state-audit test-plan IDs: {unknown}")

    requested_set = set(requested)
    selected = tuple(
        profile for profile in ordered if profile.testplan_id in requested_set
    )
    partial = [
        profile.testplan_id
        for profile in selected
        if profile.coverage is RbbAuditCoverage.PARTIAL
    ]
    if partial and not allow_partial:
        raise ValueError(
            f"partial RBB audit profiles require allow_partial=True: {partial}"
        )
    return selected


__all__ = [
    "EXISTING_PR46_TESTPLAN_IDS",
    "TESTPLAN_ID_TO_PLAYBOOK",
    "RbbAuditCoverage",
    "RbbInterfaceExpectation",
    "RbbMySidExpectation",
    "RbbNdpExpectation",
    "RbbRouteExpectation",
    "RbbServiceExpectation",
    "RbbStateAuditProfile",
    "build_rbb_state_audit_profiles",
    "select_rbb_state_audit_profiles",
]
