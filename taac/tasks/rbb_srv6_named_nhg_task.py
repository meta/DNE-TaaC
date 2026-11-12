# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Structured FBOSS named SRv6 next-hop-group lifecycle task.

The task covers the small named-NHG lifecycle shared by the RBB Phase-2
scenarios: create and read back an SRv6 named next-hop group, reference it from
a route, distinguish an unresolved RIB entry from a programmed FIB entry, and
remove only resources created by the current playbook.

Current FBOSS rejects a route that references a missing named group atomically.
``install_forward_ref`` treats only that explicit capability rejection as an
unsupported test and raises ``unittest.SkipTest`` after proving that neither a
route nor a group was left behind. Transport failures and unrelated agent
errors remain failures.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import typing as t
import unittest

from taac.constants import TestCaseFailure
from taac.tasks.base_task import BaseTask
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger

_PRECHECK = "precheck"
_PROGRAM_NHG = "program_nhg"
_VERIFY_NHG = "verify_nhg"
_INSTALL_FORWARD_REF = "install_forward_ref"
_VERIFY_RIB_ONLY = "verify_rib_only"
_PROGRAM_ROUTE = "program_route"
_VERIFY_PROGRAMMED = "verify_programmed"
_CLEANUP = "cleanup"

_ACTIONS = frozenset(
    {
        _PRECHECK,
        _PROGRAM_NHG,
        _VERIFY_NHG,
        _INSTALL_FORWARD_REF,
        _VERIFY_RIB_ONLY,
        _PROGRAM_ROUTE,
        _VERIFY_PROGRAMMED,
        _CLEANUP,
    }
)
_MEMBER_ACTIONS = frozenset({_PROGRAM_NHG, _VERIFY_NHG, _CLEANUP})
_DEFAULT_CLIENT = "TE_AGENT"
_DEFAULT_ADMIN_DISTANCE = "TE_AGENT"
_MAX_PORTABLE_GROUP_NAME_LENGTH = 31
_ALLOWED_PARAMS = frozenset(
    {
        "hostname",
        "action",
        "group_name",
        "route_prefix",
        "underlay_anchor_prefix",
        "member_source_client",
        "member_source_prefix",
        "client",
        "competing_client",
        "admin_distance",
        "members",
        "expected_programmed",
    }
)
_ALLOWED_MEMBER_FIELDS = frozenset(
    {"address", "interface", "weight", "srv6_segments", "tunnel_id"}
)


def _required_string(value: t.Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value.strip()


def _enum_name(value: t.Any, label: str) -> str:
    return _required_string(value, label).upper()


def _normalize_ipv6_network(value: t.Any, label: str) -> ipaddress.IPv6Network:
    try:
        network = ipaddress.ip_network(str(value), strict=True)
    except ValueError as exc:
        raise ValueError(f"{label} must be a canonical IP prefix") from exc
    if network.version != 6:
        raise ValueError(f"{label} must be IPv6")
    return t.cast(ipaddress.IPv6Network, network)


def _normalize_ipv6_address(value: t.Any, label: str) -> ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise ValueError(f"{label} must be an IP address") from exc
    if address.version != 6:
        raise ValueError(f"{label} must be IPv6")
    return t.cast(ipaddress.IPv6Address, address)


def _normalize_members(raw_members: t.Any) -> tuple[dict[str, t.Any], ...]:
    if not isinstance(raw_members, list) or not raw_members:
        raise ValueError("members must be a nonempty JSON list")

    members: list[dict[str, t.Any]] = []
    signatures: set[tuple[t.Any, ...]] = set()
    for index, raw_member in enumerate(raw_members):
        label = f"members[{index}]"
        if not isinstance(raw_member, dict):
            raise ValueError(f"{label} must be a JSON object")
        unknown = sorted(set(raw_member) - _ALLOWED_MEMBER_FIELDS)
        if unknown:
            raise ValueError(f"{label} contains unsupported fields: {unknown}")

        address = _normalize_ipv6_address(raw_member.get("address"), f"{label}.address")
        raw_interface = raw_member.get("interface")
        interface = (
            _required_string(raw_interface, f"{label}.interface")
            if raw_interface is not None
            else None
        )
        if address.is_link_local and interface is None:
            raise ValueError(f"{label}.interface is required for a link-local next hop")

        weight = raw_member.get("weight", 1)
        if type(weight) is not int or weight < 1:
            raise ValueError(f"{label}.weight must be a positive integer")

        raw_segments = raw_member.get("srv6_segments")
        if not isinstance(raw_segments, list) or not raw_segments:
            raise ValueError(f"{label}.srv6_segments must be a nonempty JSON list")
        segments = tuple(
            _normalize_ipv6_address(segment, f"{label}.srv6_segments[{seg_index}]")
            for seg_index, segment in enumerate(raw_segments)
        )
        tunnel_id = _required_string(raw_member.get("tunnel_id"), f"{label}.tunnel_id")

        identity = (
            str(address),
            interface,
            tuple(str(segment) for segment in segments),
            tunnel_id,
        )
        if identity in signatures:
            raise ValueError(f"{label} duplicates another named-NHG member")
        signatures.add(identity)
        members.append(
            {
                "address": address,
                "interface": interface,
                "weight": weight,
                "srv6_segments": segments,
                "tunnel_id": tunnel_id,
            }
        )
    return tuple(members)


def _normalize_params(
    params: t.Mapping[str, t.Any], fallback_hostname: str | None
) -> dict[str, t.Any]:
    unknown = sorted(set(params) - _ALLOWED_PARAMS)
    if unknown:
        raise ValueError(
            "rbb_srv6_named_nhg contains unsupported fields: " f"{unknown}"
        )

    hostname = _required_string(params.get("hostname") or fallback_hostname, "hostname")
    action = _required_string(params.get("action"), "action")
    if action not in _ACTIONS:
        raise ValueError(
            "rbb_srv6_named_nhg action must be one of "
            f"{sorted(_ACTIONS)}, got {action!r}"
        )

    group_name = _required_string(params.get("group_name"), "group_name")
    if len(group_name) > _MAX_PORTABLE_GROUP_NAME_LENGTH:
        raise ValueError(
            "group_name exceeds the portable FBOSS limit of "
            f"{_MAX_PORTABLE_GROUP_NAME_LENGTH} characters"
        )
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", group_name):
        raise ValueError(
            "group_name must use portable ASCII letters, digits, '.', '_', "
            "':', or '-'"
        )

    route_prefix = _normalize_ipv6_network(params.get("route_prefix"), "route_prefix")
    underlay_anchor_prefix = (
        _normalize_ipv6_network(
            params["underlay_anchor_prefix"], "underlay_anchor_prefix"
        )
        if params.get("underlay_anchor_prefix") is not None
        else None
    )
    if underlay_anchor_prefix is not None:
        if underlay_anchor_prefix.prefixlen != 128:
            raise ValueError("underlay_anchor_prefix must be an IPv6 /128")
        if underlay_anchor_prefix == route_prefix:
            raise ValueError("underlay_anchor_prefix must differ from route_prefix")
    member_source_client = (
        _enum_name(params["member_source_client"], "member_source_client")
        if params.get("member_source_client") is not None
        else None
    )
    member_source_prefix = (
        _normalize_ipv6_network(
            params["member_source_prefix"], "member_source_prefix"
        )
        if params.get("member_source_prefix") is not None
        else None
    )
    if (member_source_client is None) != (member_source_prefix is None):
        raise ValueError(
            "member_source_client and member_source_prefix must be supplied together"
        )
    if member_source_client not in {None, "OPENR", "BGPD"}:
        raise ValueError("member_source_client must be OPENR or BGPD")
    client = _enum_name(params.get("client", _DEFAULT_CLIENT), "client")
    competing_client = (
        _enum_name(params["competing_client"], "competing_client")
        if params.get("competing_client") is not None
        else None
    )
    admin_distance = _enum_name(
        params.get("admin_distance", _DEFAULT_ADMIN_DISTANCE), "admin_distance"
    )
    if client != _DEFAULT_CLIENT:
        raise ValueError(
            "rbb_srv6_named_nhg is restricted to the TE_AGENT route client"
        )
    if competing_client not in {None, "OPENR"}:
        raise ValueError("competing_client must be OPENR when supplied")
    if admin_distance != _DEFAULT_ADMIN_DISTANCE:
        raise ValueError(
            "rbb_srv6_named_nhg is restricted to the TE_AGENT admin distance"
        )

    expected_programmed = params.get("expected_programmed")
    if expected_programmed is not None and type(expected_programmed) is not bool:
        raise ValueError("expected_programmed must be a JSON boolean")

    members: tuple[dict[str, t.Any], ...] | None = None
    if "members" in params:
        members = _normalize_members(params["members"])
    if action in _MEMBER_ACTIONS and members is None:
        raise ValueError(f"rbb_srv6_named_nhg {action} requires 'members'")

    return {
        "hostname": hostname,
        "action": action,
        "group_name": group_name,
        "route_prefix": route_prefix,
        "underlay_anchor_prefix": underlay_anchor_prefix,
        "member_source_client": member_source_client,
        "member_source_prefix": member_source_prefix,
        "client": client,
        "competing_client": competing_client,
        "admin_distance": admin_distance,
        "members": members,
        "expected_programmed": expected_programmed,
    }


def _packed_address(value: t.Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    packed = getattr(value, "addr", value)
    return ipaddress.ip_address(bytes(packed))


def _route_prefix(route: t.Any) -> str:
    address = _packed_address(route.dest.ip)
    return str(
        ipaddress.ip_network(f"{address}/{int(route.dest.prefixLength)}", strict=False)
    )


def _named_destination(route: t.Any) -> str | None:
    destination = getattr(route, "namedRouteDestination", None)
    group_name = getattr(destination, "nextHopGroup", None)
    return str(group_name) if group_name else None


def _preferred_fib_client_ids(route: t.Any) -> set[int]:
    """Return preferred forwarding clients without guessing ambiguous state."""
    candidates = list(getattr(route, "nextHopMulti", None) or ())
    preferred = {
        int(candidate.clientId)
        for candidate in candidates
        if getattr(candidate, "clientId", None) is not None
        and getattr(candidate, "isPreferred", None) is True
    }
    if preferred:
        return preferred
    if any(
        getattr(candidate, "isPreferred", None) is not None for candidate in candidates
    ):
        return set()

    route_distance = getattr(route, "adminDistance", None)
    if route_distance is not None:
        matching = {
            int(candidate.clientId)
            for candidate in candidates
            if getattr(candidate, "clientId", None) is not None
            and getattr(candidate, "adminDistance", None) == route_distance
        }
        if len(matching) == 1:
            return matching
    if len(candidates) == 1 and getattr(candidates[0], "clientId", None) is not None:
        return {int(candidates[0].clientId)}
    return set()


def _candidate_client_ids(route: t.Any) -> set[int]:
    return {
        int(candidate.clientId)
        for candidate in (getattr(route, "nextHopMulti", None) or ())
        if getattr(candidate, "clientId", None) is not None
    }


def _enum_int(value: t.Any) -> int:
    return int(getattr(value, "value", value))


def _member_signature(next_hop: t.Any) -> tuple[t.Any, ...]:
    address = next_hop.address
    segments = tuple(
        str(_packed_address(segment))
        for segment in (getattr(next_hop, "srv6SegmentList", None) or ())
    )
    tunnel_type = getattr(next_hop, "tunnelType", None)
    return (
        str(_packed_address(address)),
        str(address.ifName) if getattr(address, "ifName", None) else None,
        int(getattr(next_hop, "weight", 0)),
        segments,
        _enum_int(tunnel_type) if tunnel_type is not None else None,
        getattr(next_hop, "tunnelId", None),
    )


def _expected_member_signatures(
    members: t.Sequence[t.Mapping[str, t.Any]], tunnel_type: t.Any
) -> list[tuple[t.Any, ...]]:
    signatures = [
        (
            str(member["address"]),
            member["interface"],
            member["weight"],
            tuple(str(segment) for segment in member["srv6_segments"]),
            _enum_int(tunnel_type),
            member["tunnel_id"],
        )
        for member in members
    ]
    return sorted(signatures, key=repr)


def _fib_signatures_match(
    expected: t.Sequence[tuple[t.Any, ...]],
    observed: t.Sequence[tuple[t.Any, ...]],
) -> bool:
    """Match exact NHEs while allowing FBOSS to resolve a global NH interface.

    A caller-supplied link-local member includes an interface and must match it
    exactly. A global member intentionally omits the interface, but RouteDetails
    may enrich that member with its resolved egress interface.
    """
    if len(expected) != len(observed):
        return False
    remaining = list(observed)
    for expected_member in expected:
        match_index = next(
            (
                index
                for index, observed_member in enumerate(remaining)
                if expected_member[0] == observed_member[0]
                and expected_member[2:] == observed_member[2:]
                and (
                    expected_member[1] is None
                    or expected_member[1] == observed_member[1]
                )
            ),
            None,
        )
        if match_index is None:
            return False
        remaining.pop(match_index)
    return not remaining


class RbbSrv6NamedNhgTask(BaseTask):
    """Program and verify one playbook-owned named SRv6 NHG and route."""

    # pyrefly: ignore [bad-override-mutable-attribute]
    NAME: str = "rbb_srv6_named_nhg"

    def __init__(
        self,
        hostname: str | None = None,
        description: str | None = None,
        ixia: t.Any | None = None,
        logger: ConsoleFileLogger | None = None,
        shared_data: dict[t.Any, t.Any] | None = None,
    ) -> None:
        super().__init__(hostname, description, ixia, logger, shared_data)

    @staticmethod
    def _group_key(hostname: str, group_name: str) -> str:
        return f"owned:group:{hostname}:{group_name}"

    @staticmethod
    def _route_key(
        hostname: str, route_prefix: ipaddress.IPv6Network, client: str
    ) -> str:
        return f"owned:route:{hostname}:{route_prefix.with_prefixlen}:{client}"

    @staticmethod
    def _members_key(hostname: str, group_name: str) -> str:
        return f"expected:group-members:{hostname}:{group_name}"

    @staticmethod
    def _resolved_members_key(hostname: str, group_name: str) -> str:
        return f"expected:resolved-fib-members:{hostname}:{group_name}"

    @staticmethod
    def _anchor_key(
        hostname: str, anchor_prefix: ipaddress.IPv6Network, client: str
    ) -> str:
        return (
            f"owned:underlay-anchor:{hostname}:"
            f"{anchor_prefix.with_prefixlen}:{client}"
        )

    def _is_owned(self, key: str) -> bool:
        return key in self._data and self._data[key] is True

    async def run(self, params: dict[str, t.Any]) -> None:
        normalized = _normalize_params(params, self.hostname)

        # Resolve generated enums before contacting the DUT so a typo is a
        # configuration error rather than an apparent device failure.
        from neteng.fboss.ctrl.types import AdminDistance, ClientID

        try:
            client_member = getattr(ClientID, normalized["client"])
        except AttributeError as exc:
            raise ValueError(
                f"unknown FBOSS ClientID {normalized['client']!r}"
            ) from exc
        competing_client_id = None
        if normalized["competing_client"] is not None:
            try:
                competing_client_id = _enum_int(
                    getattr(ClientID, normalized["competing_client"])
                )
            except AttributeError as exc:
                raise ValueError(
                    "unknown FBOSS ClientID "
                    f"{normalized['competing_client']!r}"
                ) from exc
        member_source_client_id = None
        if normalized["member_source_client"] is not None:
            try:
                member_source_client_id = _enum_int(
                    getattr(ClientID, normalized["member_source_client"])
                )
            except AttributeError as exc:
                raise ValueError(
                    "unknown FBOSS ClientID "
                    f"{normalized['member_source_client']!r}"
                ) from exc
        try:
            admin_distance = getattr(AdminDistance, normalized["admin_distance"])
        except AttributeError as exc:
            raise ValueError(
                "unknown FBOSS AdminDistance " f"{normalized['admin_distance']!r}"
            ) from exc

        driver = await async_get_device_driver(normalized["hostname"])
        await self._run_fboss_thrift(
            driver,
            normalized,
            client_id=_enum_int(client_member),
            competing_client_id=competing_client_id,
            member_source_client_id=member_source_client_id,
            admin_distance=admin_distance,
        )

    async def _read_group(self, agent: t.Any, group_name: str) -> t.Any | None:
        groups = list(await agent.getNamedNextHopGroups([group_name]))
        matching = [
            group for group in groups if getattr(group, "name", None) == group_name
        ]
        unexpected = [
            getattr(group, "name", None)
            for group in groups
            if getattr(group, "name", None) != group_name
        ]
        if unexpected or len(matching) > 1:
            raise TestCaseFailure(
                "FBOSS returned an invalid named-NHG readback for "
                f"{group_name!r}: unexpected={unexpected!r}, matches={len(matching)}"
            )
        return matching[0] if matching else None

    def _assert_group_matches(
        self,
        hostname: str,
        group: t.Any | None,
        group_name: str,
        members: t.Sequence[t.Mapping[str, t.Any]],
        tunnel_type: t.Any,
        expected_programmed: bool | None,
    ) -> None:
        if group is None:
            raise TestCaseFailure(
                f"{hostname}: named next-hop group {group_name!r} is absent"
            )
        observed = sorted(
            (
                _member_signature(next_hop)
                for next_hop in (getattr(group, "nexthops", None) or ())
            ),
            key=repr,
        )
        expected = _expected_member_signatures(members, tunnel_type)
        if not _fib_signatures_match(expected, observed):
            raise TestCaseFailure(
                f"{hostname}: named next-hop group {group_name!r} member mismatch; "
                f"expected={expected!r}, observed={observed!r}"
            )
        if expected_programmed is not None:
            programmed = getattr(group, "isProgrammed", None)
            if programmed is None or bool(programmed) != expected_programmed:
                raise TestCaseFailure(
                    f"{hostname}: named next-hop group {group_name!r} "
                    f"isProgrammed expected={expected_programmed}, "
                    f"observed={programmed!r}"
                )

    @staticmethod
    async def _client_route(
        agent: t.Any,
        client_id: int,
        route_prefix: ipaddress.IPv6Network,
    ) -> t.Any | None:
        matches = [
            route
            for route in await agent.getRouteTableByClient(client_id)
            if _route_prefix(route) == route_prefix.with_prefixlen
        ]
        if len(matches) > 1:
            raise TestCaseFailure(
                "FBOSS returned duplicate client routes for "
                f"{route_prefix.with_prefixlen}"
            )
        return matches[0] if matches else None

    @staticmethod
    def _assert_named_route(
        hostname: str,
        route: t.Any | None,
        route_prefix: ipaddress.IPv6Network,
        group_name: str,
        client: str,
    ) -> None:
        if route is None:
            raise TestCaseFailure(
                f"{hostname}: {client} route {route_prefix.with_prefixlen} is absent"
            )
        observed_group = _named_destination(route)
        if observed_group != group_name:
            raise TestCaseFailure(
                f"{hostname}: {client} route {route_prefix.with_prefixlen} "
                f"references {observed_group!r}, expected {group_name!r}"
            )

    @staticmethod
    def _assert_client_candidate(
        hostname: str,
        details: t.Sequence[t.Any],
        route_prefix: ipaddress.IPv6Network,
        group_name: str,
        client: str,
        client_id: int,
        admin_distance: t.Any,
    ) -> t.Any:
        """Validate the per-client RIB entry exposed by RouteDetails.

        getRouteTableByClient() preserves the named destination but omits the
        administrative distance and may include resolved next hops.  The
        ClientAndNextHops entry is therefore the authoritative readback for
        client ownership, distance, and the original named destination.
        """
        matches = [
            candidate
            for detail in details
            for candidate in (getattr(detail, "nextHopMulti", None) or ())
            if getattr(candidate, "clientId", None) is not None
            and int(candidate.clientId) == client_id
        ]
        if len(matches) != 1:
            raise TestCaseFailure(
                f"{hostname}: expected exactly one {client} RIB candidate for "
                f"{route_prefix.with_prefixlen}, found {len(matches)}"
            )
        candidate = matches[0]
        observed_group = _named_destination(candidate)
        if observed_group != group_name:
            raise TestCaseFailure(
                f"{hostname}: {client} RIB candidate for "
                f"{route_prefix.with_prefixlen} references "
                f"{observed_group!r}, expected {group_name!r}"
            )
        observed_distance = getattr(candidate, "adminDistance", None)
        if observed_distance is None or _enum_int(observed_distance) != _enum_int(
            admin_distance
        ):
            raise TestCaseFailure(
                f"{hostname}: {client} RIB candidate for "
                f"{route_prefix.with_prefixlen} has an unexpected admin "
                f"distance; expected={_enum_int(admin_distance)}, "
                f"observed={observed_distance!r}"
            )
        return candidate

    @staticmethod
    def _assert_client_candidate_absent(
        hostname: str,
        details: t.Sequence[t.Any],
        route_prefix: ipaddress.IPv6Network,
        client: str,
        client_id: int,
    ) -> None:
        if any(client_id in _candidate_client_ids(detail) for detail in details):
            raise TestCaseFailure(
                f"{hostname}: rejected {client} route "
                f"{route_prefix.with_prefixlen} left a RIB candidate"
            )

    @staticmethod
    async def _route_details(
        agent: t.Any, route_prefix: ipaddress.IPv6Network
    ) -> list[t.Any]:
        return [
            route
            for route in await agent.getRouteTableDetails()
            if _route_prefix(route) == route_prefix.with_prefixlen
        ]

    @staticmethod
    async def _fib_route(
        agent: t.Any, route_prefix: ipaddress.IPv6Network
    ) -> t.Any | None:
        """Read one resolved agent-FIB route, excluding unresolved RIB state."""
        matches = [
            route
            for route in await agent.getRouteTable()
            if _route_prefix(route) == route_prefix.with_prefixlen
        ]
        if len(matches) > 1:
            raise TestCaseFailure(
                "FBOSS returned duplicate resolved routes for "
                f"{route_prefix.with_prefixlen}"
            )
        return matches[0] if matches else None

    @staticmethod
    def _assert_rib_only(
        hostname: str,
        details: t.Sequence[t.Any],
        route_prefix: ipaddress.IPv6Network,
        group_name: str,
        client: str,
        client_id: int,
        admin_distance: t.Any,
        fib_route: t.Any | None,
    ) -> None:
        candidate = RbbSrv6NamedNhgTask._assert_client_candidate(
            hostname,
            details,
            route_prefix,
            group_name,
            client,
            client_id,
            admin_distance,
        )
        if getattr(candidate, "nextHops", None) or getattr(
            candidate, "nextHopAddrs", None
        ):
            raise TestCaseFailure(
                f"{hostname}: {client} RIB candidate for "
                f"{route_prefix.with_prefixlen} has resolved next hops; "
                "expected unresolved RIB-only state"
            )
        # The prefix may legitimately remain resolved through another client
        # (for example, the lower-priority BGPD route used by the source test
        # plan). The candidate above is RIB-only when its own resolved next-hop
        # fields are empty. Some FBOSS versions also preserve a named
        # destination in getRouteTable(), so reject that stronger signal when
        # available.
        if fib_route is not None and _named_destination(fib_route) == group_name:
            raise TestCaseFailure(
                f"{hostname}: {client} route {route_prefix.with_prefixlen} "
                f"resolved through named NHG {group_name!r}; expected RIB-only "
                "state"
            )

    @staticmethod
    def _assert_programmed_fib(
        hostname: str,
        details: t.Sequence[t.Any],
        route_prefix: ipaddress.IPv6Network,
        group_name: str,
        client: str,
        client_id: int,
        competing_client: str | None,
        competing_client_id: int | None,
        admin_distance: t.Any,
        fib_route: t.Any | None,
        members: t.Sequence[t.Mapping[str, t.Any]],
        tunnel_type: t.Any,
    ) -> None:
        winner = RbbSrv6NamedNhgTask._assert_client_candidate(
            hostname,
            details,
            route_prefix,
            group_name,
            client,
            client_id,
            admin_distance,
        )
        if competing_client_id is not None:
            competitors = [
                candidate
                for detail in details
                for candidate in (getattr(detail, "nextHopMulti", None) or ())
                if getattr(candidate, "clientId", None) is not None
                and int(candidate.clientId) == competing_client_id
            ]
            if len(competitors) != 1:
                raise TestCaseFailure(
                    f"{hostname}: expected exactly one {competing_client} "
                    f"candidate for {route_prefix.with_prefixlen}, found "
                    f"{len(competitors)}"
                )
            loser = competitors[0]
            winner_distance = getattr(winner, "adminDistance", None)
            loser_distance = getattr(loser, "adminDistance", None)
            if loser_distance is None or _enum_int(winner_distance) >= _enum_int(
                loser_distance
            ):
                raise TestCaseFailure(
                    f"{hostname}: {client} does not have a better admin distance "
                    f"than {competing_client} for {route_prefix.with_prefixlen}; "
                    f"winner={winner_distance!r}, competitor={loser_distance!r}"
                )
            if competing_client_id in {
                owner
                for detail in details
                for owner in _preferred_fib_client_ids(detail)
            }:
                raise TestCaseFailure(
                    f"{hostname}: {competing_client} unexpectedly remains "
                    f"preferred for {route_prefix.with_prefixlen}"
                )
        if not any(
            client_id in _preferred_fib_client_ids(detail) for detail in details
        ):
            observed = sorted(
                {
                    candidate
                    for detail in details
                    for candidate in _preferred_fib_client_ids(detail)
                }
            )
            raise TestCaseFailure(
                f"{hostname}: {client} is not the preferred RIB candidate for "
                f"{route_prefix.with_prefixlen}; observed_client_ids={observed}"
            )
        if fib_route is None:
            raise TestCaseFailure(
                f"{hostname}: {client} route {route_prefix.with_prefixlen} "
                "is absent from the resolved agent FIB"
            )
        observed_next_hops = sorted(
            (
                _member_signature(next_hop)
                for next_hop in (getattr(fib_route, "nextHops", None) or ())
            ),
            key=repr,
        )
        expected_next_hops = _expected_member_signatures(members, tunnel_type)
        if not _fib_signatures_match(expected_next_hops, observed_next_hops):
            raise TestCaseFailure(
                f"{hostname}: resolved agent-FIB route "
                f"{route_prefix.with_prefixlen} next-hop mismatch; "
                f"expected={expected_next_hops!r}, "
                f"observed={observed_next_hops!r}"
            )

    @staticmethod
    def _missing_group_rejection(exc: BaseException, group_name: str) -> bool:
        message = str(exc).lower().replace("_", " ").replace("-", " ")
        normalized_name = group_name.lower().replace("_", " ").replace("-", " ")
        return (
            normalized_name in message
            and "named next hop group" in message
            and any(
                marker in message
                for marker in ("does not exist", "non existent", "not found")
            )
        )

    async def _run_fboss_thrift(
        self,
        driver: t.Any,
        params: t.Mapping[str, t.Any],
        *,
        client_id: int,
        competing_client_id: int | None,
        member_source_client_id: int | None,
        admin_distance: t.Any,
    ) -> None:
        from facebook.network.Address.types import BinaryAddress
        from neteng.fboss.common.types import (
            NamedRouteDestination,
            NextHopGroup,
            NextHopThrift,
            TunnelType,
        )
        from neteng.fboss.ctrl.types import IpPrefix, UnicastRoute
        from neteng.fboss.fboss.types import FbossBaseError

        hostname = params["hostname"]
        action = params["action"]
        group_name = params["group_name"]
        route_prefix = params["route_prefix"]
        underlay_anchor_prefix = params["underlay_anchor_prefix"]
        member_source_client = params["member_source_client"]
        member_source_prefix = params["member_source_prefix"]
        client = params["client"]
        competing_client = params["competing_client"]
        members = params["members"]
        expected_programmed = params["expected_programmed"]
        group_key = self._group_key(hostname, group_name)
        route_key = self._route_key(hostname, route_prefix, client)
        members_key = self._members_key(hostname, group_name)
        resolved_members_key = self._resolved_members_key(hostname, group_name)
        anchor_key = (
            self._anchor_key(hostname, underlay_anchor_prefix, client)
            if underlay_anchor_prefix is not None
            else None
        )

        def _serializable_members(
            values: t.Sequence[t.Mapping[str, t.Any]],
        ) -> tuple[tuple[t.Any, ...], ...]:
            return tuple(
                (
                    str(member["address"]),
                    member["interface"],
                    member["weight"],
                    tuple(str(segment) for segment in member["srv6_segments"]),
                    member["tunnel_id"],
                )
                for member in values
            )

        def _shared_members() -> tuple[dict[str, t.Any], ...]:
            if members_key not in self._data:
                raise TestCaseFailure(
                    f"{hostname}: expected members for named NHG {group_name!r} "
                    "are absent from this playbook's shared state"
                )
            values = self._data[members_key]
            return tuple(
                {
                    "address": ipaddress.IPv6Address(value[0]),
                    "interface": value[1],
                    "weight": value[2],
                    "srv6_segments": tuple(
                        ipaddress.IPv6Address(segment) for segment in value[3]
                    ),
                    "tunnel_id": value[4],
                }
                for value in values
            )

        def _make_group(
            source_next_hops: t.Sequence[t.Any] | None = None,
        ) -> tuple[t.Any, tuple[dict[str, t.Any], ...]]:
            next_hops = []
            expected_members: list[dict[str, t.Any]] = []
            templates = t.cast(t.Sequence[t.Mapping[str, t.Any]], members)
            if source_next_hops is not None:
                if len(source_next_hops) > len(templates):
                    raise TestCaseFailure(
                        f"{hostname}: {member_source_client} route "
                        f"{member_source_prefix.with_prefixlen} has "
                        f"{len(source_next_hops)} next hops, but the SRv6 profile "
                        f"provides only {len(templates)} SID-list template(s)"
                    )
                # The live route contains only currently usable forwarding
                # paths.  It may legitimately expose fewer paths than the
                # topology declares (for example, while one core path is not
                # selected).  Build the test NHG from that active subset so
                # TC-04 validates the load-bearing path rather than requiring
                # every configured core link to be active.
                selected_templates = templates[: len(source_next_hops)]
            else:
                selected_templates = templates
            for index, template in enumerate(selected_templates):
                source = source_next_hops[index] if source_next_hops is not None else None
                if source is None:
                    address = template["address"]
                    interface = template["interface"]
                    weight = template["weight"]
                    address_kwargs: dict[str, t.Any] = {"addr": address.packed}
                    if interface is not None:
                        address_kwargs["ifName"] = interface
                    kwargs: dict[str, t.Any] = {
                        "address": BinaryAddress(**address_kwargs),
                        "weight": weight,
                    }
                else:
                    address = _packed_address(source.address)
                    interface = getattr(source.address, "ifName", None) or None
                    # Route-table clients use zero for an unspecified/default
                    # ECMP weight. Named NHGs and the resolved FIB expose that
                    # same equal-cost member as the explicit portable weight 1.
                    weight = int(getattr(source, "weight", 0)) or 1
                    kwargs = {"address": source.address, "weight": weight}
                    for field in (
                        "mplsAction",
                        "disableTTLDecrement",
                        "adjustedWeight",
                        "topologyInfo",
                        "cost",
                        "role",
                        "backupNexthops",
                    ):
                        if hasattr(source, field) and hasattr(NextHopThrift, field):
                            kwargs[field] = getattr(source, field)
                kwargs.update(
                    {
                        "srv6SegmentList": [
                            BinaryAddress(addr=segment.packed)
                            for segment in template["srv6_segments"]
                        ],
                        "tunnelType": TunnelType.SRV6_ENCAP,
                        "tunnelId": template["tunnel_id"],
                    }
                )
                next_hops.append(NextHopThrift(**kwargs))
                expected_members.append(
                    {
                        "address": address,
                        "interface": interface,
                        "weight": weight,
                        "srv6_segments": template["srv6_segments"],
                        "tunnel_id": template["tunnel_id"],
                    }
                )
            return (
                NextHopGroup(name=group_name, nexthops=next_hops),
                tuple(expected_members),
            )

        def _make_underlay_anchor() -> t.Any:
            if underlay_anchor_prefix is None:
                raise AssertionError("underlay anchor prefix is absent")
            next_hops = []
            for member in t.cast(t.Sequence[t.Mapping[str, t.Any]], members):
                address_kwargs: dict[str, t.Any] = {
                    "addr": member["address"].packed
                }
                if member["interface"] is not None:
                    address_kwargs["ifName"] = member["interface"]
                next_hops.append(
                    NextHopThrift(
                        address=BinaryAddress(**address_kwargs),
                        weight=member["weight"],
                    )
                )
            return UnicastRoute(
                dest=IpPrefix(
                    ip=BinaryAddress(
                        addr=underlay_anchor_prefix.network_address.packed
                    ),
                    prefixLength=underlay_anchor_prefix.prefixlen,
                ),
                nextHopAddrs=[],
                nextHops=next_hops,
                adminDistance=admin_distance,
            )

        route = UnicastRoute(
            dest=IpPrefix(
                ip=BinaryAddress(addr=route_prefix.network_address.packed),
                prefixLength=route_prefix.prefixlen,
            ),
            nextHopAddrs=[],
            nextHops=[],
            adminDistance=admin_distance,
            namedRouteDestination=NamedRouteDestination(nextHopGroup=group_name),
        )

        async with driver.async_agent_client as agent:
            if action == _PRECHECK:
                if await self._read_group(agent, group_name) is not None:
                    raise TestCaseFailure(
                        f"{hostname}: named next-hop group {group_name!r} already "
                        "exists; refusing to adopt an operator-owned group"
                    )
                if await self._client_route(agent, client_id, route_prefix) is not None:
                    raise TestCaseFailure(
                        f"{hostname}: {client} already owns "
                        f"{route_prefix.with_prefixlen}; refusing to adopt an "
                        "operator-owned route"
                    )
                if (
                    underlay_anchor_prefix is not None
                    and await self._client_route(
                        agent, client_id, underlay_anchor_prefix
                    )
                    is not None
                ):
                    raise TestCaseFailure(
                        f"{hostname}: {client} already owns underlay anchor "
                        f"{underlay_anchor_prefix.with_prefixlen}; refusing to "
                        "adopt an operator-owned route"
                    )
                return

            if action == _PROGRAM_NHG:
                existing = await self._read_group(agent, group_name)
                if existing is not None:
                    if not self._is_owned(group_key):
                        raise TestCaseFailure(
                            f"{hostname}: named next-hop group {group_name!r} "
                            "already exists; refusing to replace it"
                        )
                    self._assert_group_matches(
                        hostname,
                        existing,
                        group_name,
                        t.cast(t.Sequence[t.Mapping[str, t.Any]], members),
                        TunnelType.SRV6_ENCAP,
                        expected_programmed,
                    )
                    self._data[members_key] = _serializable_members(
                        t.cast(t.Sequence[t.Mapping[str, t.Any]], members)
                    )
                    return

                if underlay_anchor_prefix is not None:
                    existing_anchor = await self._client_route(
                        agent, client_id, underlay_anchor_prefix
                    )
                    if existing_anchor is not None and not self._is_owned(
                        t.cast(str, anchor_key)
                    ):
                        raise TestCaseFailure(
                            f"{hostname}: {client} already owns underlay anchor "
                            f"{underlay_anchor_prefix.with_prefixlen}; refusing "
                            "to replace it"
                        )
                    if existing_anchor is None:
                        self._data[t.cast(str, anchor_key)] = True
                        anchor = _make_underlay_anchor()
                        await agent.addUnicastRoutes(client_id, [anchor])
                        if (
                            await self._client_route(
                                agent, client_id, underlay_anchor_prefix
                            )
                            is None
                        ):
                            raise TestCaseFailure(
                                f"{hostname}: underlay anchor "
                                f"{underlay_anchor_prefix.with_prefixlen} was "
                                "not readable after install"
                            )

                source_next_hops = None
                source_fib_next_hops: tuple[t.Any, ...] = ()
                if member_source_client_id is not None:
                    source_route = await self._client_route(
                        agent,
                        member_source_client_id,
                        t.cast(ipaddress.IPv6Network, member_source_prefix),
                    )
                    if source_route is None:
                        raise TestCaseFailure(
                            f"{hostname}: cannot build named SRv6 NHG "
                            f"{group_name!r}; exact {member_source_client} route "
                            f"{member_source_prefix.with_prefixlen} is absent"
                        )
                    source_next_hops = tuple(
                        getattr(source_route, "nextHops", None) or ()
                    )
                    if not source_next_hops:
                        raise TestCaseFailure(
                            f"{hostname}: {member_source_client} route "
                            f"{member_source_prefix.with_prefixlen} has no "
                            "structured forwarding next hops to clone"
                        )
                    source_fib = await self._fib_route(
                        agent,
                        t.cast(ipaddress.IPv6Network, member_source_prefix),
                    )
                    source_fib_next_hops = tuple(
                        getattr(source_fib, "nextHops", None) or ()
                    )
                    if not source_fib_next_hops:
                        raise TestCaseFailure(
                            f"{hostname}: {member_source_client} route "
                            f"{member_source_prefix.with_prefixlen} has no "
                            "resolved agent-FIB next hops to snapshot"
                        )

                group, programmed_members = _make_group(source_next_hops)
                if source_fib_next_hops:
                    actions = {
                        (
                            tuple(member["srv6_segments"]),
                            member["tunnel_id"],
                        )
                        for member in programmed_members
                    }
                    if len(actions) != 1:
                        raise TestCaseFailure(
                            f"{hostname}: cannot map recursively flattened FIB "
                            f"members for {group_name!r} because its active "
                            "logical members use different SRv6 actions"
                        )
                    segments, tunnel_id = next(iter(actions))
                    resolved_members = tuple(
                        {
                            "address": _packed_address(next_hop.address),
                            "interface": (
                                getattr(next_hop.address, "ifName", None) or None
                            ),
                            "weight": int(getattr(next_hop, "weight", 0)) or 1,
                            "srv6_segments": segments,
                            "tunnel_id": tunnel_id,
                        }
                        for next_hop in source_fib_next_hops
                    )
                    self._data[resolved_members_key] = _serializable_members(
                        resolved_members
                    )
                self._data[group_key] = True
                self._data[members_key] = _serializable_members(programmed_members)
                add_named = getattr(agent, "addNamedNextHopGroups", None)
                if add_named is not None:
                    await add_named([group])
                else:
                    # Compatibility with FBOSS clients generated before the
                    # nondeprecated RPC was added. Never retry through the old
                    # method after a preferred-RPC failure.
                    fallback = getattr(agent, "addOrUpdateNamedNextHopGroups", None)
                    if fallback is None:
                        raise TestCaseFailure(
                            "FBOSS client exposes neither addNamedNextHopGroups "
                            "nor its deprecated compatibility predecessor"
                        )
                    await fallback([group])
                programmed = await self._read_group(agent, group_name)
                self._assert_group_matches(
                    hostname,
                    programmed,
                    group_name,
                    programmed_members,
                    TunnelType.SRV6_ENCAP,
                    expected_programmed,
                )
                self.logger.info(
                    f"{hostname} -- programmed named SRv6 NHG {group_name!r} "
                    f"with {len(programmed_members)} active member(s)"
                )
                return

            if action == _VERIFY_NHG:
                verify_members = (
                    _shared_members()
                    if members_key in self._data
                    else t.cast(t.Sequence[t.Mapping[str, t.Any]], members)
                )
                self._assert_group_matches(
                    hostname,
                    await self._read_group(agent, group_name),
                    group_name,
                    verify_members,
                    TunnelType.SRV6_ENCAP,
                    expected_programmed,
                )
                return

            if action in {_INSTALL_FORWARD_REF, _PROGRAM_ROUTE}:
                group = await self._read_group(agent, group_name)
                if action == _INSTALL_FORWARD_REF and group is not None:
                    raise TestCaseFailure(
                        f"{hostname}: forward-reference setup requires named NHG "
                        f"{group_name!r} to be absent"
                    )
                if action == _PROGRAM_ROUTE:
                    expected_members = _shared_members()
                    self._assert_group_matches(
                        hostname,
                        group,
                        group_name,
                        expected_members,
                        TunnelType.SRV6_ENCAP,
                        None,
                    )

                existing = await self._client_route(agent, client_id, route_prefix)
                if existing is not None:
                    if not self._is_owned(route_key):
                        raise TestCaseFailure(
                            f"{hostname}: {client} already owns "
                            f"{route_prefix.with_prefixlen}; refusing to replace it"
                        )
                    self._assert_named_route(
                        hostname,
                        existing,
                        route_prefix,
                        group_name,
                        client,
                    )
                    self._assert_client_candidate(
                        hostname,
                        await self._route_details(agent, route_prefix),
                        route_prefix,
                        group_name,
                        client,
                        client_id,
                        admin_distance,
                    )
                    return

                self._data[route_key] = True
                try:
                    await agent.addUnicastRoutes(client_id, [route])
                except FbossBaseError as exc:
                    missing_group = self._missing_group_rejection(exc, group_name)
                    if action != _INSTALL_FORWARD_REF or not missing_group:
                        raise
                    # FBOSS documents this update as atomic. Prove the device
                    # has no residue before classifying the semantic as
                    # unsupported on this version.
                    if await self._read_group(agent, group_name) is not None:
                        raise TestCaseFailure(
                            f"{hostname}: rejected forward reference unexpectedly "
                            f"created named NHG {group_name!r}"
                        ) from exc
                    residue = await self._client_route(agent, client_id, route_prefix)
                    if residue is not None:
                        raise TestCaseFailure(
                            f"{hostname}: rejected forward reference left "
                            f"{client} route {route_prefix.with_prefixlen} in the RIB"
                        ) from exc
                    details = await self._route_details(agent, route_prefix)
                    self._assert_client_candidate_absent(
                        hostname,
                        details,
                        route_prefix,
                        client,
                        client_id,
                    )
                    self._data[route_key] = False
                    raise unittest.SkipTest(
                        "This FBOSS version atomically rejects routes that "
                        "reference a missing named next-hop group; RIB-only "
                        "forward-reference semantics are unsupported"
                    ) from exc

                installed = await self._client_route(agent, client_id, route_prefix)
                self._assert_named_route(
                    hostname,
                    installed,
                    route_prefix,
                    group_name,
                    client,
                )
                if action == _INSTALL_FORWARD_REF:
                    if await self._read_group(agent, group_name) is not None:
                        raise TestCaseFailure(
                            f"{hostname}: named NHG {group_name!r} appeared while "
                            "validating a forward reference"
                        )
                    self._assert_rib_only(
                        hostname,
                        await self._route_details(agent, route_prefix),
                        route_prefix,
                        group_name,
                        client,
                        client_id,
                        admin_distance,
                        await self._fib_route(agent, route_prefix),
                    )
                else:
                    self._assert_client_candidate(
                        hostname,
                        await self._route_details(agent, route_prefix),
                        route_prefix,
                        group_name,
                        client,
                        client_id,
                        admin_distance,
                    )
                return

            if action == _VERIFY_RIB_ONLY:
                if await self._read_group(agent, group_name) is not None:
                    raise TestCaseFailure(
                        f"{hostname}: named NHG {group_name!r} must remain absent "
                        "for RIB-only verification"
                    )
                rib_route = await self._client_route(agent, client_id, route_prefix)
                self._assert_named_route(
                    hostname,
                    rib_route,
                    route_prefix,
                    group_name,
                    client,
                )
                self._assert_rib_only(
                    hostname,
                    await self._route_details(agent, route_prefix),
                    route_prefix,
                    group_name,
                    client,
                    client_id,
                    admin_distance,
                    await self._fib_route(agent, route_prefix),
                )
                return

            if action == _VERIFY_PROGRAMMED:
                expected_members = _shared_members()
                expected_fib_members = (
                    tuple(
                        {
                            "address": ipaddress.IPv6Address(value[0]),
                            "interface": value[1],
                            "weight": value[2],
                            "srv6_segments": tuple(
                                ipaddress.IPv6Address(segment)
                                for segment in value[3]
                            ),
                            "tunnel_id": value[4],
                        }
                        for value in self._data[resolved_members_key]
                    )
                    if resolved_members_key in self._data
                    else expected_members
                )
                group = await self._read_group(agent, group_name)
                self._assert_group_matches(
                    hostname,
                    group,
                    group_name,
                    expected_members,
                    TunnelType.SRV6_ENCAP,
                    True,
                )
                rib_route = await self._client_route(agent, client_id, route_prefix)
                self._assert_named_route(
                    hostname,
                    rib_route,
                    route_prefix,
                    group_name,
                    client,
                )
                self._assert_programmed_fib(
                    hostname,
                    await self._route_details(agent, route_prefix),
                    route_prefix,
                    group_name,
                    client,
                    client_id,
                    competing_client,
                    competing_client_id,
                    admin_distance,
                    await self._fib_route(agent, route_prefix),
                    expected_fib_members,
                    TunnelType.SRV6_ENCAP,
                )
                return

            if action == _CLEANUP:
                # A named group cannot be deleted while a route references it.
                # Attempt the route first, then the group. Preserve cancellation
                # while still making the second best-effort cleanup attempt.
                failures: list[str] = []
                cancellation: asyncio.CancelledError | None = None
                if self._is_owned(route_key):
                    try:
                        existing_route = await self._client_route(
                            agent, client_id, route_prefix
                        )
                        if existing_route is not None:
                            self._assert_named_route(
                                hostname,
                                existing_route,
                                route_prefix,
                                group_name,
                                client,
                            )
                            self._assert_client_candidate(
                                hostname,
                                await self._route_details(agent, route_prefix),
                                route_prefix,
                                group_name,
                                client,
                                client_id,
                                admin_distance,
                            )
                            await agent.deleteUnicastRoutes(client_id, [route.dest])
                            if (
                                await self._client_route(agent, client_id, route_prefix)
                                is not None
                            ):
                                raise TestCaseFailure(
                                    f"{hostname}: {client} route "
                                    f"{route_prefix.with_prefixlen} remained "
                                    "after delete"
                                )
                        self._data[route_key] = False
                    except asyncio.CancelledError as exc:
                        cancellation = exc
                        self.logger.exception(
                            f"{hostname}: named-NHG route cleanup was cancelled; "
                            "continuing with group cleanup"
                        )
                    except Exception as exc:
                        failures.append(f"route cleanup: {exc}")
                        self.logger.exception(
                            f"{hostname}: named-NHG route cleanup failed; "
                            "continuing with group cleanup"
                        )

                group_removed = not self._is_owned(group_key)
                if self._is_owned(group_key):
                    try:
                        existing_group = await self._read_group(agent, group_name)
                        if existing_group is not None:
                            cleanup_members = (
                                _shared_members()
                                if members_key in self._data
                                else t.cast(
                                    t.Sequence[t.Mapping[str, t.Any]], members
                                )
                            )
                            self._assert_group_matches(
                                hostname,
                                existing_group,
                                group_name,
                                cleanup_members,
                                TunnelType.SRV6_ENCAP,
                                None,
                            )
                            await agent.deleteNamedNextHopGroups([group_name])
                            if await self._read_group(agent, group_name) is not None:
                                raise TestCaseFailure(
                                    f"{hostname}: named next-hop group "
                                    f"{group_name!r} remained after delete"
                                )
                        self._data[group_key] = False
                        group_removed = True
                    except asyncio.CancelledError as exc:
                        if cancellation is None:
                            cancellation = exc
                        else:
                            cancellation.add_note(
                                "Named-NHG group cleanup was also cancelled."
                            )
                        self.logger.exception(
                            f"{hostname}: named-NHG group cleanup was cancelled"
                        )
                    except Exception as exc:
                        failures.append(f"group cleanup: {exc}")
                        self.logger.exception(
                            f"{hostname}: named-NHG group cleanup failed"
                        )

                if (
                    group_removed
                    and underlay_anchor_prefix is not None
                    and self._is_owned(t.cast(str, anchor_key))
                ):
                    try:
                        existing_anchor = await self._client_route(
                            agent, client_id, underlay_anchor_prefix
                        )
                        if existing_anchor is not None:
                            await agent.deleteUnicastRoutes(
                                client_id, [existing_anchor.dest]
                            )
                            if (
                                await self._client_route(
                                    agent, client_id, underlay_anchor_prefix
                                )
                                is not None
                            ):
                                raise TestCaseFailure(
                                    f"{hostname}: underlay anchor "
                                    f"{underlay_anchor_prefix.with_prefixlen} "
                                    "remained after delete"
                                )
                        self._data[t.cast(str, anchor_key)] = False
                    except asyncio.CancelledError as exc:
                        if cancellation is None:
                            cancellation = exc
                        else:
                            cancellation.add_note(
                                "Named-NHG anchor cleanup was also cancelled."
                            )
                        self.logger.exception(
                            f"{hostname}: named-NHG anchor cleanup was cancelled"
                        )
                    except Exception as exc:
                        failures.append(f"anchor cleanup: {exc}")
                        self.logger.exception(
                            f"{hostname}: named-NHG anchor cleanup failed"
                        )

                if cancellation is not None:
                    cancellation.add_note(
                        "Cancellation was deferred until route-first/group-second "
                        "named-NHG cleanup completed."
                    )
                    if failures:
                        cancellation.add_note(
                            "Additional cleanup failure(s): " + "; ".join(failures)
                        )
                    raise cancellation
                if failures:
                    raise TestCaseFailure(
                        "Named-NHG cleanup completed with failure(s): "
                        + "; ".join(failures)
                    )
                return

            raise AssertionError(f"unhandled action {action!r}")


__all__ = ["RbbSrv6NamedNhgTask"]
