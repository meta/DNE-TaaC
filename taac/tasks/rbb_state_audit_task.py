# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Structured, read-only state verification for two-node RBB scenarios.

This task complements ``rbb_srv6_verify``.  The original task intentionally
supports small CLI-token gates used by PR #46; this task provides exact route,
NDP, service, interface, and per-MySID-entry assertions shared by the follow-up
test families.  It remains a registered task so no health-check Thrift schema
change is required.
"""

from __future__ import annotations

import ipaddress
import re
import typing as t

from taac.constants import TestCaseFailure
from taac.driver.driver_constants import (
    FbossSystemctlServiceName,
    SystemctlServiceStatus,
)
from taac.tasks.base_task import BaseTask
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger


def _packed_address(value: t.Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    packed = getattr(value, "addr", value)
    return ipaddress.ip_address(bytes(packed))


def _route_prefix(route: t.Any) -> str:
    dest = route.dest
    address = _packed_address(dest.ip)
    return str(
        ipaddress.ip_network(f"{address}/{int(dest.prefixLength)}", strict=False)
    )


def _resolved_next_hops(
    route: t.Any,
) -> tuple[list[tuple[str, str | None]], set[str], set[str]]:
    """Return resolved FIB next hops, preferring the current Thrift field.

    ``RouteDetails.nextHops[].address`` is authoritative and carries resolved
    interface names. ``nextHopAddrs`` is retained only as an older-agent
    compatibility fallback.
    """
    entries: list[tuple[str, str | None]] = []
    addresses: set[str] = set()
    interfaces: set[str] = set()
    next_hops = getattr(route, "nextHops", None) or ()
    raw_addresses = (
        [next_hop.address for next_hop in next_hops]
        if next_hops
        else list(getattr(route, "nextHopAddrs", None) or ())
    )
    for address in raw_addresses:
        normalized = str(_packed_address(address))
        if_name = getattr(address, "ifName", None)
        entries.append((normalized, str(if_name) if if_name else None))
        addresses.add(normalized)
        if if_name:
            interfaces.add(str(if_name))
    return entries, addresses, interfaces


def _preferred_fib_client_ids(route: t.Any) -> set[int]:
    """Return only clients selected for forwarding, never losing candidates.

    Modern FBOSS agents set ``ClientAndNextHops.isPreferred``. For older
    agents that omit it, a single candidate is unambiguous; matching a unique
    client admin distance to the selected route distance is also safe. Multiple
    candidates without either signal remain unknown and therefore fail closed.
    """
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
        distance_matches = {
            int(candidate.clientId)
            for candidate in candidates
            if getattr(candidate, "clientId", None) is not None
            and getattr(candidate, "adminDistance", None) == route_distance
        }
        if len(distance_matches) == 1:
            return distance_matches
    if len(candidates) == 1 and getattr(candidates[0], "clientId", None) is not None:
        return {int(candidates[0].clientId)}
    return set()


def _strict_bool(value: t.Any, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a boolean")
    return value


def _reject_unknown(raw: t.Mapping[str, t.Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"{label} contains unsupported fields: {unknown}")


def _client_id(client_name: str) -> int:
    """Resolve a generated ClientID lazily so the module stays OSS-importable."""
    normalized = client_name.strip().upper()
    if not normalized:
        raise ValueError("route client must be non-empty")
    try:
        from neteng.fboss.ctrl.types import ClientID

        member = getattr(ClientID, normalized)
    except (ImportError, AttributeError) as exc:
        raise ValueError(f"unknown FBOSS route client {client_name!r}") from exc
    raw = getattr(member, "value", member)
    return int(raw)


def _service(value: str) -> FbossSystemctlServiceName:
    token = value.strip()
    if not token:
        raise ValueError("service name must be non-empty")
    try:
        return FbossSystemctlServiceName[token.upper()]
    except KeyError:
        for service in FbossSystemctlServiceName:
            if service.value == token:
                return service
    raise ValueError(f"unknown FBOSS service {value!r}")


def _normalize_route(raw: t.Mapping[str, t.Any]) -> dict[str, t.Any]:
    _reject_unknown(
        raw,
        {
            "prefix",
            "client",
            "require_fib",
            "fib",
            "next_hops",
            "interfaces",
            "exact_next_hops",
            "next_hop_count",
            "next_hop_interface_count",
            "next_hop_scope",
        },
        "route expectation",
    )
    if "require_fib" in raw and "fib" in raw:
        raise ValueError("route expectation cannot set both require_fib and fib")
    prefix = str(ipaddress.ip_network(str(raw["prefix"]), strict=True))
    client = str(raw["client"]).strip().upper()
    client_id = _client_id(client)
    next_hops = {
        str(ipaddress.ip_address(str(value).split("/", 1)[0]))
        for value in raw.get("next_hops", [])
    }
    interfaces = {str(value).strip() for value in raw.get("interfaces", [])}
    if any(not value for value in interfaces):
        raise ValueError("route interfaces must be non-empty")
    require_fib = _strict_bool(
        raw.get("require_fib", raw.get("fib", True)), "route require_fib"
    )
    exact_next_hops = _strict_bool(
        raw.get("exact_next_hops", True), "route exact_next_hops"
    )
    next_hop_count = raw.get("next_hop_count")
    if next_hop_count is not None:
        if type(next_hop_count) is not int or next_hop_count < 1:
            raise ValueError("route next_hop_count must be a positive integer")
        if next_hops and len(next_hops) != next_hop_count:
            raise ValueError(
                "route next_hop_count must equal the number of exact next_hops"
            )
    next_hop_interface_count = raw.get("next_hop_interface_count")
    if next_hop_interface_count is not None and (
        type(next_hop_interface_count) is not int or next_hop_interface_count < 1
    ):
        raise ValueError("route next_hop_interface_count must be a positive integer")
    next_hop_scope = raw.get("next_hop_scope")
    if next_hop_scope is not None:
        next_hop_scope = str(next_hop_scope).strip().lower()
        if next_hop_scope != "link_local":
            raise ValueError(f"unsupported route next_hop_scope {next_hop_scope!r}")
    if not require_fib and any(
        (
            next_hops,
            interfaces,
            next_hop_count is not None,
            next_hop_interface_count is not None,
            next_hop_scope,
        )
    ):
        raise ValueError("resolved next-hop assertions require require_fib=True")
    return {
        "prefix": prefix,
        "client": client,
        "client_id": client_id,
        "require_fib": require_fib,
        "next_hops": next_hops,
        "interfaces": interfaces,
        "exact_next_hops": exact_next_hops,
        "next_hop_count": next_hop_count,
        "next_hop_interface_count": next_hop_interface_count,
        "next_hop_scope": next_hop_scope,
    }


def _normalize_ndp(raw: t.Mapping[str, t.Any]) -> dict[str, t.Any]:
    _reject_unknown(
        raw,
        {"interface", "address", "address_scope", "states", "allowed_states"},
        "NDP expectation",
    )
    if "states" in raw and "allowed_states" in raw:
        raise ValueError("NDP expectation cannot set both states and allowed_states")
    interface = str(raw["interface"]).strip()
    if not interface:
        raise ValueError("NDP expectation requires an interface")
    address = raw.get("address")
    scope = raw.get("address_scope")
    if (address is None) == (scope is None):
        raise ValueError(
            "NDP expectation requires exactly one of address or address_scope"
        )
    normalized_address = (
        str(ipaddress.ip_address(str(address).split("/", 1)[0]))
        if address is not None
        else None
    )
    normalized_scope = str(scope).lower() if scope is not None else None
    if normalized_scope not in (None, "link_local"):
        raise ValueError(f"unsupported NDP address scope {scope!r}")
    states = {
        str(state).strip().upper()
        for state in raw.get("states", raw.get("allowed_states", ["REACHABLE"]))
    }
    if not states or "" in states:
        raise ValueError("NDP expectation requires allowed states")
    return {
        "interface": interface,
        "address": normalized_address,
        "address_scope": normalized_scope,
        "states": states,
    }


def _normalize_mysid(raw: t.Mapping[str, t.Any]) -> dict[str, t.Any]:
    _reject_unknown(
        raw,
        {"sid", "behavior", "require_resolved"},
        "MySID expectation",
    )
    sid = str(ipaddress.ip_address(str(raw["sid"]).split("/", 1)[0]))
    behavior = str(raw.get("behavior", "")).strip()
    if not behavior:
        raise ValueError("MySID expectation requires a behavior")
    return {
        "sid": sid,
        "behavior": behavior,
        "require_resolved": _strict_bool(
            raw.get("require_resolved", False), "MySID require_resolved"
        ),
    }


_IPV6_TOKEN_RE = re.compile(r"(?i)(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]*")
_MYSID_ANCHOR_RE = re.compile(r"(?i)\bmysid\s*:")
_MYSID_BEHAVIOR_RE = re.compile(
    r"(?i)\b(?:ADJACENCY_MICRO_SID|BINDING_MICRO_SID|" r"DECAPSULATE_AND_LOOKUP)\b"
)


def _ipv6_addresses(text: str) -> set[str]:
    addresses: set[str] = set()
    for candidate in _IPV6_TOKEN_RE.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 6:
            addresses.add(str(address))
    return addresses


def _mysid_entry_blocks(output: str, sid: str) -> list[str]:
    """Return blocks rooted at the requested SID, never the whole table.

    Current ``fboss2 show mysid`` output anchors entries with ``MySid:`` and
    can wrap ``resolved via fe80::...`` onto a continuation. Older tabular
    output is supported as a fallback. Address matching is canonical and exact
    so one SID can never satisfy an expectation for another SID's prefix.
    """
    lines = output.splitlines()
    sid = str(ipaddress.ip_address(sid))
    blocks: list[str] = []

    anchors = [
        (index, _ipv6_addresses(line))
        for index, line in enumerate(lines)
        if _MYSID_ANCHOR_RE.search(line)
    ]
    if anchors:
        for anchor_index, (start, addresses) in enumerate(anchors):
            if sid not in addresses:
                continue
            next_start = (
                anchors[anchor_index + 1][0]
                if anchor_index + 1 < len(anchors)
                else len(lines)
            )
            blocks.append("\n".join(lines[start : min(next_start, start + 8)]))
        return blocks

    for index, line in enumerate(lines):
        if sid not in _ipv6_addresses(line):
            continue
        block = [line]
        for continuation in lines[index + 1 : index + 5]:
            if not continuation.strip():
                break
            continuation_addresses = _ipv6_addresses(continuation)
            if (
                continuation_addresses
                and sid not in continuation_addresses
                and _MYSID_BEHAVIOR_RE.search(continuation)
            ):
                break
            block.append(continuation)
        blocks.append("\n".join(block))
    return blocks


class RbbStateAuditTask(BaseTask):
    """Assert exact common state on one explicitly selected RBB DUT."""

    # pyrefly: ignore [bad-override-mutable-attribute]
    NAME: str = "rbb_state_audit"

    def __init__(
        self,
        hostname: str | None = None,
        description: str | None = None,
        ixia: t.Any | None = None,
        logger: ConsoleFileLogger | None = None,
        shared_data: dict[t.Any, t.Any] | None = None,
    ) -> None:
        super().__init__(hostname, description, ixia, logger, shared_data)

    async def run(self, params: dict[str, t.Any]) -> None:
        _reject_unknown(
            params,
            {
                "hostname",
                "gate",
                "routes",
                "ndp",
                "mysids",
                "active_services",
                "interfaces_up",
            },
            "rbb_state_audit parameters",
        )
        hostname = params.get("hostname") or self.hostname
        if not hostname:
            raise ValueError("rbb_state_audit requires 'hostname'")
        gate = str(params.get("gate") or "rbb_state_audit")

        # Normalize and validate before opening a device connection.  A typo in
        # a client, address, or service is a configuration error, not DUT FAIL.
        routes = [_normalize_route(raw) for raw in params.get("routes", [])]
        ndp = [_normalize_ndp(raw) for raw in params.get("ndp", [])]
        mysids = [_normalize_mysid(raw) for raw in params.get("mysids", [])]
        services = [_service(value) for value in params.get("active_services", [])]
        interfaces = [str(value).strip() for value in params.get("interfaces_up", [])]
        if any(not interface for interface in interfaces):
            raise ValueError("interfaces_up entries must be non-empty")
        if not any((routes, ndp, mysids, services, interfaces)):
            raise ValueError("rbb_state_audit requires at least one assertion")

        driver = await async_get_device_driver(hostname)
        failures: list[str] = []

        if routes:
            by_client: dict[int, list[t.Any]] = {}
            for client_id in {route["client_id"] for route in routes}:
                by_client[client_id] = list(
                    await driver.async_get_route_table_by_client(client_id)
                )
            fib_details: dict[str, list[t.Any]] = {}
            if any(route["require_fib"] for route in routes):
                for detail in await driver.async_get_route_table_details():
                    fib_details.setdefault(_route_prefix(detail), []).append(detail)
            for expectation in routes:
                matching = [
                    route
                    for route in by_client[expectation["client_id"]]
                    if _route_prefix(route) == expectation["prefix"]
                ]
                if not matching:
                    failures.append(
                        f"route {expectation['prefix']} is absent from "
                        f"{expectation['client']} client RIB"
                    )
                    continue
                details = fib_details.get(expectation["prefix"], [])
                preferred_details = [
                    detail
                    for detail in details
                    if expectation["client_id"] in _preferred_fib_client_ids(detail)
                ]
                if expectation["require_fib"] and not details:
                    failures.append(
                        f"route {expectation['prefix']} is absent from the agent FIB"
                    )
                elif expectation["require_fib"]:
                    owners = {
                        client_id
                        for detail in details
                        for client_id in _preferred_fib_client_ids(detail)
                    }
                    if not preferred_details:
                        failures.append(
                            f"route {expectation['prefix']} preferred FIB owner is not "
                            f"{expectation['client']}; observed_client_ids="
                            f"{sorted(owners)}"
                        )
                detail = preferred_details[0] if preferred_details else None
                if detail is not None:
                    entries, observed_hops, observed_interfaces = _resolved_next_hops(
                        detail
                    )
                    expected_hops = expectation["next_hops"]
                    if expected_hops:
                        bad_hops = (
                            observed_hops != expected_hops
                            if expectation["exact_next_hops"]
                            else not expected_hops.issubset(observed_hops)
                        )
                        if bad_hops:
                            failures.append(
                                f"route {expectation['prefix']} resolved next hops "
                                f"expected={sorted(expected_hops)} "
                                f"observed={sorted(observed_hops)}"
                            )
                    expected_interfaces = expectation["interfaces"]
                    if (
                        expected_interfaces
                        and observed_interfaces != expected_interfaces
                    ):
                        failures.append(
                            f"route {expectation['prefix']} resolved interfaces "
                            f"expected={sorted(expected_interfaces)} "
                            f"observed={sorted(observed_interfaces)}"
                        )
                    expected_count = expectation["next_hop_count"]
                    if expected_count is not None and len(entries) != expected_count:
                        failures.append(
                            f"route {expectation['prefix']} resolved next-hop count "
                            f"expected={expected_count} observed={len(entries)}"
                        )
                    expected_interface_count = expectation["next_hop_interface_count"]
                    if (
                        expected_interface_count is not None
                        and len(observed_interfaces) != expected_interface_count
                    ):
                        failures.append(
                            f"route {expectation['prefix']} resolved interface "
                            f"count expected={expected_interface_count} "
                            f"observed={len(observed_interfaces)} "
                            f"interfaces={sorted(observed_interfaces)}"
                        )
                    if expectation["next_hop_scope"] == "link_local":
                        non_link_local = sorted(
                            address
                            for address, _ in entries
                            if not ipaddress.ip_address(address).is_link_local
                        )
                        if not entries or non_link_local:
                            failures.append(
                                f"route {expectation['prefix']} requires only "
                                "link-local resolved next hops; "
                                f"observed={entries}"
                            )

        if ndp:
            table = list(await driver.async_get_ndp_table())
            for expectation in ndp:
                interface_info = (
                    await driver.async_get_interface_name_to_port_id_and_vlan_id(
                        expectation["interface"]
                    )
                )
                vlan_id = int(interface_info.vlan_id)
                candidates: list[t.Any] = []
                for entry in table:
                    if getattr(entry, "interfaceID", None) != vlan_id:
                        continue
                    address = _packed_address(entry.ip)
                    if (
                        expectation["address"] is not None
                        and str(address) != expectation["address"]
                    ):
                        continue
                    if (
                        expectation["address_scope"] == "link_local"
                        and not address.is_link_local
                    ):
                        continue
                    candidates.append(entry)
                good = [
                    entry
                    for entry in candidates
                    if str(getattr(entry, "state", "")).upper() in expectation["states"]
                ]
                if not good:
                    observed = [
                        f"{_packed_address(entry.ip)}:{getattr(entry, 'state', None)}"
                        for entry in candidates
                    ]
                    target = expectation["address"] or expectation["address_scope"]
                    failures.append(
                        f"NDP {target} on {expectation['interface']} (VLAN {vlan_id}) "
                        f"has no state in {sorted(expectation['states'])}; "
                        f"observed={observed}"
                    )

        if services:
            for service in services:
                status = await driver.async_get_service_status(service)
                if status is not SystemctlServiceStatus.ACTIVE:
                    status_name = getattr(status, "name", str(status))
                    failures.append(
                        f"service {service.value} is {status_name}, not ACTIVE"
                    )

        if interfaces:
            states = await driver.async_get_interfaces_operational_state(interfaces)
            down = [name for name in interfaces if states.get(name) is not True]
            if down:
                failures.append(
                    f"interfaces are missing or not Up: {down}; observed={states}"
                )

        if mysids:
            output = await driver.async_run_cmd_on_shell("fboss2 show mysid") or ""
            for expectation in mysids:
                blocks = _mysid_entry_blocks(output, expectation["sid"])
                required = [expectation["behavior"]]
                if expectation["require_resolved"]:
                    required.append("resolved via")
                matching = [
                    block
                    for block in blocks
                    if all(token.casefold() in block.casefold() for token in required)
                ]
                if not matching:
                    failures.append(
                        f"MySID {expectation['sid']} has no single entry with "
                        f"tokens={required}; candidate_blocks={blocks}"
                    )

        if failures:
            raise TestCaseFailure(
                f"[{gate}] state audit failed on {hostname}: " + "; ".join(failures)
            )
        self.logger.info(f"{hostname} -- [{gate}] structured state audit passed")


__all__ = ["RbbStateAuditTask"]
