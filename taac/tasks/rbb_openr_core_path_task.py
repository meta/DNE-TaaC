# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Reversible Open/R core-path metric control for two-node RBB tests.

The public FBOSS driver intentionally gates Open/R Thrift mutation in OSS
mode.  This task uses the shipped ``breeze`` CLI instead, but accepts only a
small structured contract: core RIF addresses, exact metric values, and route
expectations.  Interface and peer names are discovered from JSON output and
strictly validated before they can be interpolated into a command.

Every mutation is owned by one playbook-scoped snapshot.  A snapshot is
accepted only when the node and all selected links are healthy and have no
pre-existing overload, metric increment, or metric override.  Restoration
therefore clears only overrides created by this task and verifies path identity,
health, and absence of overrides before releasing ownership.  The underlying
Open/R metric may legitimately move when RTT metrics are enabled.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import re
import shlex
import time
import typing as t

from taac.constants import TestCaseFailure
from taac.tasks.base_task import BaseTask
from taac.tasks.rbb_input_validation import FBOSS_INTERFACE_NAME_RE
from taac.tasks.rbb_state_audit_task import RbbStateAuditTask
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger

_SNAPSHOT = "snapshot"
_SET_METRICS = "set_metrics"
_ASSERT_ROUTES = "assert_routes"
_RESTORE = "restore"
_ACTIONS = frozenset((_SNAPSHOT, _SET_METRICS, _ASSERT_ROUTES, _RESTORE))
_NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_OPENR_METRIC = (1 << 31) - 1


def _required_string(value: t.Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value.strip()


def _strict_nonnegative_seconds(value: t.Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a finite non-negative number")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0:
        raise ValueError(f"{field} must be a finite non-negative number")
    return normalized


def _strict_positive_seconds(value: t.Any, field: str) -> float:
    normalized = _strict_nonnegative_seconds(value, field)
    if normalized <= 0:
        raise ValueError(f"{field} must be positive")
    return normalized


def _strict_metric(value: t.Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if not 1 <= value <= _MAX_OPENR_METRIC:
        raise ValueError(f"{field} must be in 1..{_MAX_OPENR_METRIC}")
    return value


def _json_object(output: t.Any, label: str) -> dict[str, t.Any]:
    try:
        parsed = json.loads(str(output or ""))
    except (TypeError, ValueError) as error:
        raise TestCaseFailure(f"{label} did not return valid JSON: {error}") from error
    if not isinstance(parsed, dict):
        raise TestCaseFailure(f"{label} JSON root must be an object")
    return parsed


def _strict_int(value: t.Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TestCaseFailure(f"{label} must be an integer, got {value!r}")
    return value


def _strict_bool(value: t.Any, label: str) -> bool:
    if type(value) is not bool:
        raise TestCaseFailure(f"{label} must be a boolean, got {value!r}")
    return value


def _core_addresses(value: t.Any) -> list[str]:
    if not isinstance(value, list) or len(value) < 2:
        raise ValueError("core_rif_cidrs must contain at least two addresses")
    addresses: list[str] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, str):
            raise ValueError(f"core_rif_cidrs[{index}] must be a CIDR string")
        try:
            interface = ipaddress.ip_interface(raw)
        except ValueError as error:
            raise ValueError(
                f"core_rif_cidrs[{index}] is not a valid CIDR: {raw!r}"
            ) from error
        address = str(interface.ip)
        if address in addresses:
            raise ValueError(f"core_rif_cidrs repeats address {address!r}")
        addresses.append(address)
    return addresses


def _metric_list(value: t.Any, path_count: int) -> list[int]:
    if not isinstance(value, list) or len(value) != path_count:
        raise ValueError(f"metrics must contain exactly {path_count} values")
    return [
        _strict_metric(item, f"metrics[{index}]") for index, item in enumerate(value)
    ]


def _path_indices(value: t.Any, path_count: int) -> list[int]:
    if not isinstance(value, list) or not value:
        raise ValueError("path_indices must be a non-empty list")
    result: list[int] = []
    for index, item in enumerate(value):
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError(f"path_indices[{index}] must be an integer")
        if not 0 <= item < path_count:
            raise ValueError(
                f"path_indices[{index}]={item} is outside 0..{path_count - 1}"
            )
        if item in result:
            raise ValueError(f"path_indices contains duplicate index {item}")
        result.append(item)
    return result


def _route_inputs(value: t.Any) -> list[dict[str, t.Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError("routes must be a non-empty list")
    routes: list[dict[str, t.Any]] = []
    allowed = {"prefix", "client", "require_fib"}
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"routes[{index}] must be an object")
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise ValueError(f"routes[{index}] has unsupported fields: {unknown}")
        try:
            prefix = str(ipaddress.ip_network(str(raw["prefix"]), strict=True))
        except (KeyError, ValueError) as error:
            raise ValueError(f"routes[{index}] requires a strict IP prefix") from error
        client = _required_string(raw.get("client"), f"routes[{index}].client")
        require_fib = raw.get("require_fib", True)
        if type(require_fib) is not bool:
            raise ValueError(f"routes[{index}].require_fib must be a boolean")
        if not require_fib:
            raise ValueError("core-path route evidence requires require_fib=True")
        routes.append({"prefix": prefix, "client": client.upper(), "require_fib": True})
    return routes


class RbbOpenrCorePathTask(BaseTask):
    """Own, program, verify, and restore exact Open/R core-path metrics."""

    # pyrefly: ignore [bad-override-mutable-attribute]
    NAME: str = "rbb_openr_core_path"

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
    def _state_key(hostname: str, sample_id: str) -> str:
        return f"openr-core:{hostname}:{sample_id}"

    @staticmethod
    def _lm_node(payload: dict[str, t.Any]) -> tuple[str, dict[str, t.Any]]:
        if len(payload) != 1:
            raise TestCaseFailure(
                "breeze lm links must return exactly one local node, "
                f"found {sorted(payload)}"
            )
        node_name, raw_node = next(iter(payload.items()))
        if not isinstance(node_name, str) or not _NODE_NAME_RE.fullmatch(node_name):
            raise TestCaseFailure(f"Open/R returned an invalid node name {node_name!r}")
        if not isinstance(raw_node, dict):
            raise TestCaseFailure("Open/R Link Monitor node payload must be an object")
        return node_name, raw_node

    @staticmethod
    def _adjacencies(
        payload: dict[str, t.Any], node_name: str
    ) -> list[dict[str, t.Any]]:
        candidates: list[dict[str, t.Any]] = []
        for area_name, raw_area in payload.items():
            if not isinstance(raw_area, dict):
                raise TestCaseFailure(
                    f"Open/R Decision area {area_name!r} must be an object"
                )
            raw_node = raw_area.get(node_name)
            if raw_node is None:
                continue
            if not isinstance(raw_node, dict):
                raise TestCaseFailure(
                    f"Open/R Decision node {node_name!r} must be an object"
                )
            if _strict_bool(
                raw_node.get("is_overloaded"),
                f"Decision node {node_name}.is_overloaded",
            ):
                raise TestCaseFailure(f"Open/R node {node_name} is overloaded")
            node_increment = _strict_int(
                raw_node.get("node_metric_increment_val"),
                f"Decision node {node_name}.node_metric_increment_val",
            )
            if node_increment != 0:
                raise TestCaseFailure(
                    f"Open/R node {node_name} has metric increment {node_increment}"
                )
            raw_adjacencies = raw_node.get("adjacencies")
            if not isinstance(raw_adjacencies, list):
                raise TestCaseFailure(
                    f"Open/R Decision node {node_name} adjacencies must be a list"
                )
            for raw_adjacency in raw_adjacencies:
                if not isinstance(raw_adjacency, dict):
                    raise TestCaseFailure("Open/R adjacency must be an object")
                candidates.append(raw_adjacency)
        if not candidates:
            raise TestCaseFailure(
                f"Open/R Decision has no adjacency database for local node {node_name!r}"
            )
        return candidates

    @classmethod
    def _inspect_payloads(
        cls,
        lm_payload: dict[str, t.Any],
        adj_payload: dict[str, t.Any],
        core_addresses: list[str],
    ) -> dict[str, t.Any]:
        node_name, node = cls._lm_node(lm_payload)
        if _strict_bool(node.get("isOverloaded"), f"LM node {node_name}.isOverloaded"):
            raise TestCaseFailure(f"Open/R node {node_name} is overloaded")
        node_increment = _strict_int(
            node.get("nodeMetricIncrementVal"),
            f"LM node {node_name}.nodeMetricIncrementVal",
        )
        if node_increment != 0:
            raise TestCaseFailure(
                f"Open/R node {node_name} has metric increment {node_increment}"
            )
        details = node.get("interfaceDetails")
        if not isinstance(details, dict):
            raise TestCaseFailure(
                "Open/R Link Monitor interfaceDetails must be an object"
            )
        adjacencies = cls._adjacencies(adj_payload, node_name)

        paths: list[dict[str, t.Any]] = []
        seen_interfaces: set[str] = set()
        for address in core_addresses:
            matches: list[tuple[str, dict[str, t.Any]]] = []
            for interface, raw_detail in details.items():
                if not isinstance(
                    interface, str
                ) or not FBOSS_INTERFACE_NAME_RE.fullmatch(interface):
                    raise TestCaseFailure(
                        f"Open/R returned an invalid interface name {interface!r}"
                    )
                if not isinstance(raw_detail, dict):
                    raise TestCaseFailure(
                        f"Link Monitor detail for {interface!r} must be an object"
                    )
                info = raw_detail.get("info")
                if not isinstance(info, dict) or not isinstance(
                    info.get("networks"), list
                ):
                    raise TestCaseFailure(
                        f"Link Monitor detail for {interface!r} has no network list"
                    )
                network_addresses: set[str] = set()
                for raw_network in info["networks"]:
                    try:
                        network_addresses.add(
                            str(ipaddress.ip_interface(raw_network).ip)
                        )
                    except (TypeError, ValueError) as error:
                        raise TestCaseFailure(
                            f"Link Monitor returned invalid network {raw_network!r} "
                            f"on {interface}"
                        ) from error
                if address in network_addresses:
                    matches.append((interface, raw_detail))
            if len(matches) != 1:
                raise TestCaseFailure(
                    f"core RIF address {address} matched {len(matches)} Open/R interfaces"
                )
            interface, detail = matches[0]
            if interface in seen_interfaces:
                raise TestCaseFailure(
                    f"multiple core RIF addresses resolve to Open/R interface {interface}"
                )
            seen_interfaces.add(interface)
            info = t.cast(dict[str, t.Any], detail["info"])
            if not _strict_bool(info.get("isUp"), f"{interface}.info.isUp"):
                raise TestCaseFailure(f"Open/R interface {interface} is down")
            if _strict_bool(detail.get("isOverloaded"), f"{interface}.isOverloaded"):
                raise TestCaseFailure(f"Open/R interface {interface} is overloaded")
            increment = _strict_int(
                detail.get("linkMetricIncrementVal"),
                f"{interface}.linkMetricIncrementVal",
            )
            if increment != 0:
                raise TestCaseFailure(
                    f"Open/R interface {interface} has metric increment {increment}"
                )
            override = detail.get("metricOverride")
            if override is not None:
                override = _strict_int(override, f"{interface}.metricOverride")
            matching_adjacencies = [
                adjacency
                for adjacency in adjacencies
                if adjacency.get("ifName") == interface
            ]
            if len(matching_adjacencies) != 1:
                raise TestCaseFailure(
                    f"Open/R interface {interface} matched "
                    f"{len(matching_adjacencies)} Decision adjacencies"
                )
            adjacency = matching_adjacencies[0]
            peer = adjacency.get("otherNodeName")
            if not isinstance(peer, str) or not _NODE_NAME_RE.fullmatch(peer):
                raise TestCaseFailure(
                    f"Open/R adjacency {interface} has invalid peer {peer!r}"
                )
            if _strict_bool(
                adjacency.get("isOverloaded"), f"adjacency {interface}.isOverloaded"
            ):
                raise TestCaseFailure(f"Open/R adjacency {interface} is overloaded")
            if _strict_bool(
                adjacency.get("adjOnlyUsedByOtherNode"),
                f"adjacency {interface}.adjOnlyUsedByOtherNode",
            ):
                raise TestCaseFailure(
                    f"Open/R adjacency {interface} is usable only by the peer"
                )
            adjacency_increment = _strict_int(
                adjacency.get("linkMetricIncrementVal"),
                f"adjacency {interface}.linkMetricIncrementVal",
            )
            if adjacency_increment != 0:
                raise TestCaseFailure(
                    f"Open/R adjacency {interface} has metric increment "
                    f"{adjacency_increment}"
                )
            metric = _strict_int(
                adjacency.get("metric"), f"adjacency {interface}.metric"
            )
            if not 1 <= metric <= _MAX_OPENR_METRIC:
                raise TestCaseFailure(
                    f"Open/R adjacency {interface} has invalid metric {metric}"
                )
            paths.append(
                {
                    "address": address,
                    "interface": interface,
                    "peer": peer,
                    "metric": metric,
                    "metric_override": override,
                }
            )
        peers = {path["peer"] for path in paths}
        if len(peers) != 1:
            raise TestCaseFailure(
                f"core Open/R interfaces do not share one peer: {sorted(peers)}"
            )
        return {"node_name": node_name, "paths": paths}

    async def _inspect(
        self, driver: t.Any, core_addresses: list[str]
    ) -> dict[str, t.Any]:
        lm_output = await driver.async_run_cmd_on_shell("breeze lm links --json")
        adj_output = await driver.async_run_cmd_on_shell("breeze decision adj --json")
        return self._inspect_payloads(
            _json_object(lm_output, "breeze lm links --json"),
            _json_object(adj_output, "breeze decision adj --json"),
            core_addresses,
        )

    @staticmethod
    def _assert_identity(
        observed: dict[str, t.Any], state: dict[str, t.Any], gate: str
    ) -> None:
        expected_paths = state["paths"]
        observed_paths = observed["paths"]
        if observed["node_name"] != state["node_name"] or len(observed_paths) != len(
            expected_paths
        ):
            raise TestCaseFailure(f"[{gate}] Open/R core-path identity changed")
        for index, (expected, current) in enumerate(
            zip(expected_paths, observed_paths)
        ):
            for field in ("address", "interface", "peer"):
                if current[field] != expected[field]:
                    raise TestCaseFailure(
                        f"[{gate}] core path {index} {field} changed: "
                        f"expected={expected[field]!r} observed={current[field]!r}"
                    )

    @classmethod
    def _assert_overrides(
        cls,
        observed: dict[str, t.Any],
        state: dict[str, t.Any],
        expected: list[int | None],
        gate: str,
        *,
        exact_metrics: bool,
    ) -> None:
        cls._assert_identity(observed, state, gate)
        for index, (current, expected_override) in enumerate(
            zip(observed["paths"], expected)
        ):
            if current["metric_override"] != expected_override:
                raise TestCaseFailure(
                    f"[{gate}] path {index} override expected={expected_override!r} "
                    f"observed={current['metric_override']!r}"
                )
            # A programmed override must project to the exact Decision metric.
            # With no override, however, the base metric may be computed from
            # live RTT and is not required to equal the one-time snapshot.
            if (
                exact_metrics
                and expected_override is not None
                and current["metric"] != expected_override
            ):
                raise TestCaseFailure(
                    f"[{gate}] path {index} Decision metric expected="
                    f"{expected_override} observed={current['metric']}"
                )

    async def _poll_overrides(
        self,
        driver: t.Any,
        state: dict[str, t.Any],
        expected: list[int | None],
        gate: str,
        timeout_seconds: float,
        poll_interval_seconds: float,
    ) -> dict[str, t.Any]:
        deadline = time.monotonic() + timeout_seconds
        last_error: TestCaseFailure | None = None
        while True:
            observed = await self._inspect(driver, state["core_addresses"])
            try:
                self._assert_overrides(
                    observed, state, expected, gate, exact_metrics=True
                )
                return observed
            except TestCaseFailure as error:
                last_error = error
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise t.cast(TestCaseFailure, last_error)
            await asyncio.sleep(min(poll_interval_seconds, remaining))

    @staticmethod
    def _decision_route_interfaces(
        payload: dict[str, t.Any],
        node_name: str,
        prefix: str,
        expected_interfaces: set[str],
        gate: str,
    ) -> None:
        if set(payload) != {node_name}:
            raise TestCaseFailure(
                f"[{gate}] Decision route payload nodes expected={[node_name]} "
                f"observed={sorted(payload)}"
            )
        node = payload[node_name]
        if not isinstance(node, dict):
            raise TestCaseFailure(f"[{gate}] Decision route node must be an object")
        routes = node.get("unicastRoutes")
        if not isinstance(routes, list):
            raise TestCaseFailure(
                f"[{gate}] Decision route payload has no unicastRoutes list"
            )
        matches: list[dict[str, t.Any]] = []
        for raw_route in routes:
            if not isinstance(raw_route, dict):
                raise TestCaseFailure(
                    f"[{gate}] Decision route entry must be an object"
                )
            try:
                destination = str(
                    ipaddress.ip_network(str(raw_route.get("dest")), strict=True)
                )
            except ValueError as error:
                raise TestCaseFailure(
                    f"[{gate}] Decision returned an invalid route destination"
                ) from error
            if destination == prefix:
                matches.append(raw_route)
        if len(matches) != 1:
            raise TestCaseFailure(
                f"[{gate}] Decision prefix {prefix} matched {len(matches)} routes"
            )
        next_hops = matches[0].get("nextHops")
        if not isinstance(next_hops, list) or not next_hops:
            raise TestCaseFailure(f"[{gate}] Decision prefix {prefix} has no next hops")
        observed_interfaces: set[str] = set()
        metrics: set[int] = set()
        for next_hop in next_hops:
            if not isinstance(next_hop, dict):
                raise TestCaseFailure(
                    f"[{gate}] Decision next hop for {prefix} must be an object"
                )
            interface = next_hop.get("ifName")
            if not isinstance(interface, str) or not FBOSS_INTERFACE_NAME_RE.fullmatch(
                interface
            ):
                raise TestCaseFailure(
                    f"[{gate}] Decision prefix {prefix} has invalid interface "
                    f"{interface!r}"
                )
            observed_interfaces.add(interface)
            metrics.add(
                _strict_int(
                    next_hop.get("metric"),
                    f"Decision prefix {prefix} next hop {interface}.metric",
                )
            )
        if observed_interfaces != expected_interfaces:
            raise TestCaseFailure(
                f"[{gate}] Decision prefix {prefix} interfaces "
                f"expected={sorted(expected_interfaces)} "
                f"observed={sorted(observed_interfaces)}"
            )
        if len(next_hops) != len(expected_interfaces):
            raise TestCaseFailure(
                f"[{gate}] Decision prefix {prefix} next-hop count "
                f"expected={len(expected_interfaces)} observed={len(next_hops)}"
            )
        if len(metrics) != 1:
            raise TestCaseFailure(
                f"[{gate}] Decision prefix {prefix} next hops do not have equal "
                f"link metrics: {sorted(metrics)}"
            )

    async def _poll_decision_routes(
        self,
        driver: t.Any,
        state: dict[str, t.Any],
        prefixes: list[str],
        path_indices: list[int],
        gate: str,
        timeout_seconds: float,
        poll_interval_seconds: float,
    ) -> None:
        if not prefixes:
            return
        expected_interfaces = {
            state["paths"][index]["interface"] for index in path_indices
        }
        deadline = time.monotonic() + timeout_seconds
        last_error: TestCaseFailure | None = None
        while True:
            try:
                for prefix in prefixes:
                    command = (
                        "breeze decision routes --no-hostnames --json "
                        f"{shlex.quote(prefix)}"
                    )
                    output = await driver.async_run_cmd_on_shell(command)
                    self._decision_route_interfaces(
                        _json_object(output, command),
                        state["node_name"],
                        prefix,
                        expected_interfaces,
                        gate,
                    )
                return
            except TestCaseFailure as error:
                last_error = error
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise t.cast(TestCaseFailure, last_error)
            await asyncio.sleep(min(poll_interval_seconds, remaining))

    @staticmethod
    async def _run_override_command(
        driver: t.Any, peer: str, interface: str, metric: int
    ) -> None:
        command = (
            "breeze lm override-adj-metric --yes --quiet "
            f"{shlex.quote(peer)} {shlex.quote(interface)} {metric}"
        )
        await driver.async_run_cmd_on_shell(command)

    @staticmethod
    async def _run_clear_command(driver: t.Any, peer: str, interface: str) -> None:
        command = (
            "breeze lm clear-adj-metric-override --yes --quiet "
            f"{shlex.quote(peer)} {shlex.quote(interface)}"
        )
        await driver.async_run_cmd_on_shell(command)

    async def _restore_owned(
        self,
        driver: t.Any,
        state: dict[str, t.Any],
        gate: str,
        timeout_seconds: float,
        poll_interval_seconds: float,
    ) -> None:
        observed = await self._inspect(driver, state["core_addresses"])
        self._assert_identity(observed, state, gate)
        expected_owned = state.get("expected_overrides")
        for index, current in enumerate(observed["paths"]):
            allowed = {None}
            if isinstance(expected_owned, list):
                allowed.add(expected_owned[index])
            attempted = state.get("attempted_overrides")
            if isinstance(attempted, list):
                allowed.add(attempted[index])
            if current["metric_override"] not in allowed:
                raise TestCaseFailure(
                    f"[{gate}] refusing to clear unowned metric override on "
                    f"{current['interface']}: {current['metric_override']!r}"
                )
        failures: list[str] = []
        for current in observed["paths"]:
            if current["metric_override"] is None:
                continue
            try:
                await self._run_clear_command(
                    driver, current["peer"], current["interface"]
                )
            except Exception as error:
                failures.append(f"{current['interface']}: {error}")
        if failures:
            raise TestCaseFailure(
                f"[{gate}] failed to clear owned Open/R overrides: "
                + "; ".join(failures)
            )
        await self._poll_overrides(
            driver,
            state,
            [None] * len(state["paths"]),
            gate,
            timeout_seconds,
            poll_interval_seconds,
        )

    async def run(self, params: dict[str, t.Any]) -> None:
        action = params.get("action")
        if action not in _ACTIONS:
            raise ValueError(
                "rbb_openr_core_path action must be snapshot, set_metrics, "
                "assert_routes, or restore"
            )
        allowed = {
            "action",
            "hostname",
            "gate",
            "sample_id",
            "timeout_seconds",
            "poll_interval_seconds",
        }
        if action == _SNAPSHOT:
            allowed.add("core_rif_cidrs")
        elif action == _SET_METRICS:
            allowed.add("metrics")
        elif action == _ASSERT_ROUTES:
            allowed.update(("path_indices", "routes"))
        unknown = sorted(set(params) - allowed)
        if unknown:
            raise ValueError(f"rbb_openr_core_path unsupported fields: {unknown}")

        hostname = _required_string(params.get("hostname") or self.hostname, "hostname")
        gate = str(params.get("gate") or self.NAME)
        sample_id = _required_string(params.get("sample_id"), "sample_id")
        timeout_seconds = _strict_nonnegative_seconds(
            params.get("timeout_seconds", 30), "timeout_seconds"
        )
        poll_interval_seconds = _strict_positive_seconds(
            params.get("poll_interval_seconds", 1), "poll_interval_seconds"
        )
        key = self._state_key(hostname, sample_id)

        if action == _SNAPSHOT:
            core_addresses = _core_addresses(params.get("core_rif_cidrs"))
            if key in self._data and self._data[key] is not None:
                raise TestCaseFailure(
                    f"[{gate}] Open/R snapshot {hostname}:{sample_id} already exists"
                )
            driver = await async_get_device_driver(hostname)
            observed = await self._inspect(driver, core_addresses)
            preexisting = [
                path["interface"]
                for path in observed["paths"]
                if path["metric_override"] is not None
            ]
            if preexisting:
                raise TestCaseFailure(
                    f"[{gate}] pre-existing Open/R metric overrides are not owned "
                    f"by this playbook: {preexisting}"
                )
            self._data[key] = {
                "hostname": hostname,
                "sample_id": sample_id,
                "core_addresses": core_addresses,
                "node_name": observed["node_name"],
                "paths": observed["paths"],
                "expected_overrides": [None] * len(observed["paths"]),
                "attempted_overrides": None,
                "mutated": False,
            }
            self.logger.info(
                f"{hostname} -- [{gate}] owns pristine Open/R paths "
                f"{[path['interface'] for path in observed['paths']]}"
            )
            return

        if key not in self._data or self._data[key] is None:
            if action == _RESTORE:
                self.logger.info(
                    f"{hostname} -- [{gate}] no owned Open/R snapshot to restore"
                )
                return
            raise TestCaseFailure(
                f"[{gate}] no owned Open/R snapshot for {hostname}:{sample_id}"
            )
        state = self._data[key]
        if not isinstance(state, dict):
            raise TestCaseFailure(f"[{gate}] Open/R snapshot state is invalid")
        driver = await async_get_device_driver(hostname)

        if action == _SET_METRICS:
            metrics = _metric_list(params.get("metrics"), len(state["paths"]))
            observed = await self._inspect(driver, state["core_addresses"])
            current_expected = state["expected_overrides"]
            self._assert_overrides(
                observed,
                state,
                current_expected,
                gate,
                exact_metrics=True,
            )
            if current_expected == metrics:
                return
            attempted_overrides: list[int | None] = [None] * len(metrics)
            state["attempted_overrides"] = attempted_overrides
            state["mutated"] = True
            self._data[key] = state
            try:
                for index, (path, metric) in enumerate(zip(state["paths"], metrics)):
                    # Record ownership immediately before each individual
                    # mutation.  A later path whose command was never reached
                    # must not become eligible for automatic cleanup merely
                    # because an operator happened to use the requested value.
                    attempted_overrides[index] = metric
                    state["attempted_overrides"] = list(attempted_overrides)
                    self._data[key] = state
                    await self._run_override_command(
                        driver, path["peer"], path["interface"], metric
                    )
                await self._poll_overrides(
                    driver,
                    state,
                    metrics,
                    gate,
                    timeout_seconds,
                    poll_interval_seconds,
                )
            except BaseException as mutation_error:
                try:
                    await self._restore_owned(
                        driver,
                        state,
                        gate,
                        timeout_seconds,
                        poll_interval_seconds,
                    )
                except BaseException as restore_error:
                    mutation_error.add_note(
                        "Automatic Open/R metric restoration also failed: "
                        f"{restore_error}"
                    )
                else:
                    # _SharedDataView deliberately exposes only a mapping
                    # subset and has no delete operation.  A tombstone releases
                    # ownership while remaining safe across task instances.
                    self._data[key] = None
                raise
            state["expected_overrides"] = metrics
            state["attempted_overrides"] = None
            self._data[key] = state
            self.logger.info(
                f"{hostname} -- [{gate}] programmed Open/R metrics {metrics}"
            )
            return

        if action == _ASSERT_ROUTES:
            indices = _path_indices(params.get("path_indices"), len(state["paths"]))
            routes = _route_inputs(params.get("routes"))
            observed = await self._inspect(driver, state["core_addresses"])
            expected_overrides = state["expected_overrides"]
            if not state.get("mutated") or any(
                value is None for value in expected_overrides
            ):
                raise TestCaseFailure(
                    f"[{gate}] route assertion requires task-owned exact metrics"
                )
            self._assert_overrides(
                observed,
                state,
                expected_overrides,
                gate,
                exact_metrics=True,
            )
            openr_prefixes = [
                route["prefix"] for route in routes if route["client"] == "OPENR"
            ]
            await self._poll_decision_routes(
                driver,
                state,
                openr_prefixes,
                indices,
                gate,
                timeout_seconds,
                poll_interval_seconds,
            )
            route_params = [
                {
                    **route,
                    "exact_next_hops": False,
                    "next_hop_count": len(indices),
                    "next_hop_interface_count": len(indices),
                    "next_hop_scope": "link_local",
                }
                for route in routes
            ]
            audit = RbbStateAuditTask(
                hostname=hostname,
                ixia=self._ixia,
                logger=self.logger,
                shared_data=self._shared_data,
            )
            await audit.run(
                {
                    "hostname": hostname,
                    "gate": gate,
                    "routes": route_params,
                    "ndp": [],
                    "mysids": [],
                    "active_services": [],
                    "interfaces_up": [],
                    "timeout_seconds": timeout_seconds,
                    "poll_interval_seconds": poll_interval_seconds,
                }
            )
            return

        # Restore is deliberately idempotent only when this playbook owns the
        # snapshot.  With no snapshot it is a no-op; with unexpected drift it
        # refuses to clear a potentially operator-owned override.
        await self._restore_owned(
            driver,
            state,
            gate,
            timeout_seconds,
            poll_interval_seconds,
        )
        self._data[key] = None
        self.logger.info(
            f"{hostname} -- [{gate}] cleared task-owned Open/R metric overrides"
        )


__all__ = ["RbbOpenrCorePathTask"]
