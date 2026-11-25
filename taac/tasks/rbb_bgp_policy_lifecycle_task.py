# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Recovery-safe BGP policy lifecycle for Phase-2 TC-65--68."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import time
import typing as t

from taac.constants import TestCaseFailure
from taac.driver.driver_constants import FbossSystemctlServiceName
from taac.tasks.base_task import BaseTask
from taac.tasks.rbb_edge_config_utils import (
    async_apply_backup_metadata,
    async_backup_before_overwrite,
    async_guard_snapshot_set,
    async_read_file_or_none,
    async_restore_backup,
    async_write_json_file,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.health_check_utils import ip_ntop
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger

_ACTIONS = frozenset(
    {"snapshot", "apply", "assert_rib", "assert_peer_routes", "restore"}
)
_BACKUP_SUFFIX = ".taac-rbb-policy-orig"


def _route_prefix(route: t.Any) -> str:
    """Normalize an FBOSS unicast route without the state-audit framework."""
    destination = route.dest
    packed = getattr(destination.ip, "addr", destination.ip)
    address = ipaddress.ip_address(bytes(packed))
    return str(
        ipaddress.ip_network(
            f"{address}/{int(destination.prefixLength)}", strict=False
        )
    )


def _bgpd_client_id() -> int:
    """Resolve BGPD lazily so importing this OSS task needs no generated IDL."""
    try:
        from neteng.fboss.ctrl.types import ClientID

        member = ClientID.BGPD
    except (ImportError, AttributeError) as exc:
        raise ValueError("FBOSS ClientID.BGPD is unavailable") from exc
    return int(getattr(member, "value", member))


def _canonical_prefixes(value: t.Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    result: list[str] = []
    for item in value:
        network = ipaddress.ip_network(str(item), strict=True)
        if network.version != 6:
            raise ValueError(f"{label} must contain only IPv6 prefixes")
        result.append(str(network))
    return result


def _prefix_key(value: t.Any) -> str:
    prefix = getattr(value, "prefix", value)
    prefix_bin = getattr(prefix, "prefix_bin", None)
    num_bits = getattr(prefix, "num_bits", None)
    if prefix_bin is not None and num_bits is not None:
        return str(
            ipaddress.ip_network(f"{ip_ntop(prefix_bin)}/{num_bits}", strict=False)
        )
    try:
        return _route_prefix(value)
    except Exception:
        return _route_prefix(prefix)


def _path_communities(path: t.Any) -> set[str]:
    raw = getattr(path, "communities", None) or []
    result: set[str] = set()
    for item in raw:
        asn = getattr(item, "asn", None)
        value = getattr(item, "value", None)
        if asn is not None and value is not None:
            result.add(f"{asn}:{value}")
        else:
            result.add(str(item))
    return result


class RbbBgpPolicyLifecycleTask(BaseTask):
    """Install one scoped policy, assert evidence, and restore exact config."""

    NAME: str = "rbb_bgp_policy_lifecycle"

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
        allowed = {
            "action", "hostname", "peer_group_name", "ingress_policy_name",
            "egress_policy_name", "policy_config", "networks6",
            "expected_present", "expected_absent", "expected_local_pref",
            "required_communities", "forbidden_communities", "fib_present",
            "fib_absent", "peer_addr", "peer_view", "timeout_seconds",
            "poll_interval_seconds", "force",
        }
        unknown = sorted(set(params) - allowed)
        if unknown:
            raise ValueError(f"rbb_bgp_policy_lifecycle unsupported fields: {unknown}")
        action = str(params.get("action") or "")
        if action not in _ACTIONS:
            raise ValueError(f"action must be one of {sorted(_ACTIONS)}")
        hostname = str(params.get("hostname") or self.hostname or "").strip()
        if not hostname:
            raise ValueError("hostname is required")
        driver = await async_get_device_driver(hostname)
        if action == "snapshot":
            await self._snapshot(driver, hostname, params.get("force", False))
            return
        if action == "apply":
            await self._apply(driver, hostname, params)
            return
        if action == "restore":
            await self._restore(driver, hostname)
            return
        timeout = self._positive(params.get("timeout_seconds", 60), "timeout_seconds")
        interval = self._positive(
            params.get("poll_interval_seconds", 2), "poll_interval_seconds"
        )
        if action == "assert_rib":
            operation = lambda: self._assert_rib(driver, hostname, params)
        else:
            operation = lambda: self._assert_peer_routes(driver, hostname, params)
        await self._poll(operation, timeout, interval)

    @staticmethod
    def _positive(value: t.Any, label: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{label} must be a positive finite number")
        result = float(value)
        if not math.isfinite(result) or result <= 0:
            raise ValueError(f"{label} must be a positive finite number")
        return result

    async def _poll(
        self,
        operation: t.Callable[[], t.Awaitable[None]],
        timeout: float,
        interval: float,
    ) -> None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                await operation()
                return
            except TestCaseFailure:
                if time.monotonic() >= deadline:
                    raise
                await asyncio.sleep(
                    min(interval, max(0.0, deadline - time.monotonic()))
                )

    async def _snapshot(self, driver: t.Any, hostname: str, force: t.Any) -> None:
        if type(force) is not bool:
            raise ValueError("force must be a boolean")
        paths = (C.BGP_CONFIG_PATH, C.BGP_POLICY_PATH)
        await async_guard_snapshot_set(
            driver, paths, hostname, force, backup_suffix=_BACKUP_SUFFIX
        )
        for path in paths:
            await async_backup_before_overwrite(
                driver, path, self.logger, hostname, force, backup_suffix=_BACKUP_SUFFIX
            )

    async def _read_json(
        self, driver: t.Any, hostname: str, path: str
    ) -> dict[str, t.Any]:
        raw = await async_read_file_or_none(driver, path)
        if raw is None:
            raise TestCaseFailure(f"{hostname}: missing {path}")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TestCaseFailure(f"{hostname}: invalid JSON in {path}: {exc}") from exc
        if not isinstance(document, dict):
            raise TestCaseFailure(f"{hostname}: {path} must contain a JSON object")
        return document

    async def _apply(
        self, driver: t.Any, hostname: str, params: dict[str, t.Any]
    ) -> None:
        for path in (C.BGP_CONFIG_PATH, C.BGP_POLICY_PATH):
            snapshot = await async_read_file_or_none(
                driver, path + _BACKUP_SUFFIX
            )
            if snapshot is None:
                raise TestCaseFailure(
                    f"{hostname}: missing recovery snapshot for {path}; "
                    "run the snapshot action before applying a policy"
                )
        peer_group_name = str(params.get("peer_group_name") or "").strip()
        if not peer_group_name:
            raise ValueError("peer_group_name is required")
        policy_fragment = params.get("policy_config")
        if not isinstance(policy_fragment, dict):
            raise ValueError("policy_config must be a JSON object")
        ingress = str(params.get("ingress_policy_name") or "").strip()
        egress = str(params.get("egress_policy_name") or "").strip()
        if bool(ingress) == bool(egress):
            raise ValueError(
                "exactly one ingress_policy_name or egress_policy_name is required"
            )
        networks = params.get("networks6", [])
        if not isinstance(networks, list) or any(
            not isinstance(item, dict) for item in networks
        ):
            raise ValueError("networks6 must be a list of objects")
        bgp = await self._read_json(driver, hostname, C.BGP_CONFIG_PATH)
        policy = await self._read_json(driver, hostname, C.BGP_POLICY_PATH)
        groups = [
            group
            for group in bgp.get("peer_groups", [])
            if group.get("name") == peer_group_name
        ]
        if len(groups) != 1:
            raise TestCaseFailure(
                f"{hostname}: expected exactly one peer group "
                f"{peer_group_name!r}, found {len(groups)}"
            )
        group = groups[0]
        group.pop("ingress_policy_name", None)
        group.pop("egress_policy_name", None)
        group["ingress_policy_name" if ingress else "egress_policy_name"] = (
            ingress or egress
        )
        managed = {
            "2001:db8:6600::/64", "2001:db8:6601::/64", "2001:db8:6700::/64"
        }
        existing = bgp.setdefault("networks6", [])
        if not isinstance(existing, list):
            raise TestCaseFailure(f"{hostname}: bgp.json networks6 must be a list")
        bgp["networks6"] = [n for n in existing if str(n.get("prefix")) not in managed]
        bgp["networks6"].extend(networks)
        live_policies = policy.setdefault("policies", {})
        fragment_policies = policy_fragment.get("policies", {})
        if not isinstance(live_policies, dict) or not isinstance(
            fragment_policies, dict
        ):
            raise TestCaseFailure(f"{hostname}: BGP policy containers must be objects")
        statements = live_policies.setdefault("bgp_policy_statements", [])
        additions = fragment_policies.get("bgp_policy_statements", [])
        if not isinstance(statements, list) or not isinstance(additions, list):
            raise TestCaseFailure(f"{hostname}: BGP policy statements must be lists")
        live_policies["bgp_policy_statements"] = [
            statement
            for statement in statements
            if not str(statement.get("name", "")).startswith("TAAC_RBB_TC")
        ] + additions
        try:
            from configerator.structs.neteng.fboss.bgp.bgp_config.thrift_types import (
                BgpConfig,
                BgpPolicyConfig,
            )
            from taac.utils.json_thrift_utils import json_to_thrift

            json_to_thrift(json.dumps(bgp), BgpConfig)
            json_to_thrift(json.dumps(policy), BgpPolicyConfig)
        except Exception as exc:
            raise TestCaseFailure(
                f"{hostname}: generated BGP policy configuration is invalid: {exc}"
            ) from exc
        await async_write_json_file(
            driver, C.BGP_POLICY_PATH, policy, hostname=hostname
        )
        await async_write_json_file(driver, C.BGP_CONFIG_PATH, bgp, hostname=hostname)
        for path in (C.BGP_POLICY_PATH, C.BGP_CONFIG_PATH):
            await async_apply_backup_metadata(
                driver, path, hostname, backup_suffix=_BACKUP_SUFFIX
            )
        await driver.async_restart_service(FbossSystemctlServiceName.BGP)

    async def _assert_rib(
        self, driver: t.Any, hostname: str, params: dict[str, t.Any]
    ) -> None:
        present = _canonical_prefixes(
            params.get("expected_present"), "expected_present"
        )
        absent = _canonical_prefixes(params.get("expected_absent"), "expected_absent")
        entries = {
            _prefix_key(entry): entry
            for entry in await driver.async_get_bgp_rib_entries()
        }
        failures: list[str] = []
        failures.extend(f"missing RIB {p}" for p in present if p not in entries)
        failures.extend(f"unexpected RIB {p}" for p in absent if p in entries)
        local_prefs = params.get("expected_local_pref", {})
        required = params.get("required_communities", {})
        forbidden = params.get("forbidden_communities", {})
        for prefix in set(local_prefs) | set(required) | set(forbidden):
            entry = entries.get(str(prefix))
            if entry is None:
                failures.append(f"missing RIB {prefix} for path attributes")
                continue
            paths = list(getattr(entry, "paths", None) or [])
            best = getattr(entry, "best_path", None)
            if best is not None:
                paths = [best]
            if not paths:
                failures.append(f"RIB {prefix} has no path attributes")
                continue
            path = paths[0]
            if prefix in local_prefs and int(
                getattr(path, "local_pref", -1)
            ) != int(local_prefs[prefix]):
                failures.append(
                    f"RIB {prefix} local-pref="
                    f"{getattr(path, 'local_pref', None)!r}, "
                    f"expected={local_prefs[prefix]}"
                )
            communities = _path_communities(path)
            missing = set(required.get(prefix, [])) - communities
            leaked = set(forbidden.get(prefix, [])) & communities
            if missing:
                failures.append(f"RIB {prefix} missing communities {sorted(missing)}")
            if leaked:
                failures.append(
                    f"RIB {prefix} retained forbidden communities {sorted(leaked)}"
                )
        bgpd_id = _bgpd_client_id()
        fib = {
            _route_prefix(route)
            for route in await driver.async_get_route_table_by_client(bgpd_id)
        }
        fib_present = _canonical_prefixes(params.get("fib_present"), "fib_present")
        fib_absent = _canonical_prefixes(params.get("fib_absent"), "fib_absent")
        failures.extend(f"missing BGPD FIB {p}" for p in fib_present if p not in fib)
        failures.extend(f"unexpected BGPD FIB {p}" for p in fib_absent if p in fib)
        if failures:
            raise TestCaseFailure(f"{hostname}: " + "; ".join(failures))

    async def _assert_peer_routes(
        self, driver: t.Any, hostname: str, params: dict[str, t.Any]
    ) -> None:
        peer = str(params.get("peer_addr") or "").strip()
        view = str(params.get("peer_view") or "postfilter_advertised")
        methods = {
            "prefilter_received": "async_get_prefilter_received_networks",
            "postfilter_received": "async_get_postfilter_received_networks",
            "postfilter_advertised": "async_get_postfilter_advertised_networks",
        }
        if not peer or view not in methods:
            raise ValueError(
                f"peer_addr and peer_view in {sorted(methods)} are required"
            )
        routes = await getattr(driver, methods[view])(peer)
        observed = {_prefix_key(prefix): path for prefix, path in routes.items()}
        present = _canonical_prefixes(
            params.get("expected_present"), "expected_present"
        )
        absent = _canonical_prefixes(params.get("expected_absent"), "expected_absent")
        failures = [f"missing {view} {p}" for p in present if p not in observed]
        failures.extend(f"unexpected {view} {p}" for p in absent if p in observed)
        required = params.get("required_communities", {})
        forbidden = params.get("forbidden_communities", {})
        for prefix in set(required) | set(forbidden):
            path = observed.get(str(prefix))
            if path is None:
                failures.append(f"missing {view} {prefix} for communities")
                continue
            communities = _path_communities(path)
            missing = set(required.get(prefix, [])) - communities
            leaked = set(forbidden.get(prefix, [])) & communities
            if missing:
                failures.append(f"{prefix} missing communities {sorted(missing)}")
            if leaked:
                failures.append(
                    f"{prefix} retained forbidden communities {sorted(leaked)}"
                )
        if failures:
            raise TestCaseFailure(f"{hostname}: " + "; ".join(failures))

    async def _restore(self, driver: t.Any, hostname: str) -> None:
        restored = False
        for path in (C.BGP_POLICY_PATH, C.BGP_CONFIG_PATH):
            restored = await async_restore_backup(
                driver, path, self.logger, hostname, backup_suffix=_BACKUP_SUFFIX
            ) or restored
        if restored:
            await driver.async_restart_service(FbossSystemctlServiceName.BGP)


__all__ = ["RbbBgpPolicyLifecycleTask"]
