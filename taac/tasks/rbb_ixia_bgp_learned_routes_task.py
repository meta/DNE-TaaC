# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Verify exact IPv6 routes in an IXIA BGP peer's learned-route tables."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import time
import typing as t

from taac.constants import TestCaseFailure
from taac.tasks.base_task import BaseTask
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger


def _column_token(value: t.Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _table_routes(table: t.Any) -> dict[str, set[str]]:
    """Extract exact prefixes and standard communities from a RESTPy table."""
    columns = list(getattr(table, "Columns", None) or ())
    rows = list(getattr(table, "Values", None) or ())
    tokens = [_column_token(column) for column in columns]
    address_index = next(
        (
            index
            for index, token in enumerate(tokens)
            if token in {"networkaddress", "network", "ipv6prefix", "routeprefix"}
            or ("network" in token and "address" in token)
        ),
        None,
    )
    length_index = next(
        (
            index
            for index, token in enumerate(tokens)
            if token in {"prefixlength", "prefixlen", "networkprefixlength"}
        ),
        None,
    )
    community_indexes = [
        index for index, token in enumerate(tokens) if "communit" in token
    ]
    routes: dict[str, set[str]] = {}
    for row in rows:
        values = list(row) if isinstance(row, (list, tuple)) else [row]
        candidates: list[str] = []
        if address_index is not None and address_index < len(values):
            address = str(values[address_index]).strip()
            if "/" in address:
                candidates.append(address)
            elif length_index is not None and length_index < len(values):
                candidates.append(f"{address}/{values[length_index]}")
        # Some IxNetwork releases expose a single CIDR column with a different
        # title. Accept only explicit CIDR cells as the fallback; this avoids
        # mistaking an IPv6 next-hop column for the learned NLRI.
        if not candidates:
            candidates.extend(
                str(value).strip() for value in values if "/" in str(value)
            )
        for candidate in candidates:
            try:
                network = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                continue
            if network.version == 6:
                prefix = str(network)
                communities = routes.setdefault(prefix, set())
                for index in community_indexes:
                    if index < len(values):
                        communities.update(
                            re.findall(r"(?<!\d)\d+:\d+(?!\d)", str(values[index]))
                        )
    return routes


def _table_has_community_column(table: t.Any) -> bool:
    return any(
        "communit" in _column_token(column)
        for column in (getattr(table, "Columns", None) or ())
    )


def _table_prefixes(table: t.Any) -> set[str]:
    """Backward-compatible exact-prefix extractor."""
    return set(_table_routes(table))


def _single_boolean_value(multivalue: t.Any) -> bool:
    """Read one uniform RESTPy boolean MultiValue without changing it."""
    raw_values = list(getattr(multivalue, "Values", None) or ())
    if not raw_values:
        raise ValueError("FilterIpV6Unicast.Values is empty")
    values: list[bool] = []
    for raw_value in raw_values:
        if isinstance(raw_value, bool):
            values.append(raw_value)
            continue
        normalized = str(raw_value).strip().casefold()
        if normalized in {"true", "1"}:
            values.append(True)
        elif normalized in {"false", "0"}:
            values.append(False)
        else:
            raise ValueError(
                f"FilterIpV6Unicast has invalid boolean value {raw_value!r}"
            )
    if len(set(values)) != 1:
        raise ValueError("FilterIpV6Unicast.Values is not uniform")
    return values[0]


class RbbIxiaBgpLearnedRoutesTask(BaseTask):
    """Poll one exact IXIA IPv6 BGP peer for expected received routes."""

    # pyrefly: ignore [bad-override-mutable-attribute]
    NAME: str = "rbb_ixia_bgp_learned_routes"

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
            "gate",
            "port_identifier",
            "expected_prefixes",
            "forbidden_prefixes",
            "expected_communities",
            "forbidden_communities",
            "timeout_seconds",
            "poll_interval_seconds",
        }
        unknown = sorted(set(params) - allowed)
        if unknown:
            raise ValueError(
                f"rbb_ixia_bgp_learned_routes unsupported fields: {unknown}"
            )
        gate = str(params.get("gate") or self.NAME)
        port_identifier = str(params.get("port_identifier") or "").strip()
        if not port_identifier:
            raise ValueError("rbb_ixia_bgp_learned_routes requires port_identifier")
        raw_prefixes = params.get("expected_prefixes")
        if not isinstance(raw_prefixes, list) or not raw_prefixes:
            raise ValueError(
                "rbb_ixia_bgp_learned_routes requires non-empty expected_prefixes"
            )
        try:
            expected = {
                str(ipaddress.ip_network(str(prefix), strict=True))
                for prefix in raw_prefixes
            }
        except ValueError as error:
            raise ValueError(f"invalid expected IPv6 prefix: {error}") from error
        if any(ipaddress.ip_network(prefix).version != 6 for prefix in expected):
            raise ValueError("IXIA BGP learned-route expectations must be IPv6")
        forbidden = {
            str(ipaddress.ip_network(str(prefix), strict=True))
            for prefix in params.get("forbidden_prefixes", [])
        }
        expected_communities = params.get("expected_communities", {})
        forbidden_communities = params.get("forbidden_communities", {})
        for label, mapping in (
            ("expected_communities", expected_communities),
            ("forbidden_communities", forbidden_communities),
        ):
            if not isinstance(mapping, dict) or any(
                not isinstance(value, list) for value in mapping.values()
            ):
                raise ValueError(f"{label} must map prefixes to community lists")
        timeout = params.get("timeout_seconds", 60)
        interval = params.get("poll_interval_seconds", 2)
        for label, value in (
            ("timeout_seconds", timeout),
            ("poll_interval_seconds", interval),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) <= 0
            ):
                raise ValueError(f"{label} must be a positive finite number")
        timeout = float(timeout)
        interval = float(interval)

        find_peer = getattr(self.ixia, "find_bgp_ipv6_peer", None)
        if not callable(find_peer):
            raise TestCaseFailure(
                f"[{gate}] IXIA backend {type(self.ixia).__name__} cannot provide "
                "IPv6 BGP learned-route evidence; this check requires the "
                "RESTPy/TaacIxia backend"
            )
        peer = find_peer(port_identifier)
        if peer is None:
            raise TestCaseFailure(
                f"[{gate}] IXIA IPv6 BGP peer for {port_identifier!r} was not found"
            )

        # IxNetwork does not populate the IPv6 learned-route view unless the
        # per-peer filter is explicitly enabled and the on-the-fly mutation is
        # applied. Keep this local to the read-only evidence task: global IXIA
        # creation should not silently opt every scenario into learned info.
        filter_control = getattr(peer, "FilterIpV6Unicast", None)
        enable_filter = getattr(filter_control, "Single", None)
        apply_changes = getattr(self.ixia, "apply_changes", None)
        get_learned_info = getattr(peer, "GetIPv6LearnedInfo", None)
        unsupported = []
        if not callable(enable_filter):
            unsupported.append("peer.FilterIpV6Unicast.Single")
        if not callable(apply_changes):
            unsupported.append("ixia.apply_changes")
        if not callable(get_learned_info):
            unsupported.append("peer.GetIPv6LearnedInfo")
        if unsupported:
            raise TestCaseFailure(
                f"[{gate}] IXIA backend cannot provide IPv6 BGP learned-route "
                f"evidence; missing methods={unsupported}"
            )
        try:
            original_filter_value = _single_boolean_value(filter_control)
        except Exception as error:
            raise TestCaseFailure(
                f"[{gate}] failed to read IXIA IPv6 Unicast learned-info "
                f"filter for {port_identifier!r}: {error}"
            ) from error

        filter_changed = not original_filter_value
        filter_mutated = False
        primary_error: BaseException | None = None
        try:
            try:
                if filter_changed:
                    try:
                        # The server may apply the mutation even when the API
                        # response is lost. Arm restoration before issuing the
                        # request so that ambiguous failures are repaired too.
                        filter_mutated = True
                        enable_filter(True)
                        apply_changes()
                    except Exception as error:
                        raise TestCaseFailure(
                            f"[{gate}] failed to enable IXIA IPv6 Unicast "
                            f"learned-info filter for {port_identifier!r}: {error}"
                        ) from error

                deadline = time.monotonic() + timeout
                observed: dict[str, set[str]] = {}
                state: t.Any = None
                while True:
                    # Refresh on every poll. GetIPv6LearnedInfo triggers an
                    # IxNetwork operation; simply re-reading a previously returned
                    # Table object can otherwise leave a stale snapshot until the
                    # timeout expires.
                    try:
                        get_learned_info()
                        learned_collection = getattr(peer, "LearnedInfo", None)
                        find_learned = getattr(learned_collection, "find", None)
                        if not callable(find_learned):
                            raise AttributeError("peer.LearnedInfo.find")
                        # RESTPy properties expose an unselected collection
                        # object.  Select the server-created learned-info
                        # resource before accessing its child Table collection;
                        # otherwise ``Table.find()`` has no parent href.
                        learned = find_learned()
                        table_collection = getattr(learned, "Table", None)
                        find_tables = getattr(table_collection, "find", None)
                        if not callable(find_tables):
                            raise AttributeError("peer.LearnedInfo.Table.find")
                        tables = find_tables()
                    except Exception as error:
                        raise TestCaseFailure(
                            f"[{gate}] failed to refresh IXIA IPv6 BGP learned "
                            f"routes for {port_identifier!r}: {error}"
                        ) from error
                    state = getattr(learned, "State", None)
                    observed = {}
                    community_view_available = False
                    for table in tables:
                        community_view_available = (
                            community_view_available
                            or _table_has_community_column(table)
                        )
                        for prefix, communities in _table_routes(table).items():
                            observed.setdefault(prefix, set()).update(communities)
                    missing = expected - set(observed)
                    leaked = forbidden & set(observed)
                    missing_communities = {
                        prefix: sorted(set(communities) - observed.get(prefix, set()))
                        for prefix, communities in expected_communities.items()
                        if set(communities) - observed.get(prefix, set())
                    }
                    leaked_communities = {
                        prefix: sorted(set(communities) & observed.get(prefix, set()))
                        for prefix, communities in forbidden_communities.items()
                        if set(communities) & observed.get(prefix, set())
                    }
                    attributes_unavailable = bool(
                        expected_communities or forbidden_communities
                    ) and not community_view_available
                    if not (
                        missing
                        or leaked
                        or missing_communities
                        or leaked_communities
                        or attributes_unavailable
                    ):
                        self.logger.info(
                            f"[{gate}] IXIA peer {port_identifier!r} learned all "
                            f"expected prefixes: {sorted(expected)}"
                        )
                        return
                    if time.monotonic() >= deadline:
                        raise TestCaseFailure(
                            f"[{gate}] IXIA peer {port_identifier!r} did not learn "
                            f"expected prefixes before timeout; "
                            f"missing={sorted(missing)}, leaked={sorted(leaked)}, "
                            f"missing_communities={missing_communities}, "
                            f"leaked_communities={leaked_communities}, "
                            f"community_view_available={community_view_available}, "
                            f"observed={sorted(observed)}, "
                            f"learned_info_state={state!r}"
                        )
                    await asyncio.sleep(interval)
            except BaseException as error:
                primary_error = error
                raise
        finally:
            if filter_mutated:
                # Learned-info filtering is a temporary observation aid, not
                # part of the declarative IXIA session. Restore it on success,
                # timeout, refresh failure, or cancellation.
                try:
                    enable_filter(original_filter_value)
                    apply_changes()
                except Exception as error:
                    message = (
                        f"[{gate}] failed to restore IXIA IPv6 Unicast "
                        f"learned-info filter for {port_identifier!r}: {error}"
                    )
                    restoration_error = TestCaseFailure(message)
                    restoration_error.__cause__ = error
                    if primary_error is None:
                        raise restoration_error from error
                    if isinstance(primary_error, Exception):
                        raise ExceptionGroup(
                            f"[{gate}] IXIA learned-route check and learned-info "
                            "filter restoration both failed",
                            [primary_error, restoration_error],
                        ) from error
                    # Cancellation and other BaseException subclasses must not
                    # be replaced by a secondary cleanup failure. Attach the
                    # restoration evidence while the primary error continues
                    # unwinding unchanged.
                    primary_error.add_note(
                        f"IXIA learned-info filter restoration also failed: "
                        f"{type(error).__name__}: {error}"
                    )


__all__ = ["RbbIxiaBgpLearnedRoutesTask", "_table_prefixes", "_table_routes"]
