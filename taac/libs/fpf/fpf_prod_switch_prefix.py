# Copyright (c) Meta Platforms, Inc. and affiliates.

"""Exact production routes in BGP and FSDB, independent of injected scale."""

import asyncio
import ipaddress
import json
import logging
import time
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass

from taac.internal.driver.fboss_switch_internal import (
    FbossSwitchInternal,
)
from taac.libs.collectors.base_collector import (
    _now_str,
    BaseCollector,
)
from taac.libs.fpf.fpf_bgp_rib import (
    _rib_entry_to_network,
    get_bgp_rib_subprefixes,
)
from taac.libs.fpf.fpf_fsdb_ribmap import get_fsdb_rib_map

logger: logging.Logger = logging.getLogger(__name__)


def normalized_prefixes(prefixes: Iterable[str]) -> list[str]:
    return sorted({str(ipaddress.IPv6Network(p, strict=False)) for p in prefixes})


def production_gtsws(gtsws: Iterable[str], plane_count: int = 4) -> list[str]:
    """Observe every requested pod; never infer a remote pod from a host name."""
    targets = set()
    for gtsw in gtsws:
        short = gtsw.removesuffix(".tfbnw.net")
        first, separator, suffix = short.partition(".")
        if first.startswith("gtsw") and first[4:].isdigit() and separator:
            targets.update(f"gtsw{n:03d}.{suffix}" for n in range(1, plane_count + 1))
        else:
            targets.add(short)
    return sorted(targets)


@dataclass(frozen=True)
class ProductionRoute:
    present: bool
    best_path: bool


@dataclass(frozen=True)
class ProductionRouteRow:
    timestamp: str
    gtsw: str
    protocol: str
    request_start_epoch: float
    request_end_epoch: float
    prefixes: dict[str, ProductionRoute] | None
    notes: str = ""


def fsdb_production_routes(
    rib: Mapping, prefixes: Iterable[str], mode: str
) -> dict[str, ProductionRoute]:
    entries = {}
    for raw, entry in rib.items():
        try:
            prefix = str(ipaddress.IPv6Network(raw, strict=False))
        except (ValueError, TypeError):
            continue
        entries[prefix] = entry
    result = {}
    for prefix in normalized_prefixes(prefixes):
        entry = entries.get(prefix)
        if prefix in entries and not isinstance(entry, dict):
            raise ValueError(f"Malformed FSDB entry for {prefix}")
        best = entry.get("best_path") if entry and mode == "canonical" else None
        if entry and mode == "ribmap":
            best = entry.get("paths", {}).get(entry.get("best_group", "best"), [])
        result[prefix] = ProductionRoute(entry is not None, bool(best))
    return result


class ProdSwitchPrefixCollector(BaseCollector):
    """One bounded request per switch at a time; errors emit NULL, not absence."""

    def __init__(
        self,
        gtsws: Iterable[str],
        prefixes: Iterable[str],
        protocol: str,
        interval_sec: float = 5,
        timeout_sec: float = 30,
        fsdb_mode: str = "canonical",
        tmp_path: str | None = None,
    ) -> None:
        if protocol not in {"bgp", "fsdb"} or fsdb_mode not in {"canonical", "ribmap"}:
            raise ValueError("Unsupported production route protocol or FSDB mode")
        if interval_sec <= 0 or timeout_sec <= 0:
            raise ValueError("Polling interval and timeout must be positive")
        self.gtsws = sorted(set(gtsws))
        self.prefixes = normalized_prefixes(prefixes)
        if not self.gtsws or not self.prefixes:
            raise ValueError(
                "Production route collection requires switches and prefixes"
            )
        self.protocol = protocol
        self.fsdb_mode = fsdb_mode
        self.timeout_sec = timeout_sec
        self.POLL_TIMEOUT_SEC = timeout_sec + 1
        super().__init__(
            tmp_path or f"/tmp/fpf_prod_{protocol}_prefix.log", interval_sec
        )

    async def _read_switch(self, gtsw: str) -> dict[str, ProductionRoute]:
        if self.protocol == "fsdb":
            driver = FbossSwitchInternal(gtsw, logger)
            rib = await get_fsdb_rib_map(driver, mode=self.fsdb_mode)
            if not isinstance(rib, dict):
                raise ValueError("FSDB returned a non-map RIB")
            return fsdb_production_routes(rib, self.prefixes, self.fsdb_mode)
        routes = {}
        for prefix in self.prefixes:
            entries = await get_bgp_rib_subprefixes(gtsw, ipaddress.IPv6Network(prefix))
            exact = [
                e
                for e in entries
                if _rib_entry_to_network(e) == ipaddress.IPv6Network(prefix)
            ]
            routes[prefix] = ProductionRoute(
                bool(exact),
                any(
                    e.best_path is not None or bool(e.paths.get("best", []))
                    for e in exact
                ),
            )
        return routes

    async def _poll_switch(self, gtsw: str) -> None:
        start = time.time()
        routes = None
        notes = ""
        try:
            routes = await asyncio.wait_for(self._read_switch(gtsw), self.timeout_sec)
        except TimeoutError:
            self._record_host_timeout(gtsw, self.timeout_sec)
            notes = f"error: poll timeout ({self.timeout_sec}s)"
        except Exception as error:  # noqa: BLE001 - collection failure is an explicit NULL observation
            notes = f"error: {type(error).__name__}: {error}"
        row = ProductionRouteRow(
            _now_str(), gtsw, self.protocol, start, time.time(), routes, notes
        )
        self.rows.append(row)
        if self._file is not None:
            try:
                self._file.write(json.dumps(asdict(row), sort_keys=True) + "\n")
                self._file.flush()
            except (OSError, ValueError) as error:
                logger.error(
                    "Production %s log write failed for %s: %s",
                    self.protocol,
                    gtsw,
                    error,
                )

    async def _poll_once(self) -> None:
        await asyncio.gather(*(self._poll_switch(gtsw) for gtsw in self.gtsws))

    async def _poll_switch_loop(self, gtsw: str) -> None:
        while not self._stop_flag.is_set():
            await self._poll_switch(gtsw)
            await asyncio.sleep(self.interval_sec)

    async def _run_loop(self) -> None:
        """A slow switch cannot delay collection on any sibling switch."""
        with open(self.tmp_path, "a" if self._append_mode else "w") as output:
            self._file = output
            workers = [
                asyncio.create_task(self._poll_switch_loop(g)) for g in self.gtsws
            ]
            try:
                await asyncio.gather(*workers)
            except asyncio.CancelledError:
                pass
            finally:
                for worker in workers:
                    worker.cancel()
                await asyncio.gather(*workers, return_exceptions=True)


@dataclass(frozen=True)
class ProductionRouteResult:
    gtsw: str
    prefix: str
    status: str
    convergence_sec: float | None
    detail: str


def _route_matches(row: ProductionRouteRow, prefix: str, expected: bool) -> bool:
    if row.prefixes is None or prefix not in row.prefixes:
        return False
    route = row.prefixes[prefix]
    return route.present and route.best_path if expected else not route.present


def _evaluate_convergence(
    samples: list[ProductionRouteRow],
    gtsw: str,
    prefix: str,
    expected: bool,
    start: float,
    max_sec: float,
) -> ProductionRouteResult:
    recovery = next((r for r in samples if _route_matches(r, prefix, expected)), None)
    if recovery is None or not _route_matches(samples[-1], prefix, expected):
        return ProductionRouteResult(
            gtsw,
            prefix,
            "FAIL",
            None,
            "Expected route state not reached or final state regressed",
        )
    elapsed = recovery.request_end_epoch - start
    if elapsed > max_sec:
        status = "WAIT" if recovery.request_start_epoch <= start + max_sec else "FAIL"
        return ProductionRouteResult(
            gtsw,
            prefix,
            status,
            elapsed,
            "Qualifying poll crossed convergence deadline"
            if status == "WAIT"
            else "Late production route convergence",
        )
    if any(
        not _route_matches(r, prefix, expected)
        for r in samples
        if r.request_end_epoch >= recovery.request_end_epoch
    ):
        return ProductionRouteResult(
            gtsw,
            prefix,
            "FAIL",
            elapsed,
            "Production route regressed after convergence",
        )
    return ProductionRouteResult(
        gtsw, prefix, "PASS", elapsed, f"Expected state observed in {elapsed:.3f}s"
    )


def _evaluate_route(
    rows: list[ProductionRouteRow],
    gtsw: str,
    prefix: str,
    expected_present: bool,
    start: float,
    end: float,
    mode: str,
    max_convergence_sec: float,
    max_sample_age_sec: float,
) -> ProductionRouteResult:
    samples = sorted(
        (
            r
            for r in rows
            if r.gtsw == gtsw
            and r.request_start_epoch >= start
            and r.request_end_epoch <= end
        ),
        key=lambda r: r.request_end_epoch,
    )
    usable = [r for r in samples if r.prefixes is not None and prefix in r.prefixes]
    if (
        not samples
        or not usable
        or samples[-1].prefixes is None
        or prefix not in samples[-1].prefixes
    ):
        return ProductionRouteResult(
            gtsw,
            prefix,
            "WAIT",
            None,
            "No readable final production-prefix observation",
        )
    if end - samples[-1].request_end_epoch > max_sample_age_sec:
        return ProductionRouteResult(
            gtsw, prefix, "WAIT", None, "Final observation is stale"
        )
    if mode == "convergence":
        return _evaluate_convergence(
            usable, gtsw, prefix, expected_present, start, max_convergence_sec
        )
    if len(usable) != len(samples):
        return ProductionRouteResult(
            gtsw, prefix, "WAIT", None, "NULL observation in stability window"
        )
    ok = all(_route_matches(r, prefix, expected_present) for r in usable)
    return ProductionRouteResult(
        gtsw,
        prefix,
        "PASS" if ok else "FAIL",
        None,
        "No change"
        if ok
        else "Unexpected production route presence or best-path state",
    )


def evaluate_production_routes(
    collector: ProdSwitchPrefixCollector,
    window_start: float,
    window_end: float,
    expected_by_gtsw: Mapping[str, Mapping[str, bool]] | None = None,
    mode: str = "stability",
    max_convergence_sec: float = 10,
    max_sample_age_sec: float = 60,
) -> list[ProductionRouteResult]:
    if mode not in {"stability", "convergence"} or window_end < window_start:
        raise ValueError("Invalid production route evaluation window or mode")
    expected = (
        expected_by_gtsw
        if expected_by_gtsw is not None
        else {g: dict.fromkeys(collector.prefixes, True) for g in collector.gtsws}
    )
    if not expected or any(not prefixes for prefixes in expected.values()):
        raise ValueError("Expected production route scope must not be empty")
    if any(
        type(present) is not bool
        for prefixes in expected.values()
        for present in prefixes.values()
    ):
        raise ValueError("Expected production route presence must be boolean")
    return [
        _evaluate_route(
            collector.rows,
            gtsw,
            str(ipaddress.IPv6Network(prefix, strict=False)),
            present,
            window_start,
            window_end,
            mode,
            max_convergence_sec,
            max_sample_age_sec,
        )
        for gtsw, prefixes in expected.items()
        for prefix, present in prefixes.items()
    ]
