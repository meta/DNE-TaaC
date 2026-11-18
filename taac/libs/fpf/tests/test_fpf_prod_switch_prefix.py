# Copyright (c) Meta Platforms, Inc. and affiliates.

import ipaddress
import logging
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from later.unittest import TestCase
from neteng.fboss.bgp_attr.types import TIpPrefix
from neteng.fboss.bgp_route_types.types import TBgpPath, TRibEntry
from taac.internal.driver.fboss_switch_internal import (
    FbossSwitchInternal,
)
from taac.libs.fpf.fpf_fsdb_ribmap import get_fsdb_rib_map
from taac.libs.fpf.fpf_prod_switch_prefix import (
    evaluate_production_routes,
    fsdb_production_routes,
    ProdSwitchPrefixCollector,
    production_gtsws,
    ProductionRoute,
    ProductionRouteRow,
)
from taac.libs.fpf.fpf_prod_switch_prefix_health import (
    check_production_routes,
)
from taac.health_check.health_check import types as hc_types

A = "2401:db00:292a:a270::/64"
B = "2401:db00:292a:a15c::/64"
SW = "gtsw001.l1002.c087.mwg2"
MODULE = "neteng.test_infra.dne.taac.libs.fpf.fpf_prod_switch_prefix"


def row(start, end, present=True, best=True, null=False):
    return ProductionRouteRow(
        "2026-11-16 23:00:00.000-0800",
        SW,
        "bgp",
        start,
        end,
        None
        if null
        else {A: ProductionRoute(present, best), B: ProductionRoute(True, True)},
    )


class ProductionRoutePolicyTest(unittest.TestCase):
    def setUp(self):
        self.collector = ProdSwitchPrefixCollector([SW], [A, B], "bgp")

    def evaluate(self, **kwargs):
        kwargs.setdefault("expected_by_gtsw", {SW: {A: True}})
        return evaluate_production_routes(self.collector, 100, 120, **kwargs)

    def test_both_pods_are_scoped_without_duplicate_switches(self):
        switches = production_gtsws([SW, "gtsw002.l1001.c087.mwg2", SW])
        self.assertEqual(8, len(switches))
        self.assertIn("gtsw004.l1001.c087.mwg2", switches)
        self.assertNotIn("gtsw005.l1001.c087.mwg2", switches)

    def test_exact_fsdb_routes_and_best_path_independent_of_scale(self):
        rib = {
            "2401:db00:292a:a270:0000::/64": {"best_path": {"path_idx": 0}},
            B: {"best_path": None},
            "5000:dd::/64": {"best_path": {"path_idx": 1}},
        }
        routes = fsdb_production_routes(
            rib, [A, B, "2401:db00:292a:ffff::/64"], "canonical"
        )
        self.assertEqual(ProductionRoute(True, True), routes[A])
        self.assertEqual(ProductionRoute(True, False), routes[B])
        self.assertEqual(3, len(routes))

    def test_missing_best_path_fails_even_with_prefix_present(self):
        self.collector.rows = [row(101, 102, best=False)]
        self.assertEqual("FAIL", self.evaluate()[0].status)

    def test_null_stale_and_missing_final_key_cannot_pass(self):
        for rows in ([row(101, 102), row(110, 111, null=True)], [], [row(50, 51)]):
            self.collector.rows = rows
            self.assertEqual("WAIT", self.evaluate()[0].status)
        self.collector.rows = [row(101, 102)]
        self.assertEqual("WAIT", self.evaluate(max_sample_age_sec=5)[0].status)

    def test_recovery_within_sla_and_stability(self):
        self.collector.rows = [
            row(101, 102, present=False),
            row(107, 108),
            row(118, 119),
        ]
        result = self.evaluate(mode="convergence")[0]
        self.assertEqual("PASS", result.status)
        self.assertEqual(8, result.convergence_sec)
        self.collector.rows.append(row(119, 120, present=False))
        self.assertEqual("FAIL", self.evaluate(mode="convergence")[0].status)

    def test_slow_rpc_is_measurement_gap_not_late_recovery_proof(self):
        self.collector.rows = [row(108, 112)]
        self.assertEqual("WAIT", self.evaluate(mode="convergence")[0].status)
        self.collector.rows = [row(111, 112)]
        self.assertEqual("FAIL", self.evaluate(mode="convergence")[0].status)

    def test_withdrawal_expected_for_only_native_prefix(self):
        self.collector.rows = [row(101, 102, present=False)]
        result = self.evaluate(
            mode="convergence", expected_by_gtsw={SW: {A: False, B: True}}
        )
        self.assertTrue(all(r.status == "PASS" for r in result))

    def test_unknown_switch_fails_measurement_instead_of_disappearing(self):
        self.collector.rows = [row(101, 102)]
        result = self.evaluate(expected_by_gtsw={"missing": {A: True}})
        self.assertEqual("WAIT", result[0].status)

    def test_convergence_requires_actual_trigger_timestamp(self):
        health_module = (
            "neteng.test_infra.dne.taac.libs.fpf.fpf_prod_switch_prefix_health"
        )
        self.collector.rows = [row(101, 102)]
        with (
            patch(f"{health_module}.get_collector", return_value=self.collector),
            patch(f"{health_module}.get_disruption_time", return_value=0),
        ):
            result = check_production_routes("bgp", {"production_mode": "convergence"})
        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("trigger timestamp", result.message)

    def test_final_missing_key_and_empty_scope_do_not_pass(self):
        self.collector.rows = [
            row(101, 102),
            ProductionRouteRow("2026-11-16 23:00:00.000-0800", SW, "bgp", 118, 119, {}),
        ]
        self.assertEqual("WAIT", self.evaluate()[0].status)
        with self.assertRaises(ValueError):
            self.evaluate(expected_by_gtsw={})

    def test_trigger_after_explicit_window_end_fails_without_exception(self):
        health_module = (
            "neteng.test_infra.dne.taac.libs.fpf.fpf_prod_switch_prefix_health"
        )
        with (
            patch(f"{health_module}.get_collector", return_value=self.collector),
            patch(f"{health_module}.get_disruption_time", return_value=200),
        ):
            result = check_production_routes(
                "bgp", {"production_mode": "convergence", "window_end": 120}
            )
        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("Invalid production", result.message)

    def test_healthcheck_reports_unreadable_collector_as_failure(self):
        health_module = (
            "neteng.test_infra.dne.taac.libs.fpf.fpf_prod_switch_prefix_health"
        )
        with patch(f"{health_module}.get_collector", return_value=self.collector):
            result = check_production_routes(
                "bgp", {"window_start": 100, "window_end": 120}
            )
        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("WAIT", result.message)


class ProductionRoutePollingTest(TestCase):
    async def test_bgp_exact_filter_ignores_more_specific_route(self):
        prefix = TIpPrefix(
            prefix_bin=ipaddress.IPv6Network(A).network_address.packed, num_bits=64
        )
        subnet = TIpPrefix(prefix_bin=prefix.prefix_bin, num_bits=128)
        entries = [
            TRibEntry(prefix=prefix, paths={"best": [TBgpPath()]}),
            TRibEntry(prefix=subnet, paths={"best": [TBgpPath()]}),
        ]
        collector = ProdSwitchPrefixCollector([SW], [A], "bgp")
        with patch(
            f"{MODULE}.get_bgp_rib_subprefixes", AsyncMock(return_value=entries)
        ):
            await collector._poll_once()
        self.assertEqual({A: ProductionRoute(True, True)}, collector.rows[0].prefixes)

    async def test_rpc_error_records_null_and_does_not_erase_other_switch(self):
        other = "gtsw002.l1002.c087.mwg2"
        collector = ProdSwitchPrefixCollector([SW, other], [A], "bgp")

        async def read(gtsw, prefix):
            if gtsw == SW:
                raise RuntimeError("unavailable")
            return []

        with patch(f"{MODULE}.get_bgp_rib_subprefixes", side_effect=read):
            await collector._poll_once()
        by_switch = {r.gtsw: r for r in collector.rows}
        self.assertIsNone(by_switch[SW].prefixes)
        self.assertIn("RuntimeError", by_switch[SW].notes)
        self.assertEqual(ProductionRoute(False, False), by_switch[other].prefixes[A])
        self.assertGreaterEqual(
            by_switch[SW].request_end_epoch, by_switch[SW].request_start_epoch
        )

    async def test_fsdb_unavailable_is_null_not_route_withdrawal(self):
        collector = ProdSwitchPrefixCollector([SW], [A], "fsdb")
        with patch(
            f"{MODULE}.get_fsdb_rib_map",
            AsyncMock(side_effect=RuntimeError("no RIB contents")),
        ):
            await collector._poll_once()
        self.assertIsNone(collector.rows[0].prefixes)
        self.assertIn("no RIB contents", collector.rows[0].notes)

    async def test_fsdb_resolution_failure_is_not_an_empty_rib(self):
        with patch(
            "neteng.fboss.lib.asyncio.hostnames.host_to_ip",
            AsyncMock(return_value=None),
        ):
            with self.assertRaisesRegex(RuntimeError, "Cannot resolve"):
                await get_fsdb_rib_map(
                    FbossSwitchInternal(SW, logging.getLogger(__name__))
                )

    async def test_fsdb_malformed_exact_entry_is_null(self):
        for entry in ("invalid", None):
            collector = ProdSwitchPrefixCollector([SW], [A], "fsdb")
            with patch(
                f"{MODULE}.get_fsdb_rib_map", AsyncMock(return_value={A: entry})
            ):
                await collector._poll_once()
            self.assertIsNone(collector.rows[0].prefixes)
            self.assertIn("Malformed FSDB entry", collector.rows[0].notes)

    async def test_closed_log_does_not_stop_polling_or_erase_observations(self):
        collector = ProdSwitchPrefixCollector([SW], [A], "bgp")
        with tempfile.TemporaryFile(mode="w+") as output:
            collector._file = output
        with patch(f"{MODULE}.get_bgp_rib_subprefixes", AsyncMock(return_value=[])):
            await collector._poll_once()
            await collector._poll_once()
        self.assertEqual(2, len(collector.rows))
        self.assertTrue(
            all(r.prefixes[A] == ProductionRoute(False, False) for r in collector.rows)
        )
