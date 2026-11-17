# pyre-unsafe
# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Unit tests for the Port Statistics traffic-stats source.

Selected with TAAC_IXIA_TRAFFIC_STATS_SOURCE=port for chassis whose traffic-item
statistics views never become ready; loss and rates are derived from per-port
counters instead.
"""

import os
import threading
import types
import unittest
from collections import defaultdict
from unittest.mock import MagicMock, patch

from ixnetwork_restpy.assistants.statistics.row import Row as IxnStatRow
from taac.ixia.ixia import Ixia
from taac.ixia.taac_ixia import (
    compute_port_loss_stats,
    compute_port_rate_stats,
    IxiaSetupError,
    TaacIxia,
    TrafficItemPorts,
)

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

_TAAC_IXIA_MODULE = (
    "taac.ixia.taac_ixia" if TAAC_OSS else "neteng.test_infra.dne.taac.ixia.taac_ixia"
)

PORT_COLUMNS = [
    "Port Name",
    "Scheduled Frames Tx.",
    "Data Integrity Frames Rx.",
]


def _port_rows(counters, columns=PORT_COLUMNS):
    """Port Statistics rows from {vport: (scheduled_tx, data_integrity_rx)}."""
    rows = [
        [name, str(tx), str(rx)][: len(columns)]
        for name, (tx, rx) in counters.items()
    ]
    return IxnStatRow("Port Statistics", columns, rows)


RATE_COLUMNS = [
    "Port Name",
    "Tx. Rate (Mbps)",
    "Rx. Rate (Mbps)",
    "Scheduled Frames Tx.",
    "Data Integrity Frames Rx.",
]


def _rate_rows(counters, columns=RATE_COLUMNS):
    """Port Statistics rows from {vport: (tx_mbps, rx_mbps, sched_tx, di_rx)}."""
    rows = [
        [name, *(str(value) for value in values)][: len(columns)]
        for name, values in counters.items()
    ]
    return IxnStatRow("Port Statistics", columns, rows)


def _create_taac_ixia():
    with patch.object(TaacIxia, "__init__", lambda self: None):
        ixia = TaacIxia()
    ixia.logger = MagicMock()
    ixia.ixnetwork = MagicMock()
    ixia._snapshot_lock = threading.RLock()
    ixia.capturing = False
    ixia.test_case_uuid = "uuid"
    ixia.captured_stats = defaultdict(dict)
    ixia.captured_stats_traffic = defaultdict(dict)
    return ixia


class ComputePortLossStatsTest(unittest.TestCase):
    def test_unidirectional_item_loss_is_tx_minus_rx_on_the_far_port(self):
        items = [TrafficItemPorts("A", frozenset({"p1"}), frozenset({"p2"}))]
        rows = _port_rows({"p1": (1000, 0), "p2": (0, 990)})

        stats = compute_port_loss_stats(items, rows, window_seconds=10)

        self.assertEqual(
            stats,
            [
                {
                    "identifier": "A",
                    "view": "Port Statistics",
                    "tx_frames": 1000.0,
                    "rx_frames": 990.0,
                    "frame_delta": 10.0,
                    "packet_loss_percentage": 1.0,
                    # 10 of 1000 frames lost over a 10 s window -> 100 ms
                    "packet_loss_duration": 100.0,
                }
            ],
        )

    def test_bidirectional_item_sums_both_directions(self):
        both = frozenset({"p1", "p2"})
        items = [TrafficItemPorts("A", both, both)]
        rows = _port_rows({"p1": (1000, 995), "p2": (1000, 1000)})

        (stat,) = compute_port_loss_stats(items, rows, window_seconds=10)

        self.assertEqual(stat["tx_frames"], 2000.0)
        self.assertEqual(stat["rx_frames"], 1995.0)
        self.assertEqual(stat["frame_delta"], 5.0)
        self.assertEqual(stat["packet_loss_percentage"], 0.25)
        self.assertEqual(stat["packet_loss_duration"], 25.0)

    def test_item_that_sent_nothing_reports_zero_loss(self):
        items = [TrafficItemPorts("A", frozenset({"p1"}), frozenset({"p2"}))]
        rows = _port_rows({"p1": (0, 0), "p2": (0, 0)})

        (stat,) = compute_port_loss_stats(items, rows, window_seconds=10)

        self.assertEqual(stat["packet_loss_percentage"], 0.0)
        self.assertEqual(stat["packet_loss_duration"], 0.0)

    def test_vport_shared_by_two_items_cannot_be_attributed(self):
        items = [
            TrafficItemPorts("A", frozenset({"p1"}), frozenset({"p2"})),
            TrafficItemPorts("B", frozenset({"p2"}), frozenset({"p3"})),
        ]
        rows = _port_rows({"p1": (1, 1), "p2": (1, 1), "p3": (1, 1)})

        with self.assertRaisesRegex(IxiaSetupError, "p2"):
            compute_port_loss_stats(items, rows, window_seconds=10)

    def test_missing_data_integrity_column_is_an_error(self):
        items = [TrafficItemPorts("A", frozenset({"p1"}), frozenset({"p2"}))]
        rows = _port_rows(
            {"p1": (1000, 0), "p2": (0, 990)}, columns=PORT_COLUMNS[:2]
        )

        with self.assertRaisesRegex(IxiaSetupError, "Data Integrity Frames Rx."):
            compute_port_loss_stats(items, rows, window_seconds=10)

    def test_vport_missing_from_port_statistics_is_an_error(self):
        items = [TrafficItemPorts("A", frozenset({"p1"}), frozenset({"p9"}))]
        rows = _port_rows({"p1": (1000, 0)})

        with self.assertRaisesRegex(IxiaSetupError, "p9"):
            compute_port_loss_stats(items, rows, window_seconds=10)

    def test_unrelated_port_with_an_empty_counter_is_ignored(self):
        items = [TrafficItemPorts("A", frozenset({"p1"}), frozenset({"p2"}))]
        rows = _port_rows({"p1": (1000, 0), "p2": (0, 990), "p3": ("", "")})

        (stat,) = compute_port_loss_stats(items, rows, window_seconds=10)

        self.assertEqual(stat["frame_delta"], 10.0)


def _topology(href, vport_hrefs):
    return types.SimpleNamespace(href=href, Vports=vport_hrefs)


def _vport(href, name):
    return types.SimpleNamespace(href=href, Name=name)


def _traffic_item(name, sources, destinations, enabled=True, bidirectional=False):
    endpoint_set = types.SimpleNamespace(Sources=sources, Destinations=destinations)
    return types.SimpleNamespace(
        Name=name,
        Enabled=enabled,
        BiDirectional=bidirectional,
        EndpointSet=types.SimpleNamespace(find=lambda: [endpoint_set]),
    )


SESSION = "/api/v1/sessions/1/ixnetwork"

A_TO_B = TrafficItemPorts("A_TO_B", frozenset({"VPORT_A"}), frozenset({"VPORT_B"}))


class EnabledTrafficItemPortsTest(unittest.TestCase):
    def setUp(self):
        self.ixia = _create_taac_ixia()
        self.ixia.ixnetwork.Topology.find.return_value = [
            _topology(f"{SESSION}/topology/1", [f"{SESSION}/vport/1"]),
            _topology(f"{SESSION}/topology/2", [f"{SESSION}/vport/2"]),
        ]
        self.ixia.ixnetwork.Vport.find.return_value = [
            _vport(f"{SESSION}/vport/1", "VPORT_A"),
            _vport(f"{SESSION}/vport/2", "VPORT_B"),
        ]

    def test_ipv6_endpoints_resolve_to_their_topology_vports(self):
        self.ixia.ixnetwork.Traffic.TrafficItem.find.return_value = [
            _traffic_item(
                "A_TO_B",
                [f"{SESSION}/topology/1/deviceGroup/1/ethernet/1/ipv6/1"],
                [f"{SESSION}/topology/2/deviceGroup/1/ethernet/1/ipv6/1"],
            )
        ]

        self.assertEqual(
            self.ixia._enabled_traffic_item_ports(),
            [A_TO_B],
        )

    def test_raw_vport_endpoints_resolve_to_the_vport(self):
        self.ixia.ixnetwork.Traffic.TrafficItem.find.return_value = [
            _traffic_item(
                "RAW",
                [f"{SESSION}/vport/1/protocols"],
                [f"{SESSION}/vport/2/protocols"],
            )
        ]

        (item,) = self.ixia._enabled_traffic_item_ports()

        self.assertEqual(item.tx_vports, frozenset({"VPORT_A"}))
        self.assertEqual(item.rx_vports, frozenset({"VPORT_B"}))

    def test_bidirectional_item_counts_both_ends_as_tx_and_rx(self):
        self.ixia.ixnetwork.Traffic.TrafficItem.find.return_value = [
            _traffic_item(
                "A_B",
                [f"{SESSION}/topology/1/deviceGroup/1/ethernet/1/ipv6/1"],
                [f"{SESSION}/topology/2/deviceGroup/1/ethernet/1/ipv6/1"],
                bidirectional=True,
            )
        ]

        (item,) = self.ixia._enabled_traffic_item_ports()

        both = frozenset({"VPORT_A", "VPORT_B"})
        self.assertEqual((item.tx_vports, item.rx_vports), (both, both))

    def test_disabled_items_are_skipped(self):
        self.ixia.ixnetwork.Traffic.TrafficItem.find.return_value = [
            _traffic_item(
                "OFF",
                [f"{SESSION}/topology/1/deviceGroup/1/ethernet/1/ipv6/1"],
                [f"{SESSION}/topology/2/deviceGroup/1/ethernet/1/ipv6/1"],
                enabled=False,
            )
        ]

        self.assertEqual(self.ixia._enabled_traffic_item_ports(), [])

    def test_enabled_item_without_receiving_ports_is_an_error(self):
        # Without this it would measure tx with no rx side: 0 frames lost.
        self.ixia.ixnetwork.Traffic.TrafficItem.find.return_value = [
            _traffic_item(
                "NO_DST", [f"{SESSION}/topology/1/deviceGroup/1/ethernet/1/ipv6/1"], []
            )
        ]

        with self.assertRaisesRegex(IxiaSetupError, "NO_DST"):
            self.ixia._enabled_traffic_item_ports()


class GetLatestStatsSourceTest(unittest.TestCase):
    def setUp(self):
        self.ixia = _create_taac_ixia()
        self.port_view = MagicMock()
        self.ixia.get_or_create_stat_view = MagicMock(return_value=self.port_view)
        self.ixia._get_stat_view_rows = MagicMock(
            return_value=_port_rows({"VPORT_A": (1000, 0), "VPORT_B": (0, 990)})
        )
        self.ixia._enabled_traffic_item_ports = MagicMock(
            return_value=[
                A_TO_B
            ]
        )
        self.ixia.traffic_item_view_assistant = MagicMock()
        self.ixia._get_packet_loss_statistics_unlocked = MagicMock(
            return_value=[{"identifier": "from-traffic-item-view"}]
        )

    @patch.dict(os.environ, {"TAAC_IXIA_TRAFFIC_STATS_SOURCE": "port"})
    def test_port_source_measures_over_the_window_from_clear_to_stop(self):
        self.ixia._traffic_start_time = 90.0
        self.ixia._stats_cleared_at = 100.0
        self.ixia._traffic_stop_time = 110.0

        (stat,) = self.ixia.get_latest_stats()

        self.ixia.get_or_create_stat_view.assert_called_once_with("Port Statistics")
        self.assertEqual(stat["identifier"], "A_TO_B")
        # 10 of 1000 frames lost over the 10 s from the clear to the stop.
        self.assertEqual(stat["packet_loss_duration"], 100.0)

    @patch.dict(os.environ, {"TAAC_IXIA_TRAFFIC_STATS_SOURCE": "port"})
    def test_port_source_window_starts_at_traffic_start_when_later_than_clear(self):
        self.ixia._stats_cleared_at = 90.0
        self.ixia._traffic_start_time = 105.0
        self.ixia._traffic_stop_time = 110.0

        (stat,) = self.ixia.get_latest_stats()

        # 10 of 1000 frames lost over the 5 s from the start to the stop.
        self.assertEqual(stat["packet_loss_duration"], 50.0)

    @patch.dict(os.environ, {"TAAC_IXIA_TRAFFIC_STATS_SOURCE": "port"})
    def test_port_source_measures_up_to_now_while_traffic_still_runs(self):
        self.ixia._traffic_stop_time = 50.0  # an earlier run's stop
        self.ixia._traffic_start_time = 90.0
        self.ixia._stats_cleared_at = 100.0

        with patch(f"{_TAAC_IXIA_MODULE}.time.time", return_value=104.0):
            (stat,) = self.ixia.get_latest_stats()

        # 10 of 1000 frames lost over the 4 s from the clear to now.
        self.assertEqual(stat["packet_loss_duration"], 40.0)

    @patch.dict(os.environ, {"TAAC_IXIA_TRAFFIC_STATS_SOURCE": "port"})
    def test_port_source_without_a_recorded_clear_or_start_is_an_error(self):
        # Traffic started outside TAAC (e.g. a retained session): the window
        # would otherwise span since the epoch.
        self.ixia._traffic_start_time = 0.0
        self.ixia._stats_cleared_at = 0.0
        self.ixia._traffic_stop_time = 110.0

        with self.assertRaisesRegex(IxiaSetupError, "window"):
            self.ixia.get_latest_stats()

    @patch.dict(os.environ, {}, clear=True)
    def test_default_source_reads_the_traffic_item_view(self):
        stats = self.ixia.get_latest_stats()

        self.assertEqual(stats, [{"identifier": "from-traffic-item-view"}])
        self.ixia.get_or_create_stat_view.assert_not_called()

    @patch.dict(os.environ, {"TAAC_IXIA_TRAFFIC_STATS_SOURCE": "ports"})
    def test_unknown_source_is_rejected(self):
        with self.assertRaisesRegex(IxiaSetupError, "TAAC_IXIA_TRAFFIC_STATS_SOURCE"):
            self.ixia.get_latest_stats()


class ClearAndStopRecordWindowTest(unittest.TestCase):
    def setUp(self):
        self.ixia = _create_taac_ixia()
        self.ixia.has_traffic_items = MagicMock(return_value=False)

    @patch.dict(os.environ, {"TAAC_IXIA_TRAFFIC_STATS_SOURCE": "port"})
    def test_port_source_clear_does_not_wait_for_traffic_stats_refresh(self):
        with patch.object(Ixia, "clear_traffic_stats") as parent_clear, patch(
            f"{_TAAC_IXIA_MODULE}.time.time", return_value=123.0
        ):
            self.ixia.clear_traffic_stats()

        parent_clear.assert_called_once_with(False)
        self.assertEqual(self.ixia._stats_cleared_at, 123.0)

    @patch.dict(os.environ, {}, clear=True)
    def test_default_source_clear_waits_for_traffic_stats_refresh(self):
        with patch.object(Ixia, "clear_traffic_stats") as parent_clear:
            self.ixia.clear_traffic_stats()

        parent_clear.assert_called_once_with(True)

    def test_stopping_running_traffic_records_the_stop_time(self):
        self.ixia.is_traffic_running = MagicMock(return_value=True)
        with patch.object(Ixia, "stop_traffic"), patch(
            f"{_TAAC_IXIA_MODULE}.time.time", return_value=456.0
        ):
            self.ixia.stop_traffic()

        self.assertEqual(self.ixia._traffic_stop_time, 456.0)

    def test_stopping_already_stopped_traffic_keeps_the_real_stop_time(self):
        # A redundant stop must not stretch the loss window over idle time.
        self.ixia._traffic_stop_time = 100.0
        self.ixia.is_traffic_running = MagicMock(return_value=False)
        with patch.object(Ixia, "stop_traffic") as parent_stop, patch(
            f"{_TAAC_IXIA_MODULE}.time.time", return_value=456.0
        ):
            self.ixia.stop_traffic()

        parent_stop.assert_called_once()
        self.assertEqual(self.ixia._traffic_stop_time, 100.0)


class ViewAssistantsTest(unittest.TestCase):
    def setUp(self):
        self.ixia = _create_taac_ixia()
        self.ixia.ixia_config = None
        self.ixia._get_traffic_item_view = MagicMock(return_value="traffic-item-view")

    @patch.dict(os.environ, {"TAAC_IXIA_TRAFFIC_STATS_SOURCE": "port"})
    def test_port_source_never_builds_the_traffic_item_view(self):
        self.ixia.wait_for_view_assistants_ready()

        self.ixia._get_traffic_item_view.assert_not_called()
        self.assertIsNone(self.ixia.traffic_item_view_assistant)

    @patch.dict(os.environ, {}, clear=True)
    def test_default_source_builds_the_traffic_item_view(self):
        self.ixia.wait_for_view_assistants_ready()

        self.assertEqual(self.ixia.traffic_item_view_assistant, "traffic-item-view")


class ComputePortRateStatsTest(unittest.TestCase):
    def test_unidirectional_item_rates_come_from_its_sending_and_receiving_ports(
        self,
    ):
        items = [TrafficItemPorts("A", frozenset({"p1"}), frozenset({"p2"}))]
        rows = _rate_rows(
            {"p1": (200000.0, 5.0, 1000, 3), "p2": (7.0, 198000.0, 2, 990)}
        )

        self.assertEqual(
            compute_port_rate_stats(items, rows),
            [
                {
                    "identifier": "A",
                    "view": "Port Statistics",
                    "Tx Rate": 200000.0,
                    "Rx Rate": 198000.0,
                    "Tx Frames": 1000,
                    "Rx Frames": 990,
                }
            ],
        )

    def test_bidirectional_item_sums_both_directions(self):
        both = frozenset({"p1", "p2"})
        items = [TrafficItemPorts("A", both, both)]
        rows = _rate_rows(
            {"p1": (100000.0, 99000.0, 500, 495), "p2": (100000.0, 100000.0, 500, 500)}
        )

        (stat,) = compute_port_rate_stats(items, rows)

        self.assertEqual(
            (stat["Tx Rate"], stat["Rx Rate"], stat["Tx Frames"], stat["Rx Frames"]),
            (200000.0, 199000.0, 1000, 995),
        )

    def test_missing_rate_column_is_an_error(self):
        items = [TrafficItemPorts("A", frozenset({"p1"}), frozenset({"p2"}))]
        rows = _rate_rows(
            {"p1": (200000.0,), "p2": (7.0,)}, columns=RATE_COLUMNS[:2]
        )

        with self.assertRaisesRegex(IxiaSetupError, r"Rx\. Rate \(Mbps\)"):
            compute_port_rate_stats(items, rows)


class GetLatestStatsTrafficSourceTest(unittest.TestCase):
    def setUp(self):
        self.ixia = _create_taac_ixia()
        self.ixia.get_or_create_stat_view = MagicMock(return_value=MagicMock())
        self.ixia._get_stat_view_rows = MagicMock(
            return_value=_rate_rows(
                {
                    "VPORT_A": (200000.0, 0.0, 1000, 0),
                    "VPORT_B": (0.0, 198000.0, 0, 990),
                }
            )
        )
        self.ixia._enabled_traffic_item_ports = MagicMock(
            return_value=[
                A_TO_B
            ]
        )
        self.ixia.traffic_item_view_assistant = MagicMock()
        self.ixia._get_traffic_rate_statistics_unlocked = MagicMock(
            return_value=[{"identifier": "from-traffic-item-view"}]
        )

    @patch.dict(os.environ, {"TAAC_IXIA_TRAFFIC_STATS_SOURCE": "port"})
    def test_port_source_reads_rates_from_port_statistics(self):
        (stat,) = self.ixia.get_latest_stats_traffic()

        self.ixia.get_or_create_stat_view.assert_called_once_with("Port Statistics")
        self.assertEqual(
            (stat["identifier"], stat["Tx Rate"], stat["Rx Rate"]),
            ("A_TO_B", 200000.0, 198000.0),
        )

    @patch.dict(os.environ, {}, clear=True)
    def test_default_source_reads_rates_from_the_traffic_item_view(self):
        stats = self.ixia.get_latest_stats_traffic()

        self.assertEqual(stats, [{"identifier": "from-traffic-item-view"}])
        self.ixia.get_or_create_stat_view.assert_not_called()


class BenchmarkRateReportPortSourceTest(unittest.TestCase):
    @patch.dict(os.environ, {"TAAC_IXIA_TRAFFIC_STATS_SOURCE": "port"})
    def test_report_uses_port_rates_and_never_the_traffic_item_view(self):
        ixia = _create_taac_ixia()
        ixia.get_or_create_stat_view = MagicMock(return_value=MagicMock())
        both = frozenset({"VPORT_A", "VPORT_B"})
        ixia._enabled_traffic_item_ports = MagicMock(
            return_value=[TrafficItemPorts("SNAKE_BENCHMARK_64B", both, both)]
        )
        ixia._get_stat_view_rows = MagicMock(
            return_value=_rate_rows(
                {
                    "VPORT_A": (100000.0, 99000.0, 0, 0),
                    "VPORT_B": (100000.0, 99000.0, 0, 0),
                }
            )
        )
        ixia.traffic_item_view_assistant = None
        ixia.get_traffic_rate_statistics = MagicMock(return_value=[])

        ixia.log_benchmark_rate_report("SNAKE_BENCHMARK_64B", frame_size_bytes=64)

        ixia.get_traffic_rate_statistics.assert_not_called()
        logged = " ".join(str(c.args[0]) for c in ixia.logger.warning.call_args_list)
        # 2 x 100 Gbps offered, 2 x 99 Gbps forwarded, both directions summed.
        self.assertIn("SNAKE_BENCHMARK_64B: forwarded 99.0% of offered", logged)
        self.assertIn("offered 100.0 Gbps L2, forwarded 99.0 Gbps L2", logged)


if __name__ == "__main__":
    unittest.main()
