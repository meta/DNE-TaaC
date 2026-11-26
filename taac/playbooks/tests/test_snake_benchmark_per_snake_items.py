# pyre-unsafe
# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Benchmark traffic items on a multi-snake config: one item per snake per size.

The IXIA layer skips a traffic item whose name already exists, so each snake
needs its own item name or only the first snake is benchmarked.
"""

import inspect
import json
import types
import unittest
from unittest.mock import MagicMock

from taac.ixia.ixia import Ixia
from taac.playbooks.playbook_definitions import gen_snake_benchmark_playbooks
from taac.health_check.health_check import types as hc_types
from taac.utils.json_thrift_utils import json_to_thrift


def _benchmark_playbook(instances):
    (playbook,) = gen_snake_benchmark_playbooks(
        traffic_item_name_by_packet_size={64: "SNAKE_BENCHMARK_64B"},
        traffic_item_instances=instances,
        min_rate_gbps_by_packet_size={64: 100},
    )
    return playbook


class BenchmarkPlaybookCoversEverySnakeTest(unittest.TestCase):
    def test_rate_check_covers_every_snake_item(self):
        playbook = _benchmark_playbook(instances=3)

        (rate_check,) = [
            hc
            for hc in playbook.postchecks
            if hc.name == hc_types.CheckName.IXIA_TRAFFIC_RATE_CHECK
        ]
        rate_in = json_to_thrift(
            rate_check.input_json, hc_types.IxiaTrafficRateHealthCheckIn
        )
        self.assertEqual(
            [list(threshold.names) for threshold in rate_in.thresholds],
            [
                [
                    "SNAKE_BENCHMARK_64B",
                    "SNAKE_BENCHMARK_64B #1",
                    "SNAKE_BENCHMARK_64B #2",
                ]
            ],
        )

    def test_throughput_is_reported_for_every_snake_item(self):
        playbook = _benchmark_playbook(instances=3)

        reported = []
        for stage in playbook.stages:
            for step in stage.steps:
                params = json.loads(step.step_params.json_params or "{}")
                if params.get("api_name") == "log_benchmark_rate_report":
                    reported.append(
                        json.loads(params["args_json"])["traffic_item_name"]
                    )
        self.assertEqual(
            reported,
            ["SNAKE_BENCHMARK_64B", "SNAKE_BENCHMARK_64B #1", "SNAKE_BENCHMARK_64B #2"],
        )


class BenchmarkSelectionTest(unittest.TestCase):
    def test_a_size_selects_all_its_snake_items_and_no_other_size(self):
        items = {
            name: types.SimpleNamespace(Name=name, Enabled=None)
            for name in (
                "SNAKE_BENCHMARK_64B",
                "SNAKE_BENCHMARK_64B #1",
                "SNAKE_BENCHMARK_640B",
                "SNAKE_BENCHMARK_640B #1",
            )
        }
        fake_ixia = MagicMock()
        fake_ixia.ixnetwork.Traffic.TrafficItem.find.return_value = list(items.values())

        (playbook,) = gen_snake_benchmark_playbooks(
            traffic_item_name_by_packet_size={64: "SNAKE_BENCHMARK_64B"},
            traffic_item_instances=2,
        )
        inspect.unwrap(Ixia.enable_traffic)(
            fake_ixia,
            regexes=list(playbook.traffic_items_to_start),
            apply_changes=False,
        )

        self.assertEqual(
            {name: item.Enabled for name, item in items.items()},
            {
                "SNAKE_BENCHMARK_64B": True,
                "SNAKE_BENCHMARK_64B #1": True,
                "SNAKE_BENCHMARK_640B": False,
                "SNAKE_BENCHMARK_640B #1": False,
            },
        )


if __name__ == "__main__":
    unittest.main()
