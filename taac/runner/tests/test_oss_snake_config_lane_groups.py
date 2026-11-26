# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Lane-group pairing in the OSS snake config (taac/testconfigs/oss/snake_config.py)."""

import importlib.util
import unittest
from pathlib import Path

from taac.runner.testbed_topology import CircuitLink, ConfigTopology, LinkType

_SNAKE_CONFIG = (
    Path(__file__).resolve().parents[2] / "testconfigs" / "oss" / "snake_config.py"
)


def _build(*ports):
    spec = importlib.util.spec_from_file_location("oss_snake_config", _SNAKE_CONFIG)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    links = tuple(
        CircuitLink("dut01", port, "ixia01", f"1/{idx}", LinkType.TGEN)
        for idx, port in enumerate(ports, start=1)
    )
    return module.test_config(topology=ConfigTopology(links=links))


def _snakes(config):
    return [
        (s.source, s.destination, s.source_ip, s.destination_ip)
        for s in config.snake_configs
    ]


class OssSnakeLaneGroupTest(unittest.TestCase):
    def test_four_taps_pair_within_each_lane_group(self) -> None:
        # CSV order puts both subports of cage 1 first: the old first-two
        # pairing would have joined /1 to /5.
        config = _build("eth1/1/1", "eth1/1/5", "eth1/2/1", "eth1/2/5")
        self.assertEqual(
            _snakes(config),
            [
                ("dut01:eth1/1/1", "dut01:eth1/2/1", "5000:1::1/64", "5000:1::2/64"),
                ("dut01:eth1/1/5", "dut01:eth1/2/5", "5000:2::1/64", "5000:2::2/64"),
            ],
        )
        self.assertEqual(
            sorted(config.endpoints[0].ixia_ports),
            ["eth1/1/1", "eth1/1/5", "eth1/2/1", "eth1/2/5"],
        )
        self.assertEqual(len(config.endpoints[0].direct_ixia_connections), 4)

    def test_two_taps_in_one_lane_group_ordered_by_cage(self) -> None:
        config = _build("eth1/2/1", "eth1/1/1")
        self.assertEqual(
            _snakes(config),
            [("dut01:eth1/1/1", "dut01:eth1/2/1", "5000:1::1/64", "5000:1::2/64")],
        )

    def test_no_complete_lane_group_falls_back_to_first_two_taps(self) -> None:
        config = _build("eth1/2/1", "eth1/1/5")
        self.assertEqual(
            _snakes(config),
            [("dut01:eth1/2/1", "dut01:eth1/1/5", "5000:1::1/64", "5000:1::2/64")],
        )
        self.assertEqual(list(config.endpoints[0].ixia_ports), ["eth1/2/1", "eth1/1/5"])


if __name__ == "__main__":
    unittest.main()
