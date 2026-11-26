# pyre-unsafe
# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Unit tests for taac/otg/otg_basic_l3_test_config.py."""

import unittest

from taac.otg.otg_basic_l3_test_config import get_test_config
from taac.test_as_a_config.types import DirectIxiaConnection

_HAS_PORT_LOCATION = hasattr(DirectIxiaConnection, "port_location")


class OtgBasicL3TestConfigTest(unittest.TestCase):
    def test_builds_against_the_schema(self) -> None:
        config = get_test_config(device_name="dut01")
        conns = config.endpoints[0].direct_ixia_connections
        self.assertEqual([c.interface for c in conns], ["eth1", "eth2"])

    @unittest.skipIf(_HAS_PORT_LOCATION, "the schema carries port_location")
    def test_location_override_without_the_schema_field_raises(self) -> None:
        with self.assertRaisesRegex(ValueError, "port_location"):
            get_test_config(device_name="dut01", port_location="other")


if __name__ == "__main__":
    unittest.main()
