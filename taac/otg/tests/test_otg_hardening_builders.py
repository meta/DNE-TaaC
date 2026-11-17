# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for taac/otg/otg_hardening_builders.py."""

import unittest

from taac.otg import otg_hardening_builders as hb


class DirectOtgConnectionTest(unittest.TestCase):
    """`port_location` is optional in the schema; the interface is the fallback."""

    def test_builds_with_or_without_the_port_location_field(self):
        conn = hb.direct_otg_connection(interface="eth1", ixia_port="1/1")
        self.assertEqual(conn.interface, "eth1")
        self.assertEqual(getattr(conn, "port_location", "eth1"), "eth1")


if __name__ == "__main__":
    unittest.main()
