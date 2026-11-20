# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""Tests for the device-column renderer in ``taac.utils.result_rendering``."""

import unittest

from taac.test_run_result import types as trr_types
from taac.utils.result_rendering import hostnames_cell


class HostnamesCellTest(unittest.TestCase):
    def test_thrift_list_is_joined(self):
        result = trr_types.CheckResult(hostnames=["switch1", "switch2"])
        self.assertEqual(hostnames_cell(result.hostnames), "switch1, switch2")

    def test_empty_and_none(self):
        self.assertEqual(hostnames_cell(None), "")
        self.assertEqual(hostnames_cell([]), "")
