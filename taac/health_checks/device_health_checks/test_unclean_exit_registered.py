# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""The OSS unclean-exit check is collector-backed, so OSS runs register it."""

import unittest

from taac.health_checks.all_health_checks import NAME_TO_HEALTH_CHECK
from taac.health_checks.device_health_checks.unclean_exit_health_check import (
    UncleanExitHealthCheck,
)
from taac.health_check.health_check import types as hc_types


class TestUncleanExitRegistered(unittest.TestCase):
    def test_unclean_exit_check_is_registered(self):
        self.assertIs(
            NAME_TO_HEALTH_CHECK[hc_types.CheckName.UNCLEAN_EXIT_CHECK],
            UncleanExitHealthCheck,
        )
