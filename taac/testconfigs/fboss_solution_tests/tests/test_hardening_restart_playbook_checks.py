# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Postchecks of the 2-IXIA hardening conveyor's service-restart playbooks."""

import json
import unittest

from taac.constants import WEDGE_AGENT_BINDS_TO_CASCADE
from taac.health_check.health_check import types as hc_types
from taac.libs.taac_runner import TaacRunner
from taac.testconfigs.fboss_solution_tests import (
    fboss_bgp_hardening_minipack3_test_config as minipack3,
)

_RESTARTED_SERVICES = {
    "test_agent_warmboot": WEDGE_AGENT_BINDS_TO_CASCADE + ["openr"],
    "test_ecmp_member_overload_limit": WEDGE_AGENT_BINDS_TO_CASCADE + ["openr"],
    "test_bgpd_restart": ["bgpd"],
    "test_qsfp_service_restart": ["qsfp_service"],
    "test_fsdb_restart": ["fsdb"],
}


def _params(playbook_name, check_name):
    playbook = next(
        p
        for p in minipack3.FBOSS_BGP_HARDENING_MINIPACK3_TEST_CONFIG.playbooks
        if p.name == playbook_name
    )
    checks = TaacRunner.get_checks_to_run(
        None,
        playbook.postchecks,
        minipack3.FBOSS_BGP_HARDENING_MINIPACK3_TEST_CONFIG.postchecks,
        False,
    )
    check = next(c for c in checks if c.name == check_name and not c.check_id)
    return json.loads(check.check_params.json_params or "{}")


class HardeningRestartPlaybookChecksTest(unittest.TestCase):
    def test_service_restart_check_keeps_allowlist(self) -> None:
        for name, services in _RESTARTED_SERVICES.items():
            with self.subTest(playbook=name):
                params = _params(name, hc_types.CheckName.SERVICE_RESTART_CHECK)
                self.assertEqual(params.get("expected_restarted_services"), services)
                self.assertEqual(3, params.get("retry_count"))
                self.assertEqual(5, params.get("retry_delay_seconds"))

    def test_rib_fib_check_ignores_flap_ranges(self) -> None:
        for name in _RESTARTED_SERVICES.keys() - {"test_ecmp_member_overload_limit"}:
            with self.subTest(playbook=name):
                params = _params(name, hc_types.CheckName.BGP_RIB_FIB_CONSISTENCY_CHECK)
                self.assertLessEqual(
                    {"6000:1::/32", "6000:e::/32", "6000:f::/32"},
                    set(params["parent_prefixes_to_ignore"]),
                )
