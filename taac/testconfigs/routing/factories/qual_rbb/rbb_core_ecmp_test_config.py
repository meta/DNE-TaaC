# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""TestConfig factory for Phase-1 Open/R core path cases."""

from __future__ import annotations

import typing as t

from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.types import Endpoint, TestConfig

from taac.playbooks.routing.factories.qual_rbb.rbb_core_ecmp_playbook import (
    create_rbb_core_ecmp_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _dut_bootstrap_setup_tasks,
    _dut_bootstrap_teardown_tasks,
    _resolve_topology,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_core_ecmp_profiles import (
    build_rbb_core_ecmp_profiles,
    select_rbb_core_ecmp_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import (
    build_rbb_inventories,
    rbb_oss_mock_device_data,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


def create_rbb_core_ecmp_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_CORE_ECMP_TEST",
    testplan_ids: t.Iterable[str] | None = None,
) -> TestConfig:
    """Build the reversible, device-only TC-02/TC-03 suite."""
    topology = _resolve_topology(topology, include_traffic=False)
    selected = select_rbb_core_ecmp_profiles(
        build_rbb_core_ecmp_profiles(topology), testplan_ids=testplan_ids
    )
    if not selected:
        raise ValueError("RBB core ECMP profile selection is empty")

    r1, r2 = build_rbb_inventories(topology)
    return TestConfig(
        name=name,
        basset_pool="",
        skip_ixia_protocol_verification=True,
        skip_advertised_prefixes_check=C.SKIP_ADVERTISED_PREFIXES_CHECK,
        skip_default_oss_setup_tasks=True,
        endpoints=[
            Endpoint(
                name=inventory.device_name,
                dut=True,
                ixia_needed=False,
            )
            for role, inventory in (("r1", r1), ("r2", r2))
        ],
        host_os_type_map={
            r1.device_name: taac_types.DeviceOsType.FBOSS,
            r2.device_name: taac_types.DeviceOsType.FBOSS,
        },
        oss_mock_device_data=rbb_oss_mock_device_data((r1, r2)),
        startup_checks=[],
        setup_tasks=_dut_bootstrap_setup_tasks(
            r1, r2, topology, include_traffic=False
        ),
        teardown_tasks=_dut_bootstrap_teardown_tasks(r1, r2),
        basic_port_configs=None,
        basic_traffic_item_configs=None,
        playbooks=[
            create_rbb_core_ecmp_playbook(profile, topology=topology)
            for profile in selected
        ],
    )


__all__ = ["create_rbb_core_ecmp_test_config"]
