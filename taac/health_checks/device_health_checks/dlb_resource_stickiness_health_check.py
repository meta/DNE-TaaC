# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""
DLB Resource Stickiness Health Check..

This health check verifies DLB (Dynamic Load Balancing) resources by analyzing
ECMP next hop groups and their distribution across prefix categories.

Based on: scripts/pavanpatil/prefix_to_dlb_resource_stickiness.py

The check counts UNIQUE ECMP GROUPS (not individual routes) and categorizes them by:
- Prefix category (configurable patterns like "5000:dd::", "5000:ee::", or "all else")
- ECMP mode (Default/DLB, PER_PACKET_RANDOM, Other Modes)

The analysis itself lives in the driver-free ``dlb_resource_analysis`` module so
it can be reused by standalone CLIs; this class only fetches the route table
from the device and adapts the result to a ``HealthCheckResult``.
"""

import typing as t

from taac.constants import TestDevice
from taac.health_checks.abstract_health_check import (
    AbstractDeviceHealthCheck,
)
from taac.health_checks.device_health_checks.dlb_resource_analysis import (
    analyze,
)
from taac.health_check.health_check import types as hc_types


class DlbResourceStickinessHealthCheck(
    AbstractDeviceHealthCheck[hc_types.BaseHealthCheckIn]
):
    """
    Health check to verify DLB resources by counting unique ECMP next hop groups.

    This check analyzes routes and groups them by their next hops, then counts
    unique ECMP groups (groups with >1 next hop) per prefix category and ECMP mode.

    Output format:
    ```
    Prefix Category      | Default (DLB) | PER_PACKET_RANDOM | Other Modes | Total | ECMP Width
    ------------------------------------------------------------------------------------------------
    5000:dd prefixes     | 2             | 0                 | 0           | 2     | 4
    5000:ee prefixes     | 3             | 0                 | 0           | 3     | 6
    all else             | 1             | 0                 | 0           | 1     | 2
    ------------------------------------------------------------------------------------------------
    TOTAL                | 6             | 0                 | 0           | 6     | n/a
    ```

    Parameters:
        prefix_patterns: List of prefix patterns to categorize (e.g., ["5000:dd::", "5000:ee::"])
                        Routes not matching any pattern are categorized as "all else"
        expected_counts: Optional dict with expected counts PER PREFIX CATEGORY:
            {
                "5000:dd prefixes": {"dlb": 2, "total": 2},
                "5000:ee prefixes": {"dlb": 3, "total": 3, "min_total": 3},
                "all else": {"dlb": 1, "total": 1}
            }
            Supported keys per category:
            - "dlb": Exact match for DLB count
            - "per_packet_random": Exact match for PER_PACKET_RANDOM count
            - "other_modes": Exact match for other modes count
            - "total": Exact match for total count
            - "min_total": Minimum total count (>=)
            - "ecmp_width": Exact match for the widest ECMP group (max next hops).
              ("max_next_hops" is accepted as a backward-compat alias.)
        expected_totals: Optional dict with expected TOTAL counts across all categories:
            - "dlb": Expected total DLB groups
            - "per_packet_random": Expected total PER_PACKET_RANDOM groups
            - "other_modes": Expected total other mode groups
            - "total": Expected total ECMP groups

    Example usage:
        {
            "prefix_patterns": ["5000:dd::", "5000:ee::"],
            "expected_counts": {
                "5000:dd prefixes": {"dlb": 2, "total": 2},
                "5000:ee prefixes": {"dlb": 3, "min_total": 3}
            },
            "expected_totals": {
                "dlb": 6,
                "total": 6
            }
        }
    """

    CHECK_NAME = hc_types.CheckName.DLB_RESOURCE_STICKINESS_CHECK
    OPERATING_SYSTEMS = ["FBOSS"]

    async def _run(
        self,
        obj: TestDevice,
        input: hc_types.BaseHealthCheckIn,
        check_params: t.Dict[str, t.Any],
    ) -> hc_types.HealthCheckResult:
        prefix_patterns = check_params.get("prefix_patterns", [])
        expected_counts = check_params.get("expected_counts", {})
        expected_totals = check_params.get("expected_totals", {})

        # Get all routes from agent
        # pyrefly: ignore [missing-attribute]
        async with self.driver.async_agent_client as client:
            routes = await client.getRouteTable()

        # Fetch the installed ECMP-group snapshot count from hardware via
        # `fboss2 show hw-object NEXT_HOP_GROUP` so the analysis can
        # cross-check the route-table-derived matrix total against what is
        # actually installed in SAI. raise_exception_on_validation_mismatch
        # mirrors every other in-tree caller (noisy parent/child mismatches
        # are tolerated; we only need the count).
        snapshot_count: t.Optional[int] = None
        try:
            ecmp_groups_snapshot = (
                # pyrefly: ignore [missing-attribute]
                await self.driver.async_get_ecmp_groups_snapshot(
                    raise_exception_on_validation_mismatch=False
                )
            )
            snapshot_count = len(ecmp_groups_snapshot)
        except Exception as e:
            self.logger.warning(
                f"async_get_ecmp_groups_snapshot failed; skipping snapshot "
                f"comparison block: {e}"
            )

        result = analyze(
            routes,
            # pyrefly: ignore [missing-attribute]
            self.driver.ip_ntop,
            prefix_patterns,
            expected_counts,
            expected_totals,
            snapshot_count=snapshot_count,
            snapshot_expected_extra_groups=check_params.get(
                "snapshot_expected_extra_groups", 0
            ),
        )

        self.logger.info(f"Total unique next hop groups: {result.total_unique_nhgs}")
        self.logger.info(
            f"ECMP groups (>1 next hop): {result.ecmp_groups}, "
            f"Single next hop groups: {result.single_hop_groups}"
        )

        return hc_types.HealthCheckResult(
            status=(
                hc_types.HealthCheckStatus.PASS
                if result.passed
                else hc_types.HealthCheckStatus.FAIL
            ),
            message=result.message,
        )
