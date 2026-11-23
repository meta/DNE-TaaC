# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Fail-closed checks for IXIA capabilities required by RBB scenarios."""

from __future__ import annotations

import typing as t

from taac.constants import TestCaseFailure
from taac.tasks.base_task import BaseTask


class RbbIxiaCapabilityTask(BaseTask):
    """Verify backend behavior before a test depends on it."""

    NAME: str = "rbb_ixia_capability"

    async def run(self, params: dict[str, t.Any]) -> None:
        allowed = {
            "gate",
            "require_controller_traffic_stats_reset",
            "require_variable_l4_flow_ranges",
        }
        unknown = sorted(set(params) - allowed)
        if unknown:
            raise ValueError(f"rbb_ixia_capability unsupported fields: {unknown}")
        gate = str(params.get("gate") or self.NAME)
        require_reset = params.get("require_controller_traffic_stats_reset", False)
        if not isinstance(require_reset, bool):
            raise TypeError("require_controller_traffic_stats_reset must be boolean")
        require_l4_ranges = params.get("require_variable_l4_flow_ranges", False)
        if not isinstance(require_l4_ranges, bool):
            raise TypeError("require_variable_l4_flow_ranges must be boolean")
        if not require_reset and not require_l4_ranges:
            raise ValueError("rbb_ixia_capability requires at least one capability")

        if require_reset:
            supports_reset = getattr(
                self.ixia, "supports_controller_traffic_stats_reset", None
            )
            if not callable(supports_reset) or not supports_reset():
                raise TestCaseFailure(
                    f"[{gate}] IXIA backend {type(self.ixia).__name__} cannot reset "
                    "controller traffic counters; isolated resilience loss windows "
                    "require the RESTPy/TaacIxia backend"
                )
        if require_l4_ranges:
            supports_l4_ranges = getattr(
                self.ixia, "supports_variable_l4_flow_ranges", None
            )
            if not callable(supports_l4_ranges) or not supports_l4_ranges():
                raise TestCaseFailure(
                    f"[{gate}] IXIA backend {type(self.ixia).__name__} does not "
                    "render variable L4 start/step/count ranges; core ECMP "
                    "distribution evidence requires the RESTPy/TaacIxia backend"
                )


__all__ = ["RbbIxiaCapabilityTask"]
