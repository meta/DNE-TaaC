# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

from __future__ import annotations

from collections.abc import Mapping


def warmboot_phase_satisfied(
    counters: Mapping[str, int],
    phase: str,
    expected_devices: int,
    expected_subscribers: int,
) -> bool:
    """Return whether HRT counters prove the requested warmboot phase."""
    if phase == "complete":
        return (
            counters.get("hrt.warm_boot.enabled") == 1
            and counters.get("hrt.warm_boot.ready") == 1
            and counters.get("hrt.handover.devices_complete") == expected_devices
            and counters.get("hrt.convergence.state") == 1
            and counters.get("hrt.subscribers.connected") == expected_subscribers
        )
    if phase == "converged_pre_handover":
        completed = counters.get("hrt.handover.devices_complete", 0)
        return (
            counters.get("hrt.warm_boot.enabled") == 1
            and counters.get("hrt.warm_boot.ready", 0) == 0
            and counters.get("hrt.convergence.state") == 1
            and 0 <= completed < expected_devices
        )
    raise ValueError(f"unknown warmboot phase: {phase!r}")
