# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""Tests for the MAX-over-window summaries carried in the result message.

The tabulated versions go to ``logger.info``, which the runner suppresses on
console; only the result message reaches the run summary table.
"""

from taac.health_checks.device_health_checks.cpu_utilization_health_check import (
    format_cpu_max_summary,
)
from taac.health_checks.device_health_checks.memory_utilization_health_check import (
    format_memory_max_summary,
)


def test_cpu_summary_orders_by_peak_descending() -> None:
    summary = format_cpu_max_summary(
        [
            {"service": "fsdb", "cpu_pct": 8.126, "threshold": 70.0},
            {"service": "bgpd", "cpu_pct": 42.5, "threshold": 70.0},
        ],
        window_sec=296.4,
    )
    assert summary == "MAX over 296s: bgpd 42.50%/70.0%, fsdb 8.13%/70.0%"


def test_cpu_summary_empty_when_no_services_sampled() -> None:
    assert format_cpu_max_summary([], window_sec=100.0) == ""


def test_memory_summary_renders_mb_and_orders_by_peak_descending() -> None:
    summary = format_memory_max_summary(
        [
            {"service": "fsdb", "memory_bytes": 512 * 1024 * 1024, "threshold": 0},
            {
                "service": "bgpd",
                "memory_bytes": 1536 * 1024 * 1024,
                "threshold": 5 * 1024 * 1024 * 1024,
            },
        ],
        window_sec=600.0,
    )
    assert summary == (
        "MAX over 600s: bgpd 1,536.0MB/5,120.0MB, fsdb 512.0MB/no limit"
    )


def test_memory_summary_empty_when_no_services_sampled() -> None:
    assert format_memory_max_summary([], window_sec=100.0) == ""


def test_cpu_summary_renders_zero_threshold_as_no_limit() -> None:
    """threshold=0 means report-only; printing "0%" would read as a ceiling
    the peak had blown through."""
    summary = format_cpu_max_summary(
        [{"service": "qsfp_service", "cpu_pct": 90.5, "threshold": 0}],
        window_sec=600.0,
    )
    assert summary == "MAX over 600s: qsfp_service 90.50%/no limit"
