# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""Unit tests for LogParsingHealthCheck (FBOSS `_run` path)."""

import calendar
import json
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from neteng.netcastle.logger import ConsoleFileLogger
from taac.constants import TestDevice
from taac.health_checks.device_health_checks import (
    log_parsing_health_check as log_parsing_health_check_module,
)
from taac.health_checks.device_health_checks.log_parsing_health_check import (
    find_resource_accountant_rejections,
    LogParsingHealthCheck,
)
from taac.health_checks.healthcheck_definitions import (
    create_resource_accountant_activation_check,
)
from taac.health_check.health_check import types as hc_types


_SAMPLE_COOP_CONFIG = """\
{
    "agent": {
        "flags": {
            "cleanup_probed_kernel_data": "true",
            "another_flag": "false"
        }
    }
}
"""


class LogParsingHealthCheckTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.logger = MagicMock(spec=ConsoleFileLogger)
        self.health_check = LogParsingHealthCheck(logger=self.logger)
        self.health_check.driver = AsyncMock()
        self.health_check.driver.async_read_file = AsyncMock(
            return_value=_SAMPLE_COOP_CONFIG
        )
        self.health_check.driver.async_read_log_file = AsyncMock(
            return_value=_SAMPLE_COOP_CONFIG
        )
        # `date +%z` on the device; the UTC default keeps windows built with
        # calendar.timegm aligned with the log stamps.
        self.health_check.driver.async_run_cmd_on_shell = AsyncMock(
            return_value="+0000\n"
        )
        self.device = MagicMock(spec=TestDevice)
        self.device.name = "test-host"
        self.input = hc_types.BaseHealthCheckIn()

    async def test_include_regex_match_returns_pass_with_count_message(self):
        """include_regex with at least one match returns PASS and reports the count."""
        check_params = {
            "log_file_path": "/etc/coop/agent/current",
            "include_regex": r'"cleanup_probed_kernel_data":\s*"true"',
        }
        result = await self.health_check._run(self.device, self.input, check_params)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn("1 line(s) matching include regex", result.message)
        self.assertIn("cleanup_probed_kernel_data", result.message)

    async def test_include_regex_no_match_returns_fail(self):
        """include_regex with no matching lines returns FAIL with regex echoed back."""
        never_match = "this_string_should_never_match_xyz123"
        check_params = {
            "log_file_path": "/etc/coop/agent/current",
            "include_regex": never_match,
        }
        result = await self.health_check._run(self.device, self.input, check_params)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn(never_match, result.message)

    async def test_exclude_regex_no_match_returns_pass_with_exclude_regex(self):
        """exclude_regex with no matching lines returns PASS and reports the regex."""
        exclude = "this_string_should_never_match_xyz123"
        check_params = {
            "log_file_path": "/etc/coop/agent/current",
            "exclude_regex": exclude,
        }
        result = await self.health_check._run(self.device, self.input, check_params)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.PASS)
        self.assertIn(exclude, result.message)
        self.assertNotIn("Found", result.message)

    async def test_tail_lines_bounds_remote_log_output(self):
        result = await self.health_check._run(
            self.device,
            self.input,
            {
                "log_file_path": "/var/facebook/logs/fboss/wedge_agent.log",
                "exclude_regex": "never-match",
                "start_time": 100,
                "end_time": 200,
                "tail_lines": 500,
            },
        )

        self.assertEqual(hc_types.HealthCheckStatus.PASS, result.status)
        self.health_check.driver.async_read_log_file.assert_awaited_once_with(
            "/var/facebook/logs/fboss/wedge_agent.log",
            start_time=100,
            end_time=200,
            tail_lines=500,
        )

    async def test_exclude_regex_match_returns_fail(self):
        """exclude_regex with at least one match returns FAIL with the lines."""
        check_params = {
            "log_file_path": "/etc/coop/agent/current",
            "exclude_regex": r'"cleanup_probed_kernel_data":\s*"true"',
        }
        result = await self.health_check._run(self.device, self.input, check_params)
        self.assertEqual(result.status, hc_types.HealthCheckStatus.FAIL)
        self.assertIn("matching criteria", result.message)

    async def test_resource_accountant_mode_accepts_canonical_in_window_event(self):
        start_time = calendar.timegm((2026, 9, 20, 10, 0, 0, 0, 0, 0))
        content = (
            "E0920 10:01:02.123456 1234 ResourceAccountant.cpp:1026] "
            "Total NDP entries in new switchState: 4101 exceeds the limit: 4100 "
            "for switchId: 0\n"
        )
        self.health_check.driver.async_read_log_file.return_value = content
        result = await self.health_check._run(
            self.device,
            self.input,
            {
                "log_file_path": "/var/facebook/logs/fboss/wedge_agent.log",
                "include_regex": "ResourceAccountant",
                "resource_accountant_activation": True,
                "start_time": start_time,
                "end_time": start_time + 120,
            },
        )

        self.assertEqual(hc_types.HealthCheckStatus.PASS, result.status)
        self.assertIn("NDP", result.message)
        self.health_check.driver.async_read_log_file.assert_awaited_once_with(
            "/var/facebook/logs/fboss/wedge_agent.log",
            start_time=start_time,
            end_time=start_time + 120,
            grep_pattern=log_parsing_health_check_module._RESOURCE_ACCOUNTANT_GREP_PATTERN,
            tail_lines=200,
            utc_offset_seconds=0,
        )
        self.health_check.driver.async_read_file.assert_not_awaited()

    async def test_resource_accountant_mode_reads_window_in_device_local_time(
        self,
    ):
        # Regression: Overcommit_ECMP_ONLY_Groups on ssw002.s002.f01.qzd1
        # (America/Los_Angeles). The device rejected the overcommit at 05:21:46
        # PST, inside the 05:16:53-05:28:46 PST window, but reading the glog
        # stamp as UTC put it eight hours early and the check failed.
        start_time = 1793539013
        end_time = 1793539726
        content = (
            "Nov  1 05:21:46 ssw002.s002.f01.qzd1.tfbnw.net "
            "fboss_sw_agent[573954]: E1101 05:21:46.686595 574442 "
            "ValidateStateUpdate.cpp:356] State updated rejected by resource "
            "accountant.\n"
        )
        self.health_check.driver.async_run_cmd_on_shell.return_value = "-0800\n"
        self.health_check.driver.async_read_log_file.return_value = content

        result = await self.health_check._run(
            self.device,
            self.input,
            {
                "log_file_path": "/var/facebook/logs/fboss/wedge_agent.log",
                "resource_accountant_activation": True,
                "start_time": start_time,
                "end_time": end_time,
            },
        )

        self.assertEqual(hc_types.HealthCheckStatus.PASS, result.status)
        self.health_check.driver.async_run_cmd_on_shell.assert_awaited_once_with(
            "date +%z"
        )
        self.health_check.driver.async_read_log_file.assert_awaited_once_with(
            "/var/facebook/logs/fboss/wedge_agent.log",
            start_time=start_time,
            end_time=end_time,
            grep_pattern=log_parsing_health_check_module._RESOURCE_ACCOUNTANT_GREP_PATTERN,
            tail_lines=200,
            utc_offset_seconds=-8 * 3600,
        )
        self.assertEqual(
            [],
            find_resource_accountant_rejections(content, start_time, end_time),
        )

    def test_resource_accountant_accepts_netos_syslog_prefixed_event(self) -> None:
        start_time = calendar.timegm((2026, 9, 20, 23, 20, 0, 0, 0, 0))
        content = (
            "Sep 20 23:20:25 fsw003.p003.f01.qzd1.tfbnw.net "
            "fboss_sw_agent[50780]: E0920 23:20:25.062138 51089 "
            "ResourceAccountant.cpp:1041] Total ARP entries in new switchState: "
            "1281 exceeds the limit: 1280 for switchId: 0\n"
        )

        self.assertEqual(
            [content.rstrip()],
            find_resource_accountant_rejections(
                content,
                start_time=start_time,
                end_time=start_time + 60,
            ),
        )

    async def test_resource_accountant_mode_rejects_historical_event(self):
        start_time = calendar.timegm((2026, 9, 20, 10, 0, 0, 0, 0, 0))
        self.health_check.driver.async_read_file.return_value = (
            "E0920 09:59:59.123456 1234 ResourceAccountant.cpp:1026] "
            "Total NDP entries in new switchState: 4101 exceeds the limit: 4100 "
            "for switchId: 0\n"
        )
        self.health_check.driver.async_read_log_file.return_value = (
            self.health_check.driver.async_read_file.return_value
        )
        result = await self.health_check._run(
            self.device,
            self.input,
            {
                "log_file_path": "/var/facebook/logs/fboss/wedge_agent.log",
                "include_regex": "ResourceAccountant",
                "resource_accountant_activation": True,
                "start_time": start_time,
                "end_time": start_time + 120,
            },
        )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("No ResourceAccountant rejection", result.message)

    async def test_resource_accountant_mode_rejects_name_only_false_positive(self):
        start_time = calendar.timegm((2026, 9, 20, 10, 0, 0, 0, 0, 0))
        content = (
            "I0920 10:01:02.123456 1234 ResourceAccountant.cpp:70] "
            "ResourceAccountant initialized\n"
        )
        self.health_check.driver.async_read_file.return_value = content
        self.health_check.driver.async_read_log_file.return_value = content
        result = await self.health_check._run(
            self.device,
            self.input,
            {
                "log_file_path": "/var/facebook/logs/fboss/wedge_agent.log",
                "include_regex": "ResourceAccountant",
                "resource_accountant_activation": True,
                "start_time": start_time,
                "end_time": start_time + 120,
            },
        )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("No ResourceAccountant rejection", result.message)

    def _flood_lines(self, first_second: int, count: int) -> str:
        """Rejection lines stamped from first_second on, three per second."""
        lines = []
        for index in range(count):
            stamp = time.gmtime(first_second + index // 3)
            lines.append(
                f"E{time.strftime('%m%d %H:%M:%S', stamp)}.{index % 3:06d} 51089 "
                "ResourceAccountant.cpp:1041] Total ARP entries in new "
                "switchState: 1281 exceeds the limit: 1280 for switchId: 0"
            )
        return "\n".join(lines) + "\n"

    async def test_resource_accountant_mode_counts_flood_lines_logged_during_read(
        self,
    ):
        # Regression: qoe/npi_qual R50-R52 ARP overload playbooks on
        # fsw003.p003.f01.qzd1. Rejections flooded the log throughout the
        # window, but the newest 200 lines were all stamped after the bound
        # taken before the read, so the check found none.
        now = calendar.timegm((time.gmtime().tm_year, 9, 20, 10, 0, 0, 0, 0, 0))
        self.health_check.driver.async_read_log_file.return_value = self._flood_lines(
            now + 1, 200
        )
        clock = iter([now])

        with patch.object(
            log_parsing_health_check_module.time,
            "time",
            side_effect=lambda: next(clock, now + 70),
        ):
            result = await self.health_check._run(
                self.device,
                self.input,
                {
                    "log_file_path": "/var/facebook/logs/fboss/wedge_agent.log",
                    "resource_accountant_activation": True,
                    "start_time": now - 300,
                },
            )

        self.assertEqual(hc_types.HealthCheckStatus.PASS, result.status)
        self.assertIn("Found 200 ResourceAccountant rejection", result.message)
        # Every counted line is one a window ending at the check start drops.
        self.assertIn(f"window={now - 300}..{now + 70}", result.message)
        self.assertIn("after_window=0", result.message)
        self.assertIn("after_check_start=200", result.message)
        self.health_check.driver.async_read_log_file.assert_awaited_once_with(
            "/var/facebook/logs/fboss/wedge_agent.log",
            start_time=now - 300,
            end_time=now,
            grep_pattern=log_parsing_health_check_module._RESOURCE_ACCOUNTANT_GREP_PATTERN,
            tail_lines=200,
            utc_offset_seconds=0,
        )

    async def test_resource_accountant_mode_keeps_explicit_end_time(self):
        end_time = calendar.timegm((time.gmtime().tm_year, 9, 20, 10, 0, 0, 0, 0, 0))
        self.health_check.driver.async_read_log_file.return_value = self._flood_lines(
            end_time + 1, 200
        )

        with patch.object(
            log_parsing_health_check_module.time,
            "time",
            return_value=end_time + 70,
        ):
            result = await self.health_check._run(
                self.device,
                self.input,
                {
                    "log_file_path": "/var/facebook/logs/fboss/wedge_agent.log",
                    "resource_accountant_activation": True,
                    "start_time": end_time - 300,
                    "end_time": end_time,
                },
            )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("No ResourceAccountant rejection", result.message)
        for field in (
            f"window={end_time - 300}..{end_time}",
            "check_start=None",
            f"read_returned={end_time + 70}",
            "lines_read=200",
            "in_window=0",
            "after_window=200",
            "earlier_or_undated=0",
        ):
            self.assertIn(field, result.message)
        self.assertNotIn("after_check_start", result.message)
        # The failed read's buffer is logged whole for later comparison.
        logged = "\n".join(str(call) for call in self.logger.info.call_args_list)
        self.assertIn("1281 exceeds the limit: 1280", logged)

    async def test_resource_accountant_mode_device_local_minute_boundary(self):
        # fsw003.p003.f01.qzd1 logs in PST (-0800). The window opens on a
        # minute boundary, so 06:22:59 is just before it and 06:23:00 inside.
        # 06:24:01 is after the check started but before the read returned.
        year = time.gmtime().tm_year
        start_time = calendar.timegm((year, 11, 21, 14, 23, 0, 0, 0, 0))
        check_start = start_time + 60
        self.health_check.driver.async_run_cmd_on_shell.return_value = "-0800\n"
        self.health_check.driver.async_read_log_file.return_value = "".join(
            f"E1121 {stamp}.500000 51089 ResourceAccountant.cpp:1041] Total ARP "
            "entries in new switchState: 1281 exceeds the limit: 1280 for "
            "switchId: 0\n"
            for stamp in ("06:22:59", "06:23:00", "06:24:01")
        )
        clock = iter([check_start])

        with patch.object(
            log_parsing_health_check_module.time,
            "time",
            side_effect=lambda: next(clock, check_start + 1.2),
        ):
            result = await self.health_check._run(
                self.device,
                self.input,
                {
                    "log_file_path": "/var/facebook/logs/fboss/wedge_agent.log",
                    "resource_accountant_activation": True,
                    "start_time": start_time,
                },
            )

        self.assertEqual(hc_types.HealthCheckStatus.PASS, result.status)
        self.assertIn("Found 2 ResourceAccountant rejection", result.message)
        for field in (
            f"window={start_time}..{check_start + 2}",
            f"check_start={check_start}",
            "utc_offset=-28800s",
            "lines_read=3",
            "stamps=E1121 06:22:59..E1121 06:24:01",
            "in_window=2",
            "after_window=0",
            "earlier_or_undated=1",
            "after_check_start=1",
        ):
            self.assertIn(field, result.message)
        self.assertNotIn("06:22:59.500000", result.message)

    def test_resource_accountant_factory_uses_requested_time_anchor_and_retries(self):
        check = create_resource_accountant_activation_check(
            start_time_jq_var="post_disruption_start_time",
            retry_count=4,
            retry_delay_seconds=3,
        )

        self.assertEqual(hc_types.CheckName.LOG_PARSING_CHECK, check.name)
        self.assertEqual(
            {"start_time": ".post_disruption_start_time"},
            check.check_params.jq_params,
        )
        params = json.loads(check.check_params.json_params)
        self.assertTrue(params["resource_accountant_activation"])
        self.assertEqual(4, params["retry_count"])
        self.assertEqual(3, params["retry_delay_seconds"])

    async def test_both_regexes_provided_raises(self):
        """Providing both include_regex and exclude_regex is an assertion error."""
        check_params = {
            "log_file_path": "/etc/coop/agent/current",
            "include_regex": "foo",
            "exclude_regex": "bar",
        }
        with self.assertRaises(AssertionError):
            await self.health_check._run(self.device, self.input, check_params)

    async def test_neither_regex_provided_raises(self):
        """Providing neither include_regex nor exclude_regex is an assertion error."""
        check_params = {"log_file_path": "/etc/coop/agent/current"}
        with self.assertRaises(AssertionError):
            await self.health_check._run(self.device, self.input, check_params)

    def _arista_params(self, **overrides):
        params = {
            "agent_name": "Bgpcpp",
            "exclude_regex": "Memory Limit Reached",
        }
        params.update(overrides)
        return params

    async def test_arista_uses_archive_when_live_log_rotated(self):
        self.health_check.driver.async_read_file.side_effect = FileNotFoundError
        with (
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "get_daemon_pid",
                new=AsyncMock(return_value="26775"),
            ),
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "get_archived_agent_logs",
                new=AsyncMock(return_value="healthy archived BGP log"),
            ) as archived_logs,
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                self._arista_params(start_time=100, end_time=200),
            )

        self.assertEqual(hc_types.HealthCheckStatus.PASS, result.status)
        archived_logs.assert_awaited_once_with(
            self.health_check.driver,
            "Bgpcpp",
            "26775",
            start_time=100,
            end_time=200,
            matching_literal=None,
        )

    async def test_arista_combines_live_and_archived_logs(self):
        self.health_check.driver.async_read_file.return_value = "healthy live BGP log"
        with (
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "get_daemon_pid",
                new=AsyncMock(return_value="26775"),
            ),
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "get_archived_agent_logs",
                new=AsyncMock(return_value="Memory Limit Reached in archive"),
            ) as archived_logs,
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                self._arista_params(start_time=100, end_time=200),
            )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("exclude regex", result.message)
        archived_logs.assert_awaited_once_with(
            self.health_check.driver,
            "Bgpcpp",
            "26775",
            start_time=100,
            end_time=200,
            matching_literal="Memory Limit Reached",
        )

    async def test_arista_archive_error_is_not_hidden_by_live_log(self):
        self.health_check.driver.async_read_file.return_value = "healthy live BGP log"
        with (
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "get_daemon_pid",
                new=AsyncMock(return_value="26775"),
            ),
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "get_archived_agent_logs",
                new=AsyncMock(side_effect=RuntimeError("archive transport failed")),
            ),
        ):
            result = await self.health_check._run_arista(
                self.device, self.input, self._arista_params()
            )

        self.assertEqual(hc_types.HealthCheckStatus.ERROR, result.status)
        self.assertIn("archive transport failed", result.message)

    async def test_arista_archive_error_is_not_hidden_when_live_log_missing(self):
        self.health_check.driver.async_read_file.side_effect = FileNotFoundError
        with (
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "get_daemon_pid",
                new=AsyncMock(return_value="26775"),
            ),
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "get_archived_agent_logs",
                new=AsyncMock(side_effect=RuntimeError("archive read failed")),
            ),
        ):
            result = await self.health_check._run_arista(
                self.device, self.input, self._arista_params()
            )

        self.assertEqual(hc_types.HealthCheckStatus.ERROR, result.status)
        self.assertIn("archive read failed", result.message)

    async def test_arista_errors_when_live_and_archived_logs_are_missing(self):
        self.health_check.driver.async_read_file.side_effect = FileNotFoundError
        with (
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "get_daemon_pid",
                new=AsyncMock(return_value="26775"),
            ),
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "get_archived_agent_logs",
                new=AsyncMock(return_value=""),
            ),
        ):
            result = await self.health_check._run_arista(
                self.device, self.input, self._arista_params()
            )

        self.assertEqual(hc_types.HealthCheckStatus.ERROR, result.status)
        self.assertIn("No live or archived Bgpcpp logs", result.message)

    async def test_arista_rejects_inverted_time_window(self):
        get_pid = AsyncMock(return_value="26775")
        with patch.object(
            log_parsing_health_check_module.arista_utils,
            "get_daemon_pid",
            new=get_pid,
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                self._arista_params(start_time=200, end_time=100),
            )

        self.assertEqual(hc_types.HealthCheckStatus.ERROR, result.status)
        self.assertIn("must not be earlier", result.message)
        get_pid.assert_not_awaited()

    async def test_arista_system_log_recovery_is_context_not_failure(self) -> None:
        recovery = (
            "[ERROR] switch: %SAND-3-L3_HOST_RESOURCE_NORMAL: "
            "All host entries are programmed in hardware"
        )
        with patch.object(
            log_parsing_health_check_module.arista_utils,
            "check_eos_system_logs",
            new=AsyncMock(return_value=[recovery]),
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                {"check_system_logs": True},
            )

        self.assertEqual(hc_types.HealthCheckStatus.PASS, result.status)
        self.assertIn("recovery context", result.message)
        self.assertIn("L3_HOST_RESOURCE_NORMAL", result.message)

    async def test_arista_other_resource_full_fails_with_recovery_context(
        self,
    ) -> None:
        issue = (
            "[ERROR] switch: %SAND-3-L3_HOST_RESOURCE_FULL: "
            "Hardware resources are insufficient"
        )
        recovery = (
            "[ERROR] switch: %SAND-3-L3_HOST_RESOURCE_NORMAL: "
            "All host entries are programmed in hardware"
        )
        with patch.object(
            log_parsing_health_check_module.arista_utils,
            "check_eos_system_logs",
            new=AsyncMock(return_value=[issue, recovery]),
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                {"check_system_logs": True},
            )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("L3_HOST_RESOURCE_FULL", result.message)
        self.assertIn("recovery context", result.message)

    async def test_arista_allowed_recovered_resource_full_passes(self) -> None:
        issue = (
            "[ERROR] switch: %SAND-3-FEC_RESOURCE_FULL: "
            "Not all FECs are programmed in hardware"
        )
        repeated_issue = (
            "[ERROR] switch: %SAND-3-FEC_RESOURCE_FULL: "
            "FEC programming remains constrained"
        )
        recovery = (
            "[ERROR] switch: %ROUTING-3-FEC_RESOURCE_NORMAL: "
            "All FECs are programmed in hardware"
        )
        for configured_mnemonic in (
            "FEC_RESOURCE",
            "FEC_RESOURCE_FULL",
            "fec_resource_normal",
        ):
            with (
                self.subTest(configured_mnemonic=configured_mnemonic),
                patch.object(
                    log_parsing_health_check_module.arista_utils,
                    "check_eos_system_logs",
                    new=AsyncMock(return_value=[issue, repeated_issue, recovery]),
                ),
                patch.object(
                    log_parsing_health_check_module.arista_utils,
                    "classify_eos_system_log_entries",
                    wraps=(
                        log_parsing_health_check_module.arista_utils.classify_eos_system_log_entries
                    ),
                ) as classify_logs,
            ):
                result = await self.health_check._run_arista(
                    self.device,
                    self.input,
                    {
                        "check_system_logs": True,
                        "allowed_recovered_resource_mnemonics": [configured_mnemonic],
                    },
                )

            self.assertEqual(hc_types.HealthCheckStatus.PASS, result.status)
            self.assertIn("allowed recovered resource issues", result.message)
            self.assertIn("FEC_RESOURCE_FULL", result.message)
            classify_logs.assert_called_once_with([issue, repeated_issue, recovery])

    async def test_arista_recovered_resource_does_not_mask_same_line_issue(
        self,
    ) -> None:
        mixed_issue = (
            "[ERROR] switch: %SYS-3-CONTROL_PLANE_FAILURE: unrelated alarm; "
            "%SAND-3-FEC_RESOURCE_FULL: FEC programming is constrained"
        )
        recovery = (
            "[ERROR] switch: %ROUTING-3-FEC_RESOURCE_NORMAL: "
            "All FECs are programmed in hardware"
        )
        with patch.object(
            log_parsing_health_check_module.arista_utils,
            "check_eos_system_logs",
            new=AsyncMock(return_value=[mixed_issue, recovery]),
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                {
                    "check_system_logs": True,
                    "allowed_recovered_resource_mnemonics": ["FEC_RESOURCE"],
                },
            )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("CONTROL_PLANE_FAILURE", result.message)

    async def test_arista_unrelated_primary_recovery_mnemonic_does_not_recover(
        self,
    ) -> None:
        issue = (
            "[ERROR] switch: %SAND-3-FEC_RESOURCE_FULL: "
            "Not all FECs are programmed in hardware"
        )
        unrelated_recovery = (
            "[ERROR] switch: %SAND-3-L3_HOST_RESOURCE_NORMAL: "
            "diagnostic context mentions FEC_RESOURCE_NORMAL:"
        )
        with patch.object(
            log_parsing_health_check_module.arista_utils,
            "check_eos_system_logs",
            new=AsyncMock(return_value=[issue, unrelated_recovery]),
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                {
                    "check_system_logs": True,
                    "allowed_recovered_resource_mnemonics": ["FEC_RESOURCE"],
                },
            )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("FEC_RESOURCE_FULL", result.message)

    async def test_arista_invalid_index_evidence_fails_without_duplicates(
        self,
    ) -> None:
        issue = "[ERROR] switch: %SYS-3-CONTROL_PLANE_FAILURE: unrelated alarm"
        classification = (
            log_parsing_health_check_module.arista_utils.EosSystemLogClassification(
                issues=(issue,),
                excluded=(),
                issues_with_indexes=((0, issue), (0, issue)),
            )
        )
        with (
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "check_eos_system_logs",
                new=AsyncMock(return_value=[issue]),
            ),
            patch.object(
                log_parsing_health_check_module.arista_utils,
                "classify_eos_system_log_entries",
                return_value=classification,
            ),
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                {
                    "check_system_logs": True,
                    "allowed_recovered_resource_mnemonics": ["FEC_RESOURCE"],
                },
            )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("Found 1 system log issues", result.message)
        self.logger.warning.assert_any_call(
            "Bypassing allowed recovered EOS resource tolerance because "
            "indexed issue evidence does not align with classified issues "
            "(%d indexed entries for %d issues)",
            2,
            1,
        )

    async def test_arista_allowed_unrecovered_resource_full_fails(self) -> None:
        issue = (
            "[ERROR] switch: %SAND-3-FEC_RESOURCE_FULL: "
            "Not all FECs are programmed in hardware"
        )
        with patch.object(
            log_parsing_health_check_module.arista_utils,
            "check_eos_system_logs",
            new=AsyncMock(return_value=[issue]),
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                {
                    "check_system_logs": True,
                    "allowed_recovered_resource_mnemonics": ["FEC_RESOURCE"],
                },
            )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("FEC_RESOURCE_FULL", result.message)

    async def test_arista_allowed_resource_must_finish_recovered(self) -> None:
        recovery = (
            "[ERROR] switch: %ROUTING-3-FEC_RESOURCE_NORMAL: "
            "All FECs are programmed in hardware"
        )
        issue = (
            "[ERROR] switch: %SAND-3-FEC_RESOURCE_FULL: "
            "Not all FECs are programmed in hardware"
        )
        with patch.object(
            log_parsing_health_check_module.arista_utils,
            "check_eos_system_logs",
            new=AsyncMock(return_value=[issue, recovery, issue]),
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                {
                    "check_system_logs": True,
                    "allowed_recovered_resource_mnemonics": ["FEC_RESOURCE"],
                },
            )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("FEC_RESOURCE_FULL", result.message)

    def test_arista_classification_preserves_duplicate_issue_indexes(self) -> None:
        issue = (
            "[ERROR] switch: %SAND-3-FEC_RESOURCE_FULL: "
            "Not all FECs are programmed in hardware"
        )
        recovery = (
            "[ERROR] switch: %ROUTING-3-FEC_RESOURCE_NORMAL: "
            "All FECs are programmed in hardware"
        )

        classification = log_parsing_health_check_module.arista_utils.classify_eos_system_log_entries(
            [issue, recovery, issue]
        )

        self.assertEqual((issue, issue), classification.issues)
        self.assertEqual(((0, issue), (2, issue)), classification.issues_with_indexes)

    async def test_arista_allowed_recovery_does_not_match_longer_mnemonic(
        self,
    ) -> None:
        issue = (
            "[ERROR] switch: %SAND-3-ROUTING_FEC_RESOURCE_FULL: "
            "Not all routing FECs are programmed in hardware"
        )
        recovery = (
            "[ERROR] switch: %ROUTING-3-FEC_RESOURCE_NORMAL: "
            "All FECs are programmed in hardware"
        )
        with patch.object(
            log_parsing_health_check_module.arista_utils,
            "check_eos_system_logs",
            new=AsyncMock(return_value=[issue, recovery]),
        ):
            result = await self.health_check._run_arista(
                self.device,
                self.input,
                {
                    "check_system_logs": True,
                    "allowed_recovered_resource_mnemonics": ["FEC_RESOURCE"],
                },
            )

        self.assertEqual(hc_types.HealthCheckStatus.FAIL, result.status)
        self.assertIn("ROUTING_FEC_RESOURCE_FULL", result.message)
