# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""Tests for helpers in ``taac.utils.health_check_utils``.

Isolates the journalctl-parsing helper for the unclean-exit fallback so a
regression in the regex or the SSH-error handling can be caught without a
full end-to-end health-check run.
"""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.utils.health_check_utils import (
    _resolve_fb303_port,
    async_query_journalctl_unclean_exits,
    FBOSS_FB303_PORT,
    FBOSS_MNPU_FB303_PORT,
)


class TestJournalctlUncleanExitsParser(unittest.IsolatedAsyncioTestCase):
    def _driver(self, output: str) -> MagicMock:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(return_value=output)
        driver.async_get_systemctl_service_name = AsyncMock(
            side_effect=lambda service: service
        )
        return driver

    async def test_empty_services_returns_empty(self) -> None:
        driver = self._driver("(never called)")
        result = await async_query_journalctl_unclean_exits(driver, [], 0, 100)
        self.assertEqual(result, {})
        driver.async_run_cmd_on_shell.assert_not_awaited()

    async def test_ssh_error_returns_empty(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(side_effect=RuntimeError("boom"))
        result = await async_query_journalctl_unclean_exits(
            driver, ["bgpd"], 0, 100
        )
        self.assertEqual(result, {})

    async def test_none_output_treated_as_empty(self) -> None:
        # OSS FbossSwitch.async_run_cmd_on_shell can return None; helper must
        # coerce to empty string, not crash on .splitlines().
        driver = self._driver(None)
        result = await async_query_journalctl_unclean_exits(
            driver, ["bgpd"], 0, 100
        )
        self.assertEqual(result, {})

    async def test_signal_kill_parsed(self) -> None:
        output = (
            "2000-01-01T00:00:32+0000 dut1 systemd[1]: "
            "fboss_sw_agent.service: Main process exited, code=killed, status=9/KILL\n"
            "2000-01-01T00:00:32+0000 dut1 systemd[1]: "
            "fboss_sw_agent.service: Failed with result 'signal'.\n"
        )
        result = await async_query_journalctl_unclean_exits(
            self._driver(output), ["fboss_sw_agent"], 0, 1e12
        )
        self.assertEqual(list(result.keys()), ["fboss_sw_agent"])
        self.assertEqual(
            [reason for _ts, reason in result["fboss_sw_agent"]], ["signal"]
        )

    async def test_instance_unit_parsed(self) -> None:
        """``fboss_hw_agent@0.service`` should parse — the ``@`` in the unit
        name has bitten similar regexes before."""
        output = (
            "2000-01-01T00:00:32+0000 dut1 systemd[1]: "
            "fboss_hw_agent@0.service: Failed with result 'core-dump'.\n"
        )
        result = await async_query_journalctl_unclean_exits(
            self._driver(output), ["fboss_hw_agent@0"], 0, 1e12
        )
        self.assertIn("fboss_hw_agent@0", result)
        self.assertEqual(result["fboss_hw_agent@0"][0][1], "core-dump")

    async def test_ignores_success_result(self) -> None:
        """A clean stop (``result 'success'``) must not be reported — the
        distinction between clean and unclean is what this helper exists for."""
        output = (
            "2000-01-01T00:00:32+0000 dut1 systemd[1]: "
            "bgpd.service: Failed with result 'success'.\n"
        )
        result = await async_query_journalctl_unclean_exits(
            self._driver(output), ["bgpd"], 0, 1e12
        )
        self.assertEqual(result, {})

    async def test_all_five_unclean_reasons_reported(self) -> None:
        reasons = ["core-dump", "signal", "watchdog", "timeout", "oom-kill"]
        output = "\n".join(
            f"2000-01-01T00:00:{i:02d}+0000 dut1 systemd[1]: "
            f"svc{i}.service: Failed with result '{r}'."
            for i, r in enumerate(reasons)
        )
        result = await async_query_journalctl_unclean_exits(
            self._driver(output),
            [f"svc{i}" for i in range(len(reasons))],
            0, 1e12,
        )
        self.assertEqual(
            sorted(reason for events in result.values() for _ts, reason in events),
            sorted(reasons),
        )

    async def test_multiple_failures_same_service(self) -> None:
        """Two crashes of the same service within the window should both be
        recorded (not deduplicated at the helper level)."""
        output = (
            "2000-01-01T00:00:32+0000 dut1 systemd[1]: "
            "bgpd.service: Failed with result 'signal'.\n"
            "2000-01-01T00:00:40+0000 dut1 systemd[1]: "
            "bgpd.service: Failed with result 'core-dump'.\n"
        )
        result = await async_query_journalctl_unclean_exits(
            self._driver(output), ["bgpd"], 0, 1e12
        )
        self.assertEqual(len(result["bgpd"]), 2)
        self.assertEqual(
            [reason for _ts, reason in result["bgpd"]],
            ["signal", "core-dump"],
        )

    async def test_default_output_format_still_parses(self) -> None:
        """``short-iso`` is what the helper requests, but a DUT with a
        different default locale might still emit the classic ``Aug 04 ...``
        format if the flag was ignored. The regex ignores the timestamp
        prefix entirely, so both should parse."""
        output = (
            "Aug 04 02:15:32 dut1 systemd[1]: "
            "bgpd.service: Failed with result 'watchdog'.\n"
        )
        result = await async_query_journalctl_unclean_exits(
            self._driver(output), ["bgpd"], 0, 1e12
        )
        self.assertEqual(result["bgpd"][0][1], "watchdog")

    async def test_daemon_stdout_line_does_not_false_match(self) -> None:
        """A monitored daemon's OWN stdout (routed through the journal) can
        contain arbitrary text. Without the ``systemd[<pid>]:`` anchor, a log
        line like ``bgpd[123]: peer log: sys.service: Failed with result
        'core-dump'`` would be attributed to a phantom ``sys`` unit. The
        regex now requires the systemd-process prefix; the ``svc in services``
        filter is a second guard on top."""
        output = (
            "2000-01-01T00:00:32+0000 dut1 bgpd[123]: "
            "peer log: sys.service: Failed with result 'core-dump'\n"
        )
        result = await async_query_journalctl_unclean_exits(
            self._driver(output), ["bgpd", "fboss_sw_agent"], 0, 1e12
        )
        # No phantom ``sys`` entry, and ``bgpd``'s own stdout doesn't imply
        # bgpd itself crashed.
        self.assertEqual(result, {})

    async def test_unrequested_service_dropped(self) -> None:
        """Even a real ``systemd[1]:`` Failed line for a unit that isn't in
        the caller's requested list must not be reported — the check
        evaluates only its declared service set."""
        output = (
            "2000-01-01T00:00:32+0000 dut1 systemd[1]: "
            "some-other.service: Failed with result 'signal'.\n"
        )
        result = await async_query_journalctl_unclean_exits(
            self._driver(output), ["bgpd"], 0, 1e12
        )
        self.assertEqual(result, {})

    async def test_command_passes_epoch_and_units(self) -> None:
        driver = self._driver("")
        await async_query_journalctl_unclean_exits(
            driver, ["bgpd", "fboss_sw_agent"], 1234, 5678
        )
        cmd = driver.async_run_cmd_on_shell.await_args.args[0]
        self.assertIn("-u bgpd.service", cmd)
        self.assertIn("-u fboss_sw_agent.service", cmd)
        self.assertIn("--since=@1234", cmd)
        self.assertIn("--until=@5679", cmd)


class TestResolveFb303Port(unittest.IsolatedAsyncioTestCase):
    """The counter port must survive an agent that cannot answer.

    Topology discovery raises during an agent outage rather than calling a
    dead box monolithic. That is right for a restart, but a counter port is
    not a topology decision: raising here takes every per-queue / buffer /
    PFC / DSF check down at the moment they are most needed.
    """

    def _driver(self, is_multi_switch):
        driver = MagicMock()
        driver.async_is_multi_switch = AsyncMock()
        if isinstance(is_multi_switch, BaseException):
            driver.async_is_multi_switch.side_effect = is_multi_switch
        else:
            driver.async_is_multi_switch.return_value = is_multi_switch
        return driver

    async def _resolve(self, is_multi_switch) -> int:
        with patch(
            f"{_resolve_fb303_port.__module__}.async_get_device_driver",
            AsyncMock(return_value=self._driver(is_multi_switch)),
        ):
            return await _resolve_fb303_port("dut")

    async def test_known_topology_picks_its_own_port(self) -> None:
        self.assertEqual(await self._resolve(True), FBOSS_MNPU_FB303_PORT)
        self.assertEqual(await self._resolve(False), FBOSS_FB303_PORT)

    async def test_unavailable_topology_falls_back_to_the_monolithic_port(self) -> None:
        for error in (
            RuntimeError("Cannot determine agent topology after RPC failure"),
            NotImplementedError("fallback is only supported in OSS"),
        ):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(await self._resolve(error), FBOSS_FB303_PORT)


if __name__ == "__main__":
    unittest.main()
