#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Tests for PatcherCleanupHelper's OSS cleanup path.

On OSS the driver implements ``async_coop_list_patchers``/
``async_coop_unregister_patchers``, so these tests drive the same
list/diff/unregister path the internal (non-OSS) mode uses, with a mocked driver.
"""

import asyncio
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.custom_test_handlers.patcher_cleanup_handler import (
    COOP_CONFIG_NAMES,
    PatcherCleanupHelper,
)
from taac.driver.driver_constants import FbossSystemctlServiceName
from taac.driver.fboss_switch import FbossSwitch
from taac.driver.oss_coop_patcher import OssPatcher

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

_PACKAGE = "taac" if TAAC_OSS else "neteng.test_infra.dne.taac"

BASE_PATH = f"{_PACKAGE}.custom_test_handlers.patcher_cleanup_handler"


def _patcher(name: str, config_name: str = "bgpcpp", **args) -> OssPatcher:
    # The real OSS type on purpose: it is an unhashable @dataclass, so a
    # stand-in fake would hide that the diff cannot use set().
    return OssPatcher(
        name=name,
        config_name=config_name,
        py_func_name="change_speed",
        args=args,
    )


class TestPatcherCleanupHelperOss(unittest.IsolatedAsyncioTestCase):
    """Driven with a mocked driver; TAAC_OSS no longer changes this path."""

    def setUp(self) -> None:
        # spec'd: an unspec'd AsyncMock answers to any attribute, so a driver
        # method renamed out from under the handler would still "pass". The
        # driver has both async_wait_for_agent_configured and
        # async_wait_for_agent_state_configured, so that trap is live here.
        self.driver = AsyncMock(spec=FbossSwitch)
        get_driver_patcher = patch(
            f"{BASE_PATH}.async_get_device_driver",
            AsyncMock(return_value=self.driver),
        )
        self.addCleanup(get_driver_patcher.stop)
        get_driver_patcher.start()

    def _use_drivers(self, *hostnames: str) -> dict:
        """Replace setUp's single driver with one spec'd mock per hostname."""
        drivers = {host: AsyncMock(spec=FbossSwitch) for host in hostnames}

        async def get_driver(hostname, *args, **kwargs):
            return drivers[hostname]

        driver_patcher = patch(f"{BASE_PATH}.async_get_device_driver", get_driver)
        self.addCleanup(driver_patcher.stop)
        driver_patcher.start()
        return drivers

    async def test_new_patcher_between_setup_and_teardown_is_unregistered(
        self,
    ) -> None:
        helper = PatcherCleanupHelper(["dut1"], logger=MagicMock())

        self.driver.async_coop_list_patchers.return_value = []
        await helper.set_initial_registered_patchers()
        # The removed short-circuit returned {config: []} without ever asking
        # the driver, so listing every config is the regression to pin. It is
        # pinned by the environment the suite runs in, not by a patch: the old
        # TAAC_OSS constant was bound at import (repo-wide convention), and
        # docker/taac-entrypoint.sh exports TAAC_OSS=1 before pytest starts.
        # Patching os.environ here would be inert.
        self.assertEqual(
            sorted(
                # Tolerate the config being passed by keyword: this assertion is
                # about which configs were listed, so it should fail on the set,
                # not IndexError on the calling convention.
                call.args[0] if call.args else call.kwargs["config_name"]
                for call in self.driver.async_coop_list_patchers.await_args_list
            ),
            sorted(COOP_CONFIG_NAMES),
        )

        leaked = {
            "bgpcpp": [_patcher("speed_flip")],
            "agent": [_patcher("queue_config", config_name="agent")],
        }

        def current_patchers(config_name, **kwargs):
            return leaked.get(config_name, [])

        self.driver.async_coop_list_patchers.side_effect = current_patchers
        await helper.set_current_registered_patchers()

        await helper.initiate_cleanup()

        self.assertEqual(
            sorted(
                call.args
                for call in self.driver.async_coop_unregister_patchers.await_args_list
            ),
            [("queue_config", "agent"), ("speed_flip", "bgpcpp")],
        )
        # The handler always restarts the agent after removing patchers, with
        # a plain restart. Pinned so the OSS path inherits exactly the internal
        # call, not a cold boot bolted on here.
        self.driver.async_restart_service.assert_awaited_once_with(
            FbossSystemctlServiceName.AGENT
        )
        # Twice: once before the restart, because the driver may have just
        # restarted the agent itself and returned mid-replay, once after.
        self.assertEqual(self.driver.async_wait_for_agent_configured.await_count, 2)

    async def test_patcher_present_at_setup_is_not_unregistered(self) -> None:
        """Non-empty initial list: the regression the empty-vs-empty cases miss.

        Re-registering the same name with different args replaces the entry in
        oss_coop_patcher.async_register, so the tearDown object is a distinct,
        non-equal OssPatcher. Diffing by value would call it new and rip out a
        patcher the test case owned before setUp.
        """
        helper = PatcherCleanupHelper(["dut1"], logger=MagicMock())

        def listed(patchers):
            def _list(config_name, **kwargs):
                return patchers if config_name == "bgpcpp" else []

            return _list

        self.driver.async_coop_list_patchers.side_effect = listed(
            [_patcher("preexisting", speed=100)]
        )
        await helper.set_initial_registered_patchers()

        self.driver.async_coop_list_patchers.side_effect = listed(
            [_patcher("preexisting", speed=400), _patcher("speed_flip")]
        )
        await helper.set_current_registered_patchers()

        await helper.initiate_cleanup()

        self.driver.async_coop_unregister_patchers.assert_awaited_once_with(
            "speed_flip", "bgpcpp"
        )

    async def test_no_new_patchers_skips_unregister_and_restart(self) -> None:
        self.driver.async_coop_list_patchers.return_value = []

        helper = PatcherCleanupHelper(["dut1"], logger=MagicMock())
        await helper.set_initial_registered_patchers()
        await helper.set_current_registered_patchers()
        await helper.initiate_cleanup()

        self.driver.async_coop_unregister_patchers.assert_not_awaited()
        self.driver.async_restart_service.assert_not_awaited()
        self.driver.async_wait_for_agent_configured.assert_not_awaited()

    async def test_two_leftovers_in_one_config_are_both_unregistered(self) -> None:
        """Two patchers in one config: two unregisters, still one restart."""
        helper = PatcherCleanupHelper(["dut1"], logger=MagicMock())

        self.driver.async_coop_list_patchers.return_value = []
        await helper.set_initial_registered_patchers()

        def current_patchers(config_name, **kwargs):
            if config_name != "bgpcpp":
                return []
            return [_patcher("speed_flip"), _patcher("mtu_shrink")]

        self.driver.async_coop_list_patchers.side_effect = current_patchers
        await helper.set_current_registered_patchers()

        await helper.initiate_cleanup()

        self.assertEqual(
            sorted(
                call.args
                for call in self.driver.async_coop_unregister_patchers.await_args_list
            ),
            [("mtu_shrink", "bgpcpp"), ("speed_flip", "bgpcpp")],
        )
        self.driver.async_restart_service.assert_awaited_once()

    async def test_diff_does_not_cross_hosts(self) -> None:
        """Per-host bookkeeping: dut2's pre-existing patcher is not dut1's leak."""
        drivers = self._use_drivers("dut1", "dut2")

        helper = PatcherCleanupHelper(["dut1", "dut2"], logger=MagicMock())

        drivers["dut1"].async_coop_list_patchers.return_value = []
        drivers["dut2"].async_coop_list_patchers.side_effect = (
            lambda config_name, **kwargs: (
                [_patcher("preexisting")] if config_name == "bgpcpp" else []
            )
        )
        await helper.set_initial_registered_patchers()

        # Both hosts now report the same name; only dut1 gained it.
        for host_driver in drivers.values():
            host_driver.async_coop_list_patchers.side_effect = (
                lambda config_name, **kwargs: (
                    [_patcher("preexisting")] if config_name == "bgpcpp" else []
                )
            )
        await helper.set_current_registered_patchers()

        await helper.initiate_cleanup()

        drivers["dut1"].async_coop_unregister_patchers.assert_awaited_once_with(
            "preexisting", "bgpcpp"
        )
        drivers["dut2"].async_coop_unregister_patchers.assert_not_awaited()
        drivers["dut2"].async_restart_service.assert_not_awaited()

    async def test_failed_unregister_raises_without_restarting(self) -> None:
        """A refused restore must not be followed by the restart it refused.

        async_restore_patched_configs writes the baseline config back before
        restarting and the restart is refused on a DUT that is not
        split-agent, so warm restarting here is the very operation that aborts the sw agent on
        replay. Siblings still run; the agent is left alone.
        """
        helper = PatcherCleanupHelper(["dut1"], logger=MagicMock())

        self.driver.async_coop_list_patchers.return_value = []
        await helper.set_initial_registered_patchers()

        leaked = {
            "bgpcpp": [_patcher("speed_flip")],
            "agent": [_patcher("queue_config", config_name="agent")],
        }
        self.driver.async_coop_list_patchers.side_effect = (
            lambda config_name, **kwargs: leaked.get(config_name, [])
        )
        await helper.set_current_registered_patchers()

        boom = RuntimeError("refusing to warm-boot into a patched config")

        async def unregister(patcher_name, config_name, **kwargs):
            if config_name == "agent":
                raise boom

        self.driver.async_coop_unregister_patchers.side_effect = unregister

        with self.assertRaises(RuntimeError) as caught:
            await helper.initiate_cleanup()
        self.assertIs(caught.exception, boom)

        # The sibling removal still ran, but the agent was not restarted.
        self.assertEqual(self.driver.async_coop_unregister_patchers.await_count, 2)
        self.driver.async_restart_service.assert_not_awaited()
        # It is still waited on: a sibling that took the is_last_patcher branch
        # cold-restarted the agent, so raising straight out would hand the next
        # test case a booting agent.
        self.driver.async_wait_for_agent_configured.assert_awaited_once()

        # The bgpcpp removal succeeded, so its registry entry is gone while the
        # config is still patched on the DUT. Nothing else records that, so the
        # log line naming it is the only trace a triager gets.
        survivor_logs = [
            str(call)
            for call in helper.logger.error.call_args_list
            if "may still be patched" in str(call)
        ]
        self.assertEqual(len(survivor_logs), 1)
        self.assertIn("bgpcpp:speed_flip", survivor_logs[0])
        # The agent removal failed, so it was never unregistered and is not a
        # survivor -- it is named by the failure log instead.
        self.assertNotIn("agent:queue_config", survivor_logs[0])

    async def test_one_host_failing_does_not_abandon_the_others(self) -> None:
        """A raise on dut1 must not strand dut2's cleanup in initiate_cleanup."""
        drivers = self._use_drivers("dut1", "dut2")

        helper = PatcherCleanupHelper(["dut1", "dut2"], logger=MagicMock())

        for host_driver in drivers.values():
            host_driver.async_coop_list_patchers.return_value = []
        await helper.set_initial_registered_patchers()

        for host_driver in drivers.values():
            host_driver.async_coop_list_patchers.side_effect = (
                lambda config_name, **kwargs: (
                    [_patcher("speed_flip")] if config_name == "bgpcpp" else []
                )
            )
        await helper.set_current_registered_patchers()

        boom = RuntimeError("refusing to warm-boot into a patched config")
        drivers["dut1"].async_coop_unregister_patchers.side_effect = boom

        # dut2 yields, so it is genuinely mid-flight when dut1 raises. Without
        # the sleep the mocks complete before the exception propagates and a
        # bare gather passes by accident.
        async def slow_unregister(patcher_name, config_name, **kwargs):
            await asyncio.sleep(0.05)

        drivers["dut2"].async_coop_unregister_patchers.side_effect = slow_unregister

        with self.assertRaises(RuntimeError) as caught:
            await helper.initiate_cleanup()
        self.assertIs(caught.exception, boom)

        drivers["dut2"].async_coop_unregister_patchers.assert_awaited_once_with(
            "speed_flip", "bgpcpp"
        )
        drivers["dut2"].async_restart_service.assert_awaited_once_with(
            FbossSystemctlServiceName.AGENT
        )
        self.assertEqual(
            drivers["dut2"].async_wait_for_agent_configured.await_count, 2
        )
        drivers["dut1"].async_restart_service.assert_not_awaited()

    async def test_down_agent_before_restart_does_not_block_the_restart(self) -> None:
        """The pre-restart wait is advisory: a down agent is what the restart fixes.

        async_is_agent_configured returns False for every error, so
        async_wait_for_agent_configured raises
        after its full timeout on a crashed or unreachable agent. Raising there
        would skip the restart that repairs it.
        """
        helper = PatcherCleanupHelper(["dut1"], logger=MagicMock())

        self.driver.async_coop_list_patchers.return_value = []
        await helper.set_initial_registered_patchers()

        self.driver.async_coop_list_patchers.side_effect = (
            lambda config_name, **kwargs: (
                [_patcher("speed_flip")] if config_name == "bgpcpp" else []
            )
        )
        await helper.set_current_registered_patchers()

        calls = []

        async def wait(*args, **kwargs):
            calls.append("wait")
            if len(calls) == 1:
                raise Exception("Agent did not reach configured state")

        self.driver.async_wait_for_agent_configured.side_effect = wait

        await helper.initiate_cleanup()

        self.driver.async_restart_service.assert_awaited_once_with(
            FbossSystemctlServiceName.AGENT
        )
        self.assertEqual(self.driver.async_wait_for_agent_configured.await_count, 2)
        # Order, not just counts: a wait that runs after the restart is not the
        # pre-restart wait, and await_count alone cannot tell them apart.
        self.assertEqual(
            [
                name
                for name, _args, _kwargs in self.driver.mock_calls
                if name
                in ("async_wait_for_agent_configured", "async_restart_service")
            ],
            [
                "async_wait_for_agent_configured",
                "async_restart_service",
                "async_wait_for_agent_configured",
            ],
        )

    async def test_missing_initial_snapshot_cleans_nothing(self) -> None:
        """No setUp snapshot must not mean "every patcher is a leak".

        _list_per_host omits a host whose listing raised, and setUp may not
        have run at all, so a hostname can be absent from initial_patchers.
        Diffing that against {} would unregister patchers this test case never
        registered and bounce the agent.
        """
        helper = PatcherCleanupHelper(["dut1"], logger=MagicMock())

        self.driver.async_coop_list_patchers.side_effect = (
            lambda config_name, **kwargs: (
                [_patcher("preexisting")] if config_name == "bgpcpp" else []
            )
        )
        await helper.set_current_registered_patchers()

        # set_initial_registered_patchers never completed.
        self.assertEqual(helper.initial_patchers, {})

        await helper.initiate_cleanup()

        self.driver.async_coop_unregister_patchers.assert_not_awaited()
        self.driver.async_restart_service.assert_not_awaited()

    async def test_missing_teardown_snapshot_is_not_a_clean_test_case(self) -> None:
        """A dropped tearDown listing must not read as "nothing to clean".

        _list_per_host omits a host whose listing raised, so an absent
        hostname means the tearDown listing failed, not that the registry is
        empty. Diffing against {} yields no removals, which is indistinguishable
        from a clean test case -- and the leak then gets snapshotted as
        pre-existing at the next setUp, hiding it from every later diff.
        """
        helper = PatcherCleanupHelper(["dut1"], logger=MagicMock())

        self.driver.async_coop_list_patchers.return_value = []
        await helper.set_initial_registered_patchers()
        self.assertEqual(list(helper.initial_patchers), ["dut1"])

        self.driver.async_coop_list_patchers.side_effect = RuntimeError("no driver")
        await helper.set_current_registered_patchers()
        # The tearDown listing raised, so the host was dropped.
        self.assertEqual(helper.current_patchers, {})

        # Nothing was cleaned, so the tearDown must not return green: a total
        # listing outage would otherwise be indistinguishable from a clean run.
        with self.assertRaises(RuntimeError):
            await helper.initiate_cleanup()

        self.driver.async_coop_unregister_patchers.assert_not_awaited()
        self.driver.async_restart_service.assert_not_awaited()
        # Not debug: a dropped snapshot must be distinguishable in the log from
        # a test case that genuinely leaked nothing.
        helper.logger.error.assert_any_call(
            "dut1: no teardown patcher snapshot, skipping cleanup"
        )

    async def test_all_removals_failing_skips_the_wait_too(self) -> None:
        """Nothing survived means nothing restored, so nothing to wait out.

        The wait before the re-raise exists for a sibling that took the
        is_last_patcher branch and cold-restarted the agent. That needs a
        removal to have succeeded; with every removal failed it is up to 300s
        of pure cost on a DUT whose agent is probably already wedged.
        """
        helper = PatcherCleanupHelper(["dut1"], logger=MagicMock())

        self.driver.async_coop_list_patchers.return_value = []
        await helper.set_initial_registered_patchers()

        leaked = {
            "bgpcpp": [_patcher("speed_flip")],
            "agent": [_patcher("queue_config", config_name="agent")],
        }
        self.driver.async_coop_list_patchers.side_effect = (
            lambda config_name, **kwargs: leaked.get(config_name, [])
        )
        await helper.set_current_registered_patchers()

        self.driver.async_coop_unregister_patchers.side_effect = RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            await helper.initiate_cleanup()

        self.assertEqual(self.driver.async_coop_unregister_patchers.await_count, 2)
        self.driver.async_restart_service.assert_not_awaited()
        self.driver.async_wait_for_agent_configured.assert_not_awaited()

    async def test_cancelled_removal_propagates_without_restarting(self) -> None:
        """A cancelled teardown is not a failed removal.

        Both gathers use return_exceptions=True, which also captures
        BaseException. Folding a CancelledError into the failure list would
        report it as a cleanup error and, worse, let the code carry on to the
        restart; it has to propagate untouched instead.
        """
        helper = PatcherCleanupHelper(["dut1"], logger=MagicMock())

        self.driver.async_coop_list_patchers.return_value = []
        await helper.set_initial_registered_patchers()

        self.driver.async_coop_list_patchers.side_effect = (
            lambda config_name, **kwargs: (
                [_patcher("speed_flip")] if config_name == "bgpcpp" else []
            )
        )
        await helper.set_current_registered_patchers()

        self.driver.async_coop_unregister_patchers.side_effect = (
            asyncio.CancelledError()
        )

        with self.assertRaises(asyncio.CancelledError):
            await helper.initiate_cleanup()

        self.driver.async_restart_service.assert_not_awaited()

    async def test_one_host_failing_to_list_does_not_block_the_others(self) -> None:
        """A listing failure must cost one host its cleanup, not every host.

        Both setters gather per host; a bare gather propagates the first
        failure out of setUp/tearDown, so on OSS -- where listing really
        talks to the driver -- one unreachable DUT would mean nothing is
        cleaned anywhere.
        """
        drivers = self._use_drivers("dut1", "dut2")
        helper = PatcherCleanupHelper(["dut1", "dut2"], logger=MagicMock())

        drivers["dut1"].async_coop_list_patchers.side_effect = RuntimeError("no driver")
        drivers["dut2"].async_coop_list_patchers.return_value = []
        await helper.set_initial_registered_patchers()
        self.assertEqual(list(helper.initial_patchers), ["dut2"])

        drivers["dut2"].async_coop_list_patchers.side_effect = (
            lambda config_name, **kwargs: (
                [_patcher("speed_flip")] if config_name == "bgpcpp" else []
            )
        )
        await helper.set_current_registered_patchers()

        # dut1 is still reported: isolating the drop keeps dut2's cleanup
        # running, it does not make dut1's skipped cleanup disappear.
        with self.assertRaises(RuntimeError):
            await helper.initiate_cleanup()

        drivers["dut2"].async_coop_unregister_patchers.assert_awaited_once_with(
            "speed_flip", "bgpcpp"
        )
        drivers["dut2"].async_restart_service.assert_awaited_once()
        # dut1 never snapshotted: fail closed there, clean dut2 anyway.
        drivers["dut1"].async_coop_unregister_patchers.assert_not_awaited()
        drivers["dut1"].async_restart_service.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
