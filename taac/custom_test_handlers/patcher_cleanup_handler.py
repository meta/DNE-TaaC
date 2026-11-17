# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
import asyncio
import typing as t

from taac.custom_test_handlers.base_custom_test_handler import (
    BaseCustomTestHandler,
)
from taac.driver.driver_constants import FbossSystemctlServiceName
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger

# A tuple, not a set: get_registered_patchers zips this against the gathered
# results, so the reader does not have to reason about iteration order.
COOP_CONFIG_NAMES: t.Tuple[str, ...] = (
    "agent",
    "bgpcpp",
    "bgpcpp_drain",
    "bgpcpp_softdrain",
)


class PatcherCleanupHelper:
    def __init__(
        self, hostnames: t.List[str], logger: ConsoleFileLogger, *args, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.hostnames = hostnames
        self.initial_patchers = {}
        self.current_patchers = {}
        # label -> {hostname: error} for hosts _list_per_host had to drop.
        # Dropping them keeps one unreachable DUT from stranding the others;
        # replaying them here at the end of initiate_cleanup is what keeps the
        # drop on the test case's record instead of turning a total listing
        # outage into a green tearDown that cleaned nothing.
        self.listing_failures: t.Dict[str, t.Dict[str, Exception]] = {}
        self.logger = logger

    async def get_registered_patchers(self, hostname: str) -> dict:
        # OSS follows the same path: oss_coop_patcher.list_patchers() is a
        # plain registry lookup that returns [] for a config it doesn't track
        # (e.g. "bgpcpp_drain", which OSS ignores) rather than raising, so no
        # per-config guard is needed here.
        driver = await async_get_device_driver(hostname)
        patchers = await asyncio.gather(
            # pyre-fixme[16]: `AbstractSwitch` has no attribute
            #  `async_coop_list_patchers`.
            *[driver.async_coop_list_patchers(config) for config in COOP_CONFIG_NAMES]
        )
        return dict(zip(COOP_CONFIG_NAMES, patchers))

    async def initiate_cleanup(self) -> None:
        # Same reasoning as the gather in _cleanup_patchers, one level up:
        # _cleanup_patchers can raise, and a bare gather would abandon the
        # other DUTs mid-cleanup on the first failure.
        results = await asyncio.gather(
            *(self._cleanup_patchers(hostname) for hostname in self.hostnames),
            return_exceptions=True,
        )
        failures = []
        failed_hosts = set()
        for hostname, result in zip(self.hostnames, results):
            # CancelledError and friends are not Exceptions and must not be
            # quietly dropped into "everything succeeded".
            if isinstance(result, BaseException) and not isinstance(result, Exception):
                raise result
            if isinstance(result, Exception):
                self.logger.error(f"Patcher cleanup failed on {hostname}: {result!r}")
                failures.append(result)
                failed_hosts.add(hostname)
        # A host whose listing was dropped cleaned nothing, so it has to surface
        # here or the tearDown returns green having skipped the work entirely.
        # Appended after the cleanup failures so a real cleanup error is still
        # the one the runner records.
        for label, dropped in self.listing_failures.items():
            for hostname, error in dropped.items():
                self.logger.error(
                    f"{hostname}: {label} listing failed, so this host was not "
                    f"cleaned: {error!r}"
                )
                failures.append(error)
                failed_hosts.add(hostname)
        if failures:
            # Distinct hosts, not len(failures): one host can contribute both
            # listing drops and a cleanup failure, and "failed on 4 of 2
            # host(s)" reads as a bug in the handler.
            self.logger.error(
                f"Patcher cleanup failed on {len(failed_hosts)} of "
                f"{len(self.hostnames)} host(s), {len(failures)} failure(s); "
                f"raising the first"
            )
            # The rest ride along as notes so they reach the recorded
            # exception, not just a log the triager has to go find.
            for extra in failures[1:]:
                failures[0].add_note(f"also: {extra!r}")
            raise failures[0]

    async def _cleanup_patchers(self, hostname: str) -> None:
        if hostname not in self.initial_patchers:
            # No setUp snapshot: diffing against {} would call every
            # pre-existing patcher a leak and rip out patchers this test case
            # never registered. Fail closed and clean nothing.
            self.logger.error(
                f"{hostname}: no initial patcher snapshot, skipping cleanup"
            )
            return
        if hostname not in self.current_patchers:
            # Mirror of the guard above, and the reason _list_per_host can drop
            # a host safely. Absent means the tearDown listing raised -- not
            # that nothing is registered -- so an empty diff here would report
            # a clean test case at debug level while the leak survives and the
            # next setUp snapshots it as pre-existing, hiding it from every
            # later diff in the file. That is the same patcher leak, one path over.
            self.logger.error(
                f"{hostname}: no teardown patcher snapshot, skipping cleanup"
            )
            return
        initial = self.initial_patchers[hostname]
        current = self.current_patchers[hostname]
        driver = await async_get_device_driver(hostname)
        removals = []
        for config, current_list in current.items():
            # Name, not value: oss_coop_patcher.async_register replaces an entry in
            # place when the same name is re-registered with different args, so
            # value equality would call that already-present patcher "new".
            # (OssPatcher is also a non-frozen dataclass, i.e. unhashable.)
            initial_names = {patcher.name for patcher in initial.get(config, [])}
            removals.extend(
                (patcher.name, config)
                for patcher in current_list
                if patcher.name not in initial_names
            )
        if not removals:
            self.logger.debug(f"No patchers to remove for {hostname}")
            return

        self.logger.debug(f"Removing {len(removals)} patchers for {hostname}")
        # return_exceptions so one failing removal does not abandon its
        # siblings mid-flight. Exception, not BaseException: a cancelled
        # teardown is not a failed removal.
        #
        # Concurrent only because async_coop_unregister_patchers reaches its
        # is_last_patcher decision with no await in front of it (for a config
        # patcher; the static-route branch returns earlier), so the gathered
        # removals serialise through that section and the last one still sees
        # a single remaining patcher and restores. An await added there would
        # let every removal read a non-last registry, restore nothing, and
        # report success on a still-patched DUT -- which a mocked driver
        # cannot catch. Remove serially if that invariant ever goes.
        results = await asyncio.gather(
            *(
                driver.async_coop_unregister_patchers(patcher_name, config)
                for patcher_name, config in removals
            ),
            return_exceptions=True,
        )
        failures = []
        cancellations = []
        for (patcher_name, config), result in zip(removals, results):
            if isinstance(result, Exception):
                self.logger.error(
                    f"{hostname}: failed to unregister "
                    f"{config}:{patcher_name}: {result!r}"
                )
                failures.append(result)
            elif isinstance(result, BaseException):
                # CancelledError and friends are not failed removals; they
                # propagate untouched below, after the survivors are named.
                cancellations.append(result)
        if failures or cancellations:
            # Deliberately no restart. async_restore_patched_configs writes the
            # baseline config back before restarting, and its restart is
            # refused outright on a DUT that is not split-agent, so restarting
            # here is the warm boot into a config the restored agent no longer
            # has that the refusal exists to prevent.
            #
            # A removal that succeeded usually took the non-last-patcher
            # branch, which drops the registry entry without restoring, so its
            # config is left patched with nothing pointing at it. Not always:
            # a concurrent last-patcher removal runs
            # async_restore_patched_configs, which restores every patched
            # config on the host and clears the whole registry -- hence "may".
            # Name them either way; after this raise they are invisible to a
            # retry, and the next test case re-baselines whatever survives.
            # BaseException, not Exception: a cancelled removal did not
            # survive either. Named before the re-raise below, because on a
            # cancelled teardown these are exactly the entries left
            # unregistered but still patched, and they would otherwise be lost.
            survived = [
                f"{config}:{patcher_name}"
                for (patcher_name, config), result in zip(removals, results)
                if not isinstance(result, BaseException)
            ]
            if survived:
                self.logger.error(
                    f"{hostname}: unregistered, may still be patched on the "
                    f"DUT (not restored unless a sibling removal restored the "
                    f"host): {', '.join(sorted(survived))}"
                )
        if cancellations:
            raise cancellations[0]
        if failures:
            # No restart, but wait if anything succeeded: such a removal may
            # have taken the is_last_patcher branch and cold-restarted the
            # agent via async_restore_patched_configs, returning mid-replay, so
            # raising straight out would hand the next test case a booting
            # agent -- surfacing as an unrelated flaky precheck rather than as
            # this teardown. Guarded on `survived` because with every removal
            # failed nothing restored, nothing restarted, and the wait would be
            # up to 300s of pure cost on a DUT that is probably already wedged.
            # Advisory for the same reason as the wait below.
            if survived:
                try:
                    await driver.async_wait_for_agent_configured()
                except Exception as e:
                    self.logger.warning(
                        f"{hostname}: agent not configured after failed "
                        f"cleanup: {e!r}"
                    )
            for extra in failures[1:]:
                failures[0].add_note(f"also failed on {hostname}: {extra!r}")
            raise failures[0]

        # Advisory wait: when the removal was the last patcher for the host the
        # driver has already restarted the agent and returned without waiting
        # for it to finish replaying config, and restarting again mid-replay is
        # what makes the second restart's start-time check flaky. But
        # async_is_agent_configured returns False for every error, so a crashed
        # or unreachable agent would poll to the deadline and raise here --
        # before the restart that is what repairs it. Warn and restart anyway.
        #
        # Deliberately the default timeout, not a shorter one: when the driver
        # restarts the agent from async_restore_patched_configs it is a cold
        # boot, and async_restart_split_agents alone budgets 300s for hw
        # readiness plus 120s to settle, so a short poll would expire during a
        # legitimate replay and warm-restart into the middle of it -- exactly
        # what this wait exists to prevent.
        try:
            await driver.async_wait_for_agent_configured()
        except Exception as e:
            self.logger.warning(
                f"{hostname}: agent not configured before restart, "
                f"restarting anyway: {e!r}"
            )
        await driver.async_restart_service(FbossSystemctlServiceName.AGENT)
        await driver.async_wait_for_agent_configured()

    async def _list_per_host(self, label: str) -> dict:
        """Listed patchers per host, omitting the hosts whose listing raised.

        A bare gather makes one unreachable DUT decide for all of them. At
        tearDown it propagates out of async_test_case_tearDown before
        initiate_cleanup runs, so no host is cleaned; at setUp it aborts the
        test case outright, since the runner appends the handler
        to _test_case_handlers_pending_cleanup only after setUp returns -- the
        handler is never queued for tearDown at all. Dropping only the host
        that raised is a deliberate policy change from that fail-fast: the
        other DUTs still get cleaned. It is not a licence to fail silently,
        so the drop is recorded and initiate_cleanup re-raises it.
        """
        results = await asyncio.gather(
            *(self.get_registered_patchers(hostname) for hostname in self.hostnames),
            return_exceptions=True,
        )
        patchers = {}
        dropped = {}
        for hostname, result in zip(self.hostnames, results):
            if isinstance(result, BaseException) and not isinstance(result, Exception):
                raise result
            if isinstance(result, Exception):
                self.logger.error(
                    f"{hostname}: failed to list {label} patchers: {result!r}"
                )
                dropped[hostname] = result
                continue
            patchers[hostname] = result
        self.listing_failures[label] = dropped
        self.logger.debug(f"{label.capitalize()} patchers: {patchers}")
        return patchers

    async def set_initial_registered_patchers(self) -> None:
        self.initial_patchers = await self._list_per_host("initial")

    async def set_current_registered_patchers(self) -> None:
        self.current_patchers = await self._list_per_host("current")


class PatcherCleanupHandler(BaseCustomTestHandler):
    """Cleanup patchers on FBOSS devices after test cases"""

    SUPPORTED_TAGS = ["patcher-cleanup"]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.fboss_devices = [
            device.name
            for device in self.test_topology.devices
            if device.attributes.operating_system == "FBOSS"
        ]
        self.test_case_patcher_cleanup_helper = ...

    async def async_test_case_setUp(self) -> None:
        # pyrefly: ignore [bad-assignment]
        self.test_case_patcher_cleanup_helper = PatcherCleanupHelper(
            self.fboss_devices, self.logger
        )
        # pyrefly: ignore [missing-attribute]
        await self.test_case_patcher_cleanup_helper.set_initial_registered_patchers()

    async def async_test_case_tearDown(self) -> None:
        # pyrefly: ignore [missing-attribute]
        await self.test_case_patcher_cleanup_helper.set_current_registered_patchers()
        # pyrefly: ignore [missing-attribute]
        await self.test_case_patcher_cleanup_helper.initiate_cleanup()
