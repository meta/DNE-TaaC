# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
import asyncio
import os
import time
import typing as t

from taac.constants import TestDevice
from taac.health_checks.abstract_health_check import (
    AbstractDeviceHealthCheck,
)
from taac.libs.collectors.registry import get_collector_for_host
from taac.libs.collectors.systemd_state_collector import (
    SystemdStateCollector,
)
from taac.utils.health_check_utils import collector_window_start
from taac.health_check.health_check import types as hc_types

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

DEFAULT_SERVICE_NAMES: t.List[str] = list(hc_types.SERVICE_NAME_MAP.values())


class SystemctlActiveStateHealthCheck(
    AbstractDeviceHealthCheck[hc_types.SystemctlActiveStateHealthCheckIn]
):
    CHECK_NAME = hc_types.CheckName.SYSTEMCTL_ACTIVE_STATE_CHECK
    OPERATING_SYSTEMS = ["FBOSS"]

    async def _run(
        self,
        obj: TestDevice,
        input: hc_types.SystemctlActiveStateHealthCheckIn,
        check_params: t.Dict[str, t.Any],
    ) -> hc_types.HealthCheckResult:
        if input.services:
            service_names = [
                hc_types.SERVICE_NAME_MAP[service] for service in input.services
            ]
        elif check_params.get("services"):
            service_names = check_params["services"]
        else:
            service_names = DEFAULT_SERVICE_NAMES

        if TAAC_OSS:
            return await self._run_oss(obj, service_names, check_params)

        # A crash-looping unit is briefly "active" on every restart, so an
        # optional stability window requires each unit to have stayed active
        # for at least min_active_seconds.
        min_active_seconds = check_params.get("min_active_seconds")
        uptime_seconds = (
            await self._async_get_uptime_seconds() if min_active_seconds else None
        )
        results = await asyncio.gather(
            *[
                self.async_get_inactive_reason(
                    obj.name, service, min_active_seconds, uptime_seconds
                )
                for service in service_names
            ]
        )
        inactive_services = [reason for reason in results if reason]
        if inactive_services:
            return hc_types.HealthCheckResult(
                status=hc_types.HealthCheckStatus.FAIL,
                message=f"Systemctl service(s) {inactive_services} are not active on {obj.name}",
            )
        return hc_types.HealthCheckResult(
            status=hc_types.HealthCheckStatus.PASS,
        )

    async def _run_oss(
        self,
        obj: TestDevice,
        service_names: t.Sequence[str],
        check_params: t.Dict[str, t.Any],
    ) -> hc_types.HealthCheckResult:
        """OSS path — window-based verdict backed by SystemdStateCollector.

        Rather than a single point-in-time ``systemctl show`` at postcheck
        time, this asks the collector: did any monitored service's
        ``ActiveState`` drop out of ``active`` at any sample during the
        check window? A service that flapped active→failed→active mid-test
        is invisible to the legacy one-shot approach; a periodic sample
        catches it. Disabled or not-loaded units are skipped (same semantics
        as the legacy per-service SSH path).

        Window defaults to ``[test_case_start_time, now]`` — the current
        playbook iteration — and can be overridden per-check via
        ``check_params["window_start"]`` / ``["window_end"]``.
        """
        return await self._run_oss_via_collector(obj, service_names, check_params)

    async def _run_oss_via_collector(
        self,
        obj: TestDevice,
        service_names: t.Sequence[str],
        check_params: t.Dict[str, t.Any],
    ) -> hc_types.HealthCheckResult:
        collector = get_collector_for_host("systemd_state", obj.name)
        if not isinstance(collector, SystemdStateCollector):
            self.logger.warning(
                "No SystemdStateCollector registered under 'systemd_state' -- "
                "CollectorsTestHandler runs by default under TAAC_OSS, so "
                "this means either no FBOSS device in the topology, the "
                "'no_oss_collectors' opt-out tag, or a failed handler setUp. "
                "Skipping."
            )
            return hc_types.HealthCheckResult(
                status=hc_types.HealthCheckStatus.SKIP,
                message=(
                    f"No SystemdStateCollector for '{obj.name}' (registry slot "
                    f"'systemd_state@{obj.name}'). CollectorsTestHandler starts one "
                    "per FBOSS node — this node got none, so the check has "
                    "nothing to evaluate."
                    ),
            )

        now = time.time()
        window_end = check_params.get("window_end", now)
        lookback_sec = check_params.get("lookback_sec", 900)
        window_start = check_params.get(
            "window_start",
            collector_window_start(check_params, window_end, lookback_sec),
        )

        # Services the playbook intentionally restarts (e.g. warmboot) get
        # split behaviour, not full exemption. If we subtracted them from
        # the query entirely — as a previous iteration did — the check
        # said nothing at all about them, including whether they came
        # back up after the restart. That is exactly the case the check
        # is meant to catch (a warmboot that leaves the agent dead
        # silently PASSes). Instead:
        #   * non-allowlisted services  -> full window verdict
        #     (any transient ``deactivating`` / ``failed`` FAILs)
        #   * allowlisted services      -> final-sample verdict
        #     (transient ``deactivating`` / ``activating`` during the
        #     intentional restart is tolerated; final state MUST be
        #     ``active``)
        expected_restarted_services = check_params.get(
            "expected_restarted_services", []
        )
        expected_set = set(expected_restarted_services or [])
        queried_services = [s for s in service_names if s not in expected_set]

        if expected_set:
            self.logger.info(
                f"Services expected to restart (final-sample-only check): "
                f"{sorted(expected_set)}"
            )

        missing_from_collector = [
            s for s in service_names if s not in collector.services
        ]
        if missing_from_collector:
            self.logger.warning(
                f"Requested services not monitored by the running "
                f"SystemdStateCollector (started with services="
                f"{collector.services}): {missing_from_collector}. These "
                f"will not be checked."
            )

        inactive = collector.services_ever_inactive_in_window(
            window_start, window_end, services=queried_services
        )
        # For the allowlist, we only verify recovery — not that the
        # service was active throughout the window. A monitored service
        # that isn't in ``expected_restarted_services`` still uses the
        # full-window verdict above, so an unrelated flap remains
        # visible.
        not_recovered = (
            collector.services_not_active_at_end(
                window_start, window_end, services=list(expected_set)
            )
            if expected_set
            else {}
        )

        if not inactive and not not_recovered:
            return hc_types.HealthCheckResult(
                status=hc_types.HealthCheckStatus.PASS,
            )

        parts: t.List[str] = []
        if inactive:
            detail = ", ".join(
                f"{svc}={state}" for svc, state in sorted(inactive.items())
            )
            parts.append(f"never-recovered during window: {detail}")
        if not_recovered:
            detail = ", ".join(
                f"{svc}={state}" for svc, state in sorted(not_recovered.items())
            )
            parts.append(f"expected-restart didn't recover: {detail}")
        return hc_types.HealthCheckResult(
            status=hc_types.HealthCheckStatus.FAIL,
            message=(
                f"Systemctl service(s) not active on {obj.name} during the "
                f"check window [{window_start:.0f}, {window_end:.0f}]: "
                + "; ".join(parts)
            ),
        )

    async def _async_get_uptime_seconds(self) -> float:
        # pyrefly: ignore [missing-attribute]
        output = await self.driver.async_run_cmd_on_shell("cat /proc/uptime")
        return float(output.split()[0])

    async def async_get_inactive_reason(
        self,
        hostname: str,
        service: str,
        min_active_seconds: t.Optional[int] = None,
        uptime_seconds: t.Optional[float] = None,
    ) -> t.Optional[str]:
        """Return why the unit is not healthy, or None if it is."""
        # FBOSS service names are stable inside Classic/NSPAWN, but native
        # NetOS exposes units such as netos.service.fboss_bgp. Keep the health
        # check on the driver's canonical service-name resolution path.
        # pyrefly: ignore [missing-attribute]
        service_name = await self.driver.async_get_systemctl_service_name(service)
        cmd = f"systemctl show {service_name} --no-page"
        # pyrefly: ignore [missing-attribute]
        output = await self.driver.async_run_cmd_on_shell(cmd)
        systemctl_unit_data = {}
        for line in output.split("\n"):
            splitted_line = line.split("=")
            if len(splitted_line) == 2:
                systemctl_unit_data[splitted_line[0]] = splitted_line[1]
        if systemctl_unit_data.get("UnitFileState") == "disabled":
            self.logger.debug(
                "Systemctl service is disabled on the device. Skipping..."
            )
            return None
        if systemctl_unit_data["LoadState"] != "loaded":
            self.logger.debug(
                f"Systemctl service {service} is not loaded on {hostname}... Skipping"
            )
            return None

        active_state = systemctl_unit_data["ActiveState"]
        self.logger.debug(
            f"The active state of the systemctl service {service_name} is: {active_state}"
        )
        if active_state != "active":
            return f"{service_name}: {active_state}"
        if min_active_seconds and uptime_seconds is not None:
            active_enter_timestamp = systemctl_unit_data.get(
                "ActiveEnterTimestampMonotonic", ""
            )
            if (
                not active_enter_timestamp.isdecimal()
                or int(active_enter_timestamp) == 0
            ):
                return f"{service_name}: active with missing or invalid ActiveEnterTimestampMonotonic"
            active_enter_us = int(active_enter_timestamp)
            active_for = int(uptime_seconds - active_enter_us / 1_000_000)
            if active_for < min_active_seconds:
                return f"{service_name}: active for {active_for}s (< {min_active_seconds}s)"
        return None
