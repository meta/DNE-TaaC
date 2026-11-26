# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Recovery-safe local-SPAN setup for RBB SRv6 wire validation.

The two-port RBB testbed has IXIA only at the service edges.  To inspect the
outer SRv6 packet leaving R1, this task temporarily mirrors R1 core egress to
the R1 IXIA-facing port.  It edits the existing AgentConfig in place, reloads
it, and restores the byte-for-byte pre-test configuration on cleanup.
"""

from __future__ import annotations

import json
import re
import typing as t

from taac.constants import TestCaseFailure
from taac.tasks.base_task import BaseTask
from taac.tasks.rbb_edge_config_utils import (
    async_apply_backup_metadata,
    async_backup_before_overwrite,
    async_discard_backup,
    async_guard_snapshot_set,
    async_read_file_or_none,
    async_restore_backup,
    async_write_json_file,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger

_BACKUP_SUFFIX = ".taac-rbb-srv6-capture-orig"
_APPLY = "apply"
_RESTORE = "restore"
_MIRROR_NAME_RE = re.compile(r"[A-Za-z0-9_.:-]{1,31}")


class RbbSrv6CaptureMirrorTask(BaseTask):
    """Install or restore one test-owned R1 local-SPAN configuration."""

    NAME = "rbb_srv6_capture_mirror"

    def __init__(
        self,
        hostname: str | None = None,
        description: str | None = None,
        ixia: t.Any | None = None,
        logger: ConsoleFileLogger | None = None,
        shared_data: dict[t.Any, t.Any] | None = None,
    ) -> None:
        super().__init__(hostname, description, ixia, logger, shared_data)

    async def run(self, params: dict[str, t.Any]) -> None:
        allowed = {
            "hostname",
            "action",
            "mirror_name",
            "source_interfaces",
            "destination_interface",
        }
        unknown = sorted(set(params) - allowed)
        if unknown:
            raise ValueError(f"rbb_srv6_capture_mirror unsupported fields: {unknown}")
        hostname = str(params.get("hostname") or self.hostname or "").strip()
        if not hostname:
            raise ValueError("rbb_srv6_capture_mirror requires hostname")
        action = params.get("action")
        if action not in (_APPLY, _RESTORE):
            raise ValueError(
                "rbb_srv6_capture_mirror action must be 'apply' or 'restore'"
            )
        driver = await async_get_device_driver(hostname)
        if action == _RESTORE:
            await self._restore(driver, hostname)
            return

        user_id = str(await driver.async_run_cmd_on_shell("id -u") or "").strip()
        if user_id != "0":
            raise TestCaseFailure(
                f"{hostname}: SRv6 capture mirroring requires a root SSH session"
            )

        mirror_name = str(params.get("mirror_name") or "").strip()
        if _MIRROR_NAME_RE.fullmatch(mirror_name) is None:
            raise ValueError(
                "mirror_name must use 1..31 portable ASCII name characters"
            )
        sources = params.get("source_interfaces")
        if (
            not isinstance(sources, list)
            or not sources
            or any(not isinstance(item, str) or not item.strip() for item in sources)
            or len(sources) != len(set(sources))
        ):
            raise ValueError("source_interfaces must be a non-empty unique string list")
        destination = str(params.get("destination_interface") or "").strip()
        if not destination or destination in sources:
            raise ValueError(
                "destination_interface must be non-empty and outside source_interfaces"
            )
        await self._apply(driver, hostname, mirror_name, sources, destination)

    @staticmethod
    def _patched_config(
        raw: str,
        hostname: str,
        mirror_name: str,
        sources: list[str],
        destination: str,
    ) -> dict[str, t.Any]:
        try:
            config = json.loads(raw)
        except json.JSONDecodeError as error:
            raise TestCaseFailure(
                f"{hostname}: {C.AGENT_CONFIG_PATH} is not valid JSON: {error}"
            ) from error
        sw = config.get("sw")
        if not isinstance(sw, dict):
            raise TestCaseFailure(
                f"{hostname}: {C.AGENT_CONFIG_PATH} must contain a sw object"
            )
        ports = sw.get("ports")
        mirrors = sw.get("mirrors")
        if not isinstance(ports, list) or any(
            not isinstance(port, dict) for port in ports
        ):
            raise TestCaseFailure(f"{hostname}: AgentConfig sw.ports is invalid")
        if not isinstance(mirrors, list) or any(
            not isinstance(mirror, dict) for mirror in mirrors
        ):
            raise TestCaseFailure(f"{hostname}: AgentConfig sw.mirrors is invalid")
        if any(mirror.get("name") == mirror_name for mirror in mirrors):
            raise TestCaseFailure(
                f"{hostname}: mirror {mirror_name!r} already exists; refusing "
                "to adopt it"
            )
        by_name: dict[str, dict[str, t.Any]] = {}
        for port in ports:
            name = port.get("name")
            if isinstance(name, str):
                if name in by_name:
                    raise TestCaseFailure(
                        f"{hostname}: AgentConfig repeats port name {name!r}"
                    )
                by_name[name] = port
        missing = sorted(set(sources + [destination]) - set(by_name))
        if missing:
            raise TestCaseFailure(
                f"{hostname}: capture mirror interfaces are absent from AgentConfig: "
                f"{missing}"
            )
        for source in sources:
            port = by_name[source]
            if port.get("egressMirror") not in (None, ""):
                raise TestCaseFailure(
                    f"{hostname}: source port {source!r} already has egressMirror "
                    f"{port.get('egressMirror')!r}"
                )
            port["egressMirror"] = mirror_name
        mirrors.append(
            {
                "name": mirror_name,
                "destination": {"egressPort": {"name": destination}},
                "dscp": 0,
                "truncate": False,
            }
        )
        return config

    async def _apply(
        self,
        driver: t.Any,
        hostname: str,
        mirror_name: str,
        sources: list[str],
        destination: str,
    ) -> None:
        await async_guard_snapshot_set(
            driver,
            (C.AGENT_CONFIG_PATH,),
            hostname,
            backup_suffix=_BACKUP_SUFFIX,
        )
        raw = await async_read_file_or_none(driver, C.AGENT_CONFIG_PATH)
        if raw is None:
            raise TestCaseFailure(
                f"{hostname}: {C.AGENT_CONFIG_PATH} is absent; cannot configure SPAN"
            )
        patched = self._patched_config(
            raw, hostname, mirror_name, sources, destination
        )
        await async_backup_before_overwrite(
            driver,
            C.AGENT_CONFIG_PATH,
            self.logger,
            hostname,
            backup_suffix=_BACKUP_SUFFIX,
        )
        try:
            await async_write_json_file(
                driver, C.AGENT_CONFIG_PATH, patched, hostname=hostname
            )
            await async_apply_backup_metadata(
                driver,
                C.AGENT_CONFIG_PATH,
                hostname,
                backup_suffix=_BACKUP_SUFFIX,
            )
            await driver.async_agent_config_reload()
            await driver.async_wait_for_agent_state_configured()
        except Exception as error:
            try:
                await self._restore(driver, hostname)
            except Exception as rollback_error:  # noqa: BLE001
                raise TestCaseFailure(
                    f"{hostname}: capture mirror apply failed ({error}); rollback "
                    f"also failed ({rollback_error})"
                ) from error
            raise TestCaseFailure(
                f"{hostname}: capture mirror apply failed and was rolled back: {error}"
            ) from error
        self._data[f"{hostname}:owned"] = True
        self.logger.info(
            f"{hostname} -- mirrored core egress {sources} to IXIA edge {destination}"
        )

    async def _restore(self, driver: t.Any, hostname: str) -> None:
        restored = await async_restore_backup(
            driver,
            C.AGENT_CONFIG_PATH,
            self.logger,
            hostname,
            backup_suffix=_BACKUP_SUFFIX,
            consume=False,
        )
        if not restored:
            self.logger.info(f"{hostname} -- no capture-mirror snapshot to restore")
            self._data[f"{hostname}:owned"] = False
            return
        await driver.async_agent_config_reload()
        await driver.async_wait_for_agent_state_configured()
        await async_discard_backup(
            driver, C.AGENT_CONFIG_PATH, backup_suffix=_BACKUP_SUFFIX
        )
        self._data[f"{hostname}:owned"] = False
        self.logger.info(f"{hostname} -- restored pre-test capture-mirror config")


__all__ = ["RbbSrv6CaptureMirrorTask"]
