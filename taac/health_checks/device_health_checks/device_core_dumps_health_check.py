# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
import time
import typing as t

from taac.constants import TestDevice
from taac.health_checks.abstract_health_check import (
    AbstractDeviceHealthCheck,
)
from taac.health_checks.constants import (
    EOS_CORE_DUMP_FILENAME_REGEX,
)
from taac.utils.health_check_utils import (
    async_find_critical_core_dumps,
    format_timestamp,
    is_fboss_core_dump_from_process,
)
from taac.health_check.health_check import types as hc_types


class DeviceCoreDumpsHealthCheck(AbstractDeviceHealthCheck[hc_types.BaseHealthCheckIn]):
    CHECK_NAME = hc_types.CheckName.DEVICE_CORE_DUMPS_CHECK
    OPERATING_SYSTEMS = ["FBOSS", "EOS"]

    @staticmethod
    def _resolve_time_window(
        check_params: t.Dict[str, t.Any],
    ) -> t.Tuple[float, float]:
        """Resolve the [start_time, end_time] window a core dump must fall in.

        A core dump counts as "new" only when ``start_time < mtime <= end_time``
        (start exclusive, end inclusive).

        ``start_time`` fail-safe: when it is ABSENT or ``None`` (e.g. a bare
        check with no ``jq_params``, or a jq expression that resolved to
        ``null`` because ``.test_case_start_time`` was not in the jq context) we
        anchor to *now* instead of the epoch. Anchoring to the epoch would treat
        every historical core dump — including cores that are days old and
        predate the test window entirely — as "new" and FAIL the stage.
        Anchoring to now means an unscoped check flags nothing pre-existing
        rather than everything, which is the safe default for a detector of
        *new* crashes.

        Note: an EXPLICIT numeric ``start_time`` (including ``0``) is honored
        verbatim — only a missing/null value triggers the fail-safe. No live
        construction passes a literal ``0`` (a bare check omits the key
        entirely, and a null jq resolution yields ``None``), so this preserves
        "epoch" semantics for any caller that deliberately asks for it while
        still fixing the bare/null regression.

        ``end_time`` follows the same rule and defaults to *now* when absent or
        null, bounding out any core with a future mtime (clock skew / bad
        ``%T@`` parse).
        """
        now = time.time()
        raw_start = check_params.get("start_time")
        start_time = float(raw_start) if raw_start is not None else now
        raw_end = check_params.get("end_time")
        end_time = float(raw_end) if raw_end is not None else now
        return start_time, end_time

    async def _run(
        self,
        obj: TestDevice,
        input: hc_types.BaseHealthCheckIn,
        check_params: t.Dict[str, t.Any],
    ) -> hc_types.HealthCheckResult:
        start_time, end_time = self._resolve_time_window(check_params)
        core_dumps_to_ignore = check_params.get("core_dumps_to_ignore", [])
        self.logger.info(
            f"Checking for new core dumps on {obj.name} in window "
            f"({start_time}, {end_time}]"
        )
        core_dumps = await async_find_critical_core_dumps(obj.name)
        self.logger.info(
            f"Found {len(core_dumps)} core dumps on {obj.name}: {core_dumps}"
        )
        new_core_dumps = []
        for core_dump, timestamp in core_dumps.items():
            if (
                start_time < timestamp <= end_time
                and core_dump not in core_dumps_to_ignore
                and not is_fboss_core_dump_from_process(
                    core_dump, check_params.get("core_dump_processes_to_ignore", [])
                )
            ):
                new_core_dumps.append(core_dump)
        if new_core_dumps:
            return hc_types.HealthCheckResult(
                status=hc_types.HealthCheckStatus.FAIL,
                message=f"New Critical core dumps found on {obj.name}: {new_core_dumps}",
            )
        return hc_types.HealthCheckResult(status=hc_types.HealthCheckStatus.PASS)

    async def _run_arista(
        self,
        obj: TestDevice,
        input: hc_types.BaseHealthCheckIn,
        check_params: t.Dict[str, t.Any],
    ) -> hc_types.HealthCheckResult:
        start_time, end_time = self._resolve_time_window(check_params)
        core_dumps_to_ignore = check_params.get("core_dumps_to_ignore", [])
        self.logger.info(
            f"Checking for new core dumps on EOS device {obj.name} in window "
            f"({format_timestamp(start_time)}, {format_timestamp(end_time)}]"
        )
        core_dumps = await async_find_critical_core_dumps(
            obj.name, start_time=start_time
        )
        self.logger.info(
            f"Found {len(core_dumps)} critical core dumps on {obj.name}: {core_dumps}"
        )
        new_core_dumps = {}
        for core_dump, timestamp in core_dumps.items():
            if core_dump in core_dumps_to_ignore:
                continue
            # Parse the real timestamp from the filename if possible
            match = EOS_CORE_DUMP_FILENAME_REGEX.match(core_dump)
            if match:
                file_ts = int(match.group("timestamp"))
            else:
                file_ts = timestamp
            if start_time < file_ts <= end_time:
                new_core_dumps[core_dump] = file_ts

        if new_core_dumps:
            details = []
            for filename, ts in new_core_dumps.items():
                match = EOS_CORE_DUMP_FILENAME_REGEX.match(filename)
                if match:
                    details.append(
                        f"  - {filename} (process={match.group('exec_name')}, "
                        f"pid={match.group('pid')}, time={format_timestamp(ts)})"
                    )
                else:
                    details.append(f"  - {filename} (time={format_timestamp(ts)})")
            detail_str = "\n".join(details)
            return hc_types.HealthCheckResult(
                status=hc_types.HealthCheckStatus.FAIL,
                message=(
                    f"New critical core dumps found on {obj.name} "
                    f"since {format_timestamp(start_time)}:\n{detail_str}"
                ),
            )
        return hc_types.HealthCheckResult(status=hc_types.HealthCheckStatus.PASS)
