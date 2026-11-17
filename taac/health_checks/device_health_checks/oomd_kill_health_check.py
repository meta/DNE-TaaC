# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
import re
import time
import typing as t
from collections import defaultdict

from taac.constants import TestDevice
from taac.health_checks.abstract_health_check import (
    AbstractDeviceHealthCheck,
)
from taac.health_checks.constants import FB_OOMD_LOG_PATH
from taac.health_check.health_check import types as hc_types
from taac.utils.oss_taac_constants import (
    OSS_MEMORY_PRESSURE_LOG,
    OSS_MEMORY_PRESSURE_PATH,
    TAAC_OSS,
)


# The driver returns stdout only (FbossSwitch.async_run_cmd_on_shell ->
# result.stdout), so journalctl's own diagnostics -- which it writes to
# stderr -- never reach us. Its exit status does, if we ask for it: non-zero
# on the permission and no-journal-files cases, zero on a genuinely quiet
# window. Matching stdout text instead would both miss those failures and
# false-positive on routine kernel lines ("failed to ..." from a firmware
# load or driver probe).
_RC_MARKER = "__TAAC_JOURNALCTL_RC="
# The runner's clock sets the window, the DUT's clock stamps the journal, and
# DUT clocks drift. A minute of slack each way costs nothing: the task_memcg=
# pattern is specific enough that extra lines are harmless.
_CLOCK_SLACK_S = 60
# The allocator step runs on one device; the playbook's postchecks run on
# every device in the topology. With a single DUT those are the same set,
# with several DUTs they are not, and a device that was never stressed must
# not report "Oom kills not detected" for a kill nothing asked it to
# produce. The pushed stand-in's mtime is the marker: the step rewrites it
# every run, so a fresh one means "this device ran the allocator" and anything
# older (or absent) means this expectation is not about this device.
_MTIME_MARKER = "__TAAC_ALLOCATOR_MTIME="


def _oss_oom_command_and_pattern(
    start_time: int, end_time: int
) -> t.Tuple[str, str]:
    """OSS has no fb-oomd; read the kernel's own OOM record instead.

    The kernel logs one "oom-kill:" line per kill with both the killed
    cgroup (``task_memcg``) and process name (``task``) already resolved,
    right before its "Out of memory: Killed process" line -- no need to
    separately correlate a systemd unit-kill message.

    Unlike the Meta branch this needs no DUT timezone at all: journalctl
    takes "@<epoch seconds>" directly. The Meta branch greps wall-clock text
    out of a log file and so is stuck with local time, but reusing that here
    would import _async_dut_utc_offset_seconds' documented wrong-answer
    fallback (the runner's offset, wrong whenever the zones differ) for no
    reason.
    """
    # No --grep: it needs systemd >= 237 built with PCRE2, and when it is
    # missing journalctl writes to stderr and leaves stdout empty, which this
    # check would report as "Oom kills not detected" -- a tooling failure
    # dressed up as a product failure. The task_memcg= pattern below already
    # selects exactly the oom-kill lines, and the window is minutes.
    since = int(start_time) - _CLOCK_SLACK_S
    until = int(end_time) + _CLOCK_SLACK_S
    # -q --no-pager: older systemd prints "-- Logs begin at ... --" on stdout,
    # which would make an empty journal look non-empty.
    cmd = (
        # stat first, so "$?" below is still journalctl's.
        f"stat -c {_MTIME_MARKER}%Y {OSS_MEMORY_PRESSURE_PATH} 2>/dev/null; "
        f"journalctl -k -q --no-pager --since @{since} --until @{until}; "
        f"echo {_RC_MARKER}$?"
    )
    # Same named group as the Meta pattern below, so the caller's slice/process
    # split (last two path segments) needs no OSS-specific branch. The comm
    # name in "task=" is kernel-truncated to 15 chars, so it is not used --
    # the cgroup path segment our own script creates ("memory-pressure") is.
    pattern = r"task_memcg=(?P<cgroup_path>[^,]+)"
    return cmd, pattern


def runner_utc_offset_seconds() -> int:
    """The runner's own UTC offset, DST-aware."""
    if time.daylight and time.localtime().tm_isdst:
        return -time.altzone
    return -time.timezone


class OomdKillHealthCheck(AbstractDeviceHealthCheck[hc_types.BaseHealthCheckIn]):
    CHECK_NAME = hc_types.CheckName.OOMD_KILL_CHECK
    # Resolved once per check instance: a DUT's zone does not change mid-run,
    # and re-reading it per retry would let one failed round trip move the
    # grep window by hours and flip the verdict.
    _dut_utc_offset_s: t.Optional[int] = None

    async def _run(
        self,
        obj: TestDevice,
        input: hc_types.BaseHealthCheckIn,
        check_params: t.Dict[str, t.Any],
    ) -> hc_types.HealthCheckResult:
        start_time = int(check_params["start_time"])
        end_time = int(check_params.get("end_time", time.time()))
        if end_time <= start_time:
            return hc_types.HealthCheckResult(
                status=hc_types.HealthCheckStatus.FAIL,
                message="OOM log window must have end_time greater than start_time",
            )
        expected_oom_kills = check_params.get(
            "expected_oom_kills", {}
        )  # { slice_1: [process_1, ...] }
        # fb-oomd (Meta) / the kernel log (OSS) stamps entries in the DUT's
        # local time, but the window is computed on the runner: a container
        # in a different zone greps for minutes that never appear and every
        # expected kill reads as missing.
        if TAAC_OSS:
            cmd, pattern = _oss_oom_command_and_pattern(start_time, end_time)
        else:
            offset = await self._async_dut_utc_offset_seconds()
            formatted_times = [
                time.strftime("%b %e %H:%M", time.gmtime(t + offset))
                for t in range(start_time, end_time, 60)
            ]
            regex = r"\(" + r"\|".join(formatted_times) + r"\)"
            cmd = f'cat {FB_OOMD_LOG_PATH} | grep -ia "{regex}"'
            pattern = r"Trying to kill (?P<cgroup_path>/sys/fs/cgroup/[^ ]+)"
        # pyrefly: ignore [missing-attribute]
        oom_log_content = await self.driver.async_run_cmd_on_shell(cmd) or ""
        if TAAC_OSS:
            # "Is this expectation even mine?" is decided before "can I
            # read the journal?" -- on a multi-device topology, most
            # devices never ran the allocator and SKIP is correct for them
            # regardless of whether journalctl works. Checking rc first
            # would report ERROR for all of them whenever journalctl is broken,
            # even though only the device that actually ran the allocator
            # has any business asking journalctl anything.
            mtime = re.search(rf"{_MTIME_MARKER}(\d+)", oom_log_content)
            if mtime is None or int(mtime.group(1)) < start_time - _CLOCK_SLACK_S:
                return hc_types.HealthCheckResult(
                    status=hc_types.HealthCheckStatus.SKIP,
                    message=(
                        f"the memory-pressure allocator was not pushed to "
                        f"{self.driver.hostname} during this window "
                        f"({OSS_MEMORY_PRESSURE_PATH}: "
                        f"{'absent' if mtime is None else 'stale'}), so the "
                        "expected OOM kill is not this device's to produce"
                    ),
                )
            # journalctl needs root or systemd-journal/adm membership, and -k
            # is current-boot only; both exit non-zero. A quiet kernel over
            # the window exits zero with no output -- that is a normal, and
            # for this playbook meaningful, observation, so it must fall
            # through to the expected/observed diff rather than being called
            # an infra problem.
            rc = re.search(rf"{_RC_MARKER}(\d+)", oom_log_content)
            if rc is None or rc.group(1) != "0":
                return hc_types.HealthCheckResult(
                    status=hc_types.HealthCheckStatus.ERROR,
                    message=(
                        f"could not read the kernel OOM record on "
                        f"{self.driver.hostname}: `{cmd}` exited "
                        f"{rc.group(1) if rc else 'unknown'}. journalctl "
                        "needs root (or systemd-journal/adm) and -k covers "
                        "the current boot only -- this is a tooling failure, "
                        "not a verdict on the device."
                    ),
                )
        observed_oom_kills = defaultdict(list)
        for log_entry in oom_log_content.split("\n"):
            match = re.search(pattern, log_entry)
            if match:
                cgroup_path = match.group("cgroup_path")
                parts = [p for p in cgroup_path.split("/") if p]
                if not parts:
                    # A victim in the root cgroup reports task_memcg=/; the
                    # split below would make it a phantom {"": [""]} kill.
                    continue
                if len(parts) == 1:
                    # A bare top-level slice: the kill was attributed to the
                    # slice itself, not to a unit under it (which is what a
                    # missing memory controller on the child looks like).
                    # Keep it visible rather than dropping it.
                    slice, process = parts[0], "<slice root>"
                else:
                    process = parts[-1]
                    slice = parts[-2]
                observed_oom_kills[slice].append(process)
        undetected_oom_kills = {}
        unexpected_oom_kills = {}
        # Union of the keys: a kill in a slice nobody listed is exactly the
        # surprise this check exists to report, and iterating the expectations
        # alone would drop it.
        slices = set(expected_oom_kills) | set(observed_oom_kills)
        if TAAC_OSS:
            # fb-oomd.log holds only oomd's own kills; journalctl -k holds
            # every OOM kill on the box. A kill in, say, user-0.slice would
            # otherwise fail a check that is not about user-0.slice.
            noise = sorted(slices - set(expected_oom_kills))
            if noise:
                self.logger.info(
                    f"ignoring OOM kills outside the expected slices: "
                    f"{ {s: observed_oom_kills[s] for s in noise} }"
                )
            slices &= set(expected_oom_kills)
        for slice in slices:
            expected = expected_oom_kills.get(slice, [])
            observed = observed_oom_kills.get(slice, [])
            undetected = [
                process for process in expected if process not in observed
            ]
            unexpected = [
                process for process in observed if process not in expected
            ]
            if unexpected:
                unexpected_oom_kills[slice] = unexpected
            if undetected:
                undetected_oom_kills[slice] = undetected
        self.logger.debug(f"expected oom kils: {expected_oom_kills}")
        self.logger.debug(f"observed oom kils: {observed_oom_kills}")
        if undetected_oom_kills or unexpected_oom_kills:
            message = (
                f"Oom kills not detected: {undetected_oom_kills}; "
                f"unexpected oom kills: {unexpected_oom_kills}"
            )
            if TAAC_OSS and undetected_oom_kills:
                # The stand-in allocator runs fire-and-forget, so the usual
                # reason for a missing kill is that it died (cgroup EACCES,
                # no python3, noexec /tmp). Its output is the answer, and
                # nothing else in the tree reads it.
                message += f"\n{await self._async_oss_allocator_log()}"
            return hc_types.HealthCheckResult(
                status=hc_types.HealthCheckStatus.FAIL,
                message=message,
            )
        return hc_types.HealthCheckResult(status=hc_types.HealthCheckStatus.PASS)

    async def _async_oss_allocator_log(self) -> str:
        """The OSS stand-in allocator's own stdout/stderr, off the DUT."""
        try:
            raw = await self.driver.async_run_cmd_on_shell(
                f"cat {OSS_MEMORY_PRESSURE_LOG}"
            )
        except Exception as error:  # diagnostics must not mask the verdict
            return f"({OSS_MEMORY_PRESSURE_LOG} unreadable: {error})"
        raw = (raw or "").strip()
        if not raw:
            return f"({OSS_MEMORY_PRESSURE_LOG} is empty)"
        return f"{OSS_MEMORY_PRESSURE_LOG}:\n{raw}"

    async def _async_dut_utc_offset_seconds(self) -> int:
        """The DUT's UTC offset, read from the DUT itself.

        Cached after the first successful read, so a retry cannot silently
        swap a real DUT offset for the runner's and report every expected
        kill as undetected. Only a first read that fails falls back to the
        runner's offset, which is right whenever the two share a zone.
        """
        if self._dut_utc_offset_s is not None:
            return self._dut_utc_offset_s
        raw = ""
        try:
            raw = (await self.driver.async_run_cmd_on_shell("date +%z")).strip()
            # Matched by shape rather than by position: the transport can
            # prepend a prompt echo or a MOTD line, and a signless "0530"
            # would otherwise parse as garbage instead of failing.
            match = re.search(r"([+-])(\d{2})(\d{2})", raw)
            if not match:
                raise ValueError(f"no +HHMM offset in {raw!r}")
            sign = -1 if match.group(1) == "-" else 1
            self._dut_utc_offset_s = sign * (
                int(match.group(2)) * 3600 + int(match.group(3)) * 60
            )
            return self._dut_utc_offset_s
        except Exception as error:
            # Not cached: a transient failure should be retried, not frozen.
            self.logger.error(
                f"could not read the DUT's UTC offset ({raw!r}: {error}); "
                "falling back to the runner's, which is wrong if the two are "
                "in different zones"
            )
            return runner_utc_offset_seconds()
