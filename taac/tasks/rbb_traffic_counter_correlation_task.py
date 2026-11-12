# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Correlate IXIA packet/byte counts with selected RBB DUT port counters.

The task is intentionally two-phase.  A snapshot step records the DUT counter
and, for IXIA-backed assertions, the matching cumulative IXIA counter.  An
assert step reads the same counters and either compares their window deltas
exactly, requires a meaningful share of the IXIA volume, enforces an IXIA-volume
lower bound for paths that may be traversed more than once, or checks a minimum
DUT-only delta. The
playbook-scoped task data keeps independent test cases from sharing baselines.

The task accepts only structured interface/direction/kind inputs.  It builds a
fixed ``fboss2 show interface ... counters`` command after validating each
interface name, then parses the selected row using the public FBOSS table
layout.  Arbitrary shell commands and regular expressions are deliberately not
part of this task's input contract.
"""

from __future__ import annotations

import math
import shlex
import time
import typing as t

from taac.constants import TestCaseFailure
from taac.tasks.base_task import BaseTask
from taac.tasks.rbb_input_validation import validated_fboss_interface_names
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger

_SNAPSHOT = "snapshot"
_ASSERT = "assert"
_ASSERT_IXIA_SHARE = "assert_ixia_share"
_ASSERT_AT_LEAST_IXIA = "assert_at_least_ixia"
_ASSERT_MIN_DELTA = "assert_min_delta"
_IXIA_COUNTER_FIELDS = frozenset(("tx_frames", "rx_frames", "tx_bytes", "rx_bytes"))
_COUNTER_DIRECTIONS = frozenset(("ingress", "egress"))
_COUNTER_KINDS = frozenset(("packets", "bytes"))


def _strict_nonnegative_number(value: t.Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{label} must be a number")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return normalized


def _strict_positive_int(value: t.Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


class RbbTrafficCounterCorrelationTask(BaseTask):
    """Snapshot DUT interface counters, then correlate their sum with IXIA."""

    # pyrefly: ignore [bad-override-mutable-attribute]
    NAME: str = "rbb_traffic_counter_correlation"

    def __init__(
        self,
        hostname: str | None = None,
        description: str | None = None,
        ixia: t.Any | None = None,
        logger: ConsoleFileLogger | None = None,
        shared_data: dict[t.Any, t.Any] | None = None,
    ) -> None:
        super().__init__(hostname, description, ixia, logger, shared_data)

    @staticmethod
    def _counter_value(
        output: str,
        interface: str,
        counter_direction: str,
        counter_kind: str,
    ) -> int:
        """Parse one exact interface row from ``fboss2`` counter output.

        The stable column order is bytes-in, unicast-in, multicast-in,
        broadcast-in, bytes-out, unicast-out, multicast-out, broadcast-out.
        Packet evidence sums all three packet classes rather than silently
        considering only unicast traffic.
        """
        rows: list[list[str]] = []
        for raw_line in output.splitlines():
            columns = raw_line.replace("|", " ").split()
            if columns and columns[0] == interface:
                rows.append(columns)
        if len(rows) != 1:
            raise ValueError(
                f"expected exactly one counter row for {interface!r}, "
                f"found {len(rows)}"
            )
        row = rows[0]
        if len(row) < 9:
            raise ValueError(
                f"counter row for {interface!r} has {len(row) - 1} values; "
                "expected at least 8"
            )
        try:
            values = [int(value.replace(",", "")) for value in row[1:9]]
        except ValueError as error:
            raise ValueError(
                f"counter row for {interface!r} contains a non-integer value"
            ) from error
        if counter_kind == "bytes":
            return values[0] if counter_direction == "ingress" else values[4]
        indexes = (1, 2, 3) if counter_direction == "ingress" else (5, 6, 7)
        return sum(values[index] for index in indexes)

    @staticmethod
    def _validated_interfaces(value: t.Any) -> list[str]:
        return validated_fboss_interface_names(value, "counter_interfaces")

    @staticmethod
    def _ixia_counter(
        stats: t.Iterable[t.Mapping[str, t.Any]],
        traffic_item: str,
        field: str,
    ) -> int:
        rows = [row for row in stats if row.get("identifier") == traffic_item]
        if not rows:
            raise TestCaseFailure(
                f"IXIA statistics have no row for traffic item {traffic_item!r}"
            )
        missing = [index for index, row in enumerate(rows) if field not in row]
        if missing:
            raise TestCaseFailure(
                f"IXIA statistics for {traffic_item!r} do not expose {field}; "
                f"missing_rows={missing}"
            )
        total = 0.0
        for row in rows:
            try:
                total += _strict_nonnegative_number(row[field], f"IXIA {field}")
            except (TypeError, ValueError) as error:
                raise TestCaseFailure(str(error)) from error
        rounded = round(total)
        if not math.isclose(total, rounded, abs_tol=1e-6):
            raise TestCaseFailure(
                f"IXIA {field} for {traffic_item!r} is not an integer counter: "
                f"{total}"
            )
        return int(rounded)

    async def _read_counters(
        self,
        hostname: str,
        interfaces: list[str],
        counter_direction: str,
        counter_kind: str,
        gate: str,
    ) -> dict[str, int]:
        driver = await async_get_device_driver(hostname)
        counters: dict[str, int] = {}
        for interface in interfaces:
            command = (
                "fboss2 show interface "
                f"{shlex.quote(interface)} counters"
            )
            output = str(await driver.async_run_cmd_on_shell(command) or "")
            try:
                counters[interface] = self._counter_value(
                    output,
                    interface,
                    counter_direction,
                    counter_kind,
                )
            except ValueError as error:
                raise TestCaseFailure(
                    f"[{gate}] failed to parse {counter_direction} "
                    f"{counter_kind} counter on {hostname}: {error}"
                ) from error
        return counters

    async def run(self, params: dict[str, t.Any]) -> None:
        """Run a snapshot, minimum/lower-bound check, or exact correlation."""
        allowed = {
            "hostname",
            "gate",
            "action",
            "sample_id",
            "counter_interfaces",
            "counter_direction",
            "counter_kind",
            "traffic_item",
            "ixia_counter_field",
            "tolerance_percent",
            "absolute_tolerance",
            "min_value",
            "min_delta",
            "min_ixia_share_percent",
            "fixed_ixia_multiples",
            "ixia_stats_cleared",
        }
        unknown = sorted(set(params) - allowed)
        if unknown:
            raise ValueError(
                f"rbb_traffic_counter_correlation unsupported fields: {unknown}"
            )
        hostname = str(params.get("hostname") or self.hostname or "").strip()
        if not hostname:
            raise ValueError("rbb_traffic_counter_correlation requires hostname")
        gate = str(params.get("gate") or self.NAME)
        action = params.get("action")
        if action not in (
            _SNAPSHOT,
            _ASSERT,
            _ASSERT_IXIA_SHARE,
            _ASSERT_AT_LEAST_IXIA,
            _ASSERT_MIN_DELTA,
        ):
            raise ValueError(
                "rbb_traffic_counter_correlation action must be "
                f"{_SNAPSHOT!r}, {_ASSERT_MIN_DELTA!r}, "
                f"{_ASSERT_IXIA_SHARE!r}, {_ASSERT_AT_LEAST_IXIA!r}, "
                f"or {_ASSERT!r}"
            )
        sample_id = str(params.get("sample_id") or "").strip()
        if not sample_id:
            raise ValueError(
                "rbb_traffic_counter_correlation requires sample_id"
            )
        interfaces = self._validated_interfaces(params.get("counter_interfaces"))
        counter_direction = str(params.get("counter_direction") or "").strip()
        counter_kind = str(params.get("counter_kind") or "").strip()
        if counter_direction not in _COUNTER_DIRECTIONS:
            raise ValueError("counter_direction must be 'ingress' or 'egress'")
        if counter_kind not in _COUNTER_KINDS:
            raise ValueError("counter_kind must be 'packets' or 'bytes'")

        traffic_item = str(params.get("traffic_item") or "").strip()
        counter_field = str(params.get("ixia_counter_field") or "").strip()
        if bool(traffic_item) != bool(counter_field):
            raise ValueError(
                f"{action} requires both traffic_item and ixia_counter_field "
                "when either is supplied"
            )
        if counter_field and counter_field not in _IXIA_COUNTER_FIELDS:
            raise ValueError(
                "ixia_counter_field must be tx_frames, rx_frames, tx_bytes, "
                "or rx_bytes"
            )
        if action not in (_SNAPSHOT, _ASSERT_MIN_DELTA) and not traffic_item:
            raise ValueError(
                "assert requires traffic_item and ixia_counter_field of "
                "tx_frames, rx_frames, tx_bytes, or rx_bytes"
            )
        fixed_ixia_multiples = params.get("fixed_ixia_multiples", 0)
        if (
            isinstance(fixed_ixia_multiples, bool)
            or not isinstance(fixed_ixia_multiples, int)
            or fixed_ixia_multiples < 0
        ):
            raise ValueError("fixed_ixia_multiples must be a non-negative integer")
        if fixed_ixia_multiples and action not in (_SNAPSHOT, _ASSERT_IXIA_SHARE):
            raise ValueError(
                "fixed_ixia_multiples is supported only for snapshot and "
                "assert_ixia_share"
            )
        ixia_stats_cleared = params.get("ixia_stats_cleared", False)
        if not isinstance(ixia_stats_cleared, bool):
            raise ValueError("ixia_stats_cleared must be a boolean")
        if ixia_stats_cleared and action not in (_SNAPSHOT, _ASSERT_IXIA_SHARE):
            raise ValueError(
                "ixia_stats_cleared is supported only for snapshot and "
                "assert_ixia_share"
            )

        key = f"{hostname}:{sample_id}"
        ixia_message = ""
        if action == _SNAPSHOT and traffic_item:
            sample_time = time.time()
            # IxNetwork ClearStats completes before its statistics view always
            # reflects the reset.  Callers which have just completed an
            # isolated clear can declare that boundary explicitly rather than
            # snapshotting the stale pre-clear total.
            baseline_value = (
                0
                if ixia_stats_cleared
                else self._ixia_counter(
                    self.ixia.get_latest_stats(since_time=sample_time),
                    traffic_item,
                    counter_field,
                )
            )
            ixia_baseline = {
                "traffic_item": traffic_item,
                "counter_field": counter_field,
                "value": baseline_value,
            }
            ixia_since_time = time.time()
            ixia_message = (
                f", IXIA {traffic_item}:{counter_field} "
                f"baseline={baseline_value}"
            )
        values = await self._read_counters(
            hostname,
            interfaces,
            counter_direction,
            counter_kind,
            gate,
        )
        if action == _SNAPSHOT:
            # Publish the snapshot only after every requested read succeeds so
            # a failed IXIA baseline cannot leave partially usable task state.
            self._data[key] = values
            if traffic_item:
                self._data[f"{key}:ixia_baseline"] = ixia_baseline
                # Require the assertion sample to be newer than the baseline.
                self._data[f"{key}:ixia_since_time"] = ixia_since_time
            self.logger.info(
                f"{hostname} -- [{gate}] counter baseline {sample_id}: "
                f"members={values}, aggregate={sum(values.values())}"
                f"{ixia_message}"
            )
            return

        if key not in self._data:
            raise TestCaseFailure(
                f"[{gate}] no DUT counter baseline for {hostname}:{sample_id}"
            )
        baseline = self._data[key]
        if not isinstance(baseline, dict) or set(baseline) != set(interfaces):
            raise TestCaseFailure(
                f"[{gate}] DUT counter baseline member set does not match "
                f"{hostname}:{sample_id}"
            )
        member_deltas: dict[str, int] = {}
        for interface in interfaces:
            baseline_value = int(baseline[interface])
            value = values[interface]
            if value < baseline_value:
                raise TestCaseFailure(
                    f"[{gate}] DUT counter moved backwards for "
                    f"{hostname}:{sample_id}:{interface}: "
                    f"baseline={baseline_value}, now={value}"
                )
            member_deltas[interface] = value - baseline_value
        dut_delta = sum(member_deltas.values())

        if action == _ASSERT_MIN_DELTA:
            min_delta = _strict_positive_int(
                params.get("min_delta", 1), "min_delta"
            )
            self.logger.info(
                f"{hostname} -- [{gate}] {sample_id}: "
                f"member deltas={member_deltas}, "
                f"DUT aggregate delta={dut_delta}, required={min_delta}"
            )
            if dut_delta < min_delta:
                raise TestCaseFailure(
                    f"[{gate}] DUT aggregate counter delta is too small for "
                    f"{hostname}:{sample_id}: delta={dut_delta}, "
                    f"required={min_delta}"
                )
            return

        ixia_baseline_key = f"{key}:ixia_baseline"
        if ixia_baseline_key not in self._data:
            raise TestCaseFailure(
                f"[{gate}] snapshot did not record an IXIA counter baseline "
                f"for {hostname}:{sample_id}"
            )
        ixia_baseline = self._data[ixia_baseline_key]
        if not isinstance(ixia_baseline, dict):
            raise TestCaseFailure(
                f"[{gate}] IXIA counter baseline is invalid for "
                f"{hostname}:{sample_id}"
            )
        since_time_key = f"{key}:ixia_since_time"
        if since_time_key not in self._data:
            raise TestCaseFailure(
                f"[{gate}] no IXIA sample-time baseline for "
                f"{hostname}:{sample_id}"
            )
        since_time = float(self._data[since_time_key])
        if (
            ixia_baseline.get("traffic_item") != traffic_item
            or ixia_baseline.get("counter_field") != counter_field
        ):
            raise TestCaseFailure(
                f"[{gate}] IXIA counter identity changed after the snapshot "
                f"for {hostname}:{sample_id}"
            )
        tolerance_percent = _strict_nonnegative_number(
            params.get("tolerance_percent", 5.0), "tolerance_percent"
        )
        if tolerance_percent > 100:
            raise ValueError("tolerance_percent must not exceed 100")
        absolute_tolerance = _strict_nonnegative_number(
            params.get("absolute_tolerance", 256), "absolute_tolerance"
        )
        min_value = _strict_positive_int(params.get("min_value", 1), "min_value")

        ixia_current = self._ixia_counter(
            self.ixia.get_latest_stats(since_time=since_time),
            traffic_item,
            counter_field,
        )
        ixia_baseline_value = int(ixia_baseline["value"])
        if ixia_current < ixia_baseline_value:
            raise TestCaseFailure(
                f"[{gate}] IXIA {counter_field} moved backwards for "
                f"{traffic_item!r}: baseline={ixia_baseline_value}, "
                f"now={ixia_current}"
            )
        ixia_value = ixia_current - ixia_baseline_value
        if ixia_value < min_value:
            raise TestCaseFailure(
                f"[{gate}] IXIA {counter_field} for {traffic_item!r} is "
                f"{ixia_value}, below required {min_value}"
            )
        allowed_delta = max(
            absolute_tolerance,
            math.ceil(ixia_value * tolerance_percent / 100.0),
        )
        difference = abs(dut_delta - ixia_value)
        if action == _ASSERT_IXIA_SHARE:
            min_share_percent = _strict_nonnegative_number(
                params.get("min_ixia_share_percent", 1.0),
                "min_ixia_share_percent",
            )
            if not 0 < min_share_percent <= 100:
                raise ValueError(
                    "min_ixia_share_percent must be greater than 0 and not "
                    "exceed 100"
                )
            fixed_delta = fixed_ixia_multiples * ixia_value
            adjusted_dut_delta = dut_delta - fixed_delta
            if adjusted_dut_delta < 0:
                raise TestCaseFailure(
                    f"[{gate}] DUT counter delta is below its declared fixed "
                    f"traversal volume for {hostname}:{sample_id}: DUT "
                    f"delta={dut_delta}, fixed={fixed_delta}"
                )
            required_delta = max(
                1, math.ceil(ixia_value * min_share_percent / 100.0)
            )
            observed_share = adjusted_dut_delta * 100.0 / ixia_value
            self.logger.info(
                f"{hostname} -- [{gate}] {sample_id}: "
                f"member deltas={member_deltas}, DUT aggregate delta={dut_delta}, "
                f"fixed traversal delta={fixed_delta}, "
                f"adjusted NHG delta={adjusted_dut_delta}, "
                f"IXIA {counter_field}={ixia_value}, "
                f"observed share={observed_share:.3f}%, "
                f"required share={min_share_percent:.3f}% "
                f"({required_delta} packets)"
            )
            if adjusted_dut_delta < required_delta:
                raise TestCaseFailure(
                    f"[{gate}] DUT counter did not carry the required IXIA "
                    f"traffic share for {hostname}:{sample_id}: DUT "
                    f"delta={dut_delta}, adjusted NHG delta={adjusted_dut_delta}, "
                    f"IXIA {counter_field}={ixia_value}, "
                    f"observed={observed_share:.3f}%, "
                    f"required={min_share_percent:.3f}%"
                )
            return
        if action == _ASSERT_AT_LEAST_IXIA:
            shortfall = max(0, ixia_value - dut_delta)
            self.logger.info(
                f"{hostname} -- [{gate}] {sample_id}: "
                f"member deltas={member_deltas}, DUT aggregate delta={dut_delta}, "
                f"IXIA {counter_field}={ixia_value}, shortfall={shortfall}, "
                f"allowed={allowed_delta}"
            )
            if shortfall > allowed_delta:
                raise TestCaseFailure(
                    f"[{gate}] DUT counter did not carry the IXIA traffic volume "
                    f"for {hostname}:{sample_id}: DUT delta={dut_delta}, IXIA "
                    f"{counter_field}={ixia_value}, shortfall={shortfall}, "
                    f"allowed={allowed_delta}"
                )
            return
        self.logger.info(
            f"{hostname} -- [{gate}] {sample_id}: member deltas={member_deltas}, "
            f"DUT aggregate delta={dut_delta}, "
            f"IXIA {counter_field}={ixia_value}, difference={difference}, "
            f"allowed={allowed_delta}"
        )
        if difference > allowed_delta:
            raise TestCaseFailure(
                f"[{gate}] DUT/IXIA counter correlation failed for "
                f"{hostname}:{sample_id}: DUT delta={dut_delta}, IXIA "
                f"{counter_field}={ixia_value}, difference={difference}, "
                f"allowed={allowed_delta}"
            )


__all__ = ["RbbTrafficCounterCorrelationTask"]
