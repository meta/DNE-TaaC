# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Safety and lifecycle tests for the OSS Open/R core-path task."""

import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.constants import TestCaseFailure
from taac.tasks.rbb_openr_core_path_task import RbbOpenrCorePathTask

_DRIVER_PATH = "taac.tasks.rbb_openr_core_path_task.async_get_device_driver"
_AUDIT_PATH = "taac.tasks.rbb_openr_core_path_task.RbbStateAuditTask.run"


class _OpenrDriver:
    def __init__(self) -> None:
        self.interfaces = ("fboss2011", "fboss2012")
        self.addresses = ("2001:db8:c0::", "2001:db8:c1::")
        self.overrides = [None, None]
        self.base_metrics = [20, 20]
        self.node_overloaded = False
        self.node_increment = 0
        self.interface_up = [True, True]
        self.interface_overloaded = [False, False]
        self.link_increments = [0, 0]
        self.fail_override_index = None
        self.drift_on_override_failure = None
        self.route_interfaces = None
        self.route_metrics = None
        self.commands = []
        self.async_run_cmd_on_shell = AsyncMock(side_effect=self._run)

    def _lm(self):
        return {
            "r1": {
                "interfaceDetails": {
                    interface: {
                        "info": {
                            "ifIndex": 20 + index,
                            "isUp": self.interface_up[index],
                            "networks": [
                                f"{self.addresses[index]}/127",
                                f"fe80::{index + 1}/64",
                            ],
                        },
                        "isOverloaded": self.interface_overloaded[index],
                        "linkFlapBackOffMs": None,
                        "linkMetricIncrementVal": self.link_increments[index],
                        "metricOverride": self.overrides[index],
                    }
                    for index, interface in enumerate(self.interfaces)
                },
                "isOverloaded": self.node_overloaded,
                "nodeMetricIncrementVal": self.node_increment,
            }
        }

    def _adj(self):
        return {
            "0": {
                "r1": {
                    "adjacencies": [
                        {
                            "adjOnlyUsedByOtherNode": False,
                            "ifName": interface,
                            "isOverloaded": self.interface_overloaded[index],
                            "linkMetricIncrementVal": self.link_increments[index],
                            "metric": (
                                self.overrides[index]
                                if self.overrides[index] is not None
                                else self.base_metrics[index]
                            ),
                            "otherNodeName": "r2",
                        }
                        for index, interface in enumerate(self.interfaces)
                    ],
                    "area": "0",
                    "is_overloaded": self.node_overloaded,
                    "node_metric_increment_val": self.node_increment,
                }
            }
        }

    async def _run(self, command):
        self.commands.append(command)
        if command == "breeze lm links --json":
            return json.dumps(self._lm())
        if command == "breeze decision adj --json":
            return json.dumps(self._adj())
        if command.startswith("breeze decision routes --no-hostnames --json "):
            prefix = command.rsplit(" ", 1)[-1]
            effective = [
                override if override is not None else self.base_metrics[index]
                for index, override in enumerate(self.overrides)
            ]
            selected = (
                list(self.route_interfaces)
                if self.route_interfaces is not None
                else [
                    interface
                    for index, interface in enumerate(self.interfaces)
                    if effective[index] == min(effective)
                ]
            )
            metrics = (
                list(self.route_metrics)
                if self.route_metrics is not None
                else [
                    effective[self.interfaces.index(interface)]
                    for interface in selected
                ]
            )
            return json.dumps(
                {
                    "r1": {
                        "mplsRoutes": [],
                        "unicastRoutes": [
                            {
                                "dest": prefix,
                                "nextHops": [
                                    {
                                        "address": f"fe80::{index + 10}",
                                        "nextHop": f"fe80::{index + 10}",
                                        "ifName": interface,
                                        "metric": metrics[index],
                                        "weight": 1,
                                    }
                                    for index, interface in enumerate(selected)
                                ],
                            }
                        ],
                    }
                }
            )
        tokens = command.split()
        if tokens[:4] == ["breeze", "lm", "override-adj-metric", "--yes"]:
            interface = tokens[-2]
            index = self.interfaces.index(interface)
            if self.fail_override_index == index:
                if self.drift_on_override_failure is not None:
                    drift_index, drift_metric = self.drift_on_override_failure
                    self.overrides[drift_index] = drift_metric
                raise RuntimeError("injected metric command failure")
            self.overrides[index] = int(tokens[-1])
            return ""
        if tokens[:4] == [
            "breeze",
            "lm",
            "clear-adj-metric-override",
            "--yes",
        ]:
            interface = tokens[-1]
            self.overrides[self.interfaces.index(interface)] = None
            return ""
        raise AssertionError(f"unexpected command: {command}")


def _base(action, **extra):
    return {
        "action": action,
        "hostname": "r1.example",
        "gate": "phase1:TC-02",
        "sample_id": "tc02:r1",
        **extra,
    }


class RbbOpenrCorePathTaskTest(unittest.IsolatedAsyncioTestCase):
    def test_task_is_registered(self) -> None:
        from taac.tasks.registry import TASK_NAME_TO_CLASS

        self.assertIs(TASK_NAME_TO_CLASS["rbb_openr_core_path"], RbbOpenrCorePathTask)

    def _task(self, shared_data=None):
        return RbbOpenrCorePathTask(
            hostname="r1.example",
            logger=MagicMock(),
            shared_data={} if shared_data is None else shared_data,
        )

    async def test_exact_owned_lifecycle_and_route_projection(self) -> None:
        driver = _OpenrDriver()
        shared_data = {}
        task = self._task(shared_data)
        with (
            patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver),
            patch(_AUDIT_PATH, new_callable=AsyncMock) as audit,
        ):
            await task.run(
                _base(
                    "snapshot",
                    core_rif_cidrs=["2001:db8:c0::/127", "2001:db8:c1::/127"],
                )
            )
            await task.run(_base("set_metrics", metrics=[10, 1000]))
            await task.run(
                _base(
                    "assert_routes",
                    path_indices=[0],
                    routes=[
                        {
                            "prefix": "192.0.2.2/32",
                            "client": "OPENR",
                            "require_fib": True,
                        }
                    ],
                )
            )
            await task.run(_base("restore"))

        self.assertEqual(driver.overrides, [None, None])
        self.assertTrue(shared_data)
        self.assertTrue(all(value is None for value in shared_data.values()))
        route = audit.await_args.args[0]["routes"][0]
        self.assertNotIn("interfaces", route)
        self.assertEqual(route["next_hop_count"], 1)
        self.assertEqual(route["next_hop_interface_count"], 1)
        self.assertEqual(route["next_hop_scope"], "link_local")
        self.assertIn(
            "breeze lm override-adj-metric --yes --quiet r2 fboss2011 10",
            driver.commands,
        )
        self.assertIn(
            "breeze lm clear-adj-metric-override --yes --quiet r2 fboss2012",
            driver.commands,
        )
        self.assertIn(
            "breeze decision routes --no-hostnames --json 192.0.2.2/32",
            driver.commands,
        )

    async def test_snapshot_rejects_preexisting_override_without_mutation(self) -> None:
        driver = _OpenrDriver()
        driver.overrides[0] = 50
        task = self._task()
        with (
            patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(TestCaseFailure, "pre-existing"),
        ):
            await task.run(
                _base(
                    "snapshot",
                    core_rif_cidrs=["2001:db8:c0::/127", "2001:db8:c1::/127"],
                )
            )

        self.assertFalse(
            any("override-adj-metric --yes" in command for command in driver.commands)
        )

    async def test_snapshot_fails_closed_on_unhealthy_openr_state(self) -> None:
        mutations = (
            ("node_overloaded", True, "node r1 is overloaded"),
            ("node_increment", 5, "metric increment"),
            ("interface_up", [True, False], "interface fboss2012 is down"),
            (
                "interface_overloaded",
                [False, True],
                "interface fboss2012 is overloaded",
            ),
            ("link_increments", [0, 7], "metric increment"),
        )
        for attribute, value, message in mutations:
            with self.subTest(attribute=attribute):
                driver = _OpenrDriver()
                setattr(driver, attribute, value)
                with (
                    patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver),
                    self.assertRaisesRegex(TestCaseFailure, message),
                ):
                    await self._task().run(
                        _base(
                            "snapshot",
                            core_rif_cidrs=[
                                "2001:db8:c0::/127",
                                "2001:db8:c1::/127",
                            ],
                        )
                    )

    async def test_partial_metric_failure_rolls_back_and_releases_ownership(
        self,
    ) -> None:
        driver = _OpenrDriver()
        shared_data = {}
        task = self._task(shared_data)
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver):
            await task.run(
                _base(
                    "snapshot",
                    core_rif_cidrs=["2001:db8:c0::/127", "2001:db8:c1::/127"],
                )
            )
            driver.fail_override_index = 1
            with self.assertRaisesRegex(RuntimeError, "injected"):
                await task.run(_base("set_metrics", metrics=[10, 1000]))

        self.assertEqual(driver.overrides, [None, None])
        self.assertTrue(all(value is None for value in shared_data.values()))

    async def test_failed_first_mutation_does_not_claim_unattempted_later_path(
        self,
    ) -> None:
        driver = _OpenrDriver()
        shared_data = {}
        task = self._task(shared_data)
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver):
            await task.run(
                _base(
                    "snapshot",
                    core_rif_cidrs=["2001:db8:c0::/127", "2001:db8:c1::/127"],
                )
            )
            driver.fail_override_index = 0
            # Model an operator changing the untouched second path to the
            # requested value while the first command fails.
            driver.drift_on_override_failure = (1, 1000)
            with self.assertRaisesRegex(RuntimeError, "injected") as context:
                await task.run(_base("set_metrics", metrics=[10, 1000]))

        notes = getattr(context.exception, "__notes__", [])
        self.assertTrue(any("refusing to clear unowned" in note for note in notes))
        self.assertEqual(driver.overrides, [None, 1000])
        self.assertFalse(all(value is None for value in shared_data.values()))
        self.assertFalse(
            any("clear-adj-metric-override" in command for command in driver.commands)
        )

    async def test_restore_accepts_changed_dynamic_base_metric(self) -> None:
        driver = _OpenrDriver()
        shared_data = {}
        task = self._task(shared_data)
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver):
            await task.run(
                _base(
                    "snapshot",
                    core_rif_cidrs=["2001:db8:c0::/127", "2001:db8:c1::/127"],
                )
            )
            await task.run(_base("set_metrics", metrics=[10, 1000]))
            # Simulate use_rtt_metric changing the legitimate base values while
            # the task-owned overrides are active.
            driver.base_metrics = [23, 27]
            await task.run(_base("restore"))

        self.assertEqual(driver.overrides, [None, None])
        self.assertEqual(driver.base_metrics, [23, 27])
        self.assertTrue(all(value is None for value in shared_data.values()))

    async def test_decision_poll_rejects_non_equal_metric_selected_paths(self) -> None:
        driver = _OpenrDriver()
        task = self._task()
        with (
            patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver),
            patch(_AUDIT_PATH, new_callable=AsyncMock) as audit,
        ):
            await task.run(
                _base(
                    "snapshot",
                    core_rif_cidrs=["2001:db8:c0::/127", "2001:db8:c1::/127"],
                )
            )
            await task.run(_base("set_metrics", metrics=[10, 10]))
            driver.route_metrics = [10, 11]
            with self.assertRaisesRegex(TestCaseFailure, "equal link metrics"):
                await task.run(
                    _base(
                        "assert_routes",
                        path_indices=[0, 1],
                        routes=[{"prefix": "192.0.2.2/32", "client": "OPENR"}],
                        timeout_seconds=0,
                    )
                )

        audit.assert_not_awaited()

    async def test_restore_refuses_unowned_override_drift(self) -> None:
        driver = _OpenrDriver()
        task = self._task()
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver):
            await task.run(
                _base(
                    "snapshot",
                    core_rif_cidrs=["2001:db8:c0::/127", "2001:db8:c1::/127"],
                )
            )
            await task.run(_base("set_metrics", metrics=[10, 1000]))
            driver.overrides[1] = 77
            with self.assertRaisesRegex(TestCaseFailure, "refusing to clear unowned"):
                await task.run(_base("restore"))

        self.assertEqual(driver.overrides, [10, 77])

    async def test_malformed_inputs_fail_before_device_access(self) -> None:
        bad_params = (
            _base(
                "snapshot",
                core_rif_cidrs=["2001:db8:c0::/127", "not-an-address"],
            ),
            _base("set_metrics", metrics=[True, 20]),
            _base(
                "assert_routes",
                path_indices=[0, 0],
                routes=[{"prefix": "192.0.2.2/32", "client": "OPENR"}],
            ),
        )
        for params in bad_params:
            with self.subTest(action=params["action"]):
                with patch(_DRIVER_PATH, new_callable=AsyncMock) as get_driver:
                    with self.assertRaises((ValueError, TestCaseFailure)):
                        await self._task().run(params)
                # set/assert fail for absent ownership before connecting;
                # snapshot validates the CIDRs before connecting.
                get_driver.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
