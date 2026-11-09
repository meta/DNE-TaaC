# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

import ast
import base64
import contextlib
import io
import json
import os
import shlex
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

import later.unittest
from neteng.netcastle.teams.taac.test_case_compiler import TestCaseCompiler
from taac.constants import ARISTA_DAEMON_EXEC_SCRIPTS
from taac.tasks.all import AristaDaemonControlTask
from taac.testconfigs.routing import (
    ixanvl_setup,
    ixanvl_setup_device as device,
)
from taac.test_as_a_config import types as taac_types

EXECS = {name: ARISTA_DAEMON_EXEC_SCRIPTS[name] for name in ixanvl_setup.DAEMONS}
DAEMON_TEXT = "\n".join(
    f"daemon {name}\n   exec {script}\n   no shutdown" for name, script in EXECS.items()
)


def task_params(task: taac_types.Task) -> dict:
    params = task.params
    assert params is not None
    encoded = params.json_params
    assert encoded is not None
    return json.loads(encoded)


class ProfileTest(unittest.TestCase):
    def test_dut_only_post_deploy_setup_and_no_destructive_teardown(self) -> None:
        config = ixanvl_setup.NRQEB010_ASH6_IXANVL_SETUP
        self.assertEqual(config.name, "NRQEB010_ASH6_IXANVL_SETUP")
        self.assertEqual(
            [(e.name, e.dut) for e in config.endpoints], [("nrqeb010.ash6", True)]
        )
        self.assertEqual(
            dict(config.host_os_type_map or {}),
            {"nrqeb010.ash6": taac_types.DeviceOsType.ARISTA_OS},
        )
        self.assertFalse(config.basic_port_configs)
        self.assertFalse(config.basic_traffic_item_configs)
        self.assertFalse(config.teardown_tasks)
        tasks = config.setup_tasks
        assert tasks is not None
        self.assertEqual(config.basset_pool, "routing.qual")
        self.assertEqual(len(tasks), 7)
        for task in tasks:
            self.assertTrue(task.ixia_needed)
            self.assertEqual(task_params(task)["hostname"], "nrqeb010.ash6")
        enables = [task_params(task) for task in tasks[1:-1]]
        self.assertEqual(
            [p["daemon_name"] for p in enables], list(ixanvl_setup.DAEMONS)
        )
        self.assertTrue(all(p["action"] == "enable" for p in enables))
        self.assertEqual(
            [task.task_name for task in tasks],
            [
                "run_commands_on_shell",
                *["arista_daemon_control"] * 5,
                "run_commands_on_shell",
            ],
        )
        for task in (tasks[0], tasks[-1]):
            self.assertTrue(task_params(task)["validate_output"])

    def test_packaged_script_uses_standard_execs_without_launcher_edits(self) -> None:
        for phase in ("prepare", "verify"):
            command = ixanvl_setup.device_command(phase)
            script = base64.b64decode(shlex.split(command)[3]).decode()
            tree = ast.parse(script)
            expression = tree.body[-1]
            assert isinstance(expression, ast.Expr)
            call = expression.value
            assert isinstance(call, ast.Call)
            payload = json.loads(ast.literal_eval(call.args[0]))
            self.assertEqual(payload, {"phase": phase, "daemon_execs": EXECS})
            self.assertIn("def ensure_config", script)
            self.assertNotIn("sed -i", script)
            self.assertNotIn("write memory", script)
        with self.assertRaises(ValueError):
            ixanvl_setup.device_command("enable")

    def test_check_only_playbook_is_discovered_by_netcastle(self) -> None:
        config = ixanvl_setup.NRQEB010_ASH6_IXANVL_SETUP
        cases = TestCaseCompiler(unittest.TestCase).create_test_cases(config)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]._testMethodName, "ixanvl_setup_readiness")
        self.assertEqual(len(config.playbooks[0].stages), 1)
        self.assertEqual(len(config.playbooks[0].stages[0].steps), 1)


class BootstrapTest(unittest.TestCase):
    def test_missing_config_gets_validated_zero_peer_bootstrap(self) -> None:
        with (
            tempfile.TemporaryDirectory() as root,
            patch.object(device, "validate_config") as validate,
        ):
            path = os.path.join(root, "bgpcpp_config")
            device.ensure_config(path, running=False)
            with open(path) as source:
                self.assertEqual(json.load(source), device.BOOTSTRAP)
            self.assertEqual(os.listdir(root), ["bgpcpp_config"])
            self.assertNotEqual(validate.call_args.args[0], path)
            self.assertEqual(device.BOOTSTRAP["peers"], [])
            self.assertEqual(device.BOOTSTRAP["networks4"], [])
            self.assertEqual(device.BOOTSTRAP["networks6"], [])

    def test_existing_valid_config_is_not_rewritten(self) -> None:
        with (
            tempfile.TemporaryDirectory() as root,
            patch.object(device, "_command", return_value="[PASS]"),
        ):
            path = os.path.join(root, "bgpcpp_config")
            with open(path, "w") as target:
                target.write('{"peers": [], "router_id": "1.2.3.4"}\n')
            before = os.stat(path)
            device.ensure_config(path, running=True)
            after = os.stat(path)
            self.assertEqual(
                (before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns)
            )

    def test_existing_invalid_config_is_refused_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "bgpcpp_config")
            with open(path, "w") as target:
                target.write("invalid existing config")
            with self.assertRaises(json.JSONDecodeError):
                device.ensure_config(path, running=False)
            with open(path) as source:
                self.assertEqual(source.read(), "invalid existing config")

    def test_validator_failure_does_not_install_bootstrap(self) -> None:
        with (
            tempfile.TemporaryDirectory() as root,
            patch.object(
                device, "validate_config", side_effect=RuntimeError("invalid bootstrap")
            ),
        ):
            path = os.path.join(root, "bgpcpp_config")
            with self.assertRaisesRegex(RuntimeError, "invalid bootstrap"):
                device.ensure_config(path, running=False)
            self.assertEqual(os.listdir(root), [])

    def test_concurrent_valid_config_writer_is_validated_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "bgpcpp_config")
            config = {**device.BOOTSTRAP, "router_id": "1.2.3.4"}

            def command(argv: list[str]) -> str:
                if argv[-1] != path:
                    with open(path, "w") as target:
                        json.dump(config, target)
                return "[PASS]"

            with patch.object(device, "_command", side_effect=command) as validate:
                device.ensure_config(path, running=False)
            self.assertEqual(validate.call_count, 2)
            self.assertEqual(
                validate.call_args.args[0], [device.VALIDATOR, "--config", path]
            )
            with open(path) as source:
                self.assertEqual(json.load(source), config)
            self.assertEqual(os.listdir(root), ["bgpcpp_config"])

    def test_concurrent_invalid_config_writer_is_refused_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "bgpcpp_config")

            def command(_argv: list[str]) -> str:
                with open(path, "w") as target:
                    target.write("concurrent owner")
                return "[PASS]"

            with (
                patch.object(device, "_command", side_effect=command),
                self.assertRaises(json.JSONDecodeError),
            ):
                device.ensure_config(path, running=False)
            with open(path) as source:
                self.assertEqual(source.read(), "concurrent owner")
            self.assertEqual(os.listdir(root), ["bgpcpp_config"])

    def test_concurrent_symlink_or_directory_is_refused(self) -> None:
        for symlink in (True, False):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as root:
                path = os.path.join(root, "bgpcpp_config")

                def command(
                    _argv: list[str], *, symlink: bool = symlink, path: str = path
                ) -> str:
                    if symlink:
                        os.symlink(os.path.join(root, "elsewhere"), path)
                    else:
                        os.mkdir(path)
                    return "[PASS]"

                with (
                    patch.object(device, "_command", side_effect=command),
                    self.assertRaisesRegex(RuntimeError, "non-regular or symlink"),
                ):
                    device.ensure_config(path, running=False)
                self.assertEqual(os.listdir(root), ["bgpcpp_config"])

    def test_running_daemon_without_config_or_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "bgpcpp_config")
            with self.assertRaisesRegex(RuntimeError, "Running Bgpcpp"):
                device.ensure_config(path, running=True)
            os.symlink(os.path.join(root, "elsewhere"), path)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                device.ensure_config(path, running=False)

    def test_validator_requires_positive_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "config")
            with open(path, "w") as target:
                json.dump(device.BOOTSTRAP, target)
            for output in ("", "unexpected output", "[FAIL]", "[PASS] [ERROR]"):
                with (
                    self.subTest(output=output),
                    patch.object(device, "_command", return_value=output),
                    self.assertRaises(RuntimeError),
                ):
                    device.validate_config(path)


class PreflightTest(unittest.TestCase):
    def test_conflicting_native_or_foreign_daemon_fails_before_bootstrap(self) -> None:
        for daemon, router in (
            ("daemon Bgp\n   exec /usr/sbin/run_bgpcpp.sh", ""),
            ("daemon Bgpcpp\n   exec /usr/sbin/unrelated", ""),
            ("daemon Foreign\n   exec /usr/sbin/run_bgpcpp.sh", ""),
            ("", "router bgp 65000\n   neighbor 1.2.3.4 shutdown"),
            ("", "router bgp 65000\n   vrf blue\n      shutdown"),
        ):
            with (
                self.subTest(daemon=daemon, router=router),
                patch.object(device, "check_inputs"),
                patch.object(device, "_cli", side_effect=[daemon, router]),
                patch.object(device, "ensure_config") as ensure,
                self.assertRaises(RuntimeError),
            ):
                device.prepare(EXECS)
            ensure.assert_not_called()

    def test_standard_daemons_and_shutdown_native_instance_are_accepted(self) -> None:
        configured = device.check_ownership(
            DAEMON_TEXT,
            "router bgp 65000\n   shutdown\n   vrf blue\n      no shutdown",
            EXECS,
        )
        self.assertEqual(configured, set(ixanvl_setup.DAEMONS))

    def test_missing_executable_fails_loudly(self) -> None:
        with (
            patch.object(device.os.path, "isfile", return_value=False),
            self.assertRaisesRegex(RuntimeError, "installed executable missing"),
        ):
            device.check_inputs()

    def test_missing_certificate_reference_is_not_materialized(self) -> None:
        with (
            patch.object(device.os.path, "isfile", return_value=False),
            self.assertRaisesRegex(RuntimeError, "Missing installed input"),
        ):
            device._check_referenced_files(
                {"net_service_config": {"mtls_cert": "/missing.pem"}}
            )

    def test_missing_or_invalid_installed_inputs_name_the_prerequisite(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "fib_agent.conf")
            for contents, expected, cause in (
                (None, "Required installed input unavailable", FileNotFoundError),
                (
                    "not JSON",
                    "Required installed input is not valid JSON",
                    json.JSONDecodeError,
                ),
            ):
                with self.subTest(contents=contents):
                    if contents is not None:
                        with open(path, "w") as target:
                            target.write(contents)
                    with (
                        patch.object(device.os.path, "isfile", return_value=True),
                        patch.object(device.os, "access", return_value=True),
                        patch.object(
                            device.shutil, "which", return_value="/usr/bin/FastCli"
                        ),
                        patch.object(device, "INPUTS", (path,)),
                        patch.object(device, "_command") as command,
                        self.assertRaisesRegex(RuntimeError, expected) as raised,
                    ):
                        device.check_inputs()
                    self.assertIn(path, str(raised.exception))
                    self.assertIsInstance(raised.exception.__cause__, cause)
                    command.assert_not_called()

    def test_mixed_rpm_ownership_is_refused(self) -> None:
        with (
            patch.object(device.os.path, "isfile", return_value=True),
            patch.object(device.os, "access", return_value=True),
            patch.object(device.shutil, "which", return_value="/usr/bin/FastCli"),
            patch.object(device, "INPUTS", ()),
            patch.object(
                device, "_command", return_value="fb-bgpcpp-a\nfb-bgpcpp-b\nfb-bgpcpp-a"
            ),
            self.assertRaisesRegex(RuntimeError, "same installed fb-bgpcpp RPM"),
        ):
            device.check_inputs()

    def test_eos_parser_rejections_are_not_success(self) -> None:
        response = Mock(returncode=0, stdout="% Invalid input", stderr="")
        with (
            patch.object(device.subprocess, "run", return_value=response),
            self.assertRaises(RuntimeError),
        ):
            device._cli("show bgpcpp summary")
        with self.assertRaises(ValueError):
            device._cli("configure terminal")


class ReadinessTest(unittest.TestCase):
    def test_transient_internal_summary_error_is_retried(self) -> None:
        summaries = iter(
            (
                RuntimeError("% Internal error while initializing"),
                "BGP is up for 1 second",
            )
        )

        def cli(command: str, timeout: float = 30) -> str:
            if command == "show running-config section daemon":
                return DAEMON_TEXT
            if command == "show running-config section router bgp":
                return ""
            if command == "show bgpcpp summary":
                result = next(summaries)
                if isinstance(result, RuntimeError):
                    raise result
                return result
            return f"Process: {command.split()[-1]} (running with PID 123)"

        with (
            patch.object(device, "_cli", side_effect=cli),
            patch.object(device.time, "sleep") as sleep,
        ):
            device.verify(EXECS, attempts=2)
        sleep.assert_called_once_with(2)

    def test_summary_authorization_failure_is_not_retried(self) -> None:
        def cli(command: str, timeout: float = 30) -> str:
            if command == "show running-config section daemon":
                return DAEMON_TEXT
            if command == "show running-config section router bgp":
                return ""
            if command == "show bgpcpp summary":
                raise RuntimeError("% Authorization denied")
            return f"Process: {command.split()[-1]} (running with PID 123)"

        with (
            patch.object(device, "_cli", side_effect=cli),
            patch.object(device.time, "sleep") as sleep,
            self.assertRaisesRegex(RuntimeError, "Authorization denied"),
        ):
            device.verify(EXECS, attempts=2)
        sleep.assert_not_called()

    def test_readiness_deadline_bounds_device_queries(self) -> None:
        with (
            patch.object(device.time, "monotonic", side_effect=[0, 3]),
            patch.object(device, "_cli") as cli,
            self.assertRaisesRegex(RuntimeError, "deadline expired"),
        ):
            device.verify(EXECS, attempts=1, delay=2)
        cli.assert_not_called()

    def test_running_state_from_another_daemon_is_not_accepted(self) -> None:
        self.assertFalse(
            device.is_running("Process: Foreign (running with PID 123)", "Bgpcpp")
        )

    def test_waiting_for_fib_5913_is_not_readiness_then_zero_peers_is_valid(
        self,
    ) -> None:
        summaries = iter(
            (
                "Waiting for FibEbbService ::1:5913",
                "BGP is up for 1 second\nPeers: UP - 0, TOTAL - 0",
            )
        )

        def cli(command: str, timeout: float = 30) -> str:
            if command == "show running-config section daemon":
                return DAEMON_TEXT
            if command == "show running-config section router bgp":
                return ""
            if command == "show bgpcpp summary":
                return next(summaries)
            return f"Process: {command.split()[-1]} (running with PID 123)"

        with (
            patch.object(device, "_cli", side_effect=cli),
            patch.object(device.time, "sleep") as sleep,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            device.verify(EXECS, attempts=2)
        sleep.assert_called_once_with(2)
        self.assertIn("IXANVL_READY_OK", output.getvalue())

    def test_missing_or_shutdown_daemon_never_passes(self) -> None:
        def cli(command: str, timeout: float = 30) -> str:
            if command == "show running-config section daemon":
                return DAEMON_TEXT
            if command == "show running-config section router bgp":
                return ""
            return "Process: FibAgentBgp (shutdown with PID 123)"

        with (
            patch.object(device, "_cli", side_effect=cli),
            self.assertRaisesRegex(RuntimeError, "did not become ready"),
        ):
            device.verify(EXECS, attempts=1)
        self.assertFalse(device.is_running("Process: Bgpcpp (shutdown with PID 123)"))
        self.assertTrue(
            device.is_running("Agent: FibGrpc (running with PID 456) uptime 10s")
        )


class StandardDaemonIdempotenceTest(later.unittest.TestCase):
    async def test_missing_daemons_are_enabled_in_canonical_dependency_order(
        self,
    ) -> None:
        enabled: list[str] = []

        async def execute(command: str, configure: bool = False) -> str:
            if configure:
                name = command.splitlines()[0].removeprefix("daemon ")
                self.assertEqual(
                    command, f"daemon {name}\nexec {EXECS[name]}\nno shutdown"
                )
                enabled.append(name)
                return ""
            if command == "show running-config section daemon":
                return "\n".join(
                    f"daemon {name}\n   exec {EXECS[name]}\n   no shutdown"
                    for name in enabled
                )
            name = command.split()[-1]
            state = "running" if name in enabled else "shutdown"
            return f"Process: {name} ({state} with PID 123)"

        driver = Mock()
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        task = AristaDaemonControlTask(logger=Mock())
        with patch(
            "neteng.test_infra.dne.taac.tasks.all.async_get_device_driver",
            new=AsyncMock(return_value=driver),
        ):
            for name in ixanvl_setup.DAEMONS:
                await task.run(
                    {
                        "hostname": "nrqeb010.ash6",
                        "daemon_name": name,
                        "action": "enable",
                    }
                )
        self.assertEqual(
            enabled, ["FibGrpc", "FibBgpGrpc", "FibAgent", "FibAgentBgp", "Bgpcpp"]
        )

    async def test_healthy_five_daemon_chain_has_no_mutating_commands(self) -> None:
        async def execute(command: str, configure: bool = False) -> str:
            self.assertFalse(configure, command)
            if command == "show running-config section daemon":
                return DAEMON_TEXT
            return f"Process: {command.split()[-1]} (running with PID 123)"

        driver = Mock()
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        task = AristaDaemonControlTask(logger=Mock())
        with patch(
            "neteng.test_infra.dne.taac.tasks.all.async_get_device_driver",
            new=AsyncMock(return_value=driver),
        ):
            for name in ixanvl_setup.DAEMONS:
                await task.run(
                    {
                        "hostname": "nrqeb010.ash6",
                        "daemon_name": name,
                        "action": "enable",
                    }
                )
        self.assertTrue(
            driver.async_execute_show_or_configure_cmd_on_shell.await_count >= 10
        )
