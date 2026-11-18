# Copyright (c) Meta Platforms, Inc. and affiliates.

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import io
import os
import shlex
import subprocess
import tempfile
import typing as t
from collections.abc import Iterator
from unittest.mock import AsyncMock, call, MagicMock, patch

from later.unittest import TestCase
from taac.driver.drivers_common import CommandExecutionError
from taac.internal.tasks import (
    eos_compiler_lifecycle_task as lifecycle_module,
)
from taac.internal.tasks.eos_compiler_lifecycle_task import (
    _directory_restore_script,
    _file_kind_script,
    _firewall_restore_script,
    _has_exact_startup_option,
    _parse_directory_state,
    _parse_file_kind,
    _parse_firewall_rules,
    _read_firewall_chain_state,
    _RestorableDirectory,
    _RestorableFirewallChain,
    _RestorableSymlink,
    _running_config_verify_script,
    _symlink_restore_script,
    _validated_firewall_chain_name,
    EosCompilerLifecycleTask,
)


_MODULE = "neteng.test_infra.dne.taac.internal.tasks.eos_compiler_lifecycle_task"
_STATE_GUARD_DAEMONS = [
    "FibGrpc",
    "FibAgent",
    "Bgpcpp",
    "bgpcpp",
    "BgpTcpdump",
]
# patternlint-disable-next-line no-dev-shm-usage
_RIB_POLICY_STATE_PATH = "/dev/shm/bgp_rp_state.txt"


def _physical_params(
    operation_id: str,
    interface: str,
    *,
    aggregate_gbps: int = 100,
    lane_count: int = 2,
) -> dict[str, object]:
    return {
        "action": "physical_apply",
        "hostname": "dut.example.com",
        "operation_id": operation_id,
        "interface": interface,
        "aggregate_gbps": aggregate_gbps,
        "lane_count": lane_count,
        "ipv4_cidrs": ["192.0.2.1/31"],
        "ipv6_cidrs": ["2001:db8::1/127"],
    }


def _readback(interface: str, speed: str = "100g-2") -> str:
    return "\n".join(
        (
            f"interface {interface}",
            f"   speed {speed}",
            "   no switchport",
            "   ip address 192.0.2.1/31",
            "   ipv6 enable",
            "   ipv6 address 2001:db8::1/127",
        )
    )


def _routing_config_params(action: str) -> dict[str, object]:
    params: dict[str, object] = {
        "action": action,
        "hostname": "dut.example.com",
        "operation_id": "routing_config:dut0",
        "destination": "/mnt/flash/bgpcpp_config",
    }
    if action in ("routing_config_install", "routing_config_verify"):
        params["source_path"] = "configerator/raw_configs/test/bgpcpp.json"
    return params


def _routing_component_params(action: str) -> dict[str, object]:
    params: dict[str, object] = {
        "action": action,
        "hostname": "dut.example.com",
        "operation_id": "component:dut0/routing_control_plane",
        "startup_path": "/usr/sbin/run_bgpcpp.sh",
    }
    if action == "routing_component_acknowledge":
        params["daemons"] = [
            {"name": "FibGrpc", "enabled": True, "dependencies": []},
            {"name": "FibBgpGrpc", "enabled": True, "dependencies": []},
            {
                "name": "FibAgent",
                "enabled": True,
                "dependencies": ["FibGrpc"],
            },
            {
                "name": "FibAgentBgp",
                "enabled": True,
                "dependencies": ["FibBgpGrpc"],
            },
            {"name": "Openr", "enabled": False, "dependencies": []},
            {
                "name": "Bgpcpp",
                "enabled": True,
                "dependencies": ["FibAgent", "FibAgentBgp"],
            },
        ]
        params["startup_options"] = [
            {
                "daemon": "Bgpcpp",
                "name": "bgp_resolve_nexthops_from_interface_state",
                "value": "true",
            }
        ]
    return params


def _state_guard_component_params(action: str) -> dict[str, object]:
    params = _routing_component_params(action)
    if action == "routing_component_snapshot":
        params["daemon_names"] = _STATE_GUARD_DAEMONS
    elif action == "routing_component_restore":
        params["force_restart_daemons"] = ["Bgpcpp"]
        params["file_restores"] = [
            {
                "operation_id": "routing_config:dut0",
                "destination": "/mnt/flash/bgpcpp_config",
            },
            {
                "operation_id": "rib_policy_state:dut0",
                "destination": _RIB_POLICY_STATE_PATH,
            },
        ]
    return params


def _file_snapshot_params(operation_id: str, destination: str) -> dict[str, object]:
    return {
        "action": "routing_config_snapshot",
        "hostname": "dut.example.com",
        "operation_id": operation_id,
        "destination": destination,
    }


_OPENR_CONFIG_LINK = "/etc/openr_config"
_SYMLINK_SNAPSHOT_KEY = (
    "__eos_compiler_lifecycle__:routing_config_snapshot:openr_config_link:dut0"
)
_OPENR_CONFIG_TARGET = b"/mnt/flash/openr_config"


def _on_device_script(command: str) -> str | None:
    """The Python an `_on_device_python_command` pipes to the device, if any."""
    if not command.startswith("bash printf '%s' "):
        return None
    return base64.b64decode(shlex.split(command)[3]).decode("utf-8")


def _run_script(script: str) -> str:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exec(compile(script, "<on-device>", "exec"), {})  # noqa: S102
    return stdout.getvalue()


def _symlink_snapshot_params() -> dict[str, object]:
    return {
        "action": "routing_config_snapshot",
        "hostname": "dut.example.com",
        "operation_id": "openr_config_link:dut0",
        "destination": _OPENR_CONFIG_LINK,
        "preserve_symlink": True,
    }


def _symlink_restore_params() -> dict[str, object]:
    return {
        "action": "routing_config_restore",
        "hostname": "dut.example.com",
        "operation_id": "openr_config_link:dut0",
        "destination": _OPENR_CONFIG_LINK,
    }


class EosSymlinkFileStateTest(TestCase):
    """Opted-in file snapshots tell a symlink from a file and from absence."""

    def test_scripts_snapshot_and_restore_a_real_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "openr_config")
            target = os.path.join(root, "flash", "openr_config")
            os.symlink(target, path)
            kind, symlink = _parse_file_kind(_run_script(_file_kind_script(path)), path)
            self.assertEqual("symlink", kind)
            self.assertEqual(
                _RestorableSymlink(
                    target=os.fsencode(target),
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                ),
                symlink,
            )
            assert symlink is not None

            # Setup replaces the link with a regular file; restore must bring
            # back the link itself, not a copy of whatever it pointed at.
            os.unlink(path)
            with open(path, "w") as replaced:
                replaced.write("test config")
            os.chmod(path, 0o600)
            output = _run_script(_symlink_restore_script(path, symlink))

            self.assertEqual("taac-symlink-restored\n", output)
            self.assertTrue(os.path.islink(path))
            self.assertEqual(target, os.readlink(path))
            self.assertEqual([os.path.basename(path)], os.listdir(root))

    def test_scripts_report_absence_and_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "openr_config")
            self.assertEqual(
                ("absent", None),
                _parse_file_kind(_run_script(_file_kind_script(path)), path),
            )
            with open(path, "w") as regular:
                regular.write("config")
            self.assertEqual(
                ("file", None),
                _parse_file_kind(_run_script(_file_kind_script(path)), path),
            )
            os.unlink(path)
            os.mkdir(path)
            with self.assertRaisesRegex(RuntimeError, "expected a file or symlink"):
                _run_script(_file_kind_script(path))

    def test_restore_script_refuses_to_replace_a_directory(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "openr_config")
            os.mkdir(path)
            with self.assertRaises(OSError):
                _run_script(
                    _symlink_restore_script(
                        path,
                        _RestorableSymlink(
                            target=b"/mnt/flash/openr_config",
                            owner_uid=os.getuid(),
                            owner_gid=os.getgid(),
                        ),
                    )
                )
            self.assertTrue(os.path.isdir(path))
            self.assertEqual([os.path.basename(path)], os.listdir(root))

    def test_malformed_file_kind_readback_fails_closed(self) -> None:
        for output in (
            "",
            "taac-file-kind:socket",
            "taac-file-kind:symlink:!!!:0:0",
            "taac-file-kind:symlink::0:0",
            "taac-file-kind:symlink:L2E=:root:0",
        ):
            with self.subTest(output=output):
                with self.assertRaisesRegex(RuntimeError, "file kind readback"):
                    _parse_file_kind(output, _OPENR_CONFIG_LINK)

    async def _snapshot_and_restore(
        self,
        probe_output: str,
        *,
        restore_output: str = "taac-symlink-restored",
    ) -> tuple[MagicMock, dict[object, object]]:
        async def execute(command: str, *, configure: bool = False) -> str:
            script = _on_device_script(command) or ""
            if "taac-file-kind:" in script:
                return f"switch#\n{probe_output}\nswitch#"
            if "taac-symlink-restored" in script:
                return f"switch#\n{restore_output}\nswitch#"
            return ""

        driver = MagicMock()
        driver.async_read_file = AsyncMock(side_effect=AssertionError("no read"))
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        shared_data: dict[object, object] = {}
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data=shared_data,
        )
        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(_symlink_snapshot_params())
            await task.run(_symlink_restore_params())
        return driver, shared_data

    async def test_symlink_restores_as_the_same_link_without_mode_changes(
        self,
    ) -> None:
        encoded_target = base64.b64encode(_OPENR_CONFIG_TARGET).decode("ascii")
        driver, shared_data = await self._snapshot_and_restore(
            f"taac-file-kind:symlink:{encoded_target}:0:0"
        )

        self.assertEqual(
            {
                _SYMLINK_SNAPSHOT_KEY: {
                    "exists": True,
                    "kind": "symlink",
                    "content_base64": "",
                    "link_target_base64": encoded_target,
                    "owner_uid": 0,
                    "owner_gid": 0,
                }
            },
            shared_data,
        )
        driver.async_read_file.assert_not_awaited()
        commands = [
            call_args.args[0]
            for call_args in driver.async_execute_show_or_configure_cmd_on_shell.await_args_list
        ]
        self.assertEqual(2, len(commands))
        restore_script = _on_device_script(commands[1])
        assert restore_script is not None
        self.assertIn(f"target = base64.b64decode({encoded_target!r})", restore_script)
        self.assertIn("owner = (0, 0)", restore_script)
        self.assertIn("os.replace(temporary, path)", restore_script)
        self.assertNotIn("chmod", restore_script)

    async def test_unconfirmed_symlink_restore_fails(self) -> None:
        encoded_target = base64.b64encode(_OPENR_CONFIG_TARGET).decode("ascii")
        with self.assertRaisesRegex(RuntimeError, "symlink restore was not confirmed"):
            await self._snapshot_and_restore(
                f"taac-file-kind:symlink:{encoded_target}:0:0",
                restore_output="Traceback (most recent call last):",
            )

    async def test_absent_path_restores_absence(self) -> None:
        driver, shared_data = await self._snapshot_and_restore("taac-file-kind:absent")

        self.assertEqual(
            {
                _SYMLINK_SNAPSHOT_KEY: {
                    "exists": False,
                    "content_base64": "",
                }
            },
            shared_data,
        )
        driver.async_read_file.assert_not_awaited()
        remove_call = driver.async_execute_show_or_configure_cmd_on_shell.await_args
        assert remove_call is not None
        self.assertEqual(
            "bash sudo rm -f '/etc/openr_config' && sudo test ! -e "
            "'/etc/openr_config' && sudo test ! -L '/etc/openr_config'",
            remove_call.args[0],
        )

    async def test_regular_file_keeps_the_legacy_snapshot_and_its_mode(
        self,
    ) -> None:
        content = b"openr config"

        async def execute(command: str, *, configure: bool = False) -> str:
            script = _on_device_script(command) or ""
            if "taac-file-kind:" in script:
                return "switch#\ntaac-file-kind:file\nswitch#"
            if "stat -c" in command:
                return "switch#\ntaac-file-metadata:644:0:0\nswitch#"
            if "sha256sum" in command:
                return f"{hashlib.sha256(content).hexdigest()}  restore.tmp"
            return ""

        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value=content.decode())
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        shared_data: dict[object, object] = {}
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data=shared_data,
        )
        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(_symlink_snapshot_params())
            await task.run(_symlink_restore_params())

        self.assertEqual(
            {
                _SYMLINK_SNAPSHOT_KEY: {
                    "exists": True,
                    "content_base64": base64.b64encode(content).decode("ascii"),
                    "mode": "644",
                    "owner_uid": 0,
                    "owner_gid": 0,
                }
            },
            shared_data,
        )
        commands = [
            call_args.args[0]
            for call_args in driver.async_execute_show_or_configure_cmd_on_shell.await_args_list
        ]
        self.assertTrue(any("chmod '644'" in command for command in commands))
        self.assertTrue(any("mv -f" in command for command in commands))

    async def test_default_snapshot_does_not_probe_file_kind(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(side_effect=FileNotFoundError)
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(return_value="")
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        params = _symlink_snapshot_params()
        del params["preserve_symlink"]

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(params)

        driver.async_read_file.assert_awaited_once_with(_OPENR_CONFIG_LINK)
        driver.async_execute_show_or_configure_cmd_on_shell.assert_not_awaited()

    async def test_invalid_preserve_symlink_flag_is_rejected(self) -> None:
        params = _symlink_snapshot_params()
        params["preserve_symlink"] = "yes"
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        get_driver = AsyncMock()

        with patch(f"{_MODULE}.async_get_device_driver", get_driver):
            with self.assertRaisesRegex(ValueError, "preserve_symlink must be a bool"):
                await task.run(params)

        get_driver.assert_not_awaited()

    async def test_invalid_symlink_snapshot_fails_before_device_io(self) -> None:
        for snapshot in (
            {"exists": True, "kind": "symlink", "content_base64": ""},
            {
                "exists": True,
                "kind": "symlink",
                "content_base64": "",
                "link_target_base64": "",
                "owner_uid": 0,
                "owner_gid": 0,
            },
            {"exists": True, "kind": "fifo", "content_base64": ""},
        ):
            with self.subTest(snapshot=snapshot):
                task = EosCompilerLifecycleTask(
                    hostname="dut.example.com",
                    logger=MagicMock(),
                    shared_data={_SYMLINK_SNAPSHOT_KEY: snapshot},
                )
                get_driver = AsyncMock()
                with patch(f"{_MODULE}.async_get_device_driver", get_driver):
                    with self.assertRaisesRegex(
                        RuntimeError, "invalid routing-config snapshot"
                    ):
                        await task.run(_symlink_restore_params())
                get_driver.assert_not_awaited()


_HELPER_LINK_OPERATION = "ns:openr_helper_link:nrqeb009.ash6:Port-Channel100308"
_HELPER_SNAPSHOT_KEY = (
    "__eos_compiler_lifecycle__:interface_config_snapshot:" + _HELPER_LINK_OPERATION
)
_MEMBER = "Ethernet3/1/1"
_PORT_CHANNEL = "Port-Channel100308"
_PEER_MEMBER = "Ethernet3/2/1"
_HELPER_BASELINE = {
    _MEMBER: ["description HELPER_BASELINE", "speed 400g-8", "no switchport"],
    _PEER_MEMBER: ["description PEER_BASELINE"],
}


class _FakeEosDevice:
    """Interface sections plus EOS configure sessions, served the way the
    lifecycle task reads and writes them."""

    def __init__(self, sections: dict[str, list[str]]) -> None:
        self.sections = {name: list(lines) for name, lines in sections.items()}
        self.sessions: dict[str, list[str]] = {}
        self.commands: list[str] = []
        self.fastcli: subprocess.CompletedProcess[bytes] | None = None
        self.raw_output: str | None = None

    def running_config(self) -> str:
        lines = ["! Command: show running-config", "!"]
        for name in sorted(self.sections):
            lines.append(f"interface {name}")
            lines.extend(f"   {line}" for line in self.sections[name])
            lines.append("!")
        return "\n".join([*lines, "end"]) + "\n"

    def _run_script(self, script: str) -> str:
        completed = self.fastcli or subprocess.CompletedProcess(
            args=[], returncode=0, stdout=self.running_config().encode(), stderr=b""
        )
        with patch("subprocess.run", return_value=completed):
            return _run_script(script)

    def _commit(self, session: str) -> None:
        current = None
        for line in self.sessions.pop(session):
            if line.startswith("default interface "):
                self.sections[line.removeprefix("default interface ")] = []
            elif line.startswith("no interface "):
                self.sections.pop(line.removeprefix("no interface "), None)
            elif line.startswith("interface "):
                current = line.removeprefix("interface ")
                self.sections.setdefault(current, [])
            else:
                assert current is not None
                self.sections[current].append(line)

    async def execute(self, command: str, *, configure: bool = False) -> str:
        self.commands.append(command)
        script = _on_device_script(command)
        if script is not None:
            return (
                self.raw_output
                if self.raw_output is not None
                else (self._run_script(script))
            )
        lines = command.split("\n")
        assert lines[0] == "enable", command
        verb = lines[1].removeprefix("configure session ")
        if len(lines) > 2:
            assert lines[-1] == "end", command
            self.sessions[verb] = lines[2:-1]
        elif verb.endswith(" commit"):
            self._commit(verb.removesuffix(" commit"))
        elif verb.endswith(" abort"):
            self.sessions.pop(verb.removesuffix(" abort"), None)
        else:
            raise AssertionError(command)
        return ""

    def driver(self) -> MagicMock:
        driver = MagicMock()
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=self.execute
        )
        return driver


def _helper_task(shared_data: dict[object, object]) -> EosCompilerLifecycleTask:
    return EosCompilerLifecycleTask(
        hostname="nrqeb009.ash6",
        logger=MagicMock(),
        shared_data=shared_data,
    )


def _interface_snapshot_params() -> dict[str, object]:
    return {
        "action": "interface_config_snapshot",
        "hostname": "nrqeb009.ash6",
        "operation_id": _HELPER_LINK_OPERATION,
        "interfaces": [
            {"name": _MEMBER, "kind": "physical"},
            {"name": _PORT_CHANNEL, "kind": "port_channel"},
        ],
    }


def _interface_restore_params() -> dict[str, object]:
    return {
        "action": "interface_config_restore",
        "hostname": "nrqeb009.ash6",
        "operation_id": _HELPER_LINK_OPERATION,
    }


def _helper_snapshot_record() -> dict[str, object]:
    return {
        "interfaces": [
            {
                "name": _MEMBER,
                "kind": "physical",
                "exists": True,
                "lines": list(_HELPER_BASELINE[_MEMBER]),
            },
            {
                "name": _PORT_CHANNEL,
                "kind": "port_channel",
                "exists": False,
                "lines": [],
            },
        ]
    }


class EosInterfaceScopedStateTest(TestCase):
    """The helper guard owns only its link's interface sections."""

    async def _run(
        self,
        device: _FakeEosDevice,
        shared_data: dict[object, object],
        *params: dict[str, object],
    ) -> None:
        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=device.driver()),
        ):
            for task_params in params:
                await _helper_task(shared_data).run(task_params)

    async def test_restore_returns_only_the_link_to_its_baseline(self) -> None:
        device = _FakeEosDevice(_HELPER_BASELINE)
        shared_data: dict[object, object] = {}
        await self._run(device, shared_data, _interface_snapshot_params())
        self.assertEqual({_HELPER_SNAPSHOT_KEY: _helper_snapshot_record()}, shared_data)

        # Setup's helper mutation, plus the peer binding's own in-flight change.
        device.sections[_MEMBER] = [
            "description OPENR_STANDALONE_TO_nrqeb008.ash6",
            "mtu 9000",
            "speed 400g-8",
            "no switchport",
            "channel-group 100308 mode active",
        ]
        device.sections[_PORT_CHANNEL] = ["no switchport", "ip address 10.0.0.1/31"]
        device.sections[_PEER_MEMBER] = ["description PEER_IN_FLIGHT"]
        device.commands.clear()
        await self._run(device, shared_data, _interface_restore_params())

        self.assertEqual(
            {
                _MEMBER: _HELPER_BASELINE[_MEMBER],
                _PEER_MEMBER: ["description PEER_IN_FLIGHT"],
            },
            device.sections,
        )
        self.assertEqual({}, device.sessions)
        staged = [
            line
            for command in device.commands
            if command.endswith("\nend")
            for line in command.split("\n")[2:-1]
        ]
        self.assertEqual(
            [
                f"default interface {_MEMBER}",
                f"no interface {_PORT_CHANNEL}",
                f"interface {_MEMBER}",
                *_HELPER_BASELINE[_MEMBER],
            ],
            staged,
        )
        self.assertFalse(
            any(
                "configure replace" in command or _PEER_MEMBER in command
                for command in device.commands
            )
        )

    async def test_repeated_restore_converges_with_fresh_sessions(self) -> None:
        device = _FakeEosDevice(_HELPER_BASELINE)
        shared_data: dict[object, object] = {
            _HELPER_SNAPSHOT_KEY: _helper_snapshot_record()
        }
        device.sections[_PORT_CHANNEL] = ["no switchport"]

        await self._run(
            device,
            shared_data,
            _interface_restore_params(),
            _interface_restore_params(),
        )

        self.assertEqual(_HELPER_BASELINE, device.sections)
        sessions = {
            command.split("\n")[1]
            for command in device.commands
            if command.endswith("\nend")
        }
        self.assertEqual(2, len(sessions))

    async def test_untrustworthy_readback_never_becomes_absence(self) -> None:
        good_payload = base64.b64encode(
            b'{"Ethernet3/1/1": [], "Port-Channel100308": null}'
        )
        for raw_output in (
            "",
            "switch#",
            "Traceback (most recent call last):\n  RuntimeError: boom",
            "% Permission denied",
            "   % Invalid input",
            "taac-interface-readback:not-base64!",
            "taac-interface-readback:" + good_payload.decode()[:-4],
            "taac-interface-readback:" + good_payload.decode() * 2,
            "taac-interface-readback:"
            + good_payload.decode()
            + "\ntaac-interface-readback:"
            + good_payload.decode(),
            "taac-interface-readback:"
            + base64.b64encode(b'{"Ethernet3/1/1": []}').decode(),
        ):
            with self.subTest(raw_output=raw_output):
                device = _FakeEosDevice(_HELPER_BASELINE)
                device.raw_output = raw_output
                shared_data: dict[object, object] = {}
                with self.assertRaisesRegex(RuntimeError, "interface readback"):
                    await self._run(device, shared_data, _interface_snapshot_params())
                self.assertEqual({}, shared_data)

    async def test_incomplete_or_failed_running_config_fails_the_snapshot(
        self,
    ) -> None:
        complete = _FakeEosDevice(_HELPER_BASELINE).running_config().encode()
        for completed, message in (
            (
                subprocess.CompletedProcess([], 1, stdout=complete, stderr=b""),
                "readback failed",
            ),
            (
                subprocess.CompletedProcess([], 0, stdout=complete, stderr=b"denied"),
                "readback failed",
            ),
            (
                subprocess.CompletedProcess(
                    [], 0, stdout=complete.removesuffix(b"end\n"), stderr=b""
                ),
                "incomplete",
            ),
            (
                subprocess.CompletedProcess(
                    [],
                    0,
                    stdout=complete.replace(
                        b"   speed 400g-8\n", b"   speed 400g-8\n      nested\n"
                    ),
                    stderr=b"",
                ),
                "nested config",
            ),
        ):
            with self.subTest(message=message):
                device = _FakeEosDevice(_HELPER_BASELINE)
                device.fastcli = completed
                shared_data: dict[object, object] = {}
                with self.assertRaisesRegex(RuntimeError, message):
                    await self._run(device, shared_data, _interface_snapshot_params())
                self.assertEqual({}, shared_data)

    async def test_missing_physical_member_fails_the_snapshot(self) -> None:
        device = _FakeEosDevice({_PEER_MEMBER: ["description PEER_BASELINE"]})
        shared_data: dict[object, object] = {}

        with self.assertRaisesRegex(RuntimeError, "invalid interface-config snapshot"):
            await self._run(device, shared_data, _interface_snapshot_params())

        self.assertEqual({}, shared_data)

    async def test_unreplayable_baseline_fails_the_snapshot(self) -> None:
        for line in ("daemon Bgpcpp", "router bgp 65000", "exit", "comment"):
            with self.subTest(line=line):
                device = _FakeEosDevice({_MEMBER: [line]})
                shared_data: dict[object, object] = {}
                with self.assertRaisesRegex(
                    RuntimeError, "invalid interface-config snapshot"
                ):
                    await self._run(device, shared_data, _interface_snapshot_params())
                self.assertEqual({}, shared_data)

    async def test_global_commands_behind_allowed_heads_are_rejected(self) -> None:
        for line in (
            "ip route 0.0.0.0/0 10.0.0.1",
            "ip access-list EVIL",
            "ipv6 prefix-list EVIL",
            "logging host 10.0.0.1",
            "lldp run",
            "no ip routing",
        ):
            with self.subTest(line=line):
                record = _helper_snapshot_record()
                interfaces = t.cast(list[dict[str, object]], record["interfaces"])
                interfaces[0]["lines"] = [line]
                with self.assertRaisesRegex(
                    RuntimeError, "invalid interface-config snapshot"
                ):
                    await _helper_task({_HELPER_SNAPSHOT_KEY: record}).run(
                        _interface_restore_params()
                    )

    async def test_existing_snapshot_must_match_the_requested_interfaces(
        self,
    ) -> None:
        record = _helper_snapshot_record()
        interfaces = t.cast(list[dict[str, object]], record["interfaces"])
        record["interfaces"] = interfaces[:1]
        get_driver = AsyncMock()
        with patch(f"{_MODULE}.async_get_device_driver", get_driver):
            with self.assertRaisesRegex(RuntimeError, "different interfaces"):
                await _helper_task({_HELPER_SNAPSHOT_KEY: record}).run(
                    _interface_snapshot_params()
                )
        get_driver.assert_not_awaited()

    async def test_snapshot_targets_must_be_typed_and_unique(self) -> None:
        for interfaces in (
            [_MEMBER, _PORT_CHANNEL],
            [{"name": _MEMBER, "kind": "physical"}] * 2,
            [{"name": "Et3/1/1", "kind": "physical"}],
            [{"name": _PORT_CHANNEL, "kind": "physical"}],
            [{"name": _MEMBER, "kind": "physical", "exists": True}],
            [],
        ):
            with self.subTest(interfaces=interfaces):
                params = _interface_snapshot_params()
                params["interfaces"] = interfaces
                get_driver = AsyncMock()
                with patch(f"{_MODULE}.async_get_device_driver", get_driver):
                    with self.assertRaises(ValueError):
                        await _helper_task({}).run(params)
                get_driver.assert_not_awaited()

    async def test_invalid_snapshot_fails_before_device_io(self) -> None:
        member = {"name": _MEMBER, "kind": "physical", "exists": True, "lines": []}
        for snapshot in (
            {},
            {"interfaces": []},
            {"interfaces": [member], "extra": True},
            {"interfaces": [member, member]},
            {"interfaces": [{**member, "exists": False}]},
            {
                "interfaces": [
                    {
                        "name": _PORT_CHANNEL,
                        "kind": "port_channel",
                        "exists": False,
                        "lines": ["mtu 9000"],
                    }
                ]
            },
            {"interfaces": [{**member, "name": "Ethernet1; reload"}]},
            {"interfaces": [{**member, "kind": "virtual"}]},
            {"interfaces": [{k: v for k, v in member.items() if k != "kind"}]},
            *(
                {"interfaces": [{**member, "lines": [line]}]}
                for line in (
                    "exit",
                    "end",
                    "!",
                    "daemon Bgpcpp",
                    "interface Ethernet9",
                    "no interface Ethernet9",
                    "default interface Ethernet9",
                    "router bgp 1",
                    " description padded",
                    "description a\tb",
                )
            ),
        ):
            with self.subTest(snapshot=snapshot):
                get_driver = AsyncMock()
                with patch(f"{_MODULE}.async_get_device_driver", get_driver):
                    with self.assertRaisesRegex(
                        RuntimeError, "interface-config snapshot"
                    ):
                        await _helper_task({_HELPER_SNAPSHOT_KEY: snapshot}).run(
                            _interface_restore_params()
                        )
                get_driver.assert_not_awaited()

    async def test_cli_error_aborts_the_session(self) -> None:
        device = _FakeEosDevice(_HELPER_BASELINE)
        shared_data: dict[object, object] = {
            _HELPER_SNAPSHOT_KEY: _helper_snapshot_record()
        }
        original = device.execute

        async def execute(command: str, *, configure: bool = False) -> str:
            output = await original(command, configure=configure)
            return "   % Invalid input" if command.endswith("\nend") else output

        device.execute = execute  # type: ignore[method-assign]

        with self.assertRaisesRegex(RuntimeError, "interface restore staging"):
            await self._run(device, shared_data, _interface_restore_params())

        self.assertEqual({}, device.sessions)
        self.assertTrue(device.commands[-1].endswith(" abort"))
        self.assertFalse(
            any(command.endswith(" commit") for command in device.commands)
        )

    async def test_cancelled_restore_aborts_the_session(self) -> None:
        device = _FakeEosDevice(_HELPER_BASELINE)
        shared_data: dict[object, object] = {
            _HELPER_SNAPSHOT_KEY: _helper_snapshot_record()
        }
        original = device.execute

        async def execute(command: str, *, configure: bool = False) -> str:
            output = await original(command, configure=configure)
            if command.endswith("\nend"):
                raise asyncio.CancelledError()
            return output

        device.execute = execute  # type: ignore[method-assign]

        with self.assertRaises(asyncio.CancelledError):
            await self._run(device, shared_data, _interface_restore_params())

        self.assertEqual({}, device.sessions)
        self.assertTrue(device.commands[-1].endswith(" abort"))

    async def test_restore_rejects_readback_drift(self) -> None:
        device = _FakeEosDevice(_HELPER_BASELINE)
        shared_data: dict[object, object] = {
            _HELPER_SNAPSHOT_KEY: _helper_snapshot_record()
        }
        original = device._commit

        def drop_last_line(session: str) -> None:
            original(session)
            device.sections[_MEMBER] = device.sections[_MEMBER][:-1]

        device._commit = drop_last_line  # type: ignore[method-assign]

        with self.assertRaisesRegex(RuntimeError, "interface restore mismatch"):
            await self._run(device, shared_data, _interface_restore_params())


_RESTORE_STAGES = (
    "_quiesce_daemons_for_restore",
    "_restore_file",
    "_restore_component_startup",
    "_configure_replace",
    "_restore_firewall_chain",
    "_restore_directory",
    "_reconcile_daemon_states",
)


class EosRoutingComponentCancellationTest(TestCase):
    """A cancelled DUT restore finishes, bounded, before cancellation leaves."""

    @staticmethod
    def _shared_data() -> dict[object, object]:
        return {
            "__eos_compiler_lifecycle__:routing_component_snapshot:"
            "component:dut0/routing_control_plane": {
                "backup_file": "flash:taac_backup",
                "startup_exists": False,
                "startup_content": "",
                "daemon_states": [{"name": "Bgpcpp", "running": True}],
                "directories": [{"path": "/mnt/fb/certs", "exists": False}],
                "firewall_chains": [
                    {"family": "ipv4", "chain": "EOS_BGP", "exists": False, "rules": []}
                ],
            },
            "__eos_compiler_lifecycle__:routing_config_snapshot:routing_config:dut0": {
                "exists": False,
                "content_base64": "",
            },
        }

    @staticmethod
    def _params() -> dict[str, object]:
        params = _routing_component_params("routing_component_restore")
        params["force_restart_daemons"] = ["Bgpcpp"]
        params["file_restores"] = [
            {
                "operation_id": "routing_config:dut0",
                "destination": "/mnt/flash/bgpcpp_config",
            }
        ]
        return params

    async def _restore(
        self,
        stage_effects: dict[str, list[BaseException | None]],
        *,
        overrides: dict[str, t.Callable[..., t.Awaitable[None]]] | None = None,
        recovery_seconds: float = 5,
    ) -> tuple[list[str], AsyncMock, BaseException | None]:
        events: list[str] = []

        def stage(name: str) -> AsyncMock:
            effects = list(stage_effects.get(name, ()))

            async def run(*args: object, **kwargs: object) -> None:
                events.append(name)
                effect = effects.pop(0) if effects else None
                if isinstance(effect, BaseException):
                    raise effect

            return AsyncMock(side_effect=run)

        delete_backup = AsyncMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data=self._shared_data(),
        )
        raised: BaseException | None = None
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch(f"{_MODULE}.async_get_device_driver", AsyncMock())
            )
            stack.enter_context(
                patch(f"{_MODULE}.arista_utils.delete_backup_config", delete_backup)
            )
            stack.enter_context(
                patch.object(
                    lifecycle_module,
                    "_CANCELLED_RESTORE_RECOVERY_SECONDS",
                    recovery_seconds,
                )
            )
            for name in _RESTORE_STAGES:
                replacement = (overrides or {}).get(name) or stage(name)
                stack.enter_context(patch(f"{_MODULE}.{name}", replacement))
            try:
                await task.run(self._params())
            except (asyncio.CancelledError, Exception) as error:
                raised = error
        return events, delete_backup, raised

    async def test_cancellation_at_each_stage_reruns_the_whole_restore(self) -> None:
        for index, stage in enumerate(_RESTORE_STAGES):
            with self.subTest(stage=stage):
                events, delete_backup, raised = await self._restore(
                    {stage: [asyncio.CancelledError()]}
                )
                self.assertIsInstance(raised, asyncio.CancelledError)
                self.assertEqual(
                    [*_RESTORE_STAGES[: index + 1], *_RESTORE_STAGES], events
                )
                delete_backup.assert_awaited_once()

    async def test_failed_recovery_retains_the_backup(self) -> None:
        events, delete_backup, raised = await self._restore(
            {
                "_configure_replace": [
                    asyncio.CancelledError(),
                    RuntimeError("replace failed"),
                ]
            }
        )

        self.assertIsInstance(raised, asyncio.CancelledError)
        assert raised is not None
        self.assertIn("restore recovery failed", raised.__notes__[-1])
        self.assertTrue(
            any("restore recovery wait failed" in note for note in raised.__notes__)
        )
        delete_backup.assert_not_awaited()
        # The failed rerun still brings daemons back to their snapshot state.
        self.assertEqual("_reconcile_daemon_states", events[-1])

    async def test_recovery_is_bounded_and_retains_the_backup(self) -> None:
        hang = asyncio.Event()
        calls = 0

        async def quiesce(*args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise asyncio.CancelledError()
            await hang.wait()

        _, delete_backup, raised = await self._restore(
            {},
            overrides={"_quiesce_daemons_for_restore": quiesce},
            recovery_seconds=0.05,
        )

        self.assertIsInstance(raised, asyncio.CancelledError)
        assert raised is not None
        self.assertIn("did not finish", raised.__notes__[-1])
        delete_backup.assert_not_awaited()

    async def test_repeated_cancellation_waits_for_recovery(self) -> None:
        started = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def startup(*args: object, **kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise asyncio.CancelledError()
            started.set()
            await release.wait()

        restore = asyncio.create_task(
            self._restore({}, overrides={"_restore_component_startup": startup})
        )
        await started.wait()
        restore.cancel()
        await asyncio.sleep(0)
        self.assertFalse(restore.done())
        release.set()
        events, delete_backup, raised = await restore

        self.assertIsInstance(raised, asyncio.CancelledError)
        self.assertEqual("_reconcile_daemon_states", events[-1])
        delete_backup.assert_awaited_once()


class EosVerifiedConfigureReplaceTest(TestCase):
    def test_verify_script_compares_statements_with_the_backup(self) -> None:
        running = (
            "> show running-config\n"
            "! Command: show running-config\n! device: dut\nhostname dut\n!\nend\n"
        )
        for backup, expected in (
            ("! saved 2026\nhostname dut\n!\nend\n", "verified"),
            ("hostname other\n!\nend\n", "differs"),
            ("hostname dut\n", "incomplete"),
        ):
            with self.subTest(backup=backup), tempfile.TemporaryDirectory() as root:
                path = os.path.join(root, "taac_backup")
                with open(path, "w") as saved:
                    saved.write(backup)
                script = _running_config_verify_script(path)
                completed = subprocess.CompletedProcess(
                    [], 0, stdout=running.encode(), stderr=b""
                )
                with patch("subprocess.run", return_value=completed):
                    if expected == "verified":
                        self.assertEqual(
                            "taac-running-config-verified\n", _run_script(script)
                        )
                    else:
                        with self.assertRaisesRegex(RuntimeError, expected):
                            _run_script(script)

    async def test_replace_requires_cli_success_and_equivalence(self) -> None:
        for replace_output, verify_output, error in (
            ("", "taac-running-config-verified", None),
            ("% Invalid input", "taac-running-config-verified", "configure replace"),
            ("", "Traceback (most recent call last):", "not verified"),
        ):
            with self.subTest(replace_output=replace_output, verify=verify_output):
                commands: list[str] = []

                async def execute(
                    command: str,
                    *,
                    configure: bool = False,
                    replace_output: str = replace_output,
                    verify_output: str = verify_output,
                    commands: list[str] = commands,
                ) -> str:
                    commands.append(command)
                    return (
                        verify_output
                        if _on_device_script(command) is not None
                        else replace_output
                    )

                driver = MagicMock()
                driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
                    side_effect=execute
                )
                if error is None:
                    await lifecycle_module._configure_replace(
                        driver, "flash:taac_backup_1"
                    )
                else:
                    with self.assertRaisesRegex(RuntimeError, error):
                        await lifecycle_module._configure_replace(
                            driver, "flash:taac_backup_1"
                        )
                self.assertEqual(
                    "enable\nconfigure replace flash:taac_backup_1", commands[0]
                )
                self.assertEqual(
                    1 if error == "configure replace" else 2, len(commands)
                )
                if len(commands) == 2:
                    script = _on_device_script(commands[1])
                    assert script is not None
                    self.assertIn("/mnt/flash/taac_backup_1", script)

    async def test_replace_rejects_unsupported_backup_names(self) -> None:
        driver = MagicMock()
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock()
        for backup in ("taac_backup", "flash:", "flash:../x", "flash:a b"):
            with self.subTest(backup=backup):
                with self.assertRaisesRegex(RuntimeError, "unsupported"):
                    await lifecycle_module._configure_replace(driver, backup)
        driver.async_execute_show_or_configure_cmd_on_shell.assert_not_awaited()


_COMPONENT_KEY = "__eos_compiler_lifecycle__:routing_component_snapshot:ns:component"
_FILE_KEY = "__eos_compiler_lifecycle__:routing_config_snapshot:ns:file"


class EosStateGuardArmTest(TestCase):
    @staticmethod
    def _arm_params(*snapshots: dict[str, object]) -> dict[str, object]:
        return {
            "action": "state_guard_arm",
            "hostname": "nrqeb008.ash6",
            "operation_id": "ns:armed",
            "snapshots": list(snapshots),
        }

    @staticmethod
    def _snapshots() -> tuple[dict[str, object], ...]:
        return (
            {"kind": "routing_component", "operation_id": "ns:component"},
            {
                "kind": "routing_config",
                "operation_id": "ns:file",
                "destination": "/mnt/flash/openr_config",
            },
            {"kind": "interface_config", "operation_id": _HELPER_LINK_OPERATION},
        )

    @staticmethod
    def _shared_data() -> dict[object, object]:
        return {
            _COMPONENT_KEY: {
                "backup_file": "flash:taac_backup",
                "startup_exists": False,
                "startup_content": "",
            },
            _FILE_KEY: {"exists": False, "content_base64": ""},
            _HELPER_SNAPSHOT_KEY: _helper_snapshot_record(),
        }

    async def test_arms_only_when_every_snapshot_is_valid(self) -> None:
        get_driver = AsyncMock()
        with patch(f"{_MODULE}.async_get_device_driver", get_driver):
            await _helper_task(self._shared_data()).run(
                self._arm_params(*self._snapshots())
            )
            for key, broken in (
                (_HELPER_SNAPSHOT_KEY, None),
                (_HELPER_SNAPSHOT_KEY, {}),
                (_HELPER_SNAPSHOT_KEY, {"interfaces": []}),
                (_FILE_KEY, {"exists": False, "content_base64": "eA=="}),
                (_FILE_KEY, {"exists": True, "content_base64": ""}),
                (_COMPONENT_KEY, {}),
            ):
                with self.subTest(key=key, broken=broken):
                    shared_data = self._shared_data()
                    if broken is None:
                        del shared_data[key]
                    else:
                        shared_data[key] = broken
                    with self.assertRaisesRegex(RuntimeError, "cannot arm"):
                        await _helper_task(shared_data).run(
                            self._arm_params(*self._snapshots())
                        )
        get_driver.assert_not_awaited()

    async def test_rejects_malformed_manifests(self) -> None:
        component, _, interface = self._snapshots()
        cases: tuple[tuple[dict[str, object], ...], ...] = (
            (),
            ({"kind": "physical", "operation_id": "ns:x"},),
            ({"kind": "routing_config", "operation_id": "ns:file"},),
            ({**component, "destination": "/tmp/x"},),
            (interface, interface),
            ({"kind": ["routing_component"], "operation_id": "ns:component"},),
        )
        for snapshots in cases:
            with self.subTest(snapshots=snapshots):
                with self.assertRaises(ValueError):
                    await _helper_task(self._shared_data()).run(
                        self._arm_params(*snapshots)
                    )


class EosCompilerLifecycleTaskTest(TestCase):
    def test_directory_state_preserves_presence_and_metadata(self) -> None:
        self.assertEqual(
            _RestorableDirectory(
                path="/mnt/fb/certs",
                exists=True,
                metadata=("750", 42, 43),
            ),
            _parse_directory_state(
                "switch#\ntaac-directory-state:present:750:42:43\nswitch#",
                "/mnt/fb/certs",
            ),
        )
        self.assertEqual(
            _RestorableDirectory(
                path="/mnt/fb/certs",
                exists=False,
                metadata=None,
            ),
            _parse_directory_state(
                "taac-directory-state:absent",
                "/mnt/fb/certs",
            ),
        )

    def test_firewall_state_requires_exact_chain_rules(self) -> None:
        self.assertEqual(
            (
                "-N EOS_BGP",
                "-A EOS_BGP -s 192.0.2.0/24 -j DROP",
                "-A EOS_BGP -j ACCEPT",
            ),
            _parse_firewall_rules(
                "\n".join(
                    (
                        "-N EOS_BGP",
                        "-A EOS_BGP -s 192.0.2.0/24 -j DROP",
                        "-A EOS_BGP -j ACCEPT",
                    )
                ),
                "EOS_BGP",
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "malformed"):
            _parse_firewall_rules("-A OTHER -j ACCEPT", "EOS_BGP")

    def test_firewall_chain_rejects_leading_option_marker(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported characters"):
            _validated_firewall_chain_name("--wait")

    async def test_firewall_snapshot_records_explicit_missing_chain(self) -> None:
        run_shell = AsyncMock(
            side_effect=CommandExecutionError(
                "iptables: No chain/target/match by that name."
            )
        )

        with patch(f"{_MODULE}._run_shell", run_shell):
            state = await _read_firewall_chain_state(MagicMock(), "ipv4", "EOS_BGP")

        self.assertEqual(
            state,
            _RestorableFirewallChain(
                family="ipv4",
                chain="EOS_BGP",
                exists=False,
                rules=(),
            ),
        )
        run_shell.assert_awaited_once()

    async def test_firewall_snapshot_propagates_transient_query_error(self) -> None:
        run_shell = AsyncMock(
            side_effect=CommandExecutionError(
                "Another app is currently holding the xtables lock"
            )
        )

        with (
            patch(f"{_MODULE}._run_shell", run_shell),
            self.assertRaisesRegex(CommandExecutionError, "xtables lock"),
        ):
            await _read_firewall_chain_state(MagicMock(), "ipv4", "EOS_BGP")

        run_shell.assert_awaited_once()

    def test_firewall_restore_script_replays_and_verifies_saved_rules(self) -> None:
        script = _firewall_restore_script(
            _RestorableFirewallChain(
                family="ipv6",
                chain="EOS_BGP",
                exists=True,
                rules=("-N EOS_BGP", "-A EOS_BGP -j DROP"),
            )
        )

        self.assertIn("binary = '/sbin/ip6tables'", script)
        self.assertIn("run([binary, '-F', chain])", script)
        self.assertIn("run([binary, *tokens])", script)
        self.assertIn("line.strip()", script)
        self.assertIn(
            "for line in run([binary, '-S', chain]).stdout.splitlines()",
            script,
        )
        self.assertIn("firewall restore mismatch", script)
        self.assertIn("snapshot owns only the chain's rules", script)

    def test_absent_firewall_restore_removes_inbound_references(self) -> None:
        script = _firewall_restore_script(
            _RestorableFirewallChain(
                family="ipv4",
                chain="EOS_BGP",
                exists=False,
                rules=(),
            )
        )

        self.assertIn("{'-j', '--jump', '-g', '--goto'}", script)
        self.assertIn("run([binary, '-D', *tokens[1:]])", script)
        self.assertIn("belongs to the test state being rolled back", script)
        self.assertLess(script.index("'-D'"), script.index("'-X'"))

    def test_absent_directory_restore_unlinks_symlinks(self) -> None:
        script = _directory_restore_script(
            _RestorableDirectory(
                path="/mnt/fb/certs",
                exists=False,
                metadata=None,
            )
        )

        self.assertIn("if path.is_symlink():", script)
        self.assertIn("path.unlink()", script)
        self.assertIn("Fail closed on unexpected contents", script)
        self.assertLess(script.index("path.unlink()"), script.index("path.rmdir()"))

    def test_startup_option_rejects_space_separated_value(self) -> None:
        self.assertFalse(
            _has_exact_startup_option(
                "--bgp_resolve_nexthops_from_interface_state true",
                "bgp_resolve_nexthops_from_interface_state",
                "true",
            )
        )

    def test_startup_option_rejects_bare_flag_followed_by_flag(self) -> None:
        self.assertFalse(
            _has_exact_startup_option(
                "--bgp_resolve_nexthops_from_interface_state --verbose",
                "bgp_resolve_nexthops_from_interface_state",
                "--verbose",
            )
        )

    async def test_physical_apply_captures_once_and_verifies_exact_readback(
        self,
    ) -> None:
        driver = MagicMock()
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=("", _readback("Ethernet1"), "", _readback("Ethernet1"))
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        params = _physical_params(
            "physical_interface:dut0/reuse_group/ebgp", "Ethernet1"
        )

        with (
            patch(f"{_MODULE}.async_get_device_driver", AsyncMock(return_value=driver)),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(return_value="flash:taac-original"),
            ) as save_running_config,
        ):
            await task.run(params)
            await task.run(params)

        save_running_config.assert_awaited_once_with(
            driver,
            backup_name=None,
            logger_instance=task.logger,
        )
        configure_call = (
            driver.async_execute_show_or_configure_cmd_on_shell.await_args_list[0]
        )
        command = configure_call.args[0]
        self.assertIn("default interface Ethernet1", command)
        self.assertIn("speed 100g-2", command)
        self.assertIn("ip address 192.0.2.1/31", command)
        self.assertIn("ipv6 address 2001:db8::1/127", command)
        self.assertTrue(configure_call.kwargs["configure"])

    async def test_physical_apply_rejects_readback_drift(self) -> None:
        driver = MagicMock()
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=("", "interface Ethernet1\n   speed 400g-8")
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        with (
            patch(f"{_MODULE}.async_get_device_driver", AsyncMock(return_value=driver)),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(return_value="flash:taac-original"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "exact readback"):
                await task.run(
                    _physical_params(
                        "physical_interface:dut0/reuse_group/ebgp",
                        "Ethernet1",
                    )
                )

    async def test_physical_restore_unwinds_snapshots_in_declared_order(self) -> None:
        driver = MagicMock()

        async def execute(command: str, *, configure: bool = False) -> str:
            if configure:
                return ""
            interface = "Ethernet2" if "Ethernet2" in command else "Ethernet1"
            return _readback(interface)

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        shared_data: dict[object, object] = {}
        logger = MagicMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=logger,
            shared_data=shared_data,
        )
        first_id = "physical_interface:dut0/reuse_group/first"
        second_id = "physical_interface:dut0/reuse_group/second"
        restore = AsyncMock()
        delete = AsyncMock()

        with (
            patch(f"{_MODULE}.async_get_device_driver", AsyncMock(return_value=driver)),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(side_effect=("flash:first", "flash:second")),
            ),
            patch(
                f"{_MODULE}.arista_utils.restore_running_config",
                restore,
            ),
            patch(
                f"{_MODULE}.arista_utils.delete_backup_config",
                delete,
            ),
        ):
            await task.run(_physical_params(first_id, "Ethernet1"))
            await task.run(_physical_params(second_id, "Ethernet2"))
            await task.run(
                {
                    "action": "physical_restore",
                    "hostname": "dut.example.com",
                    "operations": [
                        {"operation_id": second_id, "interface": "Ethernet2"},
                        {"operation_id": first_id, "interface": "Ethernet1"},
                    ],
                }
            )

        self.assertEqual(
            [
                call(driver, "flash:second", logger_instance=task.logger),
                call(driver, "flash:first", logger_instance=task.logger),
            ],
            restore.await_args_list,
        )
        self.assertEqual(2, delete.await_count)

    async def test_routing_config_restores_prior_absence(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(side_effect=FileNotFoundError)
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(return_value="")
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(_routing_config_params("routing_config_snapshot"))
            await task.run(_routing_config_params("routing_config_restore"))

        remove_call = driver.async_execute_show_or_configure_cmd_on_shell.await_args
        assert remove_call is not None
        self.assertEqual(
            "bash sudo rm -f '/mnt/flash/bgpcpp_config' && sudo test ! -e "
            "'/mnt/flash/bgpcpp_config' && sudo test ! -L "
            "'/mnt/flash/bgpcpp_config'",
            remove_call.args[0],
        )

    async def test_routing_config_snapshot_reports_transport_failure(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(
            side_effect=CommandExecutionError("transport failed")
        )
        shared_data: dict[object, object] = {}
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data=shared_data,
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "snapshot failed before install: unable to read ",
            ):
                await task.run(_routing_config_params("routing_config_snapshot"))

        self.assertEqual({}, shared_data)

    async def test_routing_config_restore_without_snapshot_fails_loudly(
        self,
    ) -> None:
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        get_driver = AsyncMock()

        with patch(f"{_MODULE}.async_get_device_driver", get_driver):
            with self.assertRaisesRegex(
                RuntimeError,
                "restore invoked without snapshot for routing_config:dut0",
            ):
                await task.run(_routing_config_params("routing_config_restore"))

        get_driver.assert_not_awaited()

    async def test_routing_config_install_uses_configerator_and_typed_overrides(
        self,
    ) -> None:
        source = '{"1":{"rec":{"5":{"i32":1},"36":{"i32":1000}}}}\n'
        expected = '{"1":{"rec":{"5":{"i32":1},"36":{"i32":60000}}}}\n'
        driver = MagicMock()
        driver.async_read_file = AsyncMock(side_effect=("old config", expected))

        async def execute(command: str, *, configure: bool = False) -> str:
            if "stat -c" in command:
                return "taac-file-metadata:640:42:43"
            if "sha256sum" in command:
                return f"{hashlib.sha256(expected.encode()).hexdigest()}  install.tmp"
            return ""

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        logger = MagicMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=logger,
            shared_data={},
        )
        client = MagicMock()
        client.__enter__.return_value.get_config_contents.return_value = source
        params = _routing_config_params("routing_config_install")
        params["json_i32_overrides"] = [
            {"path": ["1", "rec", "36", "i32"], "value": 60_000}
        ]

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(f"{_MODULE}.ConfigeratorClient", return_value=client),
        ):
            await task.run(params)

        client.__enter__.return_value.get_config_contents.assert_called_once_with(
            "configerator/raw_configs/test/bgpcpp.json"
        )
        commands = tuple(
            item.args[0]
            for item in driver.async_execute_show_or_configure_cmd_on_shell.await_args_list
        )
        encoded_expected = base64.b64encode(expected.encode()).decode("ascii")
        self.assertTrue(any(encoded_expected in command for command in commands))
        self.assertTrue(any("chown +42:+43" in command for command in commands))
        self.assertTrue(any("chmod '640'" in command for command in commands))
        self.assertTrue(any("mv -f" in command for command in commands))
        logger.info.assert_called_once()

    async def test_routing_config_install_rejects_invalid_override_before_io(
        self,
    ) -> None:
        get_driver = AsyncMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        params = _routing_config_params("routing_config_install")
        params["json_i32_overrides"] = [
            {"path": ["1", "rec", "36", "i32"], "value": True}
        ]

        with patch(f"{_MODULE}.async_get_device_driver", get_driver):
            with self.assertRaisesRegex(ValueError, "signed i32"):
                await task.run(params)

        get_driver.assert_not_awaited()

    async def test_routing_config_install_rejects_missing_override_path_before_io(
        self,
    ) -> None:
        get_driver = AsyncMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        client = MagicMock()
        client.__enter__.return_value.get_config_contents.return_value = (
            '{"1":{"rec":{}}}\n'
        )
        params = _routing_config_params("routing_config_install")
        params["json_i32_overrides"] = [
            {"path": ["1", "rec", "36", "i32"], "value": 60_000}
        ]

        with (
            patch(f"{_MODULE}.async_get_device_driver", get_driver),
            patch(f"{_MODULE}.ConfigeratorClient", return_value=client),
        ):
            with self.assertRaisesRegex(ValueError, "missing path component"):
                await task.run(params)

        get_driver.assert_not_awaited()

    async def test_routing_config_install_rejects_malformed_source_before_device_io(
        self,
    ) -> None:
        get_driver = AsyncMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        client = MagicMock()
        client.__enter__.return_value.get_config_contents.return_value = "not-json"
        params = _routing_config_params("routing_config_install")
        params["json_i32_overrides"] = [
            {"path": ["1", "rec", "36", "i32"], "value": 60_000}
        ]

        with (
            patch(f"{_MODULE}.async_get_device_driver", get_driver),
            patch(f"{_MODULE}.ConfigeratorClient", return_value=client),
        ):
            with self.assertRaisesRegex(ValueError, "valid JSON"):
                await task.run(params)

        get_driver.assert_not_awaited()

    async def test_routing_config_verifies_source_and_restores_prior_bytes(
        self,
    ) -> None:
        prior_bytes: bytes = b"prior\xffbytes"
        driver = MagicMock()
        driver.async_read_file = AsyncMock(
            side_effect=(
                prior_bytes.decode("utf-8", errors="surrogateescape"),
                "new bytes",
            )
        )

        async def execute(command: str, *, configure: bool = False) -> str:
            if "stat -c" in command:
                return "switch#\n10:23:45\ntaac-file-metadata:640:42:43\nswitch#"
            if "sha256sum" in command:
                return (
                    "switch#\n"
                    f"{hashlib.sha256(prior_bytes).hexdigest()}  restore.tmp\n"
                    "switch#"
                )
            return ""

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        shared_data: dict[object, object] = {}
        logger = MagicMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=logger,
            shared_data=shared_data,
        )
        client = MagicMock()
        client.__enter__.return_value.get_config_contents.return_value = "new bytes"

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(f"{_MODULE}.ConfigeratorClient", return_value=client),
        ):
            await task.run(_routing_config_params("routing_config_snapshot"))
            await task.run(_routing_config_params("routing_config_verify"))
            await task.run(_routing_config_params("routing_config_restore"))

        commands = tuple(
            item.args[0]
            for item in driver.async_execute_show_or_configure_cmd_on_shell.await_args_list
        )
        self.assertTrue(any("base64 -d" in command for command in commands))
        self.assertTrue(any("sha256sum" in command for command in commands))
        self.assertTrue(any("chown +42:+43" in command for command in commands))
        self.assertTrue(any("chmod '640'" in command for command in commands))
        self.assertTrue(any("mv -f" in command for command in commands))
        encoded_prior_bytes = base64.b64encode(prior_bytes).decode("ascii")
        self.assertTrue(any(encoded_prior_bytes in command for command in commands))
        self.assertTrue(
            all("/mnt/flash/bgpcpp_config" in command for command in commands)
        )
        logger.info.assert_any_call(
            "Verified exact Configerator routing artifact bytes"
        )
        logger.info.assert_any_call(
            "EOS routing-config snapshot /mnt/flash/bgpcpp_config: "
            "mode=640, uid=42, gid=43"
        )

    async def test_routing_config_rejects_exact_readback_drift(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value="unexpected")
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        client = MagicMock()
        client.__enter__.return_value.get_config_contents.return_value = "expected"

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(f"{_MODULE}.ConfigeratorClient", return_value=client),
        ):
            with self.assertRaisesRegex(RuntimeError, "exact readback"):
                await task.run(_routing_config_params("routing_config_verify"))

    async def test_routing_config_reports_missing_installed_file(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(side_effect=FileNotFoundError)
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        client = MagicMock()
        client.__enter__.return_value.get_config_contents.return_value = "expected"

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(f"{_MODULE}.ConfigeratorClient", return_value=client),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "installed file missing at /mnt/flash/bgpcpp_config",
            ):
                await task.run(_routing_config_params("routing_config_verify"))

    async def test_routing_config_restore_rejects_metadata_drift(self) -> None:
        expected = ("644", 11420360, 88)
        for label, actual in (
            ("mode", ("600", 11420360, 88)),
            ("uid", ("644", 80556623, 88)),
            ("gid", ("644", 11420360, 88088)),
        ):
            with self.subTest(field=label):
                metadata_reads = iter((expected, actual))
                driver = MagicMock()
                driver.async_read_file = AsyncMock(return_value="prior bytes")

                async def execute(
                    command: str,
                    *,
                    configure: bool = False,
                    metadata_values: Iterator[tuple[str, int, int]] = metadata_reads,
                ) -> str:
                    if "stat -c" in command:
                        mode, uid, gid = next(metadata_values)
                        return f"taac-file-metadata:{mode}:{uid}:{gid}"
                    if "sha256sum" in command:
                        return hashlib.sha256(b"prior bytes").hexdigest()
                    return ""

                driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
                    side_effect=execute
                )
                logger = MagicMock()
                task = EosCompilerLifecycleTask(
                    hostname="dut.example.com", logger=logger, shared_data={}
                )
                with patch(
                    f"{_MODULE}.async_get_device_driver", AsyncMock(return_value=driver)
                ):
                    await task.run(_routing_config_params("routing_config_snapshot"))
                    with self.assertRaisesRegex(
                        RuntimeError, "restored file metadata mismatch"
                    ) as context:
                        await task.run(_routing_config_params("routing_config_restore"))

                self.assertIn(f"expected={expected}", str(context.exception))
                self.assertIn(f"actual={actual}", str(context.exception))
                logger.info.assert_any_call(
                    "EOS restored file /mnt/flash/bgpcpp_config: "
                    f"expected_metadata={expected}, actual_metadata={actual}"
                )

    async def test_routing_config_restore_rejects_malformed_checksum_output(
        self,
    ) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value="prior bytes")

        async def execute(command: str, *, configure: bool = False) -> str:
            return "taac-file-metadata:640:42:43" if "stat -c" in command else ""

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(_routing_config_params("routing_config_snapshot"))
            with self.assertRaisesRegex(RuntimeError, "checksum output is malformed"):
                await task.run(_routing_config_params("routing_config_restore"))

        commands = tuple(
            item.args[0]
            for item in driver.async_execute_show_or_configure_cmd_on_shell.await_args_list
        )
        self.assertTrue(any("rm -f" in command for command in commands))

    async def test_routing_config_restore_logs_scratch_cleanup_failure(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value="prior bytes")

        async def execute(command: str, *, configure: bool = False) -> str:
            if "stat -c" in command:
                return "taac-file-metadata:640:42:43"
            if "sha256sum" in command:
                return hashlib.sha256(b"prior bytes").hexdigest()
            if "rm -f" in command:
                raise RuntimeError("scratch cleanup failed")
            return ""

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        logger = MagicMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=logger,
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(_routing_config_params("routing_config_snapshot"))
            await task.run(_routing_config_params("routing_config_restore"))

        logger.warning.assert_called_once()

    async def test_restore_failure_preserves_cleanup_failure_note(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value="prior bytes")

        async def execute(command: str, *, configure: bool = False) -> str:
            if "stat -c" in command:
                return "taac-file-metadata:640:42:43"
            if "base64 -d" in command:
                raise RuntimeError("primary restore failed")
            if "rm -f" in command:
                raise RuntimeError("scratch cleanup failed")
            return ""

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(_routing_config_params("routing_config_snapshot"))
            with self.assertRaisesRegex(
                RuntimeError, "primary restore failed"
            ) as context:
                await task.run(_routing_config_params("routing_config_restore"))

        self.assertIn(
            "restore cleanup also failed: scratch cleanup failed",
            context.exception.__notes__,
        )

    async def test_routing_config_restore_retries_checksum_mismatch(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value="prior bytes")
        checksum_attempts = 0

        async def execute(command: str, *, configure: bool = False) -> str:
            nonlocal checksum_attempts
            if "stat -c" in command:
                return "taac-file-metadata:640:42:43"
            if "sha256sum" in command:
                checksum_attempts += 1
                if checksum_attempts == 1:
                    return "0" * 64
                return hashlib.sha256(b"prior bytes").hexdigest()
            return ""

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        logger = MagicMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=logger,
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(_routing_config_params("routing_config_snapshot"))
            await task.run(_routing_config_params("routing_config_restore"))

        # Two staging attempts, then one exact post-install verification.
        self.assertEqual(3, checksum_attempts)
        logger.warning.assert_called_once()

    async def test_routing_config_rejects_parent_path_components(self) -> None:
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        get_driver = AsyncMock()

        with patch(f"{_MODULE}.async_get_device_driver", get_driver):
            snapshot_params = _routing_config_params("routing_config_snapshot")
            snapshot_params["destination"] = "/mnt/flash/../../etc/passwd"
            with self.assertRaisesRegex(ValueError, "safe absolute path"):
                await task.run(snapshot_params)

            verify_params = _routing_config_params("routing_config_verify")
            verify_params["source_path"] = "configerator/raw/../secret"
            with self.assertRaisesRegex(ValueError, "safe Configerator path"):
                await task.run(verify_params)

        get_driver.assert_not_awaited()

    async def test_routing_config_cancellation_does_not_start_cleanup(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value="prior bytes")

        async def execute(command: str, *, configure: bool = False) -> str:
            if "stat -c" in command:
                return "taac-file-metadata:640:42:43"
            raise asyncio.CancelledError

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(_routing_config_params("routing_config_snapshot"))
            with self.assertRaises(asyncio.CancelledError):
                await task.run(_routing_config_params("routing_config_restore"))

        commands = tuple(
            item.args[0]
            for item in driver.async_execute_show_or_configure_cmd_on_shell.await_args_list
        )
        self.assertFalse(any("rm -f" in command for command in commands))

    async def test_routing_component_restores_startup_and_running_config(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value="original startup")

        async def execute(command: str, *, configure: bool = False) -> str:
            if "stat -c" in command:
                return "taac-file-metadata:755:0:0"
            if "sha256sum" in command:
                return hashlib.sha256(b"original startup").hexdigest()
            return ""

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        restore = AsyncMock()
        delete = AsyncMock()

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(return_value="flash:component-original"),
            ),
            patch(f"{_MODULE}._configure_replace", restore),
            patch(f"{_MODULE}.arista_utils.delete_backup_config", delete),
        ):
            await task.run(_routing_component_params("routing_component_snapshot"))
            await task.run(_routing_component_params("routing_component_restore"))

        commands = tuple(
            item.args[0]
            for item in driver.async_execute_show_or_configure_cmd_on_shell.await_args_list
        )
        self.assertTrue(
            any("b3JpZ2luYWwgc3RhcnR1cA==" in command for command in commands)
        )
        self.assertTrue(any("chown +0:+0" in command for command in commands))
        self.assertTrue(any("chmod '755'" in command for command in commands))
        restore.assert_awaited_once_with(
            driver,
            "flash:component-original",
            logger_instance=task.logger,
        )
        delete.assert_awaited_once_with(
            driver,
            "flash:component-original",
            logger_instance=task.logger,
        )

    async def test_routing_component_restores_directories_and_firewall(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(side_effect=FileNotFoundError)
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(return_value="")
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        directory = _RestorableDirectory(
            path="/mnt/fb/certs",
            exists=True,
            metadata=("750", 42, 43),
        )
        firewall = _RestorableFirewallChain(
            family="ipv4",
            chain="EOS_BGP",
            exists=True,
            rules=("-N EOS_BGP", "-A EOS_BGP -j DROP"),
        )
        snapshot_params = _routing_component_params("routing_component_snapshot")
        snapshot_params["directory_paths"] = [directory.path]
        snapshot_params["firewall_chains"] = [
            {"family": firewall.family, "chain": firewall.chain}
        ]
        snapshot_params["daemon_names"] = ["Bgpcpp"]
        restore_order: list[str] = []
        restore_directory = AsyncMock(
            side_effect=lambda *_args: restore_order.append("directory")
        )
        restore_firewall = AsyncMock(
            side_effect=lambda *_args: restore_order.append("firewall")
        )
        reconcile_daemons = AsyncMock(
            side_effect=lambda *_args: restore_order.append("daemons")
        )

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(return_value="flash:component-original"),
            ),
            patch(
                f"{_MODULE}._configure_replace",
                AsyncMock(),
            ),
            patch(
                f"{_MODULE}.arista_utils.delete_backup_config",
                AsyncMock(),
            ),
            patch(
                f"{_MODULE}._read_directory_state",
                AsyncMock(return_value=directory),
            ),
            patch(
                f"{_MODULE}._read_firewall_chain_state",
                AsyncMock(return_value=firewall),
            ),
            patch(
                f"{_MODULE}._read_daemon_states",
                AsyncMock(return_value=(("Bgpcpp", True),)),
            ),
            patch(f"{_MODULE}._quiesce_daemons_for_restore", AsyncMock()),
            patch(f"{_MODULE}._reconcile_daemon_states", reconcile_daemons),
            patch(f"{_MODULE}._restore_directory", restore_directory),
            patch(f"{_MODULE}._restore_firewall_chain", restore_firewall),
        ):
            await task.run(snapshot_params)
            restore_firewall.side_effect = RuntimeError("firewall restore failed")
            with self.assertRaisesRegex(RuntimeError, "firewall restore failed"):
                await task.run(_routing_component_params("routing_component_restore"))

            # A dependency restore failure must not strand the captured daemon
            # state in the quiesced/down state.
            reconcile_daemons.assert_awaited_once()

            restore_order.clear()
            restore_firewall.reset_mock()
            restore_firewall.side_effect = lambda *_args: restore_order.append(
                "firewall"
            )
            restore_directory.reset_mock()
            reconcile_daemons.reset_mock()
            await task.run(_routing_component_params("routing_component_restore"))

        restore_firewall.assert_awaited_once_with(driver, firewall)
        restore_directory.assert_awaited_once_with(driver, directory)
        reconcile_daemons.assert_awaited_once()
        self.assertEqual(["firewall", "directory", "daemons"], restore_order)

    async def test_routing_component_snapshot_cleans_backup_on_failure(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value="original startup")
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            return_value="malformed metadata"
        )
        shared_data: dict[object, object] = {}
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data=shared_data,
        )
        delete = AsyncMock()

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(return_value="flash:component-original"),
            ),
            patch(f"{_MODULE}.arista_utils.delete_backup_config", delete),
        ):
            with self.assertRaisesRegex(RuntimeError, "metadata readback"):
                await task.run(_routing_component_params("routing_component_snapshot"))

        delete.assert_awaited_once_with(
            driver,
            "flash:component-original",
            logger_instance=task.logger,
        )
        self.assertEqual({}, shared_data)

    async def test_snapshot_failure_preserves_error_when_backup_cleanup_fails(
        self,
    ) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value="original startup")
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            return_value="malformed metadata"
        )
        logger = MagicMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=logger,
            shared_data={},
        )

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(return_value="flash:component-original"),
            ),
            patch(
                f"{_MODULE}.arista_utils.delete_backup_config",
                AsyncMock(side_effect=RuntimeError("backup cleanup failed")),
            ),
            self.assertRaisesRegex(RuntimeError, "metadata readback") as context,
        ):
            await task.run(_routing_component_params("routing_component_snapshot"))

        self.assertIn(
            "provisional snapshot backup cleanup also failed: backup cleanup failed",
            context.exception.__notes__,
        )
        logger.warning.assert_called_once()

    async def test_routing_component_restore_retains_backup_on_failure(self) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(side_effect=FileNotFoundError)
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(return_value="")
        logger = MagicMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=logger,
            shared_data={},
        )
        restore = AsyncMock(side_effect=ValueError("restore failed"))
        delete = AsyncMock()

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(return_value="flash:component-original"),
            ),
            patch(f"{_MODULE}._configure_replace", restore),
            patch(f"{_MODULE}.arista_utils.delete_backup_config", delete),
        ):
            await task.run(_routing_component_params("routing_component_snapshot"))
            with self.assertRaisesRegex(ValueError, "restore failed"):
                await task.run(_routing_component_params("routing_component_restore"))

        delete.assert_not_awaited()
        logger.warning.assert_called_once()

    async def test_routing_component_snapshot_keeps_first_daemon_state(self) -> None:
        daemon_states: dict[str, bool] = {
            "FibGrpc": True,
            "FibAgent": False,
            "Bgpcpp": False,
            "bgpcpp": True,
            "BgpTcpdump": True,
        }
        driver = MagicMock()
        driver.async_read_file = AsyncMock(return_value="original startup")

        async def execute(command: str, *, configure: bool = False) -> str:
            if "stat -c" in command:
                return "taac-file-metadata:755:0:0"
            if command.startswith("show daemon"):
                daemon_name = next(
                    name for name in reversed(_STATE_GUARD_DAEMONS) if name in command
                )
                state = (
                    "running with PID 123"
                    if daemon_states[daemon_name]
                    else "not running"
                )
                return f"Process: {daemon_name} ({state})"
            return ""

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        save = AsyncMock(return_value="flash:component-original")

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(f"{_MODULE}.arista_utils.save_running_config", save),
        ):
            params = _state_guard_component_params("routing_component_snapshot")
            await task.run(params)
            daemon_states["bgpcpp"] = False
            driver.async_read_file.return_value = "changed startup"
            await task.run(params)

        save.assert_awaited_once_with(
            driver,
            backup_name=(
                "taac_state_guard_"
                f"{hashlib.sha256(b'component:dut0/routing_control_plane').hexdigest()[:16]}"
            ),
            logger_instance=task.logger,
        )
        driver.async_read_file.assert_awaited_once_with("/usr/sbin/run_bgpcpp.sh")
        daemon_queries = [
            item.args[0]
            for item in driver.async_execute_show_or_configure_cmd_on_shell.await_args_list
            if item.args[0].startswith("show daemon")
        ]
        self.assertEqual(len(_STATE_GUARD_DAEMONS), len(daemon_queries))

    async def test_routing_component_restore_restores_files_then_daemons(self) -> None:
        startup_bytes = b"original startup\n"
        bgpcpp_bytes = b"config\xffbytes"
        rib_policy_bytes = b"\x00rib-policy\xfe"
        files: dict[str, bytes] = {
            "/usr/sbin/run_bgpcpp.sh": startup_bytes,
            "/mnt/flash/bgpcpp_config": bgpcpp_bytes,
            _RIB_POLICY_STATE_PATH: rib_policy_bytes,
        }
        metadata: dict[str, tuple[str, int, int]] = {
            "/usr/sbin/run_bgpcpp.sh": ("755", 0, 0),
            "/mnt/flash/bgpcpp_config": ("644", 11420360, 88),
            _RIB_POLICY_STATE_PATH: ("600", 44, 45),
        }
        staged_metadata: dict[str, tuple[str, int, int]] = {}
        expected_metadata = dict(metadata)
        daemon_states: dict[str, bool] = {
            "FibGrpc": True,
            "FibAgent": False,
            "Bgpcpp": False,
            "bgpcpp": True,
            "BgpTcpdump": True,
        }
        transitions: list[tuple[str, bool]] = []
        events: list[str] = []
        driver = MagicMock()

        async def read_file(path: str) -> str:
            return files[path].decode("utf-8", errors="surrogateescape")

        async def execute(command: str, *, configure: bool = False) -> str:
            if command.startswith("show daemon"):
                daemon_name = next(
                    name for name in reversed(_STATE_GUARD_DAEMONS) if name in command
                )
                state = (
                    "running with PID 123"
                    if daemon_states[daemon_name]
                    else "not running"
                )
                return f"Process: {daemon_name} ({state})"
            if configure and command.startswith("daemon"):
                daemon_name = next(
                    name for name in reversed(_STATE_GUARD_DAEMONS) if name in command
                )
                running = "no shutdown" in command
                daemon_states[daemon_name] = running
                transitions.append((daemon_name, running))
                events.append(f"daemon:{daemon_name}:{running}")
                return ""
            if "stat -c" in command:
                path = next(path for path in files if path in command)
                mode, owner_uid, owner_gid = metadata[path]
                return f"taac-file-metadata:{mode}:{owner_uid}:{owner_gid}"
            if "sha256sum" in command:
                path = next(path for path in files if path in command)
                return hashlib.sha256(files[path]).hexdigest()
            if "chown" in command:
                parts = shlex.split(command)
                owner, group = parts[3].split(":")
                uid = (
                    int(owner)
                    if owner.startswith("+")
                    else {"11420360": 80556623, "0": 11420360}.get(owner, int(owner))
                )
                gid = (
                    int(group)
                    if group.startswith("+")
                    else {"88": 88088}.get(group, int(group))
                )
                staged_metadata[parts[4]] = ("664", uid, gid)
            if "chmod" in command:
                parts = shlex.split(command)
                _, uid, gid = staged_metadata[parts[4]]
                staged_metadata[parts[4]] = (parts[3], uid, gid)
            if "mv -f" in command:
                parts = shlex.split(command)
                path = parts[-1]
                metadata[path] = staged_metadata.pop(parts[-2])
                events.append(f"file:{path}")
            return ""

        driver.async_read_file = AsyncMock(side_effect=read_file)
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        async def restore_running_config(*args: object, **kwargs: object) -> None:
            events.append("running-config")

        delete = AsyncMock()
        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(return_value="flash:component-original"),
            ),
            patch(
                f"{_MODULE}._configure_replace",
                side_effect=restore_running_config,
            ),
            patch(f"{_MODULE}.arista_utils.delete_backup_config", delete),
        ):
            await task.run(_state_guard_component_params("routing_component_snapshot"))
            await task.run(
                _file_snapshot_params(
                    "routing_config:dut0",
                    "/mnt/flash/bgpcpp_config",
                )
            )
            await task.run(
                _file_snapshot_params(
                    "rib_policy_state:dut0",
                    _RIB_POLICY_STATE_PATH,
                )
            )
            daemon_states.update(
                {
                    "FibGrpc": False,
                    "FibAgent": True,
                    "Bgpcpp": True,
                    "bgpcpp": False,
                    "BgpTcpdump": False,
                }
            )
            await task.run(_state_guard_component_params("routing_component_restore"))

        self.assertEqual(expected_metadata, metadata)
        self.assertEqual({}, staged_metadata)
        self.assertEqual(
            [
                ("Bgpcpp", False),
                ("FibAgent", False),
                ("FibGrpc", True),
                ("bgpcpp", True),
                ("BgpTcpdump", True),
            ],
            transitions,
        )
        self.assertEqual(
            {
                "FibGrpc": True,
                "FibAgent": False,
                "Bgpcpp": False,
                "bgpcpp": True,
                "BgpTcpdump": True,
            },
            daemon_states,
        )
        self.assertLess(
            events.index("daemon:Bgpcpp:False"),
            events.index("file:/mnt/flash/bgpcpp_config"),
        )
        self.assertLess(
            events.index("file:/mnt/flash/bgpcpp_config"),
            events.index("file:/dev/shm/bgp_rp_state.txt"),
        )
        self.assertLess(
            events.index("file:/dev/shm/bgp_rp_state.txt"),
            events.index("file:/usr/sbin/run_bgpcpp.sh"),
        )
        self.assertLess(
            events.index("file:/usr/sbin/run_bgpcpp.sh"), events.index("running-config")
        )
        self.assertLess(
            events.index("running-config"), events.index("daemon:bgpcpp:True")
        )

        commands = tuple(
            item.args[0]
            for item in driver.async_execute_show_or_configure_cmd_on_shell.await_args_list
        )
        for path, content in files.items():
            self.assertTrue(
                any(
                    base64.b64encode(content).decode("ascii") in command
                    for command in commands
                )
            )
            mode, owner_uid, owner_gid = metadata[path]
            self.assertTrue(
                any(
                    f"chown +{owner_uid}:+{owner_gid}" in command and path in command
                    for command in commands
                )
            )
            self.assertTrue(
                any(
                    f"chmod '{mode}'" in command and path in command
                    for command in commands
                )
            )
        delete.assert_awaited_once_with(
            driver,
            "flash:component-original",
            logger_instance=task.logger,
        )

    async def test_routing_component_does_not_reload_originally_stopped_bgp(
        self,
    ) -> None:
        daemon_running = False
        transitions: list[bool] = []
        driver = MagicMock()
        driver.async_read_file = AsyncMock(side_effect=FileNotFoundError)

        async def execute(command: str, *, configure: bool = False) -> str:
            nonlocal daemon_running
            if command.startswith("show daemon"):
                state = "running with PID 123" if daemon_running else "not running"
                return f"Process: Bgpcpp ({state})"
            if configure and command.startswith("daemon"):
                daemon_running = "no shutdown" in command
                transitions.append(daemon_running)
            return ""

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=execute
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        snapshot_params = _routing_component_params("routing_component_snapshot")
        snapshot_params["daemon_names"] = ["Bgpcpp"]
        restore_params = _routing_component_params("routing_component_restore")
        restore_params["force_restart_daemons"] = ["Bgpcpp"]

        with (
            patch(
                f"{_MODULE}.async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(return_value="flash:component-original"),
            ),
            patch(
                f"{_MODULE}._configure_replace",
                AsyncMock(),
            ),
            patch(
                f"{_MODULE}.arista_utils.delete_backup_config",
                AsyncMock(),
            ),
        ):
            await task.run(snapshot_params)
            daemon_running = True
            await task.run(restore_params)

        self.assertEqual([False], transitions)
        self.assertFalse(daemon_running)

    async def test_routing_component_validates_all_file_snapshots_before_restore(
        self,
    ) -> None:
        driver = MagicMock()
        driver.async_read_file = AsyncMock(side_effect=FileNotFoundError)
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(return_value="")
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        get_driver = AsyncMock(return_value=driver)
        delete = AsyncMock()

        with (
            patch(f"{_MODULE}.async_get_device_driver", get_driver),
            patch(
                f"{_MODULE}.arista_utils.save_running_config",
                AsyncMock(return_value="flash:component-original"),
            ),
            patch(f"{_MODULE}.arista_utils.delete_backup_config", delete),
        ):
            await task.run(_routing_component_params("routing_component_snapshot"))
            get_driver.reset_mock()
            restore_params = _routing_component_params("routing_component_restore")
            restore_params["file_restores"] = [
                {
                    "operation_id": "missing",
                    "destination": "/mnt/flash/bgpcpp_config",
                }
            ]
            with self.assertRaisesRegex(
                RuntimeError,
                "restore invoked without snapshot for missing",
            ):
                await task.run(restore_params)

        get_driver.assert_not_awaited()
        delete.assert_not_awaited()

    async def test_routing_component_acknowledges_daemons_and_startup_option(
        self,
    ) -> None:
        driver = MagicMock()

        async def daemon_status(command: str) -> str:
            names = (
                "FibBgpGrpc",
                "FibAgentBgp",
                "FibGrpc",
                "FibAgent",
                "Openr",
                "Bgpcpp",
            )
            name = next(name for name in names if name in command)
            state = "not running" if name == "Openr" else "running with PID 123"
            return f"Process: {name} ({state})"

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=daemon_status
        )
        driver.async_read_file = AsyncMock(
            return_value="\n".join(
                (
                    "--bgp_resolve_nexthops_from_interface_state=\\",
                    "true",
                )
            )
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(_routing_component_params("routing_component_acknowledge"))

        self.assertEqual(
            6,
            driver.async_execute_show_or_configure_cmd_on_shell.await_count,
        )
        driver.async_read_file.assert_awaited_once_with("/usr/sbin/run_bgpcpp.sh")

    async def test_routing_component_acknowledge_skips_unused_startup_file(
        self,
    ) -> None:
        driver = MagicMock()

        async def daemon_status(command: str) -> str:
            names = (
                "FibBgpGrpc",
                "FibAgentBgp",
                "FibGrpc",
                "FibAgent",
                "Openr",
                "Bgpcpp",
            )
            name = next(name for name in names if name in command)
            state = "not running" if name == "Openr" else "running with PID 123"
            return f"Process: {name} ({state})"

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=daemon_status
        )
        driver.async_read_file = AsyncMock()
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )
        params = _routing_component_params("routing_component_acknowledge")
        params["startup_options"] = []

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run(params)

        driver.async_read_file.assert_not_awaited()

    async def test_routing_component_acknowledge_reports_startup_read_failure(
        self,
    ) -> None:
        driver = MagicMock()

        async def daemon_status(command: str) -> str:
            names = (
                "FibBgpGrpc",
                "FibAgentBgp",
                "FibGrpc",
                "FibAgent",
                "Openr",
                "Bgpcpp",
            )
            name = next(name for name in names if name in command)
            state = "not running" if name == "Openr" else "running with PID 123"
            return f"Process: {name} ({state})"

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=daemon_status
        )
        driver.async_read_file = AsyncMock(
            side_effect=CommandExecutionError("transport failed")
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "failed to read EOS routing component startup file ",
            ):
                await task.run(
                    _routing_component_params("routing_component_acknowledge")
                )

    async def test_routing_component_rejects_unacknowledged_daemon(self) -> None:
        driver = MagicMock()
        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            return_value="Process: FibGrpc (not running)"
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            with self.assertRaisesRegex(RuntimeError, "acknowledgement mismatch"):
                await task.run(
                    _routing_component_params("routing_component_acknowledge")
                )

    async def test_routing_component_rejects_inexact_startup_option(self) -> None:
        driver = MagicMock()

        async def daemon_status(command: str) -> str:
            names = (
                "FibBgpGrpc",
                "FibAgentBgp",
                "FibGrpc",
                "FibAgent",
                "Openr",
                "Bgpcpp",
            )
            name = next(name for name in names if name in command)
            state = "not running" if name == "Openr" else "running with PID 123"
            return f"Process: {name} ({state})"

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=daemon_status
        )
        driver.async_read_file = AsyncMock(
            return_value=(
                "# --bgp_resolve_nexthops_from_interface_state=true\n"
                "--bgp_resolve_nexthops_from_interface_state=true0"
            )
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            with self.assertRaisesRegex(RuntimeError, "was not acknowledged"):
                await task.run(
                    _routing_component_params("routing_component_acknowledge")
                )

    async def test_routing_component_rejects_duplicate_startup_option(self) -> None:
        driver = MagicMock()

        async def daemon_status(command: str) -> str:
            names = (
                "FibBgpGrpc",
                "FibAgentBgp",
                "FibGrpc",
                "FibAgent",
                "Openr",
                "Bgpcpp",
            )
            name = next(name for name in names if name in command)
            state = "not running" if name == "Openr" else "running with PID 123"
            return f"Process: {name} ({state})"

        driver.async_execute_show_or_configure_cmd_on_shell = AsyncMock(
            side_effect=daemon_status
        )
        driver.async_read_file = AsyncMock(
            return_value=(
                "--bgp_resolve_nexthops_from_interface_state=false "
                "--bgp_resolve_nexthops_from_interface_state=true"
            )
        )
        task = EosCompilerLifecycleTask(
            hostname="dut.example.com",
            logger=MagicMock(),
            shared_data={},
        )

        with patch(
            f"{_MODULE}.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            with self.assertRaisesRegex(RuntimeError, "was not acknowledged"):
                await task.run(
                    _routing_component_params("routing_component_acknowledge")
                )
