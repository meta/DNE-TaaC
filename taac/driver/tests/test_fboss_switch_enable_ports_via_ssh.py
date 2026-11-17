# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""``async_enable_ports_via_ssh`` must verify the port actually changed state.

The `fboss2 set port ... state ...` SSH command can return cleanly while the
CLI's thrift bootstrap is still failing right after an agent restart, leaving
the port at its old admin state. The method must poll the real device state
(via thrift getAllPortInfo, exposed as the non-retrying
``_async_admin_status_once``) and retry the command until it matches, or raise.
"""

import asyncio
import importlib
import logging
import os
import unittest
from types import SimpleNamespace
from unittest import mock

TAAC_OSS = os.environ.get("TAAC_OSS", "").lower() in ("1", "true", "yes")

FBOSS_SWITCH_MODULE = (
    "taac.driver.fboss_switch"
    if TAAC_OSS
    else "neteng.test_infra.dne.taac.driver.fboss_switch"
)

fboss_switch = importlib.import_module(FBOSS_SWITCH_MODULE)
FbossSwitch = fboss_switch.FbossSwitch


class _YieldOnce:
    """Hand control back to the event loop exactly once.

    Not ``asyncio.sleep(0)``: tests here must not depend on asyncio.sleep,
    which other tests in the process may have patched.
    """

    def __await__(self):
        yield


def _yield_once():
    return _YieldOnce()


class EnablePortsViaSshTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.switch = FbossSwitch("dut.example.com", logging.getLogger(__name__))
        self.commands = []
        self.timeouts = []
        self.reads = 0
        # Zero the backoff rather than patching asyncio.sleep: `fboss_switch
        # .asyncio` is the same module object as this module's `asyncio`, so
        # patching "its" sleep is a global patch -- it silences every await in
        # the process, including the ones a test needs to interleave on.
        p = mock.patch.object(FbossSwitch, "_SET_PORT_STATE_RETRY_SLEEP_S", 0)
        p.start()
        self.addCleanup(p.stop)

    def _stub(self, name, fn):
        p = mock.patch.object(FbossSwitch, name, fn)
        p.start()
        self.addCleanup(p.stop)

    def _stub_shell(self, fn=None):
        """fn(cmd) -> raw stdout; default is a clean rc=0 with no output."""

        async def fake_shell(_self, cmd, *args, **kwargs):
            self.commands.append(cmd)
            self.timeouts.append(kwargs.get("timeout"))
            return fn(cmd) if fn else f"{FbossSwitch._RC_MARKER}0"

        self._stub("async_run_cmd_on_shell", fake_shell)

    def _stub_agent_client(self, ports):
        """Fake the thrift client so the real read path runs. ports: id -> info."""
        reads = self

        class _Client:
            async def getAllPortInfo(self):
                reads.reads += 1
                return ports

        class _ClientCM:
            async def __aenter__(self):
                return _Client()

            async def __aexit__(self, *exc):
                return False

        p = mock.patch.object(
            FbossSwitch,
            "async_agent_client",
            new_callable=mock.PropertyMock,
            return_value=_ClientCM(),
        )
        p.start()
        self.addCleanup(p.stop)

    def _stub_admin_status(self, statuses):
        """statuses: dicts (or exceptions) returned on successive reads."""
        it = iter(statuses)

        async def fake_status(_self):
            self.reads += 1
            value = next(it)
            if isinstance(value, Exception):
                raise value
            return value

        self._stub("_async_admin_status_once", fake_status)

    async def test_enable_succeeds_on_first_read_no_retry(self):
        self._stub_shell()
        self._stub_admin_status([{"eth1/1/1": True}])

        await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertEqual(len(self.commands), 1)
        # every token is load-bearing: --yes because the current fboss2 refuses
        # the subcommand off a TTY, </dev/null so it cannot block on stdin,
        # 2>&1 + the rc marker so the caller can see why it failed.
        self.assertEqual(
            self.commands[0],
            "fboss2 set port eth1/1/1 state enable --yes </dev/null 2>&1; "
            f"echo {FbossSwitch._RC_MARKER}$?",
        )
        # bounded, not async_run_cmd_on_shell's 300s default: 6 attempts of
        # that would outlast the step's own traffic window
        self.assertEqual(self.timeouts, [FbossSwitch._SET_PORT_STATE_TIMEOUT_S])
        self.assertLessEqual(FbossSwitch._SET_PORT_STATE_TIMEOUT_S, 60)

    async def test_enable_retries_until_state_matches(self):
        self._stub_shell()
        self._stub_admin_status(
            [
                {"eth1/1/1": False},
                {"eth1/1/1": False},
                {"eth1/1/1": True},
            ]
        )

        await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertEqual(len(self.commands), 3)

    async def test_enable_raises_with_interface_name_when_never_matches(self):
        self._stub_shell(lambda cmd: f"boom{FbossSwitch._RC_MARKER}1")
        self._stub_admin_status([{"eth1/1/1": False}] * 6)

        with self.assertRaises(RuntimeError) as ctx:
            await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        message = str(ctx.exception)
        self.assertIn("eth1/1/1", message)
        # the returncode and the command's own diagnostics, not just ''
        self.assertIn("exited 1", message)
        self.assertIn("boom", message)
        self.assertEqual(len(self.commands), 6)

    async def test_disable_missing_port_is_not_a_match(self):
        """A port absent from the admin map must not read as disabled."""
        self._stub_shell()
        self._stub_admin_status([{"eth9/9/9": False}] * 6)

        with self.assertRaises(RuntimeError) as ctx:
            await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], False)

        self.assertIn("eth1/1/1", str(ctx.exception))
        self.assertEqual(len(self.commands), 6)

    async def test_read_failure_counts_as_a_retry(self):
        self._stub_shell()
        self._stub_admin_status([RuntimeError("agent not up yet"), {"eth1/1/1": True}])

        await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertEqual(len(self.commands), 2)
        self.assertEqual(self.reads, 2)

    async def test_multi_interface_takes_one_read_per_round(self):
        self._stub_shell()
        self._stub_admin_status(
            [
                {"eth1/1/1": True, "eth1/2/1": False},
                {"eth1/1/1": True, "eth1/2/1": True},
            ]
        )

        await self.switch.async_enable_ports_via_ssh(["eth1/1/1", "eth1/2/1"], True)

        # 2 interfaces, 2 rounds -> 2 reads (not 4), and the interface that
        # already matched is not commanded again
        self.assertEqual(self.reads, 2)
        self.assertEqual(len(self.commands), 3)
        self.assertEqual(len([c for c in self.commands if "eth1/1/1" in c]), 1)

    async def test_the_verify_read_is_bounded(self):
        """The agent client's own timeout is 120s; the loop cannot absorb it."""
        self._stub_shell()

        async def never_answers(_self):
            self.reads += 1
            await _YieldOnce()
            return {"eth1/1/1": True}

        self._stub("_async_admin_status_once", never_answers)
        p = mock.patch.object(FbossSwitch, "_SET_PORT_STATE_READ_TIMEOUT_S", 0)
        p.start()
        self.addCleanup(p.stop)

        with self.assertRaises(RuntimeError) as ctx:
            await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertIn("no admin state read succeeded", str(ctx.exception))

    async def test_error_keeps_the_last_snapshot_that_was_read(self):
        """A failed last read must not report the port as absent from the map."""
        self._stub_shell()
        self._stub_admin_status(
            [{"eth1/1/1": False}] + [RuntimeError("thrift down")] * 5
        )

        with self.assertRaises(RuntimeError) as ctx:
            await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertIn("last observed enabled=False", str(ctx.exception))

    def test_unrelated_parser_error_plus_a_stray_yes_is_not_a_match(self):
        cmd = "fboss2 set port eth1/1/1 state disable --yes </dev/null 2>&1"
        self.assertFalse(
            FbossSwitch._yes_option_unsupported(
                f"{cmd}\ninvalid option -- 'q'\nreply yes to continue", cmd
            )
        )

    def test_unparseable_marker_does_not_leak_into_the_output(self):
        self.assertEqual(
            FbossSwitch._split_rc_marker(f"boom{FbossSwitch._RC_MARKER}abc"),
            (-1, "boom"),
        )

    async def test_commands_within_a_round_do_not_overlap(self):
        """Concurrent `fboss2 set port state` silently drops writes.

        Most enables issued in parallel can be lost, so a round issues one
        at a time.
        """
        in_flight = 0
        max_in_flight = 0

        async def fake_set(_self, interface, subcmd, use_yes):
            nonlocal in_flight, max_in_flight
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
            await _yield_once()  # gather would interleave here
            in_flight -= 1
            self.commands.append(interface)
            return 0, "", "cmd"

        self._stub("_async_fboss2_set_port_state", fake_set)
        self._stub_admin_status([{"eth1/1/1": True, "eth1/2/1": True}])

        await self.switch.async_enable_ports_via_ssh(["eth1/1/1", "eth1/2/1"], True)

        self.assertEqual(max_in_flight, 1)

    async def test_empty_interface_list_touches_nothing(self):
        self._stub_shell()
        self._stub_admin_status([])

        await self.switch.async_enable_ports_via_ssh([], True)

        self.assertEqual(self.commands, [])
        self.assertEqual(self.reads, 0)

    async def test_empty_port_map_is_a_failed_read(self):
        """An agent that reports no ports has told us nothing.

        Exercises the real ``_async_admin_status_once`` (only the thrift client
        is faked), so the empty-map guard and the mapping are both covered.
        """
        self._stub_shell()
        self._stub_agent_client({})

        with self.assertRaises(RuntimeError) as ctx:
            await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertIn("no admin state read succeeded", str(ctx.exception))

    async def test_ssh_failure_is_an_attempt_not_an_abort(self):
        """A raising SSH layer must not skip the remaining attempts."""
        calls = []

        def shell(cmd):
            calls.append(cmd)
            if len(calls) == 1:
                raise asyncio.TimeoutError("ssh timed out")
            return f"{FbossSwitch._RC_MARKER}0"

        self._stub_shell(shell)
        self._stub_admin_status([{"eth1/1/1": False}, {"eth1/1/1": True}])

        await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertEqual(len(self.commands), 2)

    async def test_error_says_when_the_state_was_never_read(self):
        self._stub_shell()
        self._stub_admin_status([RuntimeError("thrift down")] * 6)

        with self.assertRaises(RuntimeError) as ctx:
            await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertIn("no admin state read succeeded", str(ctx.exception))

    async def test_error_says_the_state_disagreed_when_reads_worked(self):
        self._stub_shell()
        self._stub_admin_status([{"eth1/1/1": False}] * 6)

        with self.assertRaises(RuntimeError) as ctx:
            await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertIn("did not reach admin state", str(ctx.exception))
        self.assertNotIn("no admin state read succeeded", str(ctx.exception))

    def test_map_admin_states(self):
        """The one line every other test stubs out."""
        ports = {
            1: SimpleNamespace(
                name="eth1/1/1", adminState=fboss_switch.PortAdminState.ENABLED
            ),
            2: SimpleNamespace(
                name="eth1/2/1", adminState=fboss_switch.PortAdminState.DISABLED
            ),
        }
        self.assertEqual(
            FbossSwitch._map_admin_states(ports),
            {"eth1/1/1": True, "eth1/2/1": False},
        )

    def test_yes_matcher_accepts_the_gflags_form(self):
        # gflags prints the flag without its dashes, so the matcher cannot key
        # on the literal "--yes"
        cmd = "fboss2 set port eth1/1/1 state disable --yes </dev/null 2>&1"
        self.assertTrue(
            FbossSwitch._yes_option_unsupported(
                f"{cmd}\nERROR: unknown command line flag 'yes'", cmd
            )
        )
        self.assertFalse(
            FbossSwitch._yes_option_unsupported(f"{cmd}\nUnknown port eth1/1/1", cmd)
        )

    async def test_a_real_failure_that_echoes_the_command_keeps_yes(self):
        """`Unknown port ...` must not be read as "this build lacks --yes".

        The echoed command line carries `--yes`, so a matcher that looks at the
        whole output and accepts a bare "unknown" strips the flag for the rest
        of the call and every later attempt then hits "Refusing to proceed".
        """

        def shell(cmd):
            # an SSH layer that echoes the command it ran, plus a real error
            return f"{cmd}\nUnknown port eth1/1/1\n{FbossSwitch._RC_MARKER}1"

        self._stub_shell(shell)
        self._stub_admin_status([{"eth1/1/1": False}] * 6)

        with self.assertRaises(RuntimeError):
            await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertTrue(all("--yes" in c for c in self.commands))

    async def test_no_rc_marker_is_reported_as_an_unknown_returncode(self):
        """A timed-out or dropped session never echoes the marker."""
        self._stub_shell(lambda cmd: "")
        self._stub_admin_status([{"eth1/1/1": False}] * 6)

        with self.assertRaises(RuntimeError) as ctx:
            await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertIn("exited -1", str(ctx.exception))

    async def test_falls_back_when_fboss2_does_not_know_yes(self):
        def shell(cmd):
            if "--yes" in cmd:
                return f"fboss2: unrecognized option '--yes'{FbossSwitch._RC_MARKER}1"
            return f"{FbossSwitch._RC_MARKER}0"

        self._stub_shell(shell)
        self._stub_admin_status([{"eth1/1/1": True}])

        await self.switch.async_enable_ports_via_ssh(["eth1/1/1"], True)

        self.assertEqual(len(self.commands), 2)
        self.assertIn("--yes", self.commands[0])
        self.assertNotIn("--yes", self.commands[1])
        self.assertIn("</dev/null 2>&1", self.commands[1])
