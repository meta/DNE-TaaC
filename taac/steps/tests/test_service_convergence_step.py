# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

from later.unittest import TestCase
from neteng.fboss.bgp_thrift.types import TBgpPeerState
from taac.constants import (  # oss-rewrite (force ShipIt re-export to taac.* root)
    TestDevice,
    TestTopology,
)
from taac.driver.driver_constants import (
    FbossSystemctlServiceName,
    SystemctlServiceStatus,
)
from taac.libs.parameter_evaluator import ParameterEvaluator
from taac.steps import step_definitions
from taac.steps.step_definitions import ServiceConvergenceStep
from taac.test_as_a_config import types as taac_types


def _bgp_session(peer_addr, state):
    session = MagicMock()
    session.peer_addr = peer_addr
    session.peer.peer_state = state
    session.peer.remote_as = 65000
    return session


def _bgp_sessions(count, state):
    return [_bgp_session(f"2001:db8::{i}", state) for i in range(1, count + 1)]


class TestServiceConvergenceStep(TestCase):
    def setUp(self):
        self.name = "test_service_convergence"
        self.device = MagicMock(spec=TestDevice)
        self.device.name = "rsw001.p001.f01.snc1"

        attributes_mock = MagicMock()
        attributes_mock.operating_system = "FBOSS"
        attributes_mock.role = ""
        attributes_mock.device_name = "rsw001"
        attributes_mock.hardware = ""
        attributes_mock.ai_zone = ""
        self.device.attributes = attributes_mock

        self.topology = MagicMock(spec=TestTopology)
        self.test_case_results = []
        self.test_config = MagicMock(spec=taac_types.TestConfig)
        self.test_case_name = "test_case"
        self.test_case_start_time = time.time()
        self.parameter_evaluator = MagicMock(spec=ParameterEvaluator)
        self.step_mock = MagicMock(spec=taac_types.Step)

        self.sc_step = ServiceConvergenceStep(
            name=self.name,
            device=self.device,
            topology=self.topology,
            test_case_results=self.test_case_results,
            test_config=self.test_config,
            test_case_name=self.test_case_name,
            test_case_start_time=self.test_case_start_time,
            parameter_evaluator=self.parameter_evaluator,
            step=self.step_mock,
        )

        self.driver_mock = AsyncMock()
        self.driver_mock.async_read_file.return_value = ""
        self.sc_step.driver = self.driver_mock

    async def test_run_agent_convergence(self):
        """Test convergence waiting for AGENT service."""
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.AGENT],
            timeout=300,
        )
        await self.sc_step.run(input_data, {})
        self.driver_mock.async_wait_for_agent_configured.assert_called_once_with(300)

    async def test_run_bgp_convergence(self):
        """Test convergence waiting for BGP service."""
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP],
            timeout=300,
        )
        await self.sc_step.run(input_data, {})
        self.driver_mock.async_wait_for_bgp_convergence.assert_called_once_with(300)

    async def test_run_bgp_convergence_with_ixia_on_rsw(self):
        """Test that IXIA BGP peers are restarted for RSW devices when ixia is present."""
        ixia_mock = MagicMock()
        self.sc_step.ixia = ixia_mock
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP],
            timeout=300,
        )
        await self.sc_step.run(input_data, {})
        ixia_mock.restart_bgp_peers.assert_called_once_with(["RSW001.P001.F01.SNC1"])
        self.driver_mock.async_wait_for_bgp_convergence.assert_called_once()

    async def test_run_qsfp_service_convergence(self):
        """Test convergence waiting for QSFP_SERVICE."""
        self.driver_mock.async_get_service_status.side_effect = [
            SystemctlServiceStatus.TRANSITIONING,
            SystemctlServiceStatus.ACTIVE,
        ]
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.QSFP_SERVICE],
            timeout=120,
        )
        with patch.object(step_definitions.asyncio, "sleep", AsyncMock()):
            await self.sc_step.run(input_data, {})

        self.driver_mock.async_wait_for_qsfp_service_state_active.assert_called_once_with(
            120
        )
        self.driver_mock.async_get_service_status.assert_called_with(
            FbossSystemctlServiceName.QSFP
        )
        self.assertEqual(2, self.driver_mock.async_get_service_status.call_count)

    async def test_run_fsdb_convergence(self):
        """Test convergence waiting for FSDB service."""
        self.driver_mock.async_get_service_status.side_effect = [
            SystemctlServiceStatus.TRANSITIONING,
            SystemctlServiceStatus.ACTIVE,
        ]
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.FSDB],
            timeout=120,
        )
        with patch.object(step_definitions.asyncio, "sleep", AsyncMock()):
            await self.sc_step.run(input_data, {})

        self.driver_mock.async_wait_for_fsdb_state_active.assert_called_once_with(120)
        self.driver_mock.async_get_service_status.assert_called_with(
            FbossSystemctlServiceName.FSDB
        )
        self.assertEqual(2, self.driver_mock.async_get_service_status.call_count)

    async def test_run_openr_convergence(self):
        """Test convergence waiting for OpenR."""
        self.driver_mock.async_get_service_status.side_effect = [
            SystemctlServiceStatus.TRANSITIONING,
            SystemctlServiceStatus.ACTIVE,
        ]
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.OPENR],
            timeout=120,
        )
        with patch.object(step_definitions.asyncio, "sleep", AsyncMock()):
            await self.sc_step.run(input_data, {})

        self.driver_mock.async_wait_for_openr_initialized.assert_called_once_with()
        self.driver_mock.async_get_service_status.assert_called_with(
            FbossSystemctlServiceName.OPENR
        )
        self.assertEqual(2, self.driver_mock.async_get_service_status.call_count)

    async def test_run_openr_before_bgp_convergence(self):
        """Test that OpenR initializes before BGP convergence is checked."""
        call_order = []
        self.driver_mock.async_get_service_status.return_value = (
            SystemctlServiceStatus.ACTIVE
        )

        async def record_openr() -> None:
            call_order.append(taac_types.Service.OPENR)

        async def record_bgp(_timeout: int) -> None:
            call_order.append(taac_types.Service.BGP)

        self.driver_mock.async_wait_for_openr_initialized.side_effect = record_openr
        self.driver_mock.async_wait_for_bgp_convergence.side_effect = record_bgp
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.OPENR, taac_types.Service.BGP],
            timeout=120,
        )

        await self.sc_step.run(input_data, {})

        self.assertEqual(
            call_order,
            [taac_types.Service.OPENR, taac_types.Service.BGP],
        )

    async def test_run_openr_convergence_in_oss_waits_for_systemd_active(self):
        """Test that OSS waits for openr to be systemd ACTIVE, then BGP."""
        self.driver_mock.async_get_service_status.side_effect = [
            SystemctlServiceStatus.TRANSITIONING,
            SystemctlServiceStatus.ACTIVE,
        ]
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.OPENR, taac_types.Service.BGP],
            timeout=120,
        )

        with (
            patch.object(step_definitions, "TAAC_OSS", True),
            patch.object(step_definitions.asyncio, "sleep", AsyncMock()),
        ):
            await self.sc_step.run(input_data, {})

        self.driver_mock.async_wait_for_openr_initialized.assert_not_called()
        self.driver_mock.async_get_service_status.assert_called_with(
            FbossSystemctlServiceName.OPENR
        )
        self.assertEqual(2, self.driver_mock.async_get_service_status.call_count)
        self.driver_mock.async_wait_for_bgp_convergence.assert_called_once_with(120)

    async def test_run_openr_convergence_in_oss_times_out(self):
        """Test that OSS fails when openr never reaches systemd ACTIVE."""
        self.driver_mock.async_get_service_status.return_value = (
            SystemctlServiceStatus.FAILED
        )
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.OPENR],
            timeout=0,
        )

        with (
            patch.object(step_definitions, "TAAC_OSS", True),
            self.assertRaisesRegex(TimeoutError, "openr.*FAILED"),
        ):
            await self.sc_step.run(input_data, {})

        self.driver_mock.async_wait_for_openr_initialized.assert_not_called()

    async def test_run_multiple_services(self):
        """Test convergence with multiple services."""
        input_data = taac_types.ServiceConvergenceInput(
            services=[
                taac_types.Service.AGENT,
                taac_types.Service.BGP,
            ],
            timeout=300,
        )
        await self.sc_step.run(input_data, {})
        self.driver_mock.async_wait_for_agent_configured.assert_called_once()
        self.driver_mock.async_wait_for_bgp_convergence.assert_called_once()

    async def test_run_with_per_service_timeout(self):
        """Test that per-service timeout overrides the default timeout."""
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.AGENT],
            timeout=300,
            service_convergence_timeout={taac_types.Service.AGENT: 600},
        )
        await self.sc_step.run(input_data, {})
        self.driver_mock.async_wait_for_agent_configured.assert_called_once_with(600)

    async def test_run_fsdb_with_per_service_timeout(self):
        """Test that per-service timeout overrides the default timeout for FSDB."""
        self.driver_mock.async_get_service_status.return_value = (
            SystemctlServiceStatus.ACTIVE
        )
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.FSDB],
            timeout=120,
            service_convergence_timeout={taac_types.Service.FSDB: 360},
        )
        await self.sc_step.run(input_data, {})
        self.driver_mock.async_wait_for_fsdb_state_active.assert_called_once_with(360)

    async def test_flag_waits_until_sessions_are_established(self):
        down = _bgp_sessions(24, TBgpPeerState.IDLE)
        up = _bgp_sessions(24, TBgpPeerState.ESTABLISHED)
        self.driver_mock.async_get_bgp_sessions.side_effect = [[], down, up]
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP], timeout=300
        )

        with patch.object(step_definitions.asyncio, "sleep", AsyncMock()) as sleep:
            await self.sc_step.run(input_data, {"wait_for_bgp_established": True})

        self.driver_mock.async_wait_for_bgp_convergence.assert_called_once_with(300)
        self.assertEqual(self.driver_mock.async_get_bgp_sessions.await_count, 3)
        self.assertEqual(sleep.await_count, 2)

    async def test_flag_counts_only_the_check_scope_not_idle_configured_peers(self):
        """A testbed can configure far more peers than are meant to be up. Only
        the playbook's allowlist counts, as in its check."""
        in_scope = [f"2001:db8:0:1::{i:x}" for i in range(1, 25)]
        idle = [_bgp_session(f"2001:db8:0:2::{i:x}", TBgpPeerState.IDLE) for i in range(57)]

        def sessions(state):
            return [_bgp_session(a, state) for a in in_scope] + idle

        self.driver_mock.async_get_bgp_sessions.side_effect = [
            sessions(TBgpPeerState.ACTIVE),
            sessions(TBgpPeerState.ESTABLISHED),
        ]
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP], timeout=300
        )
        params = {
            "wait_for_bgp_established": True,
            "bgp_session_check_params": {"ignore_all_prefixes_except": in_scope},
        }

        with patch.object(step_definitions.asyncio, "sleep", AsyncMock()) as sleep:
            await self.sc_step.run(input_data, params)

        self.assertEqual(self.driver_mock.async_get_bgp_sessions.await_count, 2)
        self.assertEqual(sleep.await_count, 1)

    async def test_flag_follows_the_check_pass_rule(self):
        """A check that asks for at least one Established session passes on one."""
        sessions = _bgp_sessions(24, TBgpPeerState.IDLE)
        sessions[0] = _bgp_session("2001:db8::1", TBgpPeerState.ESTABLISHED)
        self.driver_mock.async_get_bgp_sessions.return_value = sessions
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP], timeout=300
        )
        params = {
            "wait_for_bgp_established": True,
            "bgp_session_check_params": {"min_established_session_count": 1},
        }

        await self.sc_step.run(input_data, params)

        self.assertEqual(self.driver_mock.async_get_bgp_sessions.await_count, 1)

    async def test_settle_sleeps_before_the_first_session_poll(self):
        """Sessions read Established until their hold timers expire, so the wait
        sits out the settle time first."""
        calls = []
        sleep = AsyncMock(side_effect=lambda s: calls.append(("sleep", s)))
        self.driver_mock.async_get_bgp_sessions.side_effect = lambda: (
            calls.append(("poll", None)) or _bgp_sessions(24, TBgpPeerState.ESTABLISHED)
        )
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP], timeout=300
        )
        params = {"wait_for_bgp_established": True, "bgp_established_settle_s": 35}

        with patch.object(step_definitions.asyncio, "sleep", sleep):
            await self.sc_step.run(input_data, params)

        self.assertEqual([c[0] for c in calls], ["sleep", "poll"])
        # Counted from the start of the step, so the agent wait is part of it.
        self.assertGreaterEqual(calls[0][1], 34)
        self.assertLessEqual(calls[0][1], 35)

    async def test_no_settle_means_no_sleep_before_the_poll(self):
        self.driver_mock.async_get_bgp_sessions.return_value = _bgp_sessions(
            24, TBgpPeerState.ESTABLISHED
        )
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP], timeout=300
        )

        with patch.object(step_definitions.asyncio, "sleep", AsyncMock()) as sleep:
            await self.sc_step.run(input_data, {"wait_for_bgp_established": True})

        sleep.assert_not_awaited()

    async def test_settle_without_the_flag_does_nothing(self):
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP], timeout=300
        )

        with patch.object(step_definitions.asyncio, "sleep", AsyncMock()) as sleep:
            await self.sc_step.run(input_data, {"bgp_established_settle_s": 35})

        sleep.assert_not_awaited()
        self.driver_mock.async_get_bgp_sessions.assert_not_called()

    async def test_no_flag_does_not_look_at_sessions(self):
        self.driver_mock.async_get_bgp_sessions.return_value = []
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP], timeout=300
        )

        await self.sc_step.run(input_data, {})

        self.driver_mock.async_get_bgp_sessions.assert_not_called()

    async def test_flag_raises_when_sessions_never_establish(self):
        self.driver_mock.async_get_bgp_sessions.return_value = _bgp_sessions(
            3, TBgpPeerState.IDLE
        )
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP],
            service_convergence_timeout={taac_types.Service.BGP: 1},
        )
        real_sleep = asyncio.sleep

        async def slow_sleep(_seconds):
            await real_sleep(0.6)

        with patch.object(step_definitions.asyncio, "sleep", slow_sleep):
            with self.assertRaisesRegex(Exception, "BGP sessions did not all establish within 1 seconds"):
                await self.sc_step.run(input_data, {"wait_for_bgp_established": True})

    async def test_flag_keeps_polling_after_a_transient_session_read_error(self):
        up = _bgp_sessions(24, TBgpPeerState.ESTABLISHED)
        self.driver_mock.async_get_bgp_sessions.side_effect = [
            RuntimeError("thrift not ready"),
            up,
        ]
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP], timeout=300
        )

        with patch.object(step_definitions.asyncio, "sleep", AsyncMock()):
            await self.sc_step.run(input_data, {"wait_for_bgp_established": True})

        self.assertEqual(self.driver_mock.async_get_bgp_sessions.await_count, 2)

    async def test_timeout_message_carries_the_last_session_read_error(self):
        self.driver_mock.async_get_bgp_sessions.side_effect = RuntimeError(
            "thrift not ready"
        )
        input_data = taac_types.ServiceConvergenceInput(
            services=[taac_types.Service.BGP],
            service_convergence_timeout={taac_types.Service.BGP: 1},
        )
        real_sleep = asyncio.sleep

        async def slow_sleep(_seconds):
            await real_sleep(0.6)

        with patch.object(step_definitions.asyncio, "sleep", slow_sleep):
            with self.assertRaisesRegex(
                Exception,
                "BGP sessions did not all establish within 1 seconds.*thrift not ready",
            ):
                await self.sc_step.run(input_data, {"wait_for_bgp_established": True})
