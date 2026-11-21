# pyre-unsafe
"""
OSS Client Factory - Direct Thrift connections to FBOSS devices

This module provides the OSS implementation of ThriftClientFactory.
Uses direct Thrift connections without ServiceRouter.

Uses fbthrift Python bindings (thrift.python.client) which are
built from source via getdeps.py as part of the TAAC OSS build process.
"""

import asyncio
import functools
import inspect
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncIterator, Awaitable, Iterator

from neteng.fboss.bgp_thrift.thrift_clients import TBgpService

# FBOSS Thrift service clients (auto-generated from .thrift files by fbthrift compiler)
from neteng.fboss.ctrl.thrift_clients import FbossCtrl
from neteng.fboss.fsdb.thrift_clients import FsdbService
from neteng.fboss.hw_ctrl.thrift_clients import FbossHwCtrl
from neteng.fboss.qsfp.thrift_clients import QsfpService
from taac.driver.driver_constants import (
    DEFAULT_AGENT_REMOTE_PORT,
    DEFAULT_BGP_PORT,
    DEFAULT_QSFP_PORT,
    DEFAULT_THRIFT_TIMEOUT,
    FSDB_PORT,
    HW_AGENT_BASE_PORT,
)

# fbthrift Python client library (built from github.com/facebook/fbthrift)
from thrift.python.client import get_client, get_sync_client
from thrift.python.exceptions import (
    TransportError,
    TransportErrorType,
    TransportOptions,
)


class _DeadlineClient:
    """Async thrift client whose every RPC is bounded by ``timeout`` seconds.

    fbthrift stops timing a request once its reply starts arriving, so a reply cut
    off mid-stream (e.g. on a half-open connection) never completes. The deadline raises the same TIMED_OUT TransportError fbthrift
    does, so existing ThriftError retries handle it unchanged.
    """

    def __init__(self, client: Any, timeout: float) -> None:
        self._client = client
        self._timeout = timeout

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._client, name)
        if not callable(attr):
            return attr

        @functools.wraps(attr)
        def call(*args: Any, **kwargs: Any) -> Any:
            result = attr(*args, **kwargs)
            if not inspect.isawaitable(result):
                return result
            return self._bounded(name, result)

        return call

    async def _bounded(self, name: str, rpc: Awaitable[Any]) -> Any:
        deadline = asyncio.timeout(self._timeout)
        try:
            async with deadline:
                return await rpc
        except TimeoutError:
            if not deadline.expired():
                raise
            raise TransportError(
                TransportErrorType.TIMED_OUT,
                f"{name} did not complete within {self._timeout}s",
                0,
                TransportOptions.CHANNEL_IS_VALID,
            ) from None


class OSSClientFactory:
    """
    OSS implementation of ThriftClientFactory.

    Creates direct Thrift connections using fbthrift Python bindings.
    - Uses fbthrift's get_client() with THeader protocol (fbthrift default)
    - No TLS (plain text connections)
    - No automatic service discovery
    - No connection pooling
    - Manual port specification

    get_agent_client is synchronous (callers use sync `with`).
    All other client methods are async (callers use `async with`).

    Example:
        factory = OSSClientFactory()
        switch = FbossSwitch("switch1.example.com", client_provider=factory)
    """

    @contextmanager
    def get_agent_client(
        self,
        hostname: str,
        port: int = DEFAULT_AGENT_REMOTE_PORT,
        timeout: float = DEFAULT_THRIFT_TIMEOUT,
    ) -> Iterator:
        """
        Get SW Agent (FbossCtrl) client via direct connection.

        Synchronous context manager — matches existing callers that use
        sync `with self._get_fboss_agent_client() as client:`.
        """
        with get_sync_client(
            FbossCtrl, host=hostname, port=port, timeout=timeout
        ) as client:
            yield client

    @asynccontextmanager
    async def get_async_agent_client(
        self,
        hostname: str,
        port: int = DEFAULT_AGENT_REMOTE_PORT,
        timeout: float = DEFAULT_THRIFT_TIMEOUT,
    ) -> AsyncIterator:
        """Get SW Agent (FbossCtrl) async client via direct fbthrift connection."""
        async with get_client(
            FbossCtrl, host=hostname, port=port, timeout=timeout
        ) as client:
            yield _DeadlineClient(client, timeout)

    @asynccontextmanager
    async def get_hw_agent_client(
        self,
        hostname: str,
        switch_index: int,
        timeout: float = DEFAULT_THRIFT_TIMEOUT,
    ) -> AsyncIterator:
        """Get HW Agent (FbossHwCtrl) client via direct fbthrift connection."""
        port = HW_AGENT_BASE_PORT + switch_index
        async with get_client(
            FbossHwCtrl, host=hostname, port=port, timeout=timeout
        ) as client:
            yield _DeadlineClient(client, timeout)

    @asynccontextmanager
    async def get_qsfp_client(
        self,
        hostname: str,
        port: int = DEFAULT_QSFP_PORT,
        timeout: float = DEFAULT_THRIFT_TIMEOUT,
    ) -> AsyncIterator:
        """Get QSFP Service client via direct fbthrift connection."""
        async with get_client(
            QsfpService, host=hostname, port=port, timeout=timeout
        ) as client:
            yield _DeadlineClient(client, timeout)

    @asynccontextmanager
    async def get_bgp_client(
        self,
        hostname: str,
        port: int = DEFAULT_BGP_PORT,
        timeout: float = DEFAULT_THRIFT_TIMEOUT,
    ) -> AsyncIterator:
        """Get BGP Service client via direct fbthrift connection."""
        async with get_client(
            TBgpService, host=hostname, port=port, timeout=timeout
        ) as client:
            yield _DeadlineClient(client, timeout)

    @asynccontextmanager
    async def get_fsdb_client(
        self,
        hostname: str,
        port: int = FSDB_PORT,
        timeout: float = DEFAULT_THRIFT_TIMEOUT,
    ) -> AsyncIterator:
        """Get FSDB Service client via direct fbthrift connection."""
        async with get_client(
            FsdbService, host=hostname, port=port, timeout=timeout
        ) as client:
            yield _DeadlineClient(client, timeout)
