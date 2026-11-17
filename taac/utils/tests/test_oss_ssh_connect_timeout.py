# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""``AsyncSSHClient(connect_timeout=...)`` bounds setting up the connection.

``login_timeout`` only starts once TCP is connected, so a connection whose
setup stalls is otherwise left to the kernel's connect timeout (about two
minutes). The bound must surface as ``TimeoutError``, which callers treat as a
transport failure that happened before any command ran.
"""

import asyncio
import time
import unittest
from unittest import mock

from taac.utils.oss_driver_utils import AsyncSSHClient


class ConnectTimeoutTest(unittest.IsolatedAsyncioTestCase):
    async def _connect_kwargs(self, **client_kwargs):
        with mock.patch("asyncssh.connect", new=mock.AsyncMock()) as connect:
            await AsyncSSHClient("dut.example.com", **client_kwargs).async_connect()
        return connect.await_args.kwargs

    async def test_default_leaves_connect_unbounded(self):
        kwargs = await self._connect_kwargs()

        self.assertNotIn("connect_timeout", kwargs)

    async def test_stalled_setup_raises_timeout_error(self):
        # Accepts the TCP connection and never sends the SSH banner.
        writers = []

        async def silent(reader, writer):
            writers.append(writer)

        server = await asyncio.start_server(silent, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        start = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                async with AsyncSSHClient(
                    "127.0.0.1", port=port, password="x", connect_timeout=0.5
                ):
                    pass
        finally:
            for writer in writers:
                writer.close()
            server.close()
            await server.wait_closed()
        self.assertLess(time.monotonic() - start, 5)


if __name__ == "__main__":
    unittest.main()
