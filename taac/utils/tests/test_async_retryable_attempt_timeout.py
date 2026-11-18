#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe

"""Tests for ``async_retryable(attempt_timeout=...)``.

A thrift reply that stalls mid-stream on a half-open connection never returns
and never raises, so without a per-attempt deadline the retry loop never gets
another turn.
"""

import asyncio
import unittest

from taac.utils.oss_taac_lib_utils import async_retryable


class TestAsyncRetryableAttemptTimeout(unittest.IsolatedAsyncioTestCase):
    async def test_hung_attempt_is_cancelled_and_retried(self):
        calls = []

        @async_retryable(retries=3, sleep_time=0, attempt_timeout=0.05)
        async def flaky():
            calls.append(None)
            if len(calls) == 1:
                await asyncio.Event().wait()
            return "ok"

        self.assertEqual(await flaky(), "ok")
        self.assertEqual(len(calls), 2)

    async def test_attempt_timeout_retried_even_if_not_a_retryable_exception(self):
        calls = []

        @async_retryable(
            retries=2, sleep_time=0, exceptions=(ValueError,), attempt_timeout=0.05
        )
        async def always_hangs():
            calls.append(None)
            await asyncio.Event().wait()

        with self.assertRaises(TimeoutError) as ctx:
            await always_hangs()
        self.assertEqual(len(calls), 2)
        self.assertIn("always_hangs did not complete within 0.05s", str(ctx.exception))

    async def test_timeout_raised_by_the_call_itself_is_not_reclassified(self):
        calls = []

        @async_retryable(
            retries=3, sleep_time=0, exceptions=(ValueError,), attempt_timeout=5
        )
        async def raises_own_timeout():
            calls.append(None)
            raise TimeoutError("from the call")

        with self.assertRaisesRegex(TimeoutError, "from the call"):
            await raises_own_timeout()
        self.assertEqual(len(calls), 1)

    async def test_no_attempt_timeout_by_default(self):
        @async_retryable(retries=1, sleep_time=0)
        async def slow():
            await asyncio.sleep(0.1)
            return "done"

        self.assertEqual(await slow(), "done")


if __name__ == "__main__":
    unittest.main()
