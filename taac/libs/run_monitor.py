# Copyright (c) Meta Platforms, Inc. and affiliates.

from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Protocol


class RunMonitor(Protocol):
    def step(self, name: str) -> AbstractAsyncContextManager[None]: ...


class NullRunMonitor:
    @asynccontextmanager
    async def step(self, name: str) -> AsyncIterator[None]:
        yield
