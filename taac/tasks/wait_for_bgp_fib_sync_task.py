# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Hold setup until the FIB carries what bgpd learned.

``wait_for_bgp_convergence`` reads bgpd's one-shot initializationConverged
flag, which is already true once a bgpd restart has settled, so after the
traffic generator's peers come up it returns at once while bgpd is still
selecting and the agent still programming hundreds of thousands of paths. A
precheck that samples traffic at that point measures programming loss, not
forwarding.

This task polls the same RIB-versus-FIB comparison as
BGP_RIB_FIB_CONSISTENCY_CHECK and returns once, on every host:

* the RIB holds at least ``min_rib_prefixes`` best paths and the FIB at
  least as many routes, both counting the ignored prefixes (they can be
  whole traffic-generator pools), so neither a baseline RIB from before the
  peers' routes arrived nor a FIB still missing an ignored pool can pass;
* every RIB best path is in the FIB and every BGP FIB route is in the RIB,
  outside ``parent_prefixes_to_ignore`` (as in the consistency check);
* the RIB size, the BGP FIB size and the BGP FIB next-hop total have been
  identical for ``stable_polls`` consecutive polls, so ECMP sets that are
  still widening do not pass on prefix presence alone. Routes under an
  ignored prefix stay out of this, as rogue pools are re-advertised all run.

A poll whose reads fail counts as not synced. The task raises at
``timeout``, naming the last poll's numbers.
"""

import asyncio
import time
import typing as t

from taac.health_checks.device_health_checks.bgp_rib_fib_consistency_health_check import (
    drop_ignored,
    fib_bgp_prefixes,
    fib_prefixes,
    local_best_prefixes,
    not_installed_prefixes,
    rib_prefixes,
)
from taac.tasks.base_task import BaseTask
from taac.utils.driver_factory import async_get_device_driver


class _Poll(t.NamedTuple):
    rib_all: int
    fib_all: int
    rib: int
    fib_bgp: int
    fib_bgp_next_hops: int
    missing_in_fib: int
    missing_in_rib: int

    def signature(self) -> t.Tuple[int, int, int]:
        return (self.rib, self.fib_bgp, self.fib_bgp_next_hops)

    def __str__(self) -> str:
        return (
            f"rib_all={self.rib_all} fib_all={self.fib_all} "
            f"rib={self.rib} fib_bgp={self.fib_bgp} "
            f"fib_bgp_next_hops={self.fib_bgp_next_hops} "
            f"missing_in_fib={self.missing_in_fib} "
            f"missing_in_rib={self.missing_in_rib}"
        )


def _bgp_next_hop_total(details: t.Iterable[t.Any], ignore: t.Sequence[str]) -> int:
    return sum(
        len(r.nextHops or [])
        for r in details
        if drop_ignored(fib_bgp_prefixes([r]), ignore)
    )


async def async_poll_bgp_fib_sync(
    driver: t.Any, ignore: t.Sequence[str] = ()
) -> _Poll:
    entries = await driver.async_get_bgp_rib_entries()
    details = await driver.async_get_route_table_details()
    try:
        originated = await driver.async_get_bgp_originated_routes() or []
    except Exception:
        # Excluding nothing is the strict reading.
        originated = []
    rib_all = rib_prefixes(entries)
    rib = drop_ignored(rib_all, ignore)
    fib_unfiltered = fib_prefixes(details)
    fib_all = drop_ignored(fib_unfiltered, ignore)
    fib_bgp = drop_ignored(fib_bgp_prefixes(details), ignore)
    not_installed = not_installed_prefixes(originated) & local_best_prefixes(entries)
    return _Poll(
        rib_all=len(rib_all),
        fib_all=len(fib_unfiltered),
        rib=len(rib),
        fib_bgp=len(fib_bgp),
        fib_bgp_next_hops=_bgp_next_hop_total(details, ignore),
        missing_in_fib=len(rib - fib_all - not_installed),
        missing_in_rib=len(fib_bgp - rib),
    )


def is_synced(poll: _Poll, min_rib_prefixes: int) -> bool:
    return (
        poll.rib_all >= min_rib_prefixes
        and poll.fib_all >= min_rib_prefixes
        and poll.missing_in_fib == 0
        and poll.missing_in_rib == 0
    )


class WaitForBgpFibSyncTask(BaseTask):
    NAME = "wait_for_bgp_fib_sync"

    async def run(self, params: t.Dict[str, t.Any]) -> None:
        hostnames = params["hostnames"]
        if isinstance(hostnames, str):
            hostnames = [hostnames]
        await asyncio.gather(
            *[
                self._async_wait(
                    hostname,
                    timeout=params.get("timeout", 900),
                    interval=params.get("interval", 15),
                    stable_polls=params.get("stable_polls", 3),
                    min_rib_prefixes=params.get("min_rib_prefixes", 1),
                    ignore=params.get("parent_prefixes_to_ignore") or [],
                )
                for hostname in hostnames
            ]
        )

    async def _async_wait(
        self,
        hostname: str,
        timeout: float,
        interval: float,
        stable_polls: int,
        min_rib_prefixes: int,
        ignore: t.Sequence[str],
    ) -> None:
        driver = await async_get_device_driver(hostname)
        start = time.monotonic()
        deadline = start + timeout
        streak = 0
        last: t.Optional[_Poll] = None
        last_error: t.Optional[Exception] = None
        while True:
            polled_at = time.monotonic()
            try:
                poll = await async_poll_bgp_fib_sync(driver, ignore)
                last_error = None
            except Exception as ex:
                poll, last_error = None, ex
            if poll is not None and is_synced(poll, min_rib_prefixes):
                same = last is not None and poll.signature() == last.signature()
                streak = streak + 1 if same and streak else 1
            else:
                streak = 0
            last = poll if poll is not None else last
            elapsed = time.monotonic() - start
            self.logger.info(
                f"[wait_for_bgp_fib_sync] {hostname} t={elapsed:.0f}s "
                f"poll={time.monotonic() - polled_at:.1f}s "
                f"stable={streak}/{stable_polls} "
                + (str(poll) if poll is not None else f"read failed: {last_error}")
            )
            if streak >= stable_polls:
                return
            if time.monotonic() + interval > deadline:
                raise TimeoutError(
                    f"{hostname}: FIB not in sync with bgpd's RIB within {timeout}s "
                    f"(need rib_all and fib_all>={min_rib_prefixes}, no drift, {stable_polls} "
                    f"identical polls); last: {last}"
                    + (f"; last read error: {last_error}" if last_error else "")
                )
            await asyncio.sleep(interval)
