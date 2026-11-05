# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-strict
"""Single source of truth (SSOT) for TAAC health-check retry policy.

Retry is a property of the **check**, uniform across the pre-check and
post-check phases and across every Conveyor test that runs the check — it is
never decided per call site. This module is that single source of truth; the
standardized check bundles / profile registry read it instead of hand-passing
retry numbers (which is what previously allowed the numbers to drift).

Two failure kinds are retried differently (see
``AbstractPointInTimeHealthCheck.run``):

* **Transient data-fetch failure** — a check's ``_run`` raises (dropped RPC,
  timeout, empty read). This is not a real verdict, so it is retried for
  *every* check (static and stateful) until retries are exhausted, then
  surfaced as ERROR.
* **A FAIL verdict** — retried only for **stateful** checks (those whose state
  settles after a perturbation). **Static** checks read fixed config/inventory,
  so a real FAIL will not change on retry; they opt out via
  ``RETRY_ON_FAIL = False`` on the check class.

Keying is by ``CheckName`` alone. Different check *types* may carry different
numbers (e.g. a check that needs longer to settle), but a given check's numbers
are identical in every phase and every test.
"""

from __future__ import annotations

import typing as t

from taac.health_check.health_check import types as hc_types


class RetrySpec(t.NamedTuple):
    """Immutable retry parameters for a single check.

    ``delay(n) = retry_delay_seconds * retry_delay_multiplier ** n`` where
    ``n`` is the zero-based retry index (n=0 is the first retry).
    """

    retry_count: int
    retry_delay_seconds: float
    retry_delay_multiplier: float


# Fleet-wide default, matching the value EBB already used for its session /
# RIB-FIB checks (3 retries, 10s base, 1.5x backoff → 10s, 15s, 22.5s).
DEFAULT_RETRY_COUNT: int = 3
DEFAULT_RETRY_DELAY_SECONDS: float = 10.0
DEFAULT_RETRY_DELAY_MULTIPLIER: float = 1.5

DEFAULT_RETRY_SPEC: RetrySpec = RetrySpec(
    retry_count=DEFAULT_RETRY_COUNT,
    retry_delay_seconds=DEFAULT_RETRY_DELAY_SECONDS,
    retry_delay_multiplier=DEFAULT_RETRY_DELAY_MULTIPLIER,
)

# Per-check overrides, used only where a check genuinely needs different numbers
# than the fleet default; kept here so future tuning stays in one place rather
# than scattered across call sites.
_PER_CHECK_RETRY: t.Dict[hc_types.CheckName, RetrySpec] = {
    # FibAgent deletes unused nexthop groups lazily, every 3-5 minutes. A
    # capacity read just after BGP convergence can still count those groups'
    # FECs, so wait for at least one sweep (30s, 45s, 67.5s, 101s; ~4 min).
    hc_types.CheckName.HARDWARE_CAPACITY_CHECK: RetrySpec(
        retry_count=4,
        retry_delay_seconds=30.0,
        retry_delay_multiplier=1.5,
    ),
}


def get_retry_spec(check_name: hc_types.CheckName) -> RetrySpec:
    """Return the baked-in retry spec for ``check_name``.

    Uniform across pre/post phases and across all tests — this is the SSOT the
    standardized bundles / profile registry consult when constructing checks.
    """
    return _PER_CHECK_RETRY.get(check_name, DEFAULT_RETRY_SPEC)


def get_retry_kwargs(check_name: hc_types.CheckName) -> t.Dict[str, t.Any]:
    """Return the retry spec as factory kwargs.

    Convenience for the profile registry / bundles, whose ``create_*`` factories
    accept ``retry_count`` / ``retry_delay_seconds`` / ``retry_delay_multiplier``.
    """
    spec = get_retry_spec(check_name)
    return {
        "retry_count": spec.retry_count,
        "retry_delay_seconds": spec.retry_delay_seconds,
        "retry_delay_multiplier": spec.retry_delay_multiplier,
    }
