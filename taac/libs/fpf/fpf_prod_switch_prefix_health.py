# Copyright (c) Meta Platforms, Inc. and affiliates.

"""Production-route policy shared by the existing BGP and FSDB health checks."""

from taac.libs.fpf.fpf_collector_registry import (
    get_collector,
    get_disruption_time,
    get_recovery_start_time,
    get_restart_time,
    resolve_observation_window,
)
from taac.libs.fpf.fpf_prod_switch_prefix import (
    evaluate_production_routes,
)
from taac.health_check.health_check import types as hc_types


def check_production_routes(protocol: str, params: dict) -> hc_types.HealthCheckResult:
    collector = get_collector(f"prod_{protocol}_prefix")
    if collector is None:
        return hc_types.HealthCheckResult(
            status=hc_types.HealthCheckStatus.FAIL,
            message=f"Required production {protocol} collector is unavailable",
        )
    start, end = resolve_observation_window(params)
    if params.get("production_mode") == "convergence" and "window_start" not in params:
        event = params.get("trigger", "disruption")
        getters = {
            "disruption": get_disruption_time,
            "recovery": get_recovery_start_time,
            "restart": get_restart_time,
        }
        if event not in getters or (start := getters[event]()) <= 0:
            return hc_types.HealthCheckResult(
                status=hc_types.HealthCheckStatus.FAIL,
                message="Production convergence requires a recorded trigger timestamp",
            )
    try:
        results = evaluate_production_routes(
            collector,
            start,
            end,
            expected_by_gtsw=params.get("expected_by_gtsw"),
            mode=params.get("production_mode", "stability"),
            max_convergence_sec=float(params.get("max_convergence_sec", 10)),
            max_sample_age_sec=float(params.get("max_sample_age_sec", 60)),
        )
    except (ValueError, TypeError) as error:
        return hc_types.HealthCheckResult(
            status=hc_types.HealthCheckStatus.FAIL,
            message=f"Invalid production {protocol} observation contract: {error}",
        )
    status = hc_types.HealthCheckStatus.PASS
    if not results or any(r.status != "PASS" for r in results):
        status = hc_types.HealthCheckStatus.FAIL
    details = " | ".join(f"{r.gtsw} {r.prefix}: {r.status} {r.detail}" for r in results)
    return hc_types.HealthCheckResult(
        status=status, message=f"Production {protocol.upper()}: {details}"
    )
