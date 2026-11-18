# Copyright (c) Meta Platforms, Inc. and affiliates.

# pyre-unsafe
"""Driver-free DLB (Dynamic Load Balancing) resource-stickiness analysis.

Pure logic extracted from DlbResourceStickinessHealthCheck: group routes into
unique ECMP next-hop groups, categorize them by prefix pattern and ECMP mode,
render a table, and validate against expected per-category counts and
cross-category totals.

This module has NO driver / thrift dependencies (stdlib only), so it can be
reused both by the health check and by standalone CLIs that fetch a route table
directly from the FBOSS agent.

Inputs:
    routes: iterable of FBOSS UnicastRoute-like objects exposing
        ``dest.ip.addr`` (bytes), ``dest.prefixLength`` (int),
        ``nextHops[].address.addr`` (bytes), and optionally
        ``overrideEcmpSwitchingMode`` / ``overridenEcmpMode``.
    ip_ntop: callable mapping a raw address (``bytes``) to its string form.
"""

import ipaddress
import typing as t
from dataclasses import dataclass, field

IpNtop = t.Callable[[t.Any], str]


@dataclass
class NextHopGroup:
    """Structure to hold common prefixes sharing the same next hops."""

    prefixes: list = field(default_factory=list)
    ecmp_modes: set = field(default_factory=set)

    def add_route(self, prefix: str, ecmp_mode: t.Optional[str]) -> None:
        self.prefixes.append(prefix)
        self.ecmp_modes.add(str(ecmp_mode) if ecmp_mode else "None")


@dataclass
class CategoryStats:
    """Statistics for a prefix category."""

    dlb_count: int = 0
    per_packet_random_count: int = 0
    other_modes_count: int = 0
    next_hop_counts: list = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.dlb_count + self.per_packet_random_count + self.other_modes_count

    @property
    def ecmp_width(self) -> str:
        """Widest ECMP group (max next-hop count) in this category."""
        if not self.next_hop_counts:
            return "-"
        return str(max(self.next_hop_counts))


@dataclass
class DlbAnalysisResult:
    """Outcome of a DLB resource analysis run.

    ``message`` already includes the rendered table and matches the message the
    health check historically produced (so callers can surface it verbatim).

    The ``total_routes_analyzed`` field counts every route observed across all
    groups (NOT unique-NH-group count). The ``total_dlb``/``total_random``/
    ``total_other`` fields expose the per-mode group counts that were
    previously only embedded in ``message``. The ``snapshot_match`` field
    is set when the caller passes ``snapshot_count`` to :func:`analyze` —
    None means the caller didn't perform the cross-check (independent
    `getAllEcmpDetails`-style snapshot vs the route-table-derived matrix).

    Mirrors the breakdown sections from
    ``fbcode/scripts/pavanpatil/prefix_to_dlb_resource_stickiness.py`` so
    automated callers can produce the same per-test diagnostics that
    Pavan's standalone binary emits.
    """

    passed: bool
    message: str
    table: str
    total_unique_nhgs: int
    ecmp_groups: int
    single_hop_groups: int
    total_routes_analyzed: int = 0
    total_dlb: int = 0
    total_random: int = 0
    total_other: int = 0
    snapshot_match: t.Optional[bool] = None


def group_routes_by_nexthops(
    routes: t.Iterable[t.Any], ip_ntop: IpNtop
) -> t.Dict[tuple, NextHopGroup]:
    """Group routes by their (sorted) set of next hops."""
    nexthop_groups: t.Dict[tuple, NextHopGroup] = {}

    for route in routes:
        ip_addr = ip_ntop(route.dest.ip.addr)
        dest_prefix = f"{ip_addr}/{route.dest.prefixLength}"

        next_hops_list = []
        if route.nextHops:
            for nhop in route.nextHops:
                next_hops_list.append(ip_ntop(nhop.address.addr))

        overridden_mode = None
        if (
            hasattr(route, "overrideEcmpSwitchingMode")
            and route.overrideEcmpSwitchingMode is not None
        ):
            overridden_mode = route.overrideEcmpSwitchingMode
        elif (
            hasattr(route, "overridenEcmpMode") and route.overridenEcmpMode is not None
        ):
            overridden_mode = route.overridenEcmpMode

        next_hops_tuple = tuple(sorted(next_hops_list))

        if next_hops_tuple not in nexthop_groups:
            nexthop_groups[next_hops_tuple] = NextHopGroup()

        nexthop_groups[next_hops_tuple].add_route(dest_prefix, overridden_mode)

    return nexthop_groups


def categorize_prefix(route_prefix: str, prefix_patterns: list) -> str:
    """Categorize a route prefix into a configured pattern or 'all else'."""
    try:
        network = ipaddress.IPv6Network(route_prefix, strict=False)

        for pattern in prefix_patterns:
            if "/" not in pattern:
                pattern_network = ipaddress.IPv6Network(f"{pattern}/32", strict=False)
            else:
                pattern_network = ipaddress.IPv6Network(pattern, strict=False)

            if network.subnet_of(pattern_network):
                return f"{pattern.rstrip(':')} prefixes"

        return "all else"
    except ValueError:
        return "all else"


def categorize_ecmp_mode(mode_str: str) -> str:
    """Categorize ECMP mode into DLB or non-DLB categories."""
    if mode_str == "None":
        return "Default (DLB)"
    elif "PER_PACKET_RANDOM" in mode_str:
        return "PER_PACKET_RANDOM"
    else:
        return "Other Modes"


def build_matrix(
    nexthop_groups: t.Dict[tuple, NextHopGroup], prefix_patterns: list
) -> t.Tuple[t.Dict[str, CategoryStats], int, int, int]:
    """Count unique ECMP groups (>1 next hop) per prefix category and ECMP mode.

    Returns ``(matrix, ecmp_groups_count, single_hop_groups_count,
    total_routes_analyzed)``. ``total_routes_analyzed`` counts every
    route observed across all groups (single-hop + multi-hop) — distinct
    from ``len(nexthop_groups)`` which dedups by NH-set.
    """
    matrix: t.Dict[str, CategoryStats] = {}
    for pattern in prefix_patterns:
        category = f"{pattern.rstrip(':')} prefixes"
        matrix[category] = CategoryStats()
    matrix["all else"] = CategoryStats()

    ecmp_groups_count = 0
    single_hop_groups_count = 0
    total_routes_analyzed = 0

    for next_hops_tuple, group in nexthop_groups.items():
        if len(next_hops_tuple) <= 1:
            single_hop_groups_count += 1
            total_routes_analyzed += len(group.prefixes)
            continue

        ecmp_groups_count += 1
        num_next_hops = len(next_hops_tuple)
        total_routes_analyzed += len(group.prefixes)

        prefix_categories_served = set()
        for prefix in group.prefixes:
            prefix_categories_served.add(categorize_prefix(prefix, prefix_patterns))

        for prefix_category in prefix_categories_served:
            if prefix_category not in matrix:
                matrix[prefix_category] = CategoryStats()

            if len(group.ecmp_modes) == 1:
                mode_str = list(group.ecmp_modes)[0]
                ecmp_category = categorize_ecmp_mode(mode_str)

                if ecmp_category == "Default (DLB)":
                    matrix[prefix_category].dlb_count += 1
                elif ecmp_category == "PER_PACKET_RANDOM":
                    matrix[prefix_category].per_packet_random_count += 1
                else:
                    matrix[prefix_category].other_modes_count += 1
            else:
                matrix[prefix_category].other_modes_count += 1

            if prefix_category != "all else":
                matrix[prefix_category].next_hop_counts.append(num_next_hops)

    return matrix, ecmp_groups_count, single_hop_groups_count, total_routes_analyzed


def generate_table(matrix: t.Dict[str, CategoryStats], prefix_patterns: list) -> str:
    """Render the per-category DLB table."""
    lines = []

    lines.append(
        f"{'Prefix Category':<20} | {'Default (DLB)':<13} | "
        f"{'PER_PACKET_RANDOM':<17} | {'Other Modes':<11} | "
        f"{'Total':<5} | {'ECMP Width':<13}"
    )
    lines.append("-" * 100)

    categories = []
    for pattern in prefix_patterns:
        category = f"{pattern.rstrip(':')} prefixes"
        if category in matrix:
            categories.append(category)
    if "all else" in matrix:
        categories.append("all else")

    total_dlb = 0
    total_random = 0
    total_other = 0

    for category in categories:
        stats = matrix.get(category, CategoryStats())
        total_dlb += stats.dlb_count
        total_random += stats.per_packet_random_count
        total_other += stats.other_modes_count

        lines.append(
            f"{category:<20} | {stats.dlb_count:<13} | "
            f"{stats.per_packet_random_count:<17} | {stats.other_modes_count:<11} | "
            f"{stats.total:<5} | {stats.ecmp_width:<13}"
        )

    lines.append("-" * 100)
    grand_total = total_dlb + total_random + total_other

    lines.append(
        f"{'TOTAL':<20} | {total_dlb:<13} | "
        f"{total_random:<17} | {total_other:<11} | "
        f"{grand_total:<5} | {'n/a':<13}"
    )

    return "\n".join(lines)


def validate_totals(
    matrix: t.Dict[str, CategoryStats], expected_totals: t.Dict[str, int]
) -> t.Dict[str, t.Any]:
    """Validate cross-category totals against expected values."""
    if not expected_totals:
        return {"status": "PASS", "message": ""}

    actual_dlb = sum(stats.dlb_count for stats in matrix.values())
    actual_random = sum(stats.per_packet_random_count for stats in matrix.values())
    actual_other = sum(stats.other_modes_count for stats in matrix.values())
    actual_total = actual_dlb + actual_random + actual_other

    failures = []

    if "dlb" in expected_totals:
        expected = expected_totals["dlb"]
        if actual_dlb != expected:
            failures.append(f"DLB groups: expected {expected}, got {actual_dlb}")

    if "per_packet_random" in expected_totals:
        expected = expected_totals["per_packet_random"]
        if actual_random != expected:
            failures.append(
                f"PER_PACKET_RANDOM groups: expected {expected}, got {actual_random}"
            )

    if "other_modes" in expected_totals:
        expected = expected_totals["other_modes"]
        if actual_other != expected:
            failures.append(
                f"Other Modes groups: expected {expected}, got {actual_other}"
            )

    if "total" in expected_totals:
        expected = expected_totals["total"]
        if actual_total != expected:
            failures.append(
                f"Total ECMP groups: expected {expected}, got {actual_total}"
            )

    if failures:
        return {
            "status": "FAIL",
            "message": "Validation FAILED: " + "; ".join(failures),
        }

    return {"status": "PASS", "message": "All validations passed"}


def _validate_category(
    category: str,
    stats: CategoryStats,
    expected: t.Dict[str, int],
) -> t.List[str]:
    """Validate a single category's stats against expected values."""
    failures = []
    validators = {
        "dlb": ("DLB", lambda s: s.dlb_count),
        "per_packet_random": (
            "PER_PACKET_RANDOM",
            lambda s: s.per_packet_random_count,
        ),
        "other_modes": ("Other Modes", lambda s: s.other_modes_count),
        "total": ("Total", lambda s: s.total),
    }
    for key, (label, getter) in validators.items():
        if key in expected and getter(stats) != expected[key]:
            failures.append(
                f"{category} - {label}: expected {expected[key]}, got {getter(stats)}"
            )
    if "min_total" in expected and stats.total < expected["min_total"]:
        failures.append(
            f"{category} - Total: expected >= {expected['min_total']}, got {stats.total}"
        )
    # "ecmp_width" is the canonical key; "max_next_hops" is a backward-compat alias.
    expected_width = expected.get("ecmp_width", expected.get("max_next_hops"))
    if expected_width is not None:
        actual_width = max(stats.next_hop_counts) if stats.next_hop_counts else 0
        if actual_width != expected_width:
            failures.append(
                f"{category} - ECMP Width: expected {expected_width}, got {actual_width}"
            )
    return failures


def validate_counts(
    matrix: t.Dict[str, CategoryStats],
    expected_counts: t.Dict[str, t.Dict[str, int]],
) -> t.Dict[str, t.Any]:
    """Validate per-prefix-category counts against expected values."""
    if not expected_counts:
        return {"status": "PASS", "message": ""}

    failures = []
    for category, expected in expected_counts.items():
        stats = matrix.get(category, CategoryStats())
        failures.extend(_validate_category(category, stats, expected))

    if failures:
        return {
            "status": "FAIL",
            "message": "Validation FAILED: " + "; ".join(failures),
        }

    return {"status": "PASS", "message": "All per-category validations passed"}


def _format_summary_insights(
    total_dlb: int,
    total_random: int,
    total_other: int,
    total_unique: int,
    ecmp_groups: int,
    single_hop_groups: int,
) -> str:
    """Render the verbose Summary Insights block.

    Mirrors the section emitted by
    ``fbcode/scripts/pavanpatil/prefix_to_dlb_resource_stickiness.py``
    so HC output matches Pavan's standalone-binary output verbatim.
    """
    return "\n".join(
        [
            "=== Summary Insights ===",
            f"DLB-resource groups (Default mode): {total_dlb}",
            f"PER_PACKET_RANDOM override groups: {total_random}",
            f"Other ECMP-mode override groups: {total_other}",
            f"Total unique next-hop groups: {total_unique}",
            f"ECMP groups (>1 NH): {ecmp_groups}",
            f"Single-next-hop groups: {single_hop_groups}",
        ]
    )


def format_snapshot_comparison(
    snapshot_count: int,
    matrix_dlb_prefix_total: int,
    expected_extra_groups: int = 0,
) -> t.Tuple[str, bool]:
    """Render the ECMP Groups Snapshot Comparison block.

    Returns ``(rendered_block, match)``. Cross-validates the silicon
    ``async_get_ecmp_groups_snapshot()`` count against the route-table-derived
    Gold-prefix-category multi-NH total.

    V12 polish 2026-06-30 (post Run 14 evidence): the silicon snapshot
    API returns all ARS-managed groups — Default(DLB) mode AND
    ARS-PPR-spillover mode — as long as their NHs are in the per-chip
    DLB unique-NH pool. It does NOT see non-DLB ECMP groups (whose NHs
    fall outside the DLB pool by design — e.g. Silver at c002::b001+
    in our IcePack setup).

    Therefore the correct route-table-side counterpart is:
        matrix["<gold-prefix-category>"].total
    i.e. the total multi-NH groups whose prefixes fall in the
    DLB-eligible prefix range (Gold's ``5000:dd::`` in our setup).
    This regardless of mode — because silicon counts Gold-DLB AND
    Gold-PPR-spillover both.

    Two previously-attempted comparisons that FAILED:
    - V11 compared vs `total_dlb` (sum of `dlb_count` across all
      categories). This EXCLUDED CASE_04's 1 ARS-PPR spillover prefix
      (classified PPR by mode, but still in silicon's ARS registry) →
      false-FAIL on CASE_04.
    - Pre-V11 compared vs `ecmp_groups` (all multi-NH). This INCLUDED
      Silver's non-DLB PPR groups (which silicon can't see) →
      false-FAIL on CASE_05/08/10/11/23.

    V12 uses the prefix-boundary split: silicon's ARS budget applies to
    prefixes in the DLB pool = Gold's ``5000:dd::`` range. Anything in
    that range regardless of mode is in silicon's registry; anything
    outside (Silver's ``5000:ee::``) is not.
    """
    if expected_extra_groups < 0:
        raise ValueError("expected_extra_groups must be non-negative")
    expected_snapshot_count = matrix_dlb_prefix_total + expected_extra_groups
    diff = snapshot_count - expected_snapshot_count
    match = snapshot_count == expected_snapshot_count
    marker = "MATCH" if match else "MISMATCH"
    lines = [
        "=== ECMP Groups Snapshot Comparison ===",
        f"Snapshot: {snapshot_count}  Matrix DLB-prefix total: {matrix_dlb_prefix_total}  "
        f"Expected extra groups: {expected_extra_groups}  Difference: {diff}   {marker}",
    ]
    return "\n".join(lines), match


def analyze(
    routes: t.Iterable[t.Any],
    ip_ntop: IpNtop,
    prefix_patterns: t.Optional[list] = None,
    expected_counts: t.Optional[t.Dict[str, t.Dict[str, int]]] = None,
    expected_totals: t.Optional[t.Dict[str, int]] = None,
    snapshot_count: t.Optional[int] = None,
    dlb_managed_prefix_pattern: str = "5000:dd::",
    snapshot_expected_extra_groups: int = 0,
) -> DlbAnalysisResult:
    """Run the full DLB resource analysis + validation.

    Per-category (`expected_counts`) is validated first, then cross-category
    (`expected_totals`); the first failure wins. The returned ``message``
    includes the rendered table, matching the health check's historical output.

    When ``snapshot_count`` is provided (the integer length of an
    independent ``async_get_ecmp_groups_snapshot()`` fetch), the result's
    ``message`` also includes an "ECMP Groups Snapshot Comparison" block
    cross-validating the snapshot count vs the matrix-derived total. A
    mismatch flips ``passed`` to False with a descriptive failure
    message — mirrors Pavan's binary at
    ``fbcode/scripts/pavanpatil/prefix_to_dlb_resource_stickiness.py``.
    """
    prefix_patterns = prefix_patterns or []
    expected_counts = expected_counts or {}
    expected_totals = expected_totals or {}

    nexthop_groups = group_routes_by_nexthops(routes, ip_ntop)
    total_unique = len(nexthop_groups)
    matrix, ecmp_groups, single_hop_groups, total_routes_analyzed = build_matrix(
        nexthop_groups, prefix_patterns
    )
    table = generate_table(matrix, prefix_patterns)

    # Cross-category aggregates (also rendered in the Summary Insights
    # block below). Computed here so the dataclass fields stay in sync
    # with what generate_table renders into the TOTAL row.
    total_dlb = sum(stats.dlb_count for stats in matrix.values())
    total_random = sum(stats.per_packet_random_count for stats in matrix.values())
    total_other = sum(stats.other_modes_count for stats in matrix.values())

    summary_block = _format_summary_insights(
        total_dlb,
        total_random,
        total_other,
        total_unique,
        ecmp_groups,
        single_hop_groups,
    )

    # V12 polish (Run 14 CASE_04 evidence): compare snapshot vs the
    # multi-NH group count IN THE DLB-MANAGED PREFIX CATEGORY (Gold's
    # ``5000:dd::``). Silicon's ARS registry sees ALL Gold groups
    # regardless of mode (DLB / ARS-PPR-spillover) because their NHs
    # are in the DLB pool. It does NOT see Silver (NHs outside DLB
    # pool). Route-table matrix already breaks down by prefix, so the
    # correct counterpart is exactly ``matrix[gold_category].total`` —
    # all Gold multi-NH groups summed across all modes. See
    # ``_format_snapshot_comparison`` docstring for the failed-attempt
    # history (V11 used total_dlb which missed ARS-PPR spillover).
    dlb_managed_category = f"{dlb_managed_prefix_pattern.rstrip(':')} prefixes"
    dlb_managed_prefix_total = matrix.get(dlb_managed_category, CategoryStats()).total
    snapshot_block = ""
    snapshot_match: t.Optional[bool] = None
    if snapshot_count is not None:
        snapshot_block, snapshot_match = format_snapshot_comparison(
            snapshot_count,
            dlb_managed_prefix_total,
            expected_extra_groups=snapshot_expected_extra_groups,
        )

    header = (
        f"Total routes analyzed: {total_routes_analyzed}\n"
        f"Total unique next hop groups: {total_unique}\n"
        f"ECMP groups (>1 next hop): {ecmp_groups}\n"
        f"Single next hop groups (excluded): {single_hop_groups}"
    )

    def _make_result(passed: bool, body: str) -> DlbAnalysisResult:
        # Compose: validation/result body → table → snapshot → summary.
        # snapshot_block is empty unless caller passed snapshot_count.
        sections = [body, table]
        if snapshot_block:
            sections.append(snapshot_block)
        sections.append(summary_block)
        full_message = f"{header}\n\n" + "\n\n".join(sections)
        return DlbAnalysisResult(
            passed=passed,
            message=full_message,
            table=table,
            total_unique_nhgs=total_unique,
            ecmp_groups=ecmp_groups,
            single_hop_groups=single_hop_groups,
            total_routes_analyzed=total_routes_analyzed,
            total_dlb=total_dlb,
            total_random=total_random,
            total_other=total_other,
            snapshot_match=snapshot_match,
        )

    counts_result = validate_counts(matrix, expected_counts)
    if counts_result["status"] == "FAIL":
        return _make_result(False, counts_result["message"])

    totals_result = validate_totals(matrix, expected_totals)
    if totals_result["status"] == "FAIL":
        return _make_result(False, totals_result["message"])

    # Snapshot-mismatch is a soft fail surfaced in the result body.
    # V12: compare against `dlb_managed_prefix_total` (matrix
    # Gold-prefix-category multi-NH total). Silicon snapshot sees ALL
    # groups in the DLB-managed prefix range regardless of mode. Fixed
    # both Run 13 false-FAILs (05/08/10/11/23 — Silver present) and
    # Run 14 false-FAIL (CASE_04 spillover — 1 ARS-PPR group under
    # `total_dlb`).
    if snapshot_count is not None and snapshot_match is False:
        return _make_result(
            False,
            f"Snapshot mismatch: ECMP-snapshot={snapshot_count} vs "
            f"matrix-{dlb_managed_category}-total={dlb_managed_prefix_total} + "
            f"expected-extra={snapshot_expected_extra_groups} "
            f"(diff={snapshot_count - dlb_managed_prefix_total - snapshot_expected_extra_groups})",
        )

    return _make_result(True, "DLB Resource Analysis:")
