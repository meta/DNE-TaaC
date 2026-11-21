#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Set the breakout (resource-group fan-out) of IXIA 800G cages over the REST API.

Breakout ("resource group aggregation") is a writable REST attribute:
  availableHardware/chassis/card/aggregation -> `mode`

  --breakout 1x800G   the unbroken cage, 8 lanes
  --breakout 2x400G   two subports of 4 lanes
  --breakout 4x200G   four subports of 2 lanes
  --breakout 8x100G   eight subports of 1 lane

A cage's lanes are split evenly and every lane runs at line rate, so a valid
breakout uses the whole cage (per_cage * speed == 800G). Anything else is rejected.

Mode names count ports per RESOURCE GROUP, which may span several physical cages,
so the literal is derived rather than pattern-matched: the group's cage count comes
from its current mode, and each advertised mode is parsed into (ports, speed, lanes)
to find the one giving the requested per-cage breakout. On a card whose group spans
two cages, 2x400G per cage is a "FourBy..." mode, not a "TwoBy..." one.

A resource group is the atomic unit of breakout: changing it changes every cage in
it. Name the cages by their 1x800G port numbers -- port IDs shift with the mode, and
selection matches on the stable ResourcePorts superset.

Run with --dry-run first; it reports the current and target mode side by side
without touching anything. -v adds the card's port slots, every resource group, and
every advertised mode.

  ./ixia_set_breakout.py --api-server IX --chassis IX --ports 3,4 \
      --breakout 2x400G --dry-run
  ./ixia_set_breakout.py --api-server IX --chassis IX --ports 3,4 \
      --breakout 2x400G --apply
  ./ixia_set_breakout.py --api-server IX --chassis IX --ports 3,4 \
      --breakout 1x800G --apply          # restore

Setting the mode does not by itself bring a subport up, and a group already in
the target mode is a no-op ("nothing to do") even when its ports are down. To
bring ports back up -- after a mode change, or on ports that are simply stuck --
add --reset-ports, which assigns them to temporary vports, reboots the port CPU
of any that stay down, reports link, and releases them again:

  ./ixia_set_breakout.py --api-server IX --chassis IX --ports 3,4 \
      --breakout 2x400G --apply --reset-ports

The chassis may differ from the API server, and a fresh session has an empty
availableHardware list -- the chassis is registered automatically if missing.

Credentials (Linux API server) default to admin/admin. Override via environment:
    export TAAC_IXIA_USERNAME=... TAAC_IXIA_PASSWORD=...
The --username/--password flags also work but land the secret in your shell
history and in `ps` output, so prefer the environment.
"""
import argparse
import ipaddress
import os
import re
import socket
import sys
import time

from ixnetwork_restpy import SessionAssistant

# Same defaults as taac/ixia/ixnetwork_restpy_constants.py
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"

# Resource-group mode names encode "<N>By<Speed>Gig" plus an optional lane rate,
# e.g. inpt-800G-FourByFourHundredGigPAM4-106G == 4 ports of 400G at 106G/lane.
# N counts ports in the RESOURCE GROUP, which may span several physical cages, so
# the per-cage breakout is N / cages. Hence: parse, do not pattern-match.
NUM_WORD = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "twelve": 12, "sixteen": 16,
    "thirtytwo": 32, "onehundredthirtytwo": 132,
}
SPEED_WORD = {
    "sixteenhundred": 1600, "eighthundred": 800, "fourhundred": 400,
    "twohundred": 200, "onehundred": 100, "hundred": 100,
    "fifty": 50, "forty": 40, "twentyfive": 25, "ten": 10,
}
CAGE_GBPS = 800   # one physical 800G OSFP cage per 800G of group bandwidth
CAGE_LANES = 8    # an 800G OSFP cage is 8 serdes lanes


def label_for(per_cage, speed_g):
    """Canonical breakout label, e.g. (2, 400) -> '2x400G'."""
    return f"{per_cage}x{speed_g}G"


def valid_breakouts():
    """Every breakout that fully uses a cage, coarsest first."""
    return [
        label_for(n, CAGE_GBPS // n)
        for n in range(1, CAGE_LANES + 1)
        if CAGE_LANES % n == 0 and CAGE_GBPS % n == 0
    ]


def breakout_spec(text):
    """Parse a '<N>x<speed>G' breakout into a spec, or raise for argparse.

    A cage's lanes are split evenly and every lane runs at line rate, so a valid
    breakout satisfies per_cage * speed == CAGE_GBPS and divides CAGE_LANES. That
    admits 1x800G / 2x400G / 4x200G / 8x100G and rejects combinations that would
    leave the cage below line rate (e.g. 2x200G, which is 8 lanes at half rate --
    some NPUs support it, but it is not a cage fan-out the chassis can express).
    """
    m = re.fullmatch(r"(\d+)x(\d+)g", text.strip().lower())
    if not m:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a breakout; expected e.g. 2x400G"
        )
    per_cage, speed_g = int(m.group(1)), int(m.group(2))
    if per_cage * speed_g != CAGE_GBPS:
        raise argparse.ArgumentTypeError(
            f"{label_for(per_cage, speed_g)} totals {per_cage * speed_g}G but a cage "
            f"is {CAGE_GBPS}G; subports must use the whole cage. "
            f"Valid: {', '.join(valid_breakouts())}"
        )
    if CAGE_LANES % per_cage:
        raise argparse.ArgumentTypeError(
            f"{per_cage} subports cannot split {CAGE_LANES} lanes evenly"
        )
    return {
        "per_cage": per_cage,
        "speed_g": speed_g,
        "lanes": CAGE_LANES // per_cage,
        "l1_speed": f"speed{speed_g}g",
        "label": label_for(per_cage, speed_g),
    }


def parse_mode(mode):
    """-> (ports_in_group, per_port_gbps, lane_rate_g|None) or None."""
    low = mode.lower()
    if "by" not in low:
        return None
    left, right = mode[: low.rindex("by")], mode[low.rindex("by") + 2:]
    n = next(
        (NUM_WORD[w] for w in sorted(NUM_WORD, key=len, reverse=True)
         if left.lower().endswith(w)),
        None,
    )
    if n is None:
        return None
    m = re.match(r"([A-Za-z]+?)Gig", right)
    if not m:
        return None
    tok = m.group(1).lower()
    speed = next(
        (SPEED_WORD[w] for w in sorted(SPEED_WORD, key=len, reverse=True)
         if tok.startswith(w)),
        None,
    )
    if speed is None:
        return None
    lm = re.search(r"-(\d+)G(?:-|$)", right)
    return n, speed, (int(lm.group(1)) if lm else None)


def mode_summary(mode, cages):
    """Describe a mode in per-cage terms: '2x400G/cage, 4 lanes'."""
    p = parse_mode(mode)
    if not p or not cages:
        return "?"
    n, speed, lane = p
    per = n / cages
    per = int(per) if per == int(per) else per
    lanes = round(speed / lane) if lane else None
    return f"{per}x{speed}G/cage, {lanes if lanes else '?'} lanes"


def cages_in_group(current_mode):
    """How many physical 800G cages a resource group spans, from its current mode."""
    p = parse_mode(current_mode)
    if not p:
        return None
    n, speed, _ = p
    return max(1, round(n * speed / CAGE_GBPS))


def pick_mode(available, current_mode, spec):
    """Choose the fan-out mode giving `spec` on every cage in this resource group.

    Returns (chosen|None, [(mode, n, speed, lanes)] considered, warnings).
    """
    warn = []
    cages = cages_in_group(current_mode)
    if cages is None:
        warn.append(f"could not parse current mode {current_mode!r}; cannot size the group")
        return None, [], warn

    speed_g, want_lanes = spec["speed_g"], spec["lanes"]
    need_n = cages * spec["per_cage"]
    considered, exact = [], []
    for m in available:
        # RoCEv2 variants differ only in the traffic engine, not the fan-out, and
        # would duplicate every line of the listing below.
        if "roce" in m.lower():
            continue
        p = parse_mode(m)
        if not p:
            continue
        n, speed, lane = p
        lanes = round(speed / lane) if lane else None
        considered.append((m, n, speed, lanes))
        if n != need_n or speed != speed_g:
            continue
        if lanes is not None and lanes != want_lanes:
            warn.append(
                f"skipping {m}: {speed}G over {lanes} lane(s) at {lane}G, but "
                f"{spec['label']} needs {speed_g}G over {want_lanes} lanes "
                "-- these will not link"
            )
            continue
        exact.append(m)

    if not exact:
        warn.append(
            f"no advertised mode gives {need_n}x{speed_g}G "
            f"(= {spec['label']} across {cages} cage(s) in this group)"
        )
        # Say what IS reachable, in per-cage terms, so this is a decision point
        # rather than a dead end. Name the --breakout literal where one exists,
        # which is more actionable than describing the shape in prose.
        reachable = sorted({
            (n // cages, sp, lanes) for _, n, sp, lanes in considered if not n % cages
        })
        if reachable:
            warn.append("this group can instead do, per cage:")
            for per, sp, lanes in reachable:
                flag = label_for(per, sp)
                usable = per * sp == CAGE_GBPS and CAGE_LANES % per == 0
                warn.append(
                    f"     {flag}  {lanes or '?'} lane(s)  "
                    + (f"--breakout {flag}" if usable else "(not a full-cage breakout)")
                    + ("   <- same speed you asked for" if sp == speed_g else "")
                )
        return None, considered, warn

    return exact[0], considered, warn


def _as_ip(value):
    """Best-effort resolve a hostname to an IP string; pass IPs through."""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    try:
        return socket.gethostbyname(value)
    except OSError:
        return None


def _same_host(chassis, want_ip, want_raw):
    """Match a Chassis node against a target, by IP first then hostname string.

    Note `chassis.Hostname` typically holds an IP -- see
    configure_ixia_chassis() in taac/ixia/ixia.py, which does the same
    ipaddress-based comparison rather than a string match.
    """
    for attr in ("Hostname", "Ip"):
        got = getattr(chassis, attr, None)
        if not got:
            continue
        if want_ip:
            try:
                if ipaddress.ip_address(got) == ipaddress.ip_address(want_ip):
                    return True
            except ValueError:
                pass
        if str(got).lower() == str(want_raw).lower():
            return True
    return False


def describe(chassis):
    """One-line chassis summary, skipping fields that repeat one already shown.

    Hostname and Ip normally hold the same value here, and State duplicates
    StateV2, so printing all four is noise.
    """
    parts = [f"({chassis.Hostname})"]
    seen = {str(chassis.Hostname)}
    for attr in ("Ip", "ChassisType", "StateV2", "State", "ErrorDescription"):
        val = getattr(chassis, attr, None)
        if not val or str(val) in seen:
            continue
        seen.add(str(val))
        parts.append(str(val) if attr in ("Ip", "ChassisType") else f"{attr}={val}")
    return "  ".join(parts)


def _wait_ready(ixn, want_ip, want_raw, timeout):
    """Poll until the chassis reports ready. Returns the node, or None on timeout."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        for c in ixn.AvailableHardware.Chassis.find():
            if not _same_host(c, want_ip, want_raw):
                continue
            state = (getattr(c, "StateV2", None) or getattr(c, "State", "") or "").lower()
            if state != last:
                print(f"    state: {state or '<unknown>'}")
                last = state
            if "ready" in state:
                return c
            if "down" in state or "fail" in state:
                err = getattr(c, "ErrorDescription", "") or ""
                sys.exit(f"chassis {want_raw} came up '{state}' {err}".rstrip())
        time.sleep(3)
    return None


def resolve_chassis(sa, ixn, want_raw, add_if_missing, timeout=120):
    """Find the chassis in availableHardware, registering it if it is not there.

    A fresh IxNetwork session has an EMPTY availableHardware list: a chassis only
    appears once a vport has been mapped onto it (which is how normal taac runs
    register it) or once it is explicitly added. So 0 attached on first run is
    expected and does not mean the address is wrong.

    Registration mirrors configure_ixia_chassis() in taac/ixia/ixia.py: map a
    throwaway vport at the chassis address with ForceOwnership=False, and fall back to
    an explicit Chassis.add() only if that does not surface it.
    """
    want_ip = _as_ip(want_raw)

    # A previous interrupted run can leave the throwaway vport behind; drop it so
    # it does not accumulate or hold ownership.
    try:
        for stale in ixn.Vport.find(Name="^DO_NOT_USE$"):
            print("  removing stale DO_NOT_USE vport from an earlier run")
            stale.remove()
    except Exception:  # noqa: BLE001 - cleanup is best-effort
        pass

    attached = list(ixn.AvailableHardware.Chassis.find())
    for c in attached:
        if _same_host(c, want_ip, want_raw):
            return c

    # Not found. A fresh session legitimately has an empty list, so only surface
    # what *is* attached when we are about to give up or asked to stay read-only.
    if not add_if_missing:
        print(f"  {len(attached)} chassis attached to this session:")
        for c in attached:
            print(f"    - {describe(c)}")
        return None

    target = want_ip or want_raw

    # Direct registration first: this is just a chassis-list entry, so it does not
    # involve port link state and cannot stall on it.
    print(f"registering {want_raw} ({target}) in availableHardware")
    try:
        ixn.AvailableHardware.Chassis.add(Hostname=target)
    except Exception as exc:  # noqa: BLE001 - fall through to the vport path
        print(f"    Chassis.add failed ({exc})")
    found = _wait_ready(ixn, want_ip, want_raw, timeout)
    if found:
        return found

    # Fallback: the vport trick from configure_ixia_chassis() in ixia.py.
    # IgnoreLinkUp is essential here -- the throwaway port is arbitrary and will
    # never come up, and Connect() otherwise blocks for its 300s LinkUpTimeout.
    print("  Chassis.add did not surface it; trying a throwaway vport")
    vport = None
    try:
        pma = sa.PortMapAssistant()
        vport = pma.Map(IpAddress=target, CardId=1, PortId=100, Name="DO_NOT_USE")
        pma.Connect(
            ForceOwnership=False,
            IgnoreLinkUp=True,
            HostReadyTimeout=30,
            LinkUpTimeout=1,
        )
    except Exception as exc:  # noqa: BLE001 - best-effort registration
        print(f"    vport map failed ({exc})")

    found = _wait_ready(ixn, want_ip, want_raw, 30)
    if vport is not None:
        try:
            vport.remove()
        except Exception:  # noqa: BLE001
            print("    warning: could not remove the DO_NOT_USE vport; remove it by hand")
    if found:
        return found

    sys.exit(
        f"chassis {want_raw} never reached 'ready' within {timeout}s. Per "
        "configure_ixia_chassis() in taac/ixia/ixia.py, sitting in 'polling' is what "
        "happens when the address is only an IxNetwork API server and not a chassis. "
        "Get the real chassis address from ixia_chassis_ip (taac/utils/ixia_utils.py "
        "resolves it from the ixia hostname) and pass it via --chassis; --api-server "
        "can stay as it is."
    )


def load_card(chassis, card_id, chassis_name, want_ports, verbose=False):
    """Locate the card and return (card, [port nodes], {href: portId}).

    Ports are fetched once and reused -- ownership clearing needs the nodes again
    later, and Port.find() is a round trip.
    """
    card = chassis.Card.find(CardId=card_id)
    if len(card) == 0:
        present = [c.CardId for c in chassis.Card.find()]
        sys.exit(f"card {card_id} not found on {chassis_name}; cards present: {present}")
    ports = list(card.Port.find())
    href_to_port = {p.href: p.PortId for p in ports}
    present = sorted(href_to_port.values())
    print(f"card {card_id} {card.Description!r}  aggregation={card.AggregationMode}  "
          f"({len(present)} port slots)")
    if verbose:
        print(f"  port slots: {present}")
    missing = sorted(set(want_ports) - set(present))
    if missing:
        sys.exit(f"requested port(s) {missing} not present on card {card_id} "
                 f"(ports present: {present})")
    return card, ports, href_to_port


def group_ports(agg, href_to_port):
    """Port numbers a resource group owns.

    ResourcePorts is the stable superset: it lists every slot the group could
    expose in any fan-out, including the 1x800G cage numbering. The regex is a
    fallback for hrefs the card's own port list did not cover.
    """
    out = []
    for href in (agg.ResourcePorts or []):
        if href in href_to_port:
            out.append(href_to_port[href])
        else:
            m = re.search(r"/port/(\d+)$", str(href))
            if m:
                out.append(int(m.group(1)))
    return sorted(set(out))


def select_groups(card, href_to_port, want_ports, card_id, verbose=False):
    """Resource groups owning any requested port, as [(agg, gports, hit)]."""
    groups = list(card.Aggregation.find())
    selected = []
    for agg in groups:
        gports = group_ports(agg, href_to_port)
        hit = sorted(set(gports) & set(want_ports))
        if hit:
            selected.append((agg, gports, hit))
        if verbose:
            print(f"  group slots={gports or '?'} mode={agg.Mode}"
                  + (f"   <-- matches {hit}" if hit else ""))
    n = len(selected)
    print(f"{len(groups)} resource groups on card {card_id}; "
          f"{n} contain{'s' if n == 1 else ''} ports "
          f"{','.join(map(str, want_ports))}")
    if not selected:
        sys.exit(
            f"no resource group on card {card_id} contains port(s) {want_ports}. "
            "Re-run with --verbose to list the groups; if their slots show as '?', "
            "ResourcePorts did not resolve and this needs a closer look rather than "
            "a blind mode write."
        )
    return selected


def build_parser():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-server", default="localhost")
    ap.add_argument("--api-port", type=int, default=11009)
    ap.add_argument(
        "--chassis",
        required=True,
        help="chassis hostname or IP. NOTE: this is the CHASSIS, which may differ "
             "from --api-server. A hostname is resolved to an IP before matching, "
             "because availableHardware reports chassis by IP.",
    )
    ap.add_argument(
        "--no-add",
        action="store_true",
        help="do not register the chassis if it is missing; just report what is attached",
    )
    ap.add_argument(
        "--card",
        type=int,
        default=1,
        help="card holding the ports (default 1). On single-card chassis the 800G "
             "cages are PORTS on that card, not cards themselves.",
    )
    ap.add_argument(
        "--ports",
        required=True,
        help="comma-separated PORT numbers to break out, e.g. 3,4",
    )
    ap.add_argument(
        "--allow-collateral",
        action="store_true",
        help="proceed even when a resource group also contains ports you did not "
             "ask for (changing its mode reconfigures those too)",
    )
    ap.add_argument(
        "--breakout",
        required=True,
        type=breakout_spec,
        metavar="NxSPEEDG",
        help="target per-cage breakout, one of " + " / ".join(valid_breakouts())
             + ". 1x800G is the unbroken cage; the rest split its lanes evenly.",
    )
    ap.add_argument(
        "--username",
        default=os.environ.get("TAAC_IXIA_USERNAME", DEFAULT_USERNAME),
        help="API server user (env TAAC_IXIA_USERNAME, default admin)",
    )
    ap.add_argument(
        "--password",
        default=os.environ.get("TAAC_IXIA_PASSWORD", DEFAULT_PASSWORD),
        help="API server password (env TAAC_IXIA_PASSWORD, default admin). Prefer the "
             "env var: a flag is visible in `ps` and your shell history.",
    )
    ap.add_argument(
        "--reset-ports",
        action="store_true",
        help="bring the group's subports back up: assign them to temporary "
             "vports, reboot the port CPU of any that stay down, report link, "
             "then release. Independent of the mode change, so it also works "
             "when the group is already in the target mode.",
    )
    ap.add_argument(
        "--reset-all",
        action="store_true",
        help="with --reset-ports, reboot every subport instead of only the ones "
             "still down after assignment. A port CPU reboot is disruptive, so "
             "the default spends it only where it is needed.",
    )
    ap.add_argument(
        "--reset-timeout",
        type=int,
        default=300,
        help="seconds to wait for assignment and for the port CPU to come back "
             "(default 300)",
    )
    ap.add_argument(
        "--keep-ownership",
        action="store_true",
        help="with --reset-ports, leave the ports assigned to this session "
             "instead of releasing them. Not needed to hold link: these ports "
             "stay up unowned. Use it to hand a configured session to a test.",
    )
    ap.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="also list every card port slot, every resource group, and every "
             "advertised mode",
    )
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--apply", action="store_true")
    return ap


def process_group(agg, gports, hit, spec, args, ports, href_to_port):
    """Report and (unless --dry-run) apply the target mode to one group.

    Returns 0 on success/no-op, 1 if the group was refused or unreachable.
    """
    # PORT IDs SHIFT WITH THE MODE: a cage is port 3 in 1x800G but shows up as
    # ports 9/10 once the group is in 4x400G. ResourcePorts is the stable superset
    # (every slot the group could ever expose, including the 1x800G numbering),
    # which is what selection matched on.
    active = sorted(
        href_to_port[h] for h in (agg.ActivePorts or []) if h in href_to_port
    )
    cur = agg.Mode
    cages = cages_in_group(cur)
    mode, considered, warns = pick_mode(agg.AvailableModes, cur, spec)

    named = ",".join(map(str, hit))
    print(f"\nresource group covering ports {named}"
          + (f"  (spans {cages} cages)" if cages and cages > len(hit) else ""))
    if active and set(active) != set(hit):
        print(f"  in the current mode these cages appear as subports "
              f"{','.join(map(str, active))}")

    # The before/after comparison is the point of this tool, so keep the two lines
    # adjacent and column-aligned rather than separated by diagnostics.
    print(f"  now     {mode_summary(cur, cages):<24} {cur}")
    if mode:
        print(f"  target  {mode_summary(mode, cages):<24} {mode}")

    if args.verbose:
        print("  advertised:")
        for m, n, sp, lanes in sorted(considered, key=lambda t: (-t[2], t[1])):
            print(f"    {n:>3} x {sp:>4}G  {lanes or '?'} lane(s)  {m}")
    for w in warns:
        print(f"  !! {w}")

    # Collateral is structural: a resource group is the atomic unit of breakout, so
    # changing it changes every cage in it. Naming fewer ports than the group has
    # cages means the unnamed ones move too.
    if cages and cages > len(hit):
        print(f"  !! you named {len(hit)} of this group's {cages} cages; the rest "
              "change too")
        if args.apply and not args.allow_collateral:
            print("     refusing -- pass --allow-collateral to override")
            return 1

    if mode is None:
        return 1  # pick_mode already explained why, via warns
    if cur == mode:
        print("  already in target mode; nothing to do")
        return 0
    if args.dry_run:
        print("  dry run: not changed")
        return 0

    # Ownership must be released before the mode change is accepted. Only this
    # group's ports, so the rest of the card is undisturbed.
    for prt in ports:
        if prt.PortId in gports and prt.Owner:
            print(f"  releasing port {prt.PortId} (owner {prt.Owner})")
            prt.ClearOwnership()

    agg.Mode = mode
    print(f"  changed -> {agg.Mode}")
    return 0


def wait_until(predicate, timeout, interval=3):
    """Poll predicate() until it is truthy or timeout expires; return the last value."""
    deadline = time.time() + timeout
    val = predicate()
    while not val and time.time() < deadline:
        time.sleep(interval)
        val = predicate()
    return val


def reset_ports(ixn, ports, targets, args, session_id):
    """Bring `targets` (subport ids) back up. Returns 0 if all end up linked.

    Two different failures look identical from outside, and each needs a
    different remedy: a subport whose L1 was never configured comes up as soon
    as a vport is assigned to it, while a subport whose CPU is wedged stays down
    until it is rebooted. So assign first, then reboot only what is still down --
    a port CPU reboot is disruptive and pointless on a port that just recovered.

    Reboot and L1 both live on Vport, not on the availableHardware port (which
    only offers ClearOwnership / RestoreDefaults / TAP settings), so the vports
    exist purely as handles and are removed again unless --keep-ownership.
    """
    by_id = {p.PortId: p for p in ports if p.PortId in targets}
    missing = sorted(set(targets) - set(by_id))
    if missing:
        print(f"  !! subports not present on card {args.card}: {missing}")
    if not by_id:
        print("  !! no subports to reset")
        return 1

    print(f"\nreset-ports: subports {', '.join(str(i) for i in sorted(by_id))}")
    for pid, prt in sorted(by_id.items()):
        if prt.Owner:
            print(f"  port {pid}: clearing stale owner {prt.Owner}")
            prt.ClearOwnership()

    vports = {}
    for pid, prt in sorted(by_id.items()):
        vp = ixn.Vport.add(Name=f"reset-{args.card}.{pid}")
        vp.ConnectedTo = prt.href
        vports[pid] = vp

    def refresh():
        for vp in vports.values():
            vp.refresh()

    # "unassigned" means the bind has not landed yet; State only reports link
    # (up/down) once the port actually belongs to this session.
    def assigned():
        refresh()
        return all(vp.State != "unassigned" for vp in vports.values())

    if not wait_until(assigned, args.reset_timeout):
        print("  !! assignment did not finish; states="
              + ", ".join(f"{p}={v.State}" for p, v in sorted(vports.items())))
    for pid in sorted(vports):
        print(f"  port {pid}: after assign state={vports[pid].State}")

    todo = sorted(vports) if args.reset_all else sorted(
        p for p, v in vports.items() if v.State != "up"
    )
    if todo:
        why = "--reset-all" if args.reset_all else "still down after assignment"
        print(f"  rebooting port CPU on {todo} ({why})")
        for pid in todo:
            vports[pid].ResetPortCpu()

        def all_up():
            refresh()
            return all(vp.State == "up" for vp in vports.values())

        wait_until(all_up, args.reset_timeout)
    else:
        print("  every subport came up on assignment; no reboot needed")

    refresh()
    rc = 0
    print(f"\n  {'port':>5}  {'state':>10}  speed")
    for pid in sorted(vports):
        vp = vports[pid]
        print(f"  {pid:>5}  {vp.State:>10}  {vp.ActualSpeed}")
        if vp.State != "up":
            rc = 1

    if args.keep_ownership:
        print(f"\n  holding subports in session {session_id}")
    else:
        for vp in vports.values():
            vp.remove()
        print("\n  released; link persists with no owner")
    return rc


def print_l1_summary(spec):
    """Point at the flag that finishes the job; the mode alone leaves ports down."""
    print(f"\nSubports may need a port reboot before they are assignable, and still "
          f"need L1 configured: Speed={spec['l1_speed']} over {spec['lanes']} lane(s), "
          "plus FEC / auto-negotiation / link training matching the peer.\n"
          "Re-run with --reset-ports to assign, reboot whatever stays down, and "
          "report link.")


def main():
    args = build_parser().parse_args()
    want_ports = [int(x) for x in args.ports.split(",")]
    spec = args.breakout

    if args.verbose:
        print(f"connecting to {args.api_server}:{args.api_port} as {args.username}")
    sa = SessionAssistant(
        IpAddress=args.api_server,
        RestPort=args.api_port,
        UserName=args.username,
        Password=args.password,
        LogLevel="info",
    )
    ixn = sa.Ixnetwork
    chassis = resolve_chassis(sa, ixn, args.chassis, add_if_missing=not args.no_add)
    if chassis is None:
        sys.exit(
            f"chassis {args.chassis} is not registered in this session and "
            "--no-add was given; drop --no-add to add it, or pick one of the "
            "chassis listed above."
        )
    print(f"{args.chassis} {describe(chassis)}")

    card, ports, href_to_port = load_card(
        chassis, args.card, args.chassis, want_ports, args.verbose
    )
    selected = select_groups(
        card, href_to_port, want_ports, args.card, args.verbose
    )
    rc = 0
    for agg, gports, hit in selected:
        rc |= process_group(
            agg, gports, hit, spec, args, ports, href_to_port
        )
    if args.apply:
        print_l1_summary(spec)

    # Deliberately independent of whether the mode changed: the common case is a
    # group already in the target mode whose subports are nonetheless down, where
    # process_group correctly reports "nothing to do" and leaves them that way.
    if args.reset_ports:
        if args.apply:
            # PORT IDs SHIFT WITH THE MODE (see process_group): if a mode write
            # just landed, the card was loaded with the *old* numbering, and
            # restpy serves cached properties after find() -- agg.Mode = mode
            # does not refresh agg.ActivePorts, ports, or href_to_port. Reload
            # the card so targets use the post-shift subport IDs.
            card, ports, href_to_port = load_card(
                chassis, args.card, args.chassis, want_ports, args.verbose
            )
            selected = select_groups(
                card, href_to_port, want_ports, args.card, args.verbose
            )
        targets = sorted(
            {href_to_port[h]
             for agg, _, _ in selected
             for h in (agg.ActivePorts or [])
             if h in href_to_port}
        )
        if args.dry_run:
            print(f"\ndry run: would reset subports {targets} -- assign to "
                  "temporary vports, reboot any that stay down, then "
                  + ("hold them" if args.keep_ownership else "release them"))
        else:
            rc |= reset_ports(ixn, ports, targets, args, sa.Session.Id)

    return rc


if __name__ == "__main__":
    sys.exit(main())
