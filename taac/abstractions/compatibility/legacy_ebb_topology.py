# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-strict

"""Legacy EBB topology shape and scale compatibility values."""

BGP_MON_REMOTE_AS = 64001
EBGP_REMOTE_AS = 65334
IBGP_REMOTE_AS = 64981

BGP_MON_PEER_COUNT = 2
EBGP_PEER_COUNT_V4 = 140
EBGP_PEER_COUNT_V6 = 140

# 62 peers in each of the four DC and four MP device sets is 496 DUT addresses
# per AFI on the one FY26 iBGP interface, inside TAAC's own guard of 500 per
# interface and AFI (binding.py, from D112268835). That guard is a TAAC
# convention, not a documented Arista EOS limit.
IBGP_PEER_SCALE_PER_PLANE = 62

EBB_BGP_HOLD_TIMER_S = 180
EBB_BGP_KEEPALIVE_TIMER_S = 60
EBB_DEVICE_PREFIX_LIMIT = 2_000_000
EBB_DEVICE_PER_PEER_MAX_ROUTE_LIMIT = 1_500_000
EBB_DEVICE_ROUTE_LIMIT = 5_000_000

EGRESS_PEER_SCALE_SWEEP_PEER_COUNTS = (100, 200, 300, 400, 500)
