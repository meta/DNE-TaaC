# HRT warmboot network-event cases: WB-10 through WB-14

These cases run inside `fpf_shared_injection_suite`. The suite keeps one prefix
injection and collector set alive across all playbooks. Existing FPF cases are
the control runs; the `fpf_wb*` playbooks add the HRT warm restart.

| Warmboot case | Automated playbook | Control playbook(s) |
|---|---|---|
| WB-10: interface disabled across warmboot | `fpf_wb10_interface_disable_warmboot_{disrupt,restore}` | `fpf_tc15_interface_disable_{disrupt,restore}` |
| WB-11: STSW s001 drained across warmboot | `fpf_wb11_stsw_drain_warmboot` | `fpf_tc54_stsw_device_drain_disrupt`, `fpf_tc35_stsw_undrain_reinject_longevity` |
| WB-12: link drain before warmboot | `fpf_wb12_link_drain_warmboot_{disrupt,restore}` | `fpf_tc17_link_drain_{disrupt,restore}` |
| WB-13: link drain after convergence, before handover | `fpf_wb13_warmboot_then_link_drain_{disrupt,restore}` | `fpf_tc17_link_drain_{disrupt,restore}` |
| WB-14: link drain and warmboot launched together | `fpf_wb14_simultaneous_link_drain_warmboot_{disrupt,restore}` | `fpf_tc17_link_drain_{disrupt,restore}` |

## Automated contract

Every warmboot case preserves its non-warmboot control contract. WB-11 is one
atomic playbook: drain, HRT warmboot, fail-closed mid-test drained-state
validation, undrain, and final recovered-state validation. The other cases use
ordered disruption/restore pairs.

Every warmboot pair:

- records HRT restart initiation and command completion;
- polls HRT thrift counters instead of sleeping blindly;
- requires `warm_boot.enabled=1`, `warm_boot.ready=1`, convergence, and 8/8
  handover. WB-10 expects 31/32 subscribers while its physical interface is
  down and 32/32 after restore; WB-11 through WB-14 require 32/32;
- retains continuous BGP, FSDB ribMap, HRT bulk, remote-failure, production
  prefix, plane-status, traffic-spray, memory, Lifeguard, and discard checks;
- runs the control's full disrupted-state assertions before restoration, then
  runs the control's full restored-state assertions;
- owns link-drain cleanup with a mutation token, so cleanup cannot clear an
  unrelated ambient drain.

WB-13 uses a 100 ms counter poll to enter the interval where HRT is converged
but handover is incomplete. WB-14 launches the HRT restart and owned link drain
as concurrent asyncio tasks and logs their shared start epoch.

TC15 and WB-10 enforce a 10-second SLA for both the impacted HRT
remote-failure transition and production-prefix reachable-to-unreachable
transition. A dedicated one-second collector also requires the exact production
route to be present at baseline and withdrawn within 10 seconds from both BGP
RIB and FSDB ribMap on the local and remote observer GTSWs.

When `TAAC_FPF_SKIP_TWSHARED_SSH=1`, all five warmboot playbooks are omitted.
This is fail-closed: an agent cannot accidentally execute only the switch-side
mutation while silently skipping the HRT restart.

## Human preflight

1. Reserve both hosts, local/remote GTSWs, and STSW s001.
2. Verify all target devices are undrained. Do not clear an ambient drain you
   do not own.
3. Confirm both hosts have 32/32 HRT subscribers and all four traffic lanes at
   line rate. Do not begin from the current degraded beth0/31-of-32 state.
4. Authenticate both GPU hosts from the same terminal:

   ```bash
   sush2 root@twshared1354.03.mwg2.facebook.com -- true
   sush2 root@twshared1379.03.mwg2.facebook.com -- true
   ```

   TAAC uses the same direct noninteractive `sush2` transport for every
   twshared traffic and HRT command. Do not route twshared through lab-SSH;
   `TAAC_SSH_VIA_LAB_SSH` applies only to the switch-side devices.

5. Stop any separately running traffic supervisor before letting TAAC own the
   `ib_write_bw` processes.

## Current MWG2 pair

Run from `/home/pavanpatil/fbsource`:

```bash
unset TAAC_FPF_SKIP_TWSHARED_SSH

FPF_GPU_HOSTS=twshared1354.03.mwg2,twshared1379.03.mwg2 \
FPF_HRT_LANES=0,1,2,3 \
FPF_HRT_DEVICE_IDS=0,1,2,3,4,5,6,7 \
FPF_HRT_VF1_DEVICE_IDS=0,2,4,6 \
FPF_HRT_VF2_DEVICE_IDS=1,3,5,7 \
FPF_VF_GROUP_PODS=16 \
FPF_VF_PREFIXES_PER_POD=252 \
FPF_VF_BASE_ASN_PATH=4203699001 \
TAAC_FPF_IB_BINARY=/usr/bin/ib_write_bw \
TAAC_FPF_IB_DEVICE=mlx5_bveth0 \
TAAC_FPF_LINK_DRAIN_INTERFACE=eth1/37/1 \
buck2 run @fbcode//mode/opt fbcode//neteng/netcastle:netcastle_taac -- \
  --team taac --test-config fpf_shared_injection_suite \
  --regex 'fpf_wb10_|fpf_wb11_stsw_drain_warmboot$|fpf_wb12_|fpf_wb13_|fpf_wb14_' \
  --dev --skip-basset-reservation --skip-testbed-isolation \
  --debug --continue-on-precheck-failure --skip-fboss-rsyslog
```

To include the control runs in the same campaign, use:

```text
--regex 'fpf_tc15_interface_disable_(disrupt|restore)|fpf_tc17_link_drain_(disrupt|restore)|fpf_tc54_stsw_device_drain_disrupt|fpf_tc35_stsw_undrain_reinject_longevity|fpf_wb10_|fpf_wb11_stsw_drain_warmboot$|fpf_wb12_|fpf_wb13_|fpf_wb14_'
```

Run one case at a time when first qualifying the automation. After every case,
preserve the original collector artifacts and do not continue until the cleanup
has restored the target state.

## Fast external-baseline mode

For repeated cases, prefixes and traffic may be provisioned once outside TAAC.
Set all three variables on the TAAC command:

```bash
TAAC_FPF_EXTERNAL_IB_TRAFFIC=1 \
TAAC_FPF_PREINJECTED_PREFIXES=1 \
TAAC_FPF_COLLECTOR_BASELINE_SEC=30 \
...
```

In this mode the only setup task is `fpf_start_collectors`. TAAC does not start,
stop, probe, or repair `ib_write_bw`; the external supervisor owns it. ODS
host-spray checks remain enabled. TAAC also preserves the pre-injected VF
prefixes during teardown, while every playbook precheck still fails closed if
the expected BGP, FSDB, HRT, session, production-prefix, or traffic baseline is
not healthy.

Do not pass `--skip-setup-tasks`: that would skip the collectors too. Do not set
`TAAC_FPF_SKIP_IB_TRAFFIC=1`: that mode intentionally removes traffic health
checks rather than treating traffic as externally owned.

## Agent-safe validation

The agent environment cannot mint the GPU-host root certificate. It can still
run the construction and contract tests without touching hardware:

```bash
buck2 test @fbcode//mode/dev-nosan \
  fbcode//neteng/test_infra/dne/taac/testconfigs/fpf/tests:test_fpf_warmboot_network_events \
  fbcode//neteng/test_infra/dne/taac/testconfigs/fpf/tests:test_fpf_drain_safety \
  fbcode//neteng/test_infra/dne/taac/testconfigs/fpf/tests:test_fpf_tc52_restart_recovery \
  fbcode//neteng/test_infra/dne/taac/testconfigs/fpf/tests:test_fpf_twshared_campaign_configs
```
