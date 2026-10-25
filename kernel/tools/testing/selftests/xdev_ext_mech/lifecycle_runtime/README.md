# FANOUT execution verification

The bind fix is necessary but CREATE success is not an execution verdict.
This regression reuses the existing lifecycle guest's
`NVMe READ -> {NVMe WRITE, AF_XDP TX}` chain and its `nic-nvme` peer receiver.
No second network receiver or independent scheduler is introduced.

## Existing coverage and the added checks

| Test | Existing coverage | Added verification | Boundary |
| --- | --- | --- | --- |
| `fanout_scheduler/run.py` | Production scheduler/handoff, completion ordering, duplicate/late callbacks, EAGAIN, failure, STOP, quarantine | Production `frames_release`, explicit refs/custody/generation checks, reverse failure, delayed peers, reuse, JSON | Fake device submissions and callbacks; deterministic host interleavings |
| `poll/run.py` | Split flags, session bind, worker polling; NVMe/DMA/XSK functions with surrounding recorders | Reused unchanged | No DMA/NAPI execution; its flag-shape fixture does not call a full native bind |
| `fanout_bind_counterfactual.py` | Reuses the poll session-bind fixture | Exact historical splitter vs current, native NVMe/XSK flag guards, seven scenarios | Only the old splitter is substituted, not an entire historical kernel; device-resource binding mocked |
| `guest_harness_test.py` | Runs the real image preparation; checks four sink regions and execution hook | Reused unchanged | Does not boot a guest |
| `xdev_ext_mech_lifecycle_guest.sh` | Strict ZC fanout, peer RX->NVMe, both byte comparisons; two further CPU-transform outputs | Exact stage/recycle counts, isolated native trace, loss counters | Requires matching kernel/BPF/tools, KVM, QEMU NVMe and virtio-net |
| `fanout_validate.py` | Reuses those sink images and native-event ABI/loss parser | Both consumer completions before recycle; same frame/generation/span; driver TX completion; whole-image guards; JSON | Synthetic validator tests are not guest execution; guest execution is not physical DMA proof |

The trace joins session-less AF_XDP driver events through the actual
`descriptor_bind` pool/address/sequence. A generic CQE or
`downstream_complete` cannot replace a native completion. Loss, missing or
duplicate events, wrong counters, copy fallback, changed source bytes,
corrupt sinks or guards, and nonzero QEMU exit all fail validation.
The fixed guest geometry also binds each frame ID to its UMEM payload address,
keeps TX addresses live until native completion, and checks each NVMe command's
LBA, full opcode/NLB and stage completion ticket.

## Host command and machine-readable result

Run from a full Git clone (history is needed for the exact pre-fix header):

```sh
python3 kernel/tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/verify_fanout.py \
  --results /tmp/xdev-fanout-results
```

The output directory must not already exist and must be outside the checkout.
The runner retains commands, exit codes and hashed logs, plus:

* `result.json`: separate `fanout_host_status`, `host_status`, `guest.status`
  and `multi_device_execution_verified`; NOT_RUN is never converted to PASS.
* `counterfactual.json`: seven observed before/after bind scenarios.
* `scheduler.json`: seventeen observed callback/lifetime scenarios.

The broad `scripts/test_host.py` gate also runs; any unrelated failure remains
a failure and the runner exits nonzero. Focused FANOUT checks are reported
separately. Synthetic trace/verdict tests cannot populate a guest PASS.

For a shallow clone, fetch the old fix and parent before running, or supply
`--before-header PATH` with the exact old header:

```sh
git fetch --no-tags --depth=2 origin 6723cf8797ce1d8006a5e7c0cb3ff3bf79b6664a
git show 6723cf8797ce1d8006a5e7c0cb3ff3bf79b6664a^:kernel/io_uring/xdev_ext_mech_poll.h > /tmp/pre-fanout-poll.h
python3 kernel/tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/fanout_bind_counterfactual.py \
  --before-header /tmp/pre-fanout-poll.h --output /tmp/fanout-bind.json
```

In the five FANOUT cases, both versions pass generic CREATE admission. The
old splitter (`5af4e835e1cb27ca45457152adcdbfdfe7582f4c`) then fails the third
class flag guard with `-EINVAL` (`-22`, two stages bound). The fixed splitter
binds all three, preserves the core FANOUT grouping, and installs two
consumer references. Sequential and unknown-flag controls must behave the
same in both arms. This is an isolated executable red/green control, **not
a claimed red/green KVM boot**.

## Actual KVM command

Commit/apply the patch to a clean source snapshot, prepare the pinned full
Linux sources, and use the existing build prerequisites in `docs/build.md`.
The harness currently expects `/usr/local/bin/qemu-system-x86_64`, `/dev/kvm`,
GCC 14, Clang, libbpf/libelf, bpftool, pahole, BusyBox and cpio. Its two virtual
NICs use a private QEMU hub; `/dev/net/tun` and a host NIC are not required.

```sh
python3 scripts/prepare_sources.py --component linux
# The harness requires this /tmp scratch name. On shared servers, keep large
# build/tools/initroot/evidence/image children in a persistent project-owned
# NVMe directory through child links; retain caches after the run.
run_dir=$(mktemp -d /tmp/xdev-ext-e2e.XXXXXX)
bash kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh \
  --source "$PWD/kernel" --scratch "$run_dir" --lifecycle --groups 16 --depth 1
cat "$run_dir/evidence/fanout-result.json"
```

Repeat with a fresh scratch directory and `--depth 2` to exercise multiple
outstanding batches. The harness enforces exact clean source/build identity;
do not reuse old kernel artifacts with new tools. The normal kernel trace
captures observed ordering; controlled delayed/error callbacks currently run
only in the host scheduler fixture, not on emulated or physical devices.

For offline revalidation of retained real guest evidence:

```sh
python3 kernel/tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/fanout_validate.py \
  --dir "$run_dir" --log "$run_dir/evidence/guest.log" \
  --result "$run_dir/evidence/fanout-revalidated.json" \
  --groups 16 --depth 1 --qemu-exit "$(cat "$run_dir/evidence/qemu.exit")"
```

## Expected observations

For 8192 payload bytes/group, MTU 1500, `seg_len=1432`, each group contains
six frames: five 1432-byte payloads and one 1032-byte payload.

| Observation | Formula | `groups=16, depth=1` |
| --- | --- | --- |
| Stage submitted/completed (READ, WRITE, TX, unused) | `[G,G,G,0]` | `[16,16,16,0]` |
| Native NVMe commands | READ=G, WRITE=G | 16 + 16 |
| AF_XDP native descriptor completions | 6G | 96 |
| Frame returns to kernel pool | 6G | 96 |
| Payload bytes per sink | 8192G | 131072 |
| Active window groups / frames | min(G,D) / 6min(G,D) | 1 / 6 |
| Abort/reject/timeout/protocol-error/inflight/sequestered | all zero | all zero |
| User-loan `published` counter | zero | 0 |

Window size is **not** the entire XSK UMEM allocation. Per-command completions
and per-frame/descriptor completions have different denominators.

The one-frame host test observes producer READY with refs=2; after the first
consumer, refs=1 and the peer remains busy; after the last callback, refs=0,
FREE and generation+1. Provider custody stays INFLIGHT until the worker
barrier invokes production frame release and returns it once to K_FREE.
Terminal consumers do not publish READY again. `published=0` counts user
loans and says nothing about internal READY transitions. Returning a frame
to its pool does not mean unpinning the session's physical page.

The current trace ABI does not expose transient refs/busy/READY, so those
claims remain host-core coverage. Successful guest evidence establishes a
patched-kernel execution through emulated NVMe and virtio-net, not physical
NVMe/NIC DMA ordering, IOMMU behavior, cache coherency or hardware performance.
