# NHI and XDOMAIN host composition

`nhi_stack_test.py` joins the existing XDOMAIN source composition to the actual
Thunderbolt NHI ring implementation in one host executable. It complements
`stack_test.py` and `peer_graph/xdomain_nhi_test.py`; their original fixtures,
frozen expectations and independent lifecycle regressions remain in place.

## Production and environmental boundaries

| Execution | Actual production code | Environmental substitutes |
| --- | --- | --- |
| Existing `stack_test.py` | Complete X3 login/lifecycle, X4 ring glue, X5 class, network family and X6 BPF C source | Handwritten `tb_ring` API; deterministic work scheduling; core session/provider storage; host BPF invocation |
| Existing `xdomain_nhi_test.py` | Complete `nhi.c` ring section, shared-interrupt dispatch, production ring declarations and register definitions | MMIO, coherent allocations, PCI references, IRQ registration/work scheduling; pthread synchronization in lifecycle cases |
| New `nhi_stack_test.py` | Both production sets above, with the same real ring declarations in every translation unit | MMIO/controller completion, IRQ delivery, work scheduling and link transport; core session/provider storage and host BPF invocation |

The two old suites share an intended ring API, but no common executed production
C implementation. In the old stack fixture, `native_post()` records a frame and
`invoke()` calls its callback without a hardware descriptor. The new backend
enqueues the actual X4 frames into the actual NHI queue, writes only descriptors
made visible by a real doorbell, and receives completions through actual NHI
work or polling before forwarding to the actual X4 callback.

The generator reuses the existing NHI extraction helpers. It includes the whole
ring section before `nhi_mailbox_cmd()` plus `nhi_interrupt_work()` and
`nhi_msi()`, without replacing local ring algorithms. Unrelated NHI PCI probe,
firmware mailbox and power-management code is outside this executable. The
shared `tb_nhi`, `tb_ring`, `ring_frame` and descriptor layouts come from the
selected production headers; host observation metadata lives separately.
Ordinary composed cases use MSI-X. The shared-MSI helpers are compiled but
their lookup/unlink interleavings remain exercised by the original standalone
NHI suite, not by the new deterministic composition.

The device boundary does not execute payload DMA or copy payload bytes.
Control-wire buffers are copied between simulated endpoints so the real decoder
and dispatch execute. Payload tests inspect addresses, lengths, sequences and
completion/ownership transitions using the existing independent stack oracle.
No CPU payload copy stands in for a physical transfer.

## Production mode and host adapter experiments

The first four cases preserve the APIs currently selected by production X4:
ordinary `tb_ring_tx()` / `tb_ring_rx()`, immediate notification and interrupt
completion. Production XDOMAIN does not currently select `NO_INTERRUPT`,
`*_more()` or the NHI polling APIs.

The remaining cases explicitly configure a host adapter:

- `nhi_poll`: allocates both data and control rings with `NO_INTERRUPT`. A
  deterministic external dispatcher uses actual `tb_ring_poll_pending()` and
  `tb_ring_poll()`, then calls the callback of the returned frame outside the
  ring lock. The poll API itself does not invoke the callback.
- `nhi_batch`: uses batched enqueue for data frames, then explicitly notifies at
  a scheduler boundary. Control messages retain immediate notifications.
- `nhi_ring_size=3`: reduces data rings to three entries, leaving two usable
  descriptor slots under the real NHI one-slot-empty rule. A four-frame group
  therefore needs real queue replenishment and wraparound. Control rings keep
  their production size.

These configurations test composition of existing NHI algorithms with XDOMAIN
callbacks. They do not add a production polling mode or demonstrate that a
concurrent kernel poller can safely retire a ring. The deterministic poller is
excluded before `tb_ring_free_quarantined()`, satisfying that API's external
producer/lifecycle precondition within this host schedule.

## Cases and reused evidence

| Case | Observable contract |
| --- | --- |
| `production_happy_path` | Existing nine-group, two-stage-index address/wire/CQE oracle through actual NHI descriptors and callbacks |
| `production_ack_orders` | ACK before local TX completion and local completion before ACK; neither alone permits early TX publication or lease release |
| `production_stop_phases` | Existing ARMED, ANNOUNCED, CTS-committed, POSTED and local-done/ACK-owed phases through actual NHI stop callbacks |
| `production_loss_teardown` | Existing remove, suspend, going-away and lost-completion scenarios retain unknown custody and never falsely release payload leases |
| `no_interrupt_poll_refill` | Zero IRQ allocation, no descriptor interrupt bit, actual poll-returned callbacks and four frames progressing through two usable slots |
| `batched_doorbells_wrap` | Multiple descriptors published by one actual doorbell; no device progress before notification; wrap/refill preserves the independent address and completion oracle |
| `poll_batch_retirement` | Queued and posted frames retired through actual NHI; unknown descriptor backing retained, key unregistered, software callback paths detached and no false payload release |

`stack_nhi_cases.c` includes the existing independent `stack_cases.c` assertions.
It reuses `addresses()`, `wire()`, custody/balance checks and lifecycle cases
instead of maintaining a second protocol oracle. Raw descriptor and NHI
resource observations add evidence at the previously simulated boundary.
The original NHI pthread IRQ/lookup/flush tests retain responsibility for their
specific concurrent software interleavings.

The old model's direct callback replay and control corruption/duplication/replay
injections are explicitly rejected with `-EOPNOTSUPP` by the new backend. They
remain in the old suite; accepting them without a descriptor action would give
false injection coverage. HOLD/DROP callback faults in the new backend withhold
hardware descriptor completion; real NHI owns the subsequent cancellation.
The STOP_RESULT fixture makes the simulated controller unavailable because the
real `tb_ring_stop()` has no error return.

Retirement observations read surviving descriptor storage after the real
quarantine call and record its actual descriptor-DMA free count. Key checks use
an external registration ledger, so zeroing the ring cannot conceal a missing
unregister. The observations do not treat software callback retirement as proof
that hardware DMA has quiesced.

## Commands and artifacts

From the repository root, prepare the pinned upstream register header and run:

```sh
python3 scripts/prepare_xdomain_host_inputs.py
python3 kernel/tools/testing/selftests/xdev_ext_mech/xdomain/nhi_stack_test.py \
  --keep-build /tmp/xdomain-nhi-stack
python3 kernel/tools/testing/selftests/xdev_ext_mech/xdomain/nhi_stack_test.py \
  --sanitize --keep-build /tmp/xdomain-nhi-stack-sanitize
python3 kernel/tools/testing/selftests/xdev_ext_mech/xdomain/test_nhi_stack_mutations.py \
  --keep-build /tmp/xdomain-nhi-stack-mutations
```

Select one bounded case with `--case NAME`. `--kernel PATH` selects an actual
source tree containing both production inputs and these fixtures. Missing
inputs or a compile failure return 2; failed runtime assertions return 1.
The runner requires an independent assertion-count marker for a passing case.

Each retained build contains `compile-command.json`, `compile.log`, the host
executable, generated production includes, per-case logs with runtime exit
codes, and `manifest.json`. The manifest records source SHA256 values, the
exact NHI prefix boundary/hash, generated-input hashes, compilation status and
case assertion counts. It also records only the relevant `ASAN_OPTIONS`,
`LSAN_OPTIONS` and `UBSAN_OPTIONS` runtime environment values, not the process's
full environment. Hashes identify the code actually used even if the
working tree differs from its Git HEAD.

The sanitizer command needs the host sanitizer runtime. Where procfs policy
prevents LeakSanitizer from inspecting tasks, an explicit
`ASAN_OPTIONS=detect_leaks=0` run can still check ASan/UBSan; report the unavailable
leak scan separately. It is not evidence that retained/quarantined allocations
were checked for leaks.

The mutation gate first requires an unmodified passing baseline. It creates
private source copies and removes batch notification, poll refill,
NO_INTERRUPT IRQ suppression or quarantine key release, deliberately lets ACK
bypass local completion, or shifts the physical address in the actual NHI
descriptor while leaving X4 acceptance records unchanged. A mutation counts as
killed only after a successful build, exit 1 from the selected case, and a named independent
`STACK_ASSERT`. Compile failures, signals, timeouts and sanitizer reports are
not accepted as mutation sensitivity. `mutation.diff`, the same build/runtime
artifacts and `mutations.json` retain the evidence.

The old targeted checks remain available:

```sh
python3 kernel/tools/testing/selftests/xdev_ext_mech/peer_graph/xdomain_nhi_test.py
python3 kernel/tools/testing/selftests/xdev_ext_mech/xdomain/stack_test.py
python3 kernel/tools/testing/selftests/xdev_ext_mech/xdomain/test_mutations.py
```

`scripts/check_xdomain_host.py --log-dir PATH` explicitly includes both new
entrypoints in the existing host closure gate. The Host checks workflow already
calls that gate. Its other prerequisites, including qualified CUDA declaration
headers, are unchanged.

## What a passing result establishes

This is **host software composition**: selected production C bodies execute
together under a controlled device and scheduling model. It can detect a
cross-layer lost notification, stalled refill, premature completion, wrong
descriptor address or incorrect software retirement in those schedules.

It is not execution in the Linux kernel. Real workqueue concurrency, IRQ
delivery, kernel lockdep, BPF verification/JIT, RCU and the complete core batch
engine require their kernel/guest gates. It is not physical dual-host
Thunderbolt DMA: controller/PCIe ordering, coherent DMA visibility, IOMMU
translation, link faults and payload integrity require matching kernels and
actual controllers on both hosts. Neither host CI success nor these semantic
mutation kills upgrades that hardware evidence.
