# Guest-only peer provider tests

Everything in this directory runs only inside a private KVM guest. The module
`xdev_ext_peer_sw.ko` registers a provider whose "device memory" is 64 KiB of
ordinary guest RAM. It exercises the real provider registry and the real NVMe
PCI DMA mapping path, not VRAM, a GPU, or GPU performance. Nothing here
measures time.

## One-shot ioctl test (`peer_nvme_e2e`, `run-guest.sh`)

Driven by `xdev_ext_integration/xdev_ext_mech_zc_kvm.sh --peer`. It uses the
synchronous `XDEV_EXT_PEER_NVME_BATCH` ioctl, not a mechanism session.

## Session test (`peer_session_e2e`, `run-session-guest.sh`, `session_kvm.sh`)

Runs mechanism sessions whose frame pool is the provider allocation
(`XDEV_EXT_MECH_POOL_PEER`): stage 0 is an NVMe read into the pool, stage 1 an
NVMe write from it, with one CREATE, one NOTIFY_ARM and one START per session.
Cases, in one guest boot:

- `reject-map`: the provider refuses the DMA map. No command completes, no
  write is issued, `last_err` is `-EOPNOTSUPP`, no mapping is ever created.
  Every batch of the START aborts, nothing is sequestered and the session
  stays ACTIVE.
- `cli`: the product controller `xdev_ext_peer_chain --allocation-fd`
  (64 KiB frame, depth 1, 64 batches of 16 KiB).
- `depth4`: 4 KiB frames, two frames per batch, depth 4, 96 batches. A
  second CREATE on the claimed allocation must fail with `-EBUSY`.
- `stop-inflight`: 4 KiB frames, depth 4, 1024 batches; after START, bounded
  STATS polling must observe `submitted > completed` for a native stage and
  `inflight > 0` before STOP. STOP releases the
  session (0 or `-ECANCELED`, never `-EBUSY`), the mappings stay cached, and
  each destination group is the source group or untouched guard.
- `kill-inflight`: 4 KiB frames, depth 4, 512 batches, owned by a child
  process. The parent uses the same native-incomplete STATS observation before
  sending SIGKILL. Ring exit
  releases the session (STATS from another ring returns `-ENOENT`), the
  allocation can be claimed again, the mappings stay cached, and each
  destination group is the source group or untouched guard.
- `fd-release`: 32 KiB frames, depth 2, 8 batches; the ring and the last
  allocation fd are closed without STOP, and every provider pin and map must
  still be released. Before this run, a bounded CREATE probe retries only
  `-EBUSY` on the same ring/request until the previous owner's claim is released;
  STATS `-ENOENT` alone does not establish that the claim is reusable.

The two teardown cases retain the pre-action STATS snapshots in the console.
The host rejects missing, zero-submission, completed, or inconsistent native
observations. If no qualifying snapshot is observed, the case fails rather
than claiming teardown-inflight coverage. STATS reads individual fields, and
the snapshot and teardown are separate operations: completions can race either,
so the observation does not prove a command remains incomplete at the exact
STOP/SIGKILL instant. Only producer work may have been observed; therefore all
destination groups may legitimately remain guard bytes.
The submission counter increments before the class submit call and rolls back
on a pre-acceptance failure; this observation is not a hardware acceptance
certificate.

The guest compares both whole disks and the provider counters; afterwards
the host validator `session_validate.py` regenerates the source pattern and
compares the raw images QEMU wrote, checks the TAP stream (no `not ok`, no
skip, exact plan), the case plan, module unload, and the kernel console for
the debug report families rejected by `xdev_ext_mech_zc_debug.py`.

`session_kvm.sh` does not build a kernel. It takes a prebuilt kernel `O=`
directory and the tools directory of the KVM harness run that built it
(`xdev_ext_peer_chain`, `nvme_s0.bpf.o`, `peer-guest/xdev_ext_peer_sw.ko`) and
refuses to run unless the source checkout differs from that build's recorded
commit only inside this guest directory, the library selftests, `.gitignore`,
or the host workflow. Provider module source must still match the built copy.

    bash session_kvm.sh --scratch PRIVATE_0700_DIR --source CLEAN_CHECKOUT \
        --build KERNEL_O_DIR --tools HARNESS_TOOLS_DIR

`python3 -I session_validate_test.py` checks that the host oracle rejects
single-byte, guard, offset, source, TAP, plan, unload and kernel-report
mutations, as well as missing or invalid native-inflight observations.
`peer_session_observe_test.c` exercises bounded polling with controlled STATS
responses at the syscall boundary; it creates no device and runs no guest:

Set `HOST_TEST_OUT` to an existing private directory within the project.

    gcc -O2 -std=gnu11 -Wall -Wextra -Werror -iquote ../../../../../include/uapi \
        peer_session_observe_test.c -o "$HOST_TEST_OUT/peer_session_observe_test" -lbpf -lelf -lz
    timeout 10s "$HOST_TEST_OUT/peer_session_observe_test"

Not covered by the session test: real device memory, GPU copy engines, NIC
stages (the provider maps only for NVMe functions), IOMMU, unknown-DMA
quarantine, ambiguous or stale-ticket completions (the fixture can only
refuse a map, and QEMU NVMe completes every accepted command), a device reset
during a run, or any timing.

## Reset recovery test (`peer_reset_e2e`, `run-reset-guest.sh`, `reset_kvm.sh`)

Synchronous `XDEV_EXT_PEER_NVME_RW` reads whose outcome is UNKNOWN, and their
release by a proven NVMe Controller Reset. The UNKNOWN outcomes come from the
kernel's own fault injection, so the kernel needs
`CONFIG_FAULT_INJECTION_DEBUG_FS` and `CONFIG_FAIL_IO_TIMEOUT`: an injected
error status on a command QEMU completed (`fault_inject`), and a swallowed
completion that times out, is aborted, times out again and is cancelled by the
controller reset (`fail_io_timeout`). Each case is its own process:

- `control`: a completed read releases at owner close.
- `error-status`: the UNKNOWN region stays pinned and mapped through owner
  close, keeps the provider module loaded, survives a completed reset of the
  other controller and a wait, and is released once by the source
  controller's completed reset.
- `timeout-cancel`: the command cancelled inside the proven reset is released
  at owner close, with no further reset.
- `owner-open`: a region recovered while its owner holds it admits no new
  command (`-ESTALE`) and is released by the owner close.
- `session-error-status` (`peer_reset_session_e2e`, the mechanism-session
  path): a POOL_PEER session reads from the source controller into the
  allocation and writes to the other controller. The read gets an injected
  error status, the batch is sequestered and STOP quarantines the session
  (`-EBUSY`). The session stays parked (another ring's STATS still finds it
  as ZOMBIE) and the allocation stays pinned and mapped through closing every
  fd, a completed reset of the other controller (stage 1's device) and a wait;
  the source controller's completed reset releases the session (STATS
  `-ENOENT`) and every provider reference once. The provider is loaded with
  `host_backing=1` so that it describes its allocation as what it is (host
  RAM with struct pages) and the session's NVMe requester admission accepts
  it; without a description CREATE refuses the pool (`-EXDEV`).

The provider must then unload. `reset_validate.py` checks every case verdict
and its exact check count, the unload, the exit status and the kernel console
for the debug report families `xdev_ext_mech_zc_debug.py` rejects;
`python3 -I reset_validate_test.py` checks that it rejects single-defect
consoles. `reset_kvm.sh` builds only the two guest programs from an
assembled Linux tree (the fd program static, the session program dynamic,
with its libraries copied into the initramfs); `--tools` names a directory
with `nvme_s0.bpf.o` built against the same kernel's BTF:

    bash reset_kvm.sh --scratch PRIVATE_0700_DIR --linux ASSEMBLED_TREE \
        --build KERNEL_O_DIR --module KERNEL_O_DIR_MATCHED/xdev_ext_peer_sw.ko \
        --tools DIR_WITH_NVME_S0_BPF_O

This certifies the software release state machine against a QEMU controller
reset. It does not show that a physical controller stops DMA at reset, nor
anything about IOMMU or provider-side revocation.
