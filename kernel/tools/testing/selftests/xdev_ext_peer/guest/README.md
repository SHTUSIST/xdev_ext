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
- `stop-inflight`: 4 KiB frames, depth 4, 1024 batches; STOP right after
  START while NVMe commands on the allocation are accepted. STOP releases the
  session (0 or `-ECANCELED`, never `-EBUSY`), the mappings stay cached, and
  each destination group is the source group or untouched guard.
- `kill-inflight`: 4 KiB frames, depth 4, 512 batches, owned by a child
  process that is killed with SIGKILL before the START ends. Ring exit
  releases the session (STATS from another ring returns `-ENOENT`), the
  allocation can be claimed again, the mappings stay cached, and each
  destination group is the source group or untouched guard.
- `fd-release`: 32 KiB frames, depth 2, 8 batches; the ring and the last
  allocation fd are closed without STOP, and every provider pin and map must
  still be released.

The guest compares both whole disks and the provider counters; afterwards
the host validator `session_validate.py` regenerates the source pattern and
compares the raw images QEMU wrote, checks the TAP stream (no `not ok`, no
skip, exact plan), the case plan, module unload, and the kernel console for
the debug report families rejected by `xdev_ext_mech_zc_debug.py`.

`session_kvm.sh` does not build a kernel. It takes a prebuilt kernel `O=`
directory and the tools directory of the KVM harness run that built it
(`xdev_ext_peer_chain`, `nvme_s0.bpf.o`, `peer-guest/xdev_ext_peer_sw.ko`) and
refuses to run unless the source checkout differs from that build's recorded
commit only inside this directory.

    bash session_kvm.sh --scratch PRIVATE_0700_DIR --source CLEAN_CHECKOUT \
        --build KERNEL_O_DIR --tools HARNESS_TOOLS_DIR

`python3 -I session_validate_test.py` checks that the host oracle rejects
single-byte, guard, offset, source, TAP, plan, unload and kernel-report
mutations.

Not covered: real device memory, GPU copy engines, NIC stages (the provider
maps only for NVMe functions), IOMMU, unknown-DMA quarantine, ambiguous or
stale-ticket completions (the fixture can only refuse a map, and QEMU NVMe
completes every accepted command), a device reset during a run, or any
timing.
