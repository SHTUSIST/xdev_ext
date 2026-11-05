# Concurrent multi-page peer NVMe batch guest test

This test runs only inside a private KVM guest. It checks the synchronous
`XDEV_EXT_PEER_NVME_BATCH` ioctl after the 42-PEER-BATCH and 42-RANDOM
changes: one descriptor is one NVMe command that may span provider pages,
the whole list is admitted before any command reaches the device, and the
commands of one batch may be in flight together. The device memory is a
dma-buf exported by the kernel's system heap and imported through
`/dev/xdev_ext_peer` with `XDEV_EXT_PEER_REGISTER_F_DMABUF`. The disks are
three QEMU NVMe controllers with `mdts=8`, so one command can carry 1 MiB.
No provider fixture, device stand-in or GPU is involved, and nothing
measures time.

## Phases (one guest boot)

- Pool setup: 32 dma-bufs of 1 MiB are allocated and every other one is
  freed, then the 6 MiB + 68 KiB pool is allocated and imported. One probe
  read per MiB runs with the `xdev_ext:native_event` tracepoint enabled; its
  `peer_dma_span` events give the DMA address the controller received for
  every 4 KiB page. There must be at least one DMA discontinuity inside the
  window [4 MiB + 128 KiB, end - 64 KiB]; the first one is the boundary used
  in A3. (`/proc/self/pagemap` cannot be used: the system heap maps the
  buffer with `remap_pfn_range`, and pagemap reports such ranges as holes.)
- A: one 1 MiB read (the NVMe tracepoints must show one 2048-LBA command),
  three 1 MiB reads in one batch out of address order (three commands, at
  least two outstanding at once), and three reads across the DMA
  boundary and inside page tails. The whole pool is compared in the guest
  and dumped to the destination disk.
- B: 40 random disjoint read targets in shuffled order, two of them reading
  the same source LBA as a third. 40 commands, at least two outstanding at
  once; the pool is compared and dumped.
- C: the CPU fills the pool, then a 1 MiB write and 32 random disjoint LBA
  write targets whose sources may overlap.
- D: nine refusals (duplicate target, overlap at the last index, write LBA
  overlap, target past the pool, LBA past the namespace, u64 wrap of the
  device-memory span and of the LBA, wrong generation, request above the
  transfer limit). Each must return its errno with `completed == 0`, and
  the tracepoints must show no command on any controller; the pool and the
  destination must be unchanged.
- E: the third controller's QEMU block backend fails reads of one sector
  (`blkdebug`), and its I/O queues hold one command (`mqes=1`); the guest
  program runs on CPU 0, so it uses one of those queues. A six-request read
  batch into a separate 1 MiB dma-buf, whose third request covers the
  failing sector, must return the native NVMe status with
  `completed == 2`. Each request allocation waits for the previous
  completion, so the failure is seen before the fourth request is issued:
  exactly three commands, one at a time, the failed one once, and the last
  three requests untouched (a partial accept). The allocation must then be
  refused (`ESTALE`); after its fd is closed, the MEMLOCK charge and the
  requester attachment stay, and importing the same dma-buf again fails with
  `EBUSY`. Closing the pool's own allocation fd returns its charge and drops
  its attachments.

The host oracle `validate.py` regenerates the three disk images, rebuilds
the plan on its own (the random phases from the same generator, A3 from the
boundary the guest reported), and compares the whole 64 MiB destination
image byte for byte, including every guard byte. It also checks the TAP
stream, the command counts and outstanding counts read from the
tracepoints, the refusal and UNKNOWN observations, and the kernel console
with the debug-report detector of the KVM harness. `python3 -I
validate_test.py` mutates a correct run one fact at a time and requires the
oracle to reject each mutation; it boots nothing.

The tracepoints give the order of submissions and completions only; the
number of commands outstanding at once and the count of completions that
overtook an earlier submission are observations, not performance results.
The oracle also takes the number of issued requests of phase E from the
tracepoints and requires exactly three.

## Running

`peer_batch_kvm.sh` builds no kernel. It takes a kernel `O=` directory with
`CONFIG_DMABUF_HEAPS_SYSTEM=y`, `CONFIG_XDEV_EXT_PEER_DMABUF=y`,
`CONFIG_DEBUG_FS=y` and `CONFIG_EVENT_TRACING=y`, and a clean canonical
checkout that differs
from the build's recorded commit only in test inputs outside the kernel:

    bash tests/storage/nvme/peer_batch/peer_batch_kvm.sh --scratch PRIVATE_0700_DIR \
        --source CLEAN_CHECKOUT --build KERNEL_O_DIR

The build directory must contain `xdev-ext-source.commit` and
`xdev-ext-artifacts.sha256` (absolute path of the bzImage); the runner
verifies both before booting.

Not covered: GPU memory, an IOMMU, exporters other than the system heap,
fences, a device reset during a batch, and any timing. A partial accept
caused by a request-allocation error cannot be produced in the guest; the
host test `tests/network/peer/session/xdev_ext_peer_batch_test.py` covers
it, together with chosen completion orders and cancellation.
