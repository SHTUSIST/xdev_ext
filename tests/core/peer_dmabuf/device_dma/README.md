# dma-buf device DMA guest test

This test runs only inside a private KVM guest. It checks that a dma-buf
exported by the kernel's system heap, imported through `/dev/xdev_ext_peer`
with `XDEV_EXT_PEER_REGISTER_F_DMABUF`, is read and written by real QEMU NVMe
PCI DMA, both through the synchronous `XDEV_EXT_PEER_NVME_BATCH` ioctl and as
the `XDEV_EXT_MECH_POOL_PEER` frame pool of a mechanism session. No provider
fixture, device stand-in or GPU is involved; nothing measures time.

## Cases (one guest boot)

- `batch-read`: 16 NVMe READ commands of 4 KiB each land in the dma-buf in
  reverse LBA order. The guest compares the CPU view of the dma-buf (mmap
  with `DMA_BUF_IOCTL_SYNC`) with the source pages and prints its FNV-1a
  hash, which the host recomputes from the source image.
- `batch-write`: the CPU fills the dma-buf with a fixed pattern and 16 NVMe
  WRITE commands copy it to the destination disk.
- `chain`: a POOL_PEER session on a second dma-buf, stage 0 NVMe read and
  stage 1 NVMe write, one START for 96 groups of 8 KiB. `STAGE_CAPS` must
  report the storage family, `HOST_DMA_MAPPED` reachability, an established
  requester mapping and `HOST_SYSTEM | STRUCT_PAGE` backing for both stages.
- `exporter-close`: the dma-buf fd returned by the heap is closed after STATS
  has observed native NVMe commands submitted but not completed. The importer
  holds its own buffer reference, so every one of 1024 groups must still
  complete exactly, and the MEMLOCK charge stays until the allocation fd
  closes.
- `kill`: a child process allocates and imports its own dma-buf, starts a
  512-group session and is killed with SIGKILL after native commands were
  observed in flight. With the soft MEMLOCK limit set to exactly the victim's
  export plus one more, a further import fails with `ENOMEM` while the child
  lives and succeeds after its exit, which shows the dead importer's charge
  was returned. Each destination group must be its source group or untouched
  guard bytes.
- `victim`: before the child starts, the parent imports a separate dma-buf and
  starts a 1536-group session on it. STATS taken just before the kill must
  show it still running; after the kill it must still complete every group
  exactly, and its accounting and attachments follow the same rules as below.

For `batch`, `chain`, `exporter-close` and `victim`, `VmPin` must rise by exactly the
64 KiB export while the allocation fd is open and return after it closes.
The dma-buf debugfs file `bufinfo` must list both NVMe PCI functions as
attached devices while the buffer is registered (one attachment per
requester), and must no longer list the buffer after its last reference is
gone.

STATS sampling and the following close or kill are separate operations, so
the observation does not prove that a command was still incomplete at the
exact instant of the close or kill. QEMU NVMe completes every accepted
command, so the "result unknown, retain forever" path is not reachable
here; the test checks release after completion, not quarantine.

## Running

`dmabuf_dma_kvm.sh` builds no kernel. It takes a kernel `O=` directory with
`CONFIG_DMABUF_HEAPS_SYSTEM=y`, `CONFIG_XDEV_EXT_PEER_DMABUF=y` and
`CONFIG_DEBUG_FS=y`, the directory holding the BTF-matched `nvme_s0.bpf.o`,
and a clean canonical checkout that differs from the build's recorded commit
only in test inputs outside the kernel and the BPF object:

    bash tests/core/peer_dmabuf/device_dma/dmabuf_dma_kvm.sh --scratch PRIVATE_0700_DIR \
        --source CLEAN_CHECKOUT --build KERNEL_O_DIR --tools TOOLS_DIR [--viommu]

The build directory must contain `xdev-ext-source.commit` and
`xdev-ext-artifacts.sha256` (absolute paths of the bzImage and
`nvme_s0.bpf.o`); the runner verifies both before booting.

`--viommu` puts an emulated Intel VT-d (`intel-iommu,intremap=on,caching-mode=on`,
`kernel-irqchip=split`) in front of both NVMe controllers and boots the guest
with `intel_iommu=on iommu.strict=1`. The host oracle then also requires DMAR
enabled, translated domains with strict invalidation, each NVMe function in
its own IOMMU group and no DMA remapping fault. Without `--viommu` it requires
that DMAR is not enabled.

The host oracle `validate.py` regenerates the 32 MiB source image, rebuilds
the whole expected destination image from its own copy of the plan, and
checks the TAP stream (no `not ok`, no skip, exact plan), the observations
above and the kernel console with the debug-report detector of the KVM
harness. `python3 -I validate_test.py` mutates a correct run one fact at a
time and requires the oracle to reject each mutation; it boots nothing.

Not covered: device memory other than host RAM, exporters other than the
system heap, fences, an exporter that moves or revokes the buffer, unknown
DMA quarantine, and any timing.
