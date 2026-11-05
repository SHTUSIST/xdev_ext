# Undescribed dma-buf exporter guest test (prototype for ASK.70)

This test runs only inside a private KVM guest. It checks the opt-in import of a
dma-buf whose exporter registered no xdev_ext backing descriptor. The exporter
is the upstream `udmabuf` driver (a memfd turned into a dma-buf); it has no
`pin` operation and maps each attaching device with `dma_map_sgtable`. The
requesters are two QEMU NVMe controllers driven through the
`XDEV_EXT_PEER_NVME_BATCH` ioctl. No provider fixture, device stand-in or GPU
is involved; nothing measures time.

## Cases (one guest boot per mode)

Both modes first check that the default `REGISTER` with only
`XDEV_EXT_PEER_REGISTER_F_DMABUF` still fails with `EOPNOTSUPP` for this
exporter, that the opt-in bit without `F_DMABUF` and the reserved bit 1 fail
with `EINVAL`, that none of these refusals charges `VmPin`, and that the opt-in
import returns a CLOEXEC allocation fd, charges exactly the 64 KiB export and
refuses a duplicate with `EBUSY`. Both modes end by closing the allocation fd,
requiring `VmPin` back at its baseline and the buffer gone from the dma-buf
debugfs `bufinfo`, then importing and releasing a second udmabuf.

- `normal`: 16 NVMe READ commands of 4 KiB land in the buffer in reverse LBA
  order and the guest compares the memfd view with the source formula;
  `bufinfo` then lists exactly the source NVMe function. The CPU writes a
  pattern and 16 NVMe WRITE commands copy it to the destination disk; `bufinfo`
  then lists exactly two attachments, one per NVMe function. The application
  unmaps and closes the memfd and the udmabuf fd; the charge stays, and a
  further READ and WRITE through the allocation fd still copy another source
  range to the destination.
- `refuse`: the guest boots with `swiotlb=force`. Both batches must fail with
  `EXDEV` and zero completed commands, the buffer must keep its fill bytes,
  `bufinfo` must list no attachment (the requester was refused before the
  exporter was asked to attach), and the destination disk must stay zero.

The host oracle `validate.py` requires the exact check-id list for the mode,
the TAP plan and `RESULT` lines, the guest exit code, the two batch results,
the boot command line (`swiotlb=force` exactly in `refuse`, `intel_iommu=on`
exactly with `--viommu`), the IOMMU group of both NVMe functions (present
exactly with `--viommu`), the unmodified source image, the whole destination
image rebuilt from its own plan, and a kernel console without debug reports
(`tests/integration/session/native/xdev_ext_mech_zc_debug.py`).
`python3 -I validate_test.py` mutates a correct run one fact at a time and
requires the oracle to reject each mutation for its own reason; it boots
nothing.

## Running

`undescribed_dma_kvm.sh` builds no kernel. It takes a kernel `O=` directory
with `CONFIG_UDMABUF=y`, `CONFIG_XDEV_EXT_PEER_DMABUF=y`, `CONFIG_DEBUG_FS=y`
and `CONFIG_SWIOTLB=y`, and a clean canonical checkout whose HEAD differs from
the build's recorded commit only in test inputs:

    bash tests/core/peer_dmabuf/undescribed_dma/undescribed_dma_kvm.sh \
        --scratch PRIVATE_0700_DIR --source CLEAN_CHECKOUT --build KERNEL_O_DIR \
        [--mode normal|refuse] [--viommu]

The build directory must contain `xdev-ext-source.commit` and
`xdev-ext-artifacts.sha256` (with the absolute bzImage path). The runner
records `uptime` and the host QEMU process list before and after the guest.
`--baseline-kernel` accepts a kernel built from an ancestor commit, to observe
the behaviour before the feature (a RED run); such a run is labelled
`BASELINE` and its verdict is always FAIL.

Not covered: exporters with a `pin` operation (dynamic exporters), an
exporter that calls `move_notify`, device memory, fences, unknown-DMA
quarantine, mechanism sessions (`STAGE_CAPS` reporting) and any timing. The
host importer cases in `../importer_cases.c` cover move_notify, quarantine and
admission for this path.
