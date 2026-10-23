# SPDK pipeline: partial host correctness port

This directory currently provides `plan` and `offline-check`. The latter runs
an ordinary regular file through an actual private loopback TCP connection,
then compares the complete captured stream against the reference. It has no
SPDK, DMA, physical-device or performance execution. The native modes reserve
the intended CLI and return unavailable (4); the native workload body, SDK
linkage and command-lifetime admission remain unfinished. The presence of
`bench_nvme_pipeline.c` does not certify a migrated native SPDK implementation.

The host fixture preserves the original QD1 xorshift* slot sequence, warmup,
one reused payload buffer and optional little-endian uint64 calculation. It
preallocates a guarded receiver buffer, handles partial TCP I/O and EINTR,
waits for actual receiver delivery, checks EOF and verifies every byte and both
guards after the producer/receiver finish. No hashes or byte oracle run per
transfer. Optional calculation remains a workload operation, with its result
checked afterward. No timing or speed result is emitted.

All modes require an explicit canonical PCI BDF, namespace ID, qualified sector
size and namespace/window geometry; these are metadata only in this partial
port. The reference file contains exactly the window bytes, with offset zero
representing `start-lba`. The namespace is never initialized or written. A
capture must be new; existing files and final-component symlinks are refused.

Example, with a separately prepared 16 KiB reference:

```sh
python3 run.py --mode offline-check --traddr 0000:01:00.0 --nsid 7 \
  --sector-size 512 --namespace-lbas 4096 --start-lba 101 --window-lbas 32 \
  --block-bytes 1024 --iterations 7 --warmup 2 --calc-bytes 24 \
  --reference reference.bin --capture new-received.bin
python3 test_contract.py -v
```

`--send-max` and `--recv-max` exercise short calls. Offline `--inject` accepts
`send-eintr,recv-eintr` and the payload, guard, EOF, extra-byte, stalled-receiver
and zero-send failure cases listed by the acceptance contract. The injection
adapters exercise the same transfer loops; they do not simulate a native
device. Help and plan need only Python. Offline-check additionally needs a C11
compiler, POSIX threads and Linux loopback sockets. Builds occur before the
workload in a temporary directory owned by that invocation. `CC` may select
the compiler and compiler flags. All runtime failures return 1, invalid inputs
return 2 and missing facilities return 4, without a success row.

The pending native implementation must use official SPDK headers and SDK
link flags, one DMA allocation reused for all operations, the explicit PCI
allowlist/namespace, qualified real geometry and no host reconfiguration. Its
UNKNOWN state must keep every accepted command's memory and callback ownership
until completion or documented definitive quiescence. A timeout, failed poll,
disconnect or process exit alone is insufficient. A strong reused-registration
baseline must remain distinct from any forced polling comparison. Physical
qualification and performance require a separately authorized isolated device;
no VM performance result qualifies.

Origin: the author's original `bench_spdk_nvme_pipeline.c`, raw SHA256
`a11c028d94ab62d1f42059aa9e2ffdd8ba0e7aa14c1ed9535e73fd4fb2e6dd69`,
Git blob `900a53e8f906cf1bffb53f8f0604d9f9e0a0b11c`. The original native source
is retained pending completion of this partial port. This adaptation preserves
its trace and workload shape; it replaces its unsafe host transport/oracle and
does not copy a fake SPDK ABI. The original has no file license notice; this
origin note does not infer or grant a new license for it.
