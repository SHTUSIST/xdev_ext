# IAA syscall contract gate

This MIT-licensed gate moves and adapts the historical
`test_iaa_unified_ops.c` (original SHA-256
`b38e590f25c93b7c8b3118330522c21f141b2758be46f18ff5d5be1b9a685691`).
It retains the deterministic 9KiB plaintext, raw-DEFLATE generation and five
native syscall cases. The old copy has been retired. This is an adapted source
migration, not a byte-identical move.

The program includes the current canonical io_uring UAPI and the maintained
`mini_liburing` helper. It requires Linux, a C compiler, make and zlib development
headers/library; an installed liburing and the kernel selftest `lib.mk` are not
required. Build commands work in the public source overlay.

```sh
make -C tests/iaa
make -C tests/iaa check
./tests/iaa/test_iaa_unified_ops --preflight
./tests/iaa/test_iaa_unified_ops
```

`check` runs host observation and lifetime-control fixtures. It rejects incorrect
CQE identity/flags, produced length, complete output bytes, source/guard/tail
changes and statistics, plus timeout and premature cleanup. It neither submits a
device request nor emulates IAA execution. It cannot certify actual DMA or speed.

Preflight returns **4** when 4KiB physical pages, a registered `deflate-iaa`
CryptoAPI driver, io_uring access or the canonical unified opcode are unavailable.
It performs read-only provider discovery and ring capability probing; it does not
load modules or enable work queues. A preflight exit **0** means these prerequisites
are visible; it does not mean the decompression cases ran. Set up the custom
kernel, registered provider and usable device queues before running the gate.

The native gate returns **0** only after all five cases pass, **1** for a failed
contract/cleanup or unknown ownership, and **2** for invocation/local setup errors.
Once preflight succeeds, an unexpected `EINVAL`, provider disappearance or invalid
UMEM registration is a failure, never a skip. Run the executable directly to retain
these exit values; make may report its own recipe-failure exit value.

| Case | Native result and checks |
| --- | --- |
| A | Exact 9KiB produced count, all output bytes, exact success statistics, unchanged source/guards/tail |
| B | Exact `-EOVERFLOW`, error statistics and no writes beyond the 256-byte capacity |
| C | Source range exceeds UMEM: exact `-EINVAL`, error statistics, all UMEM unchanged |
| D | Zero input length: exact `-EINVAL`, error statistics, all UMEM unchanged |
| E | Destination exceeds UMEM: exact `-EINVAL`, error statistics, all UMEM unchanged |

Every case owns a fresh ring and UMEM registration. Logical frames are 16KiB so a
16KiB output window is admitted, while the 9KiB plaintext still spans three actual
4KiB pages. This avoids reusing the successful case's READY output. Decompression
uses canonical sub-opcode 5 rather than the old local 4; the ring opcode is never
hardcoded. Case B uses the current provider's `EOVERFLOW` contract rather than the
historical draft's `ENOSPC` expectation. Each completion has a unique exact cookie,
with no continuation flag, and a five-second bounded wait.

A terminal CQE precedes UMEM unregister, ring close and user-memory release. On an
unknown completion/timeout the program explicitly avoids unregister/free/unmap and
terminates; the kernel must retain request/page references through process teardown.
That termination does not prove an unresponsive device has quiesced.

Even a passing native gate certifies the **CryptoAPI syscall contract** only.
The IAA CryptoAPI driver can fall back to software for some streams/errors; a
registered driver or correct decompressed bytes do not prove physical IAA DMA.
Device/provider tracing or appropriate native counters are required to attribute
execution to hardware. No physical IAA execution or performance result is claimed
by this migration or the host fixtures.
