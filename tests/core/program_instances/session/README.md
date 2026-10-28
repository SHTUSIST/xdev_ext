# Session-selected mechanism programs: host tests

These tests exercise the additive CREATE_PROGRAMS operation while preserving
CREATE_REPORT delivery, rollback and retention semantics. They are correctness
tests; no output is a physical-DMA or performance result.

Run from the source checkout:

```sh
python3 tests/core/program_instances/session/run.py --output /absolute/private/output/core
python3 tests/core/program_instances/session/run.py --suite library --output /absolute/private/output/library
python3 tests/core/program_instances/session/selection_run.py --output /absolute/private/output/selected
```

`--source-root` selects an independently prepared checkout. The runner reads its
source-layout mapping and materializes private headers; it does not change the
shared prepared source view. GCC compiles the actual selected production bodies
with undefined-behavior checking. Compiler/linker errors are SETUP_ERROR, not a
behavioral failure.

The core suite compiles the actual CREATE, requester bind, session bind,
admission, report delivery and release bodies. Its seven cases cover default
selectors, second PREPARE failure, UNKNOWN rollback retention, failed report
copyout, unused selectors, malformed outer size and unchanged pool rejection.
It reuses the qualified admission-report host device/OS/PREPARE boundary.
All valid selectors in this suite are -1. Any call into its private instance
boundary aborts, so this suite cannot certify private instance lookup or BPF
execution. The separate actual-kernel guest provides the stage-selection and
payload oracle.

The library suite compiles the actual session library and injects only its
syscall boundary. It checks wire fields, one-attempt/no-fallback behavior,
malformed report rejection, explicit input rejection and retention through the
session API even with an omitted public report. It deliberately leaves the
retained test handle alive at process exit. It does not claim a real kernel
retention allocation or a real BPF link.

`wire.h` is an independent frozen declaration: opcode12, request offset24,
wrapper520, old envelope496, old STAGE_DIAG11. On the original implementation,
the compiled default-delivery case reached actual dispatch and failed because
opcode12 returned -EINVAL. Preserve that behavioral RED separately from later
setup errors or successful runs.

The selected composition compiles the actual private instance component,
session binding, stage/member selection, admission, stop reason, exact-instance
withdrawal, callback identity/invocation/frame_rw and release functions. Its
host environment supplies kernel primitives, BPF reference operations and a
CPU class/PREPARE boundary; it never supplies selected-instance lookup or
liveness success functions. It checks two repeated-class private sessions plus
default, real sealed callback payloads and complete frame guards, global default
changes, same-map sibling isolation, reattach without resurrection, partial
selector/PREPARE failures and UNKNOWN selected-pin retention until safe release.
A controlled copyout boundary withdraws a selected link before publication;
the actual common CREATE final check must prevent admission and record cancellation.
The test records and balances each selected ops pin and temporary link reference.
Single-threaded host primitives do not prove actual kernel mutex/RCU behavior,
accepted DMA custody or the C_REFERENCE module-pin implementation.
