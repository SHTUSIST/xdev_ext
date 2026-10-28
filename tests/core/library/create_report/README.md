# CREATE_REPORT library and ctl contracts

Run `python3 tests/core/library/create_report/run.py --out /absolute/output/path` from the repository root. The runner builds isolated copies of the normal library and ctl sources using the canonical layout mapping. A compatible installed libbpf is required for ctl; `--libbpf-build DIR` can reuse an existing libbpf build containing `include/bpf/` and `libbpf.a`.

The C cases call normal library APIs and replace only their external syscall boundary. The ctl cases execute the real `cpu-chain` command and wrap external open/ioctl/io_uring syscalls. These tests cover op 10 report delivery, malformed schema rejection, cleanup ownership, old CREATE packing and diagnostic failure output. A library error without a delivered report clears `out`; a delivered negative CREATE result keeps its full value report. Retained authority is intentionally left alive until the test process exits.

Runner exit 0 means the bounded contracts passed, 1 means a behavior assertion failed, and 2 means compilation or linking failed. The output includes the build log, TAP, ctl transcripts, input list and verdict. The tests do not establish kernel admission correctness, describe count, STAGE_DIAG, DMA behavior or performance. Initial execution against an API that already exists is independent conformance, not a fabricated feature RED.
