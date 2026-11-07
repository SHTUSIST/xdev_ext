# Actual kernel sharedpool custody qualification

`sharedpool_session_guest` uses two distinct single-stage USER sessions on one
ring and one IOU UMEM. It exercises real kernel borrowing, USER ready/completion,
CREATE_PROGRAMS reports and STOP_REPORT. It has no kernel model and performs no
NVMe/GPU DMA or performance measurement.

Build the optional target against the existing source view, built libxdev_ext
archive and benchmark support headers; it does not build a kernel or rebuild
the supplied archive:

```sh
make -C USER_GUEST_DIR KERNEL_SRC=KERNEL_VIEW \
  SHAREDPOOL_LIBXDEV=EXISTING_LIBXDEV_ARCHIVE \
  SHAREDPOOL_COMMON=BENCHMARK_COMMON_DIR sharedpool_session_guest
```

`BENCHMARK_COMMON_DIR` contains the existing `fd_check.h` (the logical view uses
`tests/eval/common`). Reuse the existing `chain_plan.bpf.o`; only its
`chain_user_ops` map is attached by the public library. CREATE_PROGRAMS uses the
global default selector `-1`, not an explicit PRIVATE link. This utility does
not qualify PRIVATE-program isolation.

```sh
./sharedpool_session_guest --case all --plan-obj CHAIN_PLAN_OBJECT
```

The cases can also run separately as `returned-stop` or `busy-start`:

- `returned-stop` completes A and proves its frame return, then keeps B's
  original USER grant held while A stops. B's live ticket, unique READY,
  frame/ring metadata, counters and every payload/guard byte must remain
  unchanged. B must then complete using its original batch successfully.
- `busy-start` keeps A held and requires B's same-frame START to return exactly
  EBUSY. A must remain unchanged and finish normally; B must then borrow and
  complete the same indices successfully.

The fixed layout uses a 4 KiB group across two noncontiguous frames with header
and tail guards. USER has a 60-second deadline; individual waits, hold observation
and the complete case use smaller bounded budgets. These clocks only enforce
correctness deadlines, and no elapsed-time or rate result is emitted. A syscall
that returns beyond its budget fails qualification.

Both sessions have independent validated report IDs and terminal eventfds.
Known USER grants are relinquished before normal STOP. Shared resources close
once after synchronous releases, and the complete FD check precedes the final
`SHAREDPOOL_KERNEL_QUALIFICATION=PASS` line. Unknown delivery or failed teardown
retains the owner and reports failure. Stderr contains case, ID and STOP
diagnostics; it does not turn cleanup success into a passed failed case.

The Python component test executes the utility's actual observation verdicts
without replacing syscalls. Its result does not prove these kernel cases ran.
The actual kernel qualification is complementary to the separate NVMe/CE
device coordinator and establishes neither sustained pipelining nor physical
device performance.
