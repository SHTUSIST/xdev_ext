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

The cases can also run separately:

- `returned-stop` completes A and proves its frame return, then keeps B's
  original USER grant held while A stops. B's live ticket, unique READY,
  frame/ring metadata, counters and every payload/guard byte must remain
  unchanged. B must then complete using its original batch successfully.
- `busy-start` keeps A held and requires B's same-frame START to return exactly
  EBUSY. A must remain unchanged and finish normally; B must then borrow and
  complete the same indices successfully.
- `duplicate-start` repeats A's START while A still holds its original grant.
  The repeated START must return exactly EBUSY, leave B idle and preserve A's
  original ticket, metadata, data and guards. A then returns the frames for B.
- `concurrent-start` releases two control threads from one launch gate to START
  A and B on the same indices. Exactly one START must succeed and the other
  must return EBUSY. The winner keeps its grant until both calls have returned;
  the loser stays idle, then borrows and completes the frames after the winner
  finishes. The winning thread may vary; the required result does not. Same-ring
  registration is serialized by `uring_lock`; this case does not exercise
  simultaneous cross-ring custody CAS operations.
- `stale-completion` completes A, lets B hold the returned frames, then posts
  A's saved completion again to A's own USER stage fd. A must consume and
  reject exactly that duplicate without another terminal notification or
  another completed batch. B's original grant and every payload/guard byte
  must remain unchanged, and B must complete successfully.
- `early-stop` holds A's frames `{1,4}` and B's disjoint frames `{2,5}` at the
  same time. A's CPU owner stops all payload access, then STOP cancels A's
  held batch, clears A's ticket and reports its frame return. B must keep its
  original grant, metadata, bytes and guards and complete successfully.

The layout uses a 4 KiB group across two noncontiguous frames with header
and tail guards. Each observation verifies the exact indices requested for that
session, including the disjoint layout in `early-stop`. USER has a 60-second
deadline; polling and hold observation use smaller budgets, and the case budget
starts after setup. These clocks only determine correctness failures, and no
elapsed-time or rate result is emitted. A syscall that returns beyond its budget
fails qualification. The budget cannot interrupt a blocked ioctl or thread join;
use an outer guest/VM watchdog to detect hangs and preserve diagnostics.

Both sessions have independent validated report IDs and terminal eventfds.
Known USER grants are relinquished before normal STOP. The `early-stop` case
instead tests cancellation after the CPU owner has quiesced. Shared resources close
once after synchronous releases, and the complete FD check precedes the final
`SHAREDPOOL_KERNEL_QUALIFICATION=PASS` line. Unknown delivery or failed teardown
retains the owner and reports failure. Stderr contains case, ID and STOP
diagnostics; it does not turn cleanup success into a passed failed case.

The Python component test executes the utility's actual observation verdicts,
including acceptance of the requested disjoint layout and rejection of the wrong
layout. It executes no syscalls or device operations and does not prove these
kernel cases ran.
The actual kernel qualification is complementary to the separate NVMe/CE
device coordinator and establishes neither sustained pipelining nor physical
device performance.

These cases use non-strict USER stages. STOP and deadlines can cancel their
grants, but cannot revoke a CPU thread's raw mapping of IOU_UMEM. An application
that keeps storing through an old payload pointer can corrupt a new owner's
bytes. `early-stop` therefore proves cancellation and isolation between
cooperating owners; it does not prove protection from a CPU writer after STOP.
Likewise, completion tickets are scoped to their USER stage fd, not transferable
cross-session credentials. Strict asynchronous USER UNKNOWN/quarantine and late
device completions require their separate lifecycle tests.
