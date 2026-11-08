# NVMe LBA window handles: host and KVM guest tests

A process that holds a namespace (`/dev/ngXnY`, opened for write) issues a
window handle with `NVME_IOCTL_XDEV_EXT_WINDOW`: a new fd that names one LBA
range of that namespace and an access (read, write or both). A tenant that
receives the handle, for example over `SCM_RIGHTS`, presents it as the NVMe
stage fd of a mechanism session instead of the namespace node. The kernel then
binds the stage only inside the handle's range and only in a granted
direction, and admits every command the stage's program builds only inside
the stage window. Handles of one namespace that share an LBA are refused
unless both are read-only. A handle's range stays reserved until its last
reference goes; a session holds its stage file until it is released, and a
quarantined session keeps it for good, so a range is not issued again while
its previous owner may still write it.

Tenants are isolated from each other only when they receive handles and never
the namespace node: an fd of the node itself still binds any window and keeps
whole-namespace NVMe passthrough, as before.

## What the guest test checks

On real QEMU NVMe PCI with a kernel built from the commit under test
(correctness only, nothing timed, no hardware touched):

- issue errors: no or unknown access bit, nonzero reserved word, empty window,
  past capacity, and any handle from an fd that cannot write the namespace
  (a read-only handle too, because a handle reserves its range);
- handles of one namespace that share an LBA are refused (`-EBUSY`) unless
  both are read-only; adjacent handles and handles of another namespace are
  independent; a closed, unused handle frees its range; two threads issuing
  the same writable range at once get exactly one handle per round;
- an unprivileged tenant (uid 65534, cannot open either namespace node) that
  holds only handles for window W0:
  - cannot CREATE at the victim's window W1, a window straddling into it, a
    window one LBA longer, a READ outside its read handle (`-EACCES`), a WRITE
    on a read-only or a READ on a write-only handle (`-EBADF`); each refusal
    is reported by the class bind of the stage that presented the handle;
  - cannot use a handle for NVMe passthrough, to issue another handle, or to
    read or write data;
  - runs its session exactly inside its handles;
  - with a program that aims every command at the victim's window or across
    the window end, in either direction, gets every batch refused with
    `-ERANGE` before any command of that stage is submitted;
- the victim closes its only handle fds right after CREATE, victim2 right
  after START while its writes are still in flight (the runner rate-limits
  writes to the destination image with QEMU's own throttle so that the run
  outlasts the close): each session keeps its window and completes exactly,
  and the range stays reserved until the session is released;
- tenant2 exits with its session, ring and handles still open: its range stays
  reserved while it lives and is free once the kernel has released the
  session;
- the victim's bytes are unchanged after the tenant's attempts, and the raw
  namespace fds still bind any window as before;
- a whole-disk oracle in the guest and again on the host
  (`window_validate.py`, which checks itself first with
  `window_validate_test.py`).

## Multi-tenant mode (`--mode multi`, `window_multi.h`)

Four tenants share one namespace at the same time, each running its own
program, and one of them fails. The DST controller has two namespaces: ns1 is
the shared destination, ns2 a private source of the failing tenant (filled
with 0x3c, so nothing read from it may ever appear on ns1). Four rounds, four
tenant processes each. Every tenant loads its own BPF object (the guest checks
that the four struct_ops maps, build programs and links are distinct), sets
up its ring as root, receives a read and a write handle over `SCM_RIGHTS`,
drops to uid 65534, CREATEs, closes its handle fds and STARTs when the holder
says go. Tenant 0 fails; tenants 1 to 3 must complete 8/8 batches with no
abort, reject, timeout or sequester, STOP with 0 and be released, and their
windows must hold exactly their source windows:

- `kill`: tenant 0 is SIGKILLed after two batches completed, with more of its
  batches still to run; its range is free once the kernel released the
  session, and each of its groups is its own source group or guard;
- `escape`: tenant 0's write stage runs `escape_ops`, which aims odd keys at
  tenant 1's window and even keys across its own window end: every batch is
  refused with `-ERANGE` and no write is submitted;
- `unknown`: tenant 0 reads ns2 with the kernel's nvme `fault_inject` setting
  an error status on commands QEMU completed: its batches are sequestered,
  STOP quarantines the session (`-EBUSY`) and its range stays reserved;
- `timeout`: tenant 0 reads ns2 with `fail_io_timeout` swallowing every
  completion: STOP passes the 5 s drain bound with commands in flight
  (`-EBUSY`, release deferred) and its range stays reserved. After this last
  round, with nothing else running, the holder resets the DST controller:
  the reset cancels those commands, they end, and the deferred release frees
  the session and its range (so the guest can also power off).

The runner boots with `nvme_core.io_timeout=600`, so no command timeout fires
on its own and no controller reset happens while innocent tenants run; the
faults touch ns2 only. The kernel log must show exactly one quarantined
session (the `unknown` round) and one deferred release (the `timeout` round). `window_validate.py --multi` repeats the
whole-disk oracle on the host. Each round prints how its innocent tenants'
run overlapped the fault and requires at least one of them to be still
running when the fault began.

A controller reset is a different fault: it aborts every in-flight command of
every tenant on that controller, and a command timeout escalates to one
(`nvme_timeout`: abort, then reset on the second expiry). The NVMe class
(`class_complete` in `xdev_ext_mech_nvme.c`) treats a failed host-page command
as uncertain only when the request still carries residual bytes, so the
outcome depends on how the completion arrives: in the `timeout` round a
command cancelled by the reset ended as a definite failure, while the
`unknown` round's error status was sequestered. The `multi` mode keeps resets
out of the innocent tenants' runs. `--mode multi-reset` is a diagnostic, not
a gate: the same four tenants, with the holder resetting the DST controller
while the three innocent tenants still have commands in flight; the guest
prints one `XDEV_EXT_WINDOW_RESET_DIAG` line per tenant (batches done,
aborted, sequestered, STOP result, window exact) and the runner gates only on
the run and the kernel log. Observed on a strict-debug guest (2026-11-08): the reset
quarantined two of the three innocent tenants (their in-flight batches came
back as error completions with residual bytes and were sequestered, STOP
returned -EBUSY, their window ranges stay reserved); the third finished exact.
Isolation therefore does not yet hold across a shared-controller reset, and
any tenant's command timeout escalates to such a reset.

## Host tests (no kernel, no device)

- `host_tenant_matrix_test.py [ROOT]` compiles `host_tenant_matrix.c` against
  the unmodified product headers (`xdev_ext_storfam_core.h`,
  `nvme_xdev_ext_passthru.h`) under gcc and UBSan: four tenants with adjacent
  writable handles and overlapping read-only source handles on one namespace;
  the registry, bind admission of every tenant at every window, and the
  per-descriptor check of every group-sized SQE of every tenant from below
  tenant 0 to past tenant 3, plus the fields C owns. Each listed mutant of
  those headers must make it fail.

- `host_window_test.py [ROOT]` checks that the ioctl has its own `'N'` number
  in the product UAPI and outside the upstream-registered ranges, pastes the
  production window handle block and `nvme_xdev_ext_member_bind` verbatim
  into `host_window_fixture.c` (OS objects only), runs it under gcc and UBSan,
  and requires each of its listed production mutants to fail.
- `../../family_window_grant/run.sh ROOT OUT` and `mutate.py ROOT OUT` check
  the pure grant rules in `xdev_ext_storfam_core.h`.

## Running the guest test

On a host with KVM, from a clean checkout of the commit under test:

    bash tests/storage/nvme/window_handle/window_kvm.sh --scratch DIR \
        --source CANON --native ASSEMBLED_LINUX --build KERNEL_BUILD [--mode multi|multi-reset]

`DIR` must be an existing private 0700 directory. The kernel build needs the
config symbols listed in the runner. A kernel from another commit is accepted
only to show the test failing there; `provenance.txt` and `result.json` record
`kernel_is_test_commit` and whether the kernel sources equal the test
commit's.

## Not covered

The block class (`/dev/nvmeXnY`), multipath head nodes and the per-command
`F_XDEV_EXT_BUILD` uring_cmd path do not accept handles. Sessions of the raw
namespace fd are not entered in the registry. A handle cannot be revoked by its
issuer or narrowed into a smaller one. The guest's NVMe is QEMU's: these runs
show the software rules, not that a physical controller has stopped DMA.
