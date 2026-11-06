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
  after START: each session keeps its window and completes exactly, and the
  range stays reserved until the session is released;
- tenant2 exits with its session, ring and handles still open: its range stays
  reserved while it lives and is free once the kernel has released the
  session;
- the victim's bytes are unchanged after the tenant's attempts, and the raw
  namespace fds still bind any window as before;
- a whole-disk oracle in the guest and again on the host
  (`window_validate.py`, which checks itself first with
  `window_validate_test.py`).

## Host tests (no kernel, no device)

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
        --source CANON --native ASSEMBLED_LINUX --build KERNEL_BUILD

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
