# NVMe LBA window handles: KVM guest test (prototype for ASK.69)

Prototype for the user's decision ASK.69; not to be merged before it.

What it checks, on real QEMU NVMe PCI with a kernel built from the commit
under test (correctness only, nothing timed, no hardware touched):

- issue errors of `NVME_IOCTL_XDEV_EXT_WINDOW` (no or unknown access bit,
  nonzero reserved word, empty window, past capacity, access the holder's fd
  does not have);
- handles of one namespace that share an LBA are refused (`-EBUSY`) unless
  both are read-only; adjacent handles and handles of another namespace are
  independent; a closed, unused handle frees its range;
- an unprivileged tenant (uid 65534, cannot open either namespace node) that
  holds only handles for window W0 cannot CREATE at the victim's window W1,
  a window straddling into it, a window one LBA longer, a READ outside its
  read handle (`-EACCES`), a WRITE on a read-only or a READ on a write-only
  handle (`-EBADF`); each refusal is reported by the class bind of the stage
  that presented the handle; inside its handles its session runs exactly;
- the victim closes its only handle fds right after CREATE: the session keeps
  its window and completes exactly, the range stays reserved (`-EBUSY`) after
  START and after the run settles, and is free only once the session is
  released;
- the victim's bytes are unchanged after the tenant's attempts, and the raw
  namespace fds still bind any window as before;
- a whole-disk oracle in the guest and again on the host
  (`window_validate.py`, which checks itself first with
  `window_validate_test.py`).

Host test of the same code without a kernel: `host_window_test.py [ROOT]`
pastes the production window handle block and `nvme_xdev_ext_member_bind`
verbatim into `host_window_fixture.c` (OS objects only), runs it under gcc
and UBSan, and requires each of its listed production mutants to fail.

Run the guest test on a host with KVM, from a clean checkout of the commit
under test:

    bash tests/storage/nvme/window_handle/window_kvm.sh --scratch DIR \
        --source CANON --native ASSEMBLED_LINUX --build KERNEL_BUILD

`DIR` must be an existing private 0700 directory. The kernel build needs the
config symbols listed in the runner. A kernel from another commit is accepted
only to show the test failing there; `provenance.txt` and `result.json` record
`kernel_is_test_commit`.
