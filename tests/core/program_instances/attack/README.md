# Attacker-brought program isolation

Real-kernel (KVM guest) correctness evidence that one session loading its own
PRIVATE mechanism program cannot hurt another session that shares the same
devices. A VICTIM session (NVMe READ source window to NVMe WRITE destination
window) and an ATTACK session run concurrently over the same two QEMU NVMe
namespaces; both select programs through `CREATE_PROGRAMS`, so they run
different programs over the same device at once. Correctness only, nothing is
timed, and no virtual device model is added: the attacks are ordinary PRIVATE
programs plus a stalling user thread and a link detach.

Each attack keeps a valid session topology but crosses one boundary the kernel
enforces, and must stop the ATTACK session with its declared reason while the
VICTIM completes with zero aborts and a byte-exact destination window:

| case     | what the attacker's program does              | declared reason |
|----------|-----------------------------------------------|-----------------|
| reserved | valid in-window WRITE SQE, one reserved dword | `-EPERM`        |
| outside  | WRITE SQE one window past its LBA window       | `-ERANGE`       |
| frame    | reads frame bytes past the frame (host-frame)  | `-EPROTO`       |
| verdict  | returns an illegal build verdict               | `-ECANCELED`    |
| user     | an attacker USER stage thread never completes  | `-ETIMEDOUT`    |
| detach   | detaches its own PRIVATE link mid-run          | `-ECANCELED`    |

The destination windows of the victim and every attacker are disjoint, so the
kernel clamps every attacker SQE to the attacker's own window. After all six
cases, the guest and the host validator (`attack_validate.py`) each compare the
whole destination disk against an independent expected image: the victim window
is an exact copy of the source read window, every byte outside it is guard, and
only the detach attacker window may additionally hold completed source groups.
No attacker byte reaches the victim window, and no batch is sequestered.

The frame-window attack uses the host-frame variant (`POOL_IOU_UMEM`); a
peer/VRAM pool is not required, so no provider module is loaded.

## Running

The test adds no kernel code, so it runs against a prebuilt kernel the caller
owns. `--build` is a kernel build directory (a `bzImage` and a `vmlinux` BTF),
`--native` the assembled native source tree that produced it (its UAPI headers
and `libxdev_ext`), and `--source` the canonical Git root the test files come
from. The kernel needs `CONFIG_XDEV_EXT_MECH=y` with the NVMe and USER classes;
`CONFIG_XDEV_EXT_MECH_CPU` is not required.

```sh
bash attack_kvm.sh --scratch /abs/private-0700 --source /abs/canonical \
    --native /abs/assembled/linux --build /abs/kernel-build
```

Build in a private output directory first with the standalone `Makefile`
(`KERNEL_SRC=<native tree>`, `VMLINUX_BTF=<build>/vmlinux`) to check the guest
and the six BPF objects compile; a successful build does not certify runtime
behaviour. The userspace driver uses GCC; only the mandatory BPF bytecode uses
clang. Evidence (compiler commands, QEMU command, guest log, whole-disk oracle,
artifact hashes, provenance) is written under the scratch's `evidence/`.
