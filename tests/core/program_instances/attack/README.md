# Attacker-brought program isolation

Real-kernel (KVM guest) correctness evidence that one session loading its own
PRIVATE mechanism program cannot hurt another session that shares the same
devices. A VICTIM session (NVMe READ source window to NVMe WRITE destination
window) and an ATTACK session run over the same two QEMU NVMe namespaces; both
select programs through `CREATE_PROGRAMS`, so they run different programs over
the same device at once. Correctness only, nothing is timed, and no virtual
device model is added: the attacks are ordinary PRIVATE programs plus a user
thread and a link detach.

Each attack keeps a valid session topology but crosses one boundary the kernel
enforces. The victim must complete every batch with zero aborts, and the
attacker must end with its declared reason:

| case          | what the attacker's program does                                   | declared reason |
|---------------|--------------------------------------------------------------------|-----------------|
| reserved      | valid in-window WRITE SQE with one reserved dword set               | `-EPERM`        |
| outside       | WRITE SQE one window past its own window, which is the victim's LBAs | `-ERANGE`       |
| outside-after | the same, started only after the victim wrote its window             | `-ERANGE`       |
| frame         | reads frame bytes past the frame (host-frame window)                 | `-EPROTO`       |
| verdict       | returns an illegal build verdict                                     | `-ECANCELED`    |
| user-stall    | its USER stage thread never completes a batch                        | `-ETIMEDOUT`    |
| detach        | detaches its PRIVATE write link while a batch is in flight           | `-ECANCELED`    |

For the first six cases every attacker batch ends (refused, failed or timed
out), the attack session stays ACTIVE with `last_err` latched to the declared
reason, and the user STOP returns that reason. For the refused SQEs the write
stage counts no native submission. In the detach case the attacker runs NVMe
READ to USER to NVMe WRITE; its user thread completes two batches and holds
every later one, the victim STARTs, and the attacker detaches its write-stage
link. The retraction stops the attack session with `-ECANCELED`: exactly two
batches are written, the batches in flight are cancelled, the rest are never
admitted, and a new
valid START is refused with `-ESHUTDOWN` (a START with mismatched frame counts
fails its argument check with `-EINVAL` first, so the two are told apart).

## Whole-disk oracle

The source disk is position-unique: the 8-byte word at byte offset `o` holds
`low32 = ((o / 512) << 7) | (((o % 512) / 8) << 1) | 1` and `high32` = a random
per-run seed. Every case has its own windows (64 LBAs each): on the destination
the attacker window `3c` sits directly below the victim window `3c+1`, followed
by a spare window `3c+2`; on the source the victim reads window `2c` and the
attacker window `2c+1`. The two OUTSIDE attackers are bound at `3c`, so their
refused SQEs (one window past their own) target the victim's LBAs. Nothing
later overwrites a case's victim window.

After all cases, the guest and the host validator (`attack_validate.py`) each
compare every byte of the destination with an expected image: each victim
window is an exact copy of its victim's source window; the detach attacker
window holds exactly its two completed groups, each its own source group at
its own slot, and guard elsewhere; every other byte is guard. Because every
source word is unique to its position, attacker bytes in a victim window,
victim groups from the wrong place or order, and misplaced detach groups all
fail. The validator recovers the seed, regenerates the whole source image and
requires the source image to equal it. `attack_validate_test.py` checks the
validator itself (run by `attack_kvm.sh` before boot).

## Scope

- The kernel boundary tested is that a program cannot leave the LBA window and
  frames the session bound at `CREATE`, nor bypass verdict, deadline and
  retraction handling. The NVMe stage authorizes the window itself through the
  namespace file's access mode and the controller's command-effects check; the
  kernel does not record which session owns which LBAs, so two sessions that
  may both write a namespace can bind overlapping windows. Isolation between
  writers of one namespace therefore needs separate namespaces or partitions.
- No attack produces an UNKNOWN (sequestered) frame; every case asserts zero
  for the victim and reports the attacker's count. Producing one needs an
  accepted command that never completes, which needs a device that withholds a
  completion.
- Victim and attacker overlap in time is recorded per case (`# overlap ...`),
  not asserted, because it depends on scheduling.
- The frame-window attack uses the host-frame variant (`POOL_IOU_UMEM`); a
  peer/VRAM pool is not used, so no provider module is loaded.
- Root only; a non-root BPF-token variant is not included.

## Running

The test adds no kernel code, so it runs against a prebuilt kernel the caller
owns. `--build` is a kernel build directory (a `bzImage` and a `vmlinux` BTF),
`--native` the assembled native source tree that produced it (its UAPI headers
and `libxdev_ext`), and `--source` the canonical Git root the test files come
from. The kernel needs `CONFIG_XDEV_EXT_MECH=y` with the NVMe and USER classes;
`CONFIG_XDEV_EXT_MECH_CPU` is not required.

```sh
python3 -I attack_validate_test.py     # host-only oracle self-test
bash attack_kvm.sh --scratch /abs/private-0700 --source /abs/canonical \
    --native /abs/assembled/linux --build /abs/kernel-build
```

Build in a private output directory first with the standalone `Makefile`
(`KERNEL_SRC=<native tree>`, `VMLINUX_BTF=<build>/vmlinux`) to check the guest
and the six BPF objects compile; a successful build does not certify runtime
behaviour. The userspace driver uses GCC; only the mandatory BPF bytecode uses
clang. Evidence (compiler commands, QEMU command, guest log, oracle self-test,
source seed, whole-disk oracle, artifact hashes, provenance) is written under
the scratch's `evidence/`.
