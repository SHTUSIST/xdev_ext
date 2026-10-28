# Actual-kernel session program selection

This driver uses actual io_uring, UMEM, libbpf, struct_ops links and mechanism
callbacks. There is no replacement registry, selected-ops resolver, admission
predicate or callback invocation in this suite. It requires a kernel built from
the tested production checkout and BPF objects compiled from its genuine BTF.
A successful build alone does not certify runtime behavior.
Enable `CONFIG_XDEV_EXT_MECH_CPU=y` in the target kernel; an XDOMAIN-only
profile correctly refuses CPU stage creation and cannot run these cases.

Build in a private output directory:

```sh
BPF_CLANG=clang-14 python3 tests/core/program_instances/guest/run.py \
  --vmlinux-h /absolute/generated/vmlinux.h \
  --output /absolute/private/output
```

The userspace driver uses GCC. Only mandatory BPF bytecode uses clang.
`--libbpf-build DIR` selects an existing static libbpf build with `include/`
and `libbpf.a`; otherwise the driver uses pkg-config libbpf. `--driver-only`
checks the driver without BPF. No synthetic vmlinux header is supplied.
The runner records all compiler commands and exits; setup failures are distinct
from behavioral failures.

Root may execute the built `session-programs /absolute/private/output` inside
the matching correctness guest. Its `--wire-only` mode needs no BPF objects and
checks actual opcode12 report delivery for an invalid pure CREATE request; the
original kernel rejects the unknown operation. The runner's explicit `--run`
option invokes the same binary locally, without SSH or remote orchestration.

The six runtime cases are:

- Actual opcode12 delivers the unchanged CREATE_REPORT error envelope.
- Two sessions select A then B and B then A for two CPU stages of the same
  class, while a third uses the global default. All are started before waiting.
  Independent payload literals are 0x1117, 0x1711 and 0x2b2b.
- Two links attached to the same B map remain separate: detaching the original
  rejects new admission to its sessions while the second link and default
  continue producing their exact payloads.
- Reattaching the same map creates fresh liveness; old sessions stay rejected.
  Destroying the fresh link retracts its session without affecting the sibling.
- Missing, nonlink, wrong-class and nonprivate explicit descriptors fail with
  their specified errors, without a session or fallback.
- Second-stage PREPARE rejection delivers its failure stage and RELEASED
  cleanup; other selected/default sessions still produce the original bytes.

The BPF CPU transforms shift the first payload word eight bits and append an
independently chosen tag (A=0x11, B=0x17, default=0x2b). The guest checks literal
expected words, not a second copy of the transform. Before each START, while
USER owns the allocation, the driver poisons all four registered frames and
zeros the eight input bytes. After completion with no inflight work it checks
the literal word and every remaining registered byte, including padding and
unused frames. The five BPF objects include
one deliberate wrong-class map and one deliberate PREPARE refusal.

This suite does not yet establish accepted-native NVMe drain/quarantine,
unpublished-CREATE detach races, or a C_REFERENCE default installed alongside
PRIVATE selection. Its completed CPU batches followed by detach are not an
accepted-native drain test. Preserve the existing dedicated lifecycle and
NVMe tests and require the remaining targeted lifetime acceptance separately.
No performance or physical-device result is inferred from guest execution.
