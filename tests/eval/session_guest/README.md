# Eval session correctness in the existing KVM guest

This driver runs the actual `chains`, `nvme_gpu` and `gpu_nic` session
binaries against the project's existing NVMe/AF_XDP devices and CPU-memcpy
CE stand-in. It adds no provider or virtual device. No result is GPU DMA
or performance evidence: the console explicitly records
`performance_claim=none` and prints no timing values.

`make check` runs host tests of the independent byte oracle, descriptor
leak detection, actual shell cleanup functions and console validator.
`eval_session_fixtures/*.log` are explicitly synthetic validator inputs,
not records of guest execution. Oracle host tests use ordinary files only
to exercise its byte comparisons; they do not implement device behavior.

Build (outside the guest, from the product checkout):

```sh
make -C tests/eval/session_guest guest GUEST_OUT=/abs/private/eval \
  CC=gcc CLANG=clang-14
```

`chain_bench` requires libbpf >= 1.0. Set `LIBBPF_CFLAGS` and
`LIBBPF_LIBS` for a private libbpf build when necessary. All outputs go to
`GUEST_OUT`; every C binary builds with `-Wall -Wextra -Werror`. The guest
contains `chain_bench`, `chain_plan.bpf.o`, `session_nvme_ce`,
`session_gpu_nic`, `eval_session_oracle` and
`xdev_ext_eval_session_guest.sh`. No compiler or Python is needed there.

## KVM harness integration

The integrator owns `xdev_ext_mech_zc_kvm.sh`. For an explicitly enabled
normal correctness run with CE simulation (not a fault campaign):

1. Before constructing its image, run the above make target. Copy its six
   files into `$ROOT/opt/xdev_ext/eval/`. Add the four ELF executables to
   `GUEST_PROGRAMS` before the existing per-program `ldd` loop, which copies
   their dynamic libraries. Record their SHA-256 in the harness artifact
   manifest, together with the driver, BPF object and host validator.
2. In the generated guest script, after both NICs and namespaces are ready
   and before attaching the ordinary suite's `nxp_nvme_ops`,
   `nxp_afxdp_ops` and `ce_plan_ops`, invoke:

   ```sh
   sh /opt/xdev_ext/eval/xdev_ext_eval_session_guest.sh \
     /opt/xdev_ext/eval /opt/xdev_ext \
     "$source_block" "$source_ng" "$destination_block" "$destination_ng" \
     "$cli_timeout_ms"
   ```

   Use the harness's actual destination variable names. The module must
   initially be unloaded; the driver loads it, attaches its own plans,
   detaches those plans, verifies zero module references and unloads it.
3. On the host, require exit 0 from:

   ```sh
   python3 kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_eval_session_validate.py guest.log
   ```

   The enclosing guest exit, dmesg checks and whole-disk comparison remain
   required. Never manufacture a console from the synthetic fixtures.

## Coverage and evidence

The 16 cases cover NVMe↔CE load/save at 8/64 KiB (depth 4, two sessions
per case); CE→AF_XDP→CE at 4/16 KiB (both directions, depth 4); paired
NVMe↔NIC and NVMe↔CE↔NIC chains under closed/sustained starts; and
NVMe→software IAA→CE at 4/64 KiB under both start modes. NIC chains have
four measured records and one untimed warmup record; the entire destination
is compared. IAA cases intentionally produce one record without warmup,
so every produced byte remains observable despite LIFO slot reuse; they
exercise the two start modes, not pipeline throughput. Other cases retain
and independently check the complete active window, including duplicate,
missing and torn slot rejection.

`eval_session_oracle.c` shares no payload generator or comparison helper
with the arms. It reads actual output bytes and compares them with its own
formula, then hashes those readback bytes. The host validator has a third
Python implementation checked against the arms' C generators. SHA-256 has
standard known-answer comparisons. Any arm's exit 4 is a failure of this
required guest run, never a PASS or silently skipped case.

Before each case the driver snapshots both disks' 1 MiB scratch regions
at offset 12 MiB plus 4 KiB guards on each side, and the entire existing
4 MiB CE window. Afterwards it compares every byte outside that case's
declared write regions. It also requires zero CE module references. The
arm's own process checks `/proc/self/fd` before process exit can hide a
leak. Raw per-stage statistics, successful STOP and the actual before/after
FD counts are forwarded to the host validator. The validator rejects
missing/duplicate cases, wrong bytes/hash, bad counts, missing STOP/FD/guard
observations, extra FAIL, and premature scratch restoration or DONE.

Only after every case and teardown succeed does the driver restore and
read back both original scratch regions. On any failure it stops, retains
the scratch bytes and temporary logs, and never restores a potentially
active DMA target. The kernel's STOP/ring-close quarantine retains pool
pins, stage files and backend regions when quiescence is unknown; process
FD closure is not a replacement for that guarantee. This script does not
force release, reset a controller, or run on a host's physical devices.
