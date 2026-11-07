# Blocktable actual-kernel correctness acceptance

## Opt-in same-namespace PRIVATE instance case

`build.py --private-parallel` builds `blocktable-private-parallel` instead of
the original eight-case driver. All other build/guest arguments and the original
BPF object, loader, BTF-resolved PRIVATE flag, registered-byte checker and
CREATE/START/STATS/STOP helpers are retained. The original default mode remains
the eight cases documented below. This mode adds no provider or descriptor
algorithm and requires no new kernel/module build.

Two independent loads of the original ELF must produce distinct nonzero HASH,
struct_ops, link, build-program and complete-program IDs. Two sessions bind the
same actual namespace rdev and admitted 64-LBA window, opening it read-only;
both original namespace fds close immediately after their CREATE. Separate
maps use the same logical key100: A selects slot2, B selects slot5. Cross-session
decoy entries select other slots, so using the other instance cannot produce
the expected bytes. A completes first while B's whole allocation stays poison;
B then completes while A's entire completed allocation stays unchanged.

After that completed boundary, only A's link detaches. A's START101 must return
`-ESHUTDOWN`, with original completed-owner withdrawal stats and unchanged
allocations. B's still-selected program then completes key101 from slot7 while
A's full allocation stays unchanged. STOP A returns `-ECANCELED`, STOP B returns
zero; both require subsequent STATS/START `-ENOENT`, full memory recheck,
successful close/unmap and final process FD count equal to the pre-load count.
Both sessions coexist; this ordered one-batch schedule makes no physical
concurrent-I/O claim.

The extra `parallel_oracle_test.c` only exercises the unchanged byte checker
with independent synthetic slot data: exact A/B/continuation inputs, swapped
slots, zero-slot fallback, stale prior payload, and corruption at payload,
header, padding and unused-frame boundaries including the final registered
byte. Its host success never counts as native PRIVATE acceptance. Root first
reviews these component controls and obtains actual RED for checker mutations;
runtime source and selector/withdrawal mutations require separate review and
actual guest acceptance. No RED or runtime success is implied by this source.

Use a fresh private output and the existing exact normal951 kernel/BTF. Root's
original independent expected-window and whole source-image before/after byte
oracle remain required. The test never seeds or writes a device; only the
existing guest owner may prepare its private source image before guest access.
Record Linux/KVM and QEMU NVMe model truthfully, without a physical DMA or
performance claim. Do not rerun CPU PRIVATE6 or the original eight cases merely
to execute this new mode.

This test loads the original `examples/storage/nvme_blocktable.bpf.c` ELF with
modern libbpf, updates its actual HASH map after CREATE returns the session ID,
and reads the already existing private guest NVMe source into registered
IOU_UMEM. It uses a single NVMe READ stage, so it needs neither a NIC nor a
compute provider. No replacement device, registry, callback, or provider is
implemented. GCC builds the userspace driver; clang builds mandatory BPF only.
A build is not runtime acceptance and no time is a performance measurement.

## Build

From the canonical product checkout, use a fresh absolute output directory:

```sh
BPF_CLANG=clang LDFLAGS='-static -lzstd' \
python3 tests/storage/nvme/blocktable/guest/build.py \
  --libbpf-build /absolute/existing/modern-libbpf \
  --vmlinux-h /absolute/genuine-target/vmlinux.h \
  --output /absolute/new/build-output
```

The libbpf directory must contain `include/bpf/`; its `libbpf.a` may instead
be supplied with `--libbpf-archive /absolute/libbpf.a`. Use the target's
existing libbpf, ELF, zlib and optional zstd dependencies; no downloads are
performed. Remove `-lzstd` if that libbpf does not use it. The entrypoint records
all commands, compiler output, exact source/artifact hashes and its build-only
state. It never dispatches a guest or runs the device driver. `--driver-only`
builds the GCC driver and runs the host byte-oracle selfcheck without inventing a
vmlinux header. The oracle selfcheck requires nine deliberately corrupted
payload/header/padding/unused-frame positions to fail, including the last
registered byte. It proves only the test byte checker.

The generated header projection uses the existing canonical `tools/layout.py`
mapping. The BPF command compiles the original example directly and preserves
its build and complete bodies. After open and before load, the driver resolves
the original `xdev_ext_nvme_mech_ops.flags` member with the object's BTF and sets
only that initial member to PRIVATE. The recorded initial map image and flag
change document this selection. No default registry is replaced. Both original
BPF programs have separate successful verifier buffers and queried program IDs.

## Root-controlled guest contract

Use the existing private correctness guest, its exact matching kernel/BTF and
QEMU NVMe source device. The existing integration harness identifies that source
by serial `UBRZCSRC01`; resolve its block and generic nodes with that harness's
serial-based procedure, not an assumed controller number. No host device run is
authorized by this test. The explicit `--private-guest` switch is mandatory.

The root integrator prepares **the existing source image** and an independent
32768-byte expected-window file before guest execution. The admitted window is
64 LBAs of 512 bytes. The provider checks namespace/window eligibility during
actual CREATE; the frozen byte oracle requires this geometry. Eight 4096-byte
slots must differ. Reuse the established independent signature generator:

```sh
python3 tests/benchmarks/mechanism_variants/image.py seed NEW_EXPECTED_WINDOW
```

That generator fixes absolute LBA 2048..2111, so use `--window-slba 2048` with its
unmodified output. Root alone places those bytes into the private existing
source image at byte offset 1048576. For another window, root supplies its
independently generated expected file and exact source image; the driver does
not seed, write, resize, or create any device/image. Retain the complete expected
source and destination images and check both whole images before and after the
run. A matching selected window alone does not replace the whole-image check.
Do not change the source while a guest/provider can access it.

Copy `blocktable-native`, `nvme_blocktable.bpf.o` and the expected window into the
matching private guest. Root runs, with the serial-resolved source generic node:

```sh
/opt/xdev_ext/blocktable-native --private-guest \
  --object /opt/xdev_ext/nvme_blocktable.bpf.o \
  --device "$source_ng" --window-slba 2048 --window-nlb 64 \
  --expected-window /opt/xdev_ext/expected-window.bin \
  --output /absolute/fresh/guest-capture
```

The driver requires root, an explicit character device and regular exact-length
expected file, and refuses an existing output directory. It opens the namespace
read-only after argument/input validation. The owner closes that original fd
immediately after every successful CREATE, before START; subsequent native reads
must use the session's retained file. The root harness must keep an outer guest
timeout and preserve failures. Missing prerequisites produce SETUP_ERROR/exit 2,
assertion failures produce BEHAVIOR_RED/exit 1, and neither counts as a passing
negative. Exit 0 covers the eight actual-kernel cases below, subject to root's
independent kernel/object provenance and whole-image acceptance.

## Runtime matrix

The fixed layout is four registered 65536-byte frames, header room 128,
seg_len/group_bytes 4096, depth 1. Each START lends frame 0 for one batch. All
registered bytes are poisoned while USER owns the allocation; after the batch
returns to USER, the checker compares the complete selected 4096-byte payload
against the independent window and every other registered byte against poison.

| Case | Required behavior |
| --- | --- |
| Ordinary | Actual `(session_id,100..107)` HASH updates select literal slots `0,1,2,3,4,5,6,7`; all eight full payloads and all guards match. |
| Reverse | Fresh session selects literal slots `7,6,5,4,3,2,1,0` with the same original object/provider/window. |
| Shuffled | Fresh session selects literal slots `3,0,6,1,7,4,2,5`. |
| Missing entry | Successful CREATE, absent current-session key 500, successful START, exactly one abort with `last_err=-ECANCELED`; zero native submit/complete and unchanged entire mapping. |
| Outside window | Successful map update/readback of offset 32768 and length 4096; same exact BUILD_ABORT outcome. |
| Stale session | Entry key 500 exists only under a completed/stopped session's ID; current-session lookup is absent; same exact BUILD_ABORT outcome. |
| Wrong length | Current-session entry length 512 conflicts with the 4096-byte group; same exact BUILD_ABORT outcome. |
| Link owner | After an actual completed native read, detach the selected PRIVATE link, require START `-ESHUTDOWN`, unchanged done/abort/native counts, no inflight/sequestered frames, unchanged bytes, then STOP `-ECANCELED` and removal checks. |

Each map update is read back from the actual HASH map. A positive run requires
exact cumulative done/submitted/completed/published counts; all other stages'
native counts remain zero. A negative requires one returned USER frame
(`published=1`), one abort, no done/native submission/completion, no descriptor
reject/protocol error/timeouts/sequestering/inflight/held frame, and unchanged
entire memory. The original BPF deliberately aborts before class validation for
these entries; a class errno or CREATE failure is not the expected result.

Every case requires synchronous STOP with its exact final result: zero for
positive sessions and `-ECANCELED` for BUILD_ABORT or link-retraction sessions.
Legacy STOP returns the final session error even after definite resource
release; it is not a setup failure. Subsequent STATS and START must both return
`-ENOENT`, and all registered bytes are checked again and saved after STOP.
Close/unmap follows these checks; `-EBUSY` or another error never permits it. The link test preserves complete raw stats immediately before detach and after
the refused START. Both must have no held, timeout, rejection, protocol error,
inflight or sequestered state, exactly one done/published/native submission and
completion, no abort or other-stage native work, and stable recycled/native_publish
counts. The session state and last_err may change during withdrawal. It is
a real completed-native ownership test; it does not claim racing detach against
accepted in-flight DMA, quarantine recovery or physical DMA correctness.

## Evidence and interpretation

Retain the original ELF copy, both verifier logs, BTF/PRIVATE map initial image,
queried HASH/struct_ops/program/link metadata, full raw CREATE input/output,
MAP_UPDATE/readback/START/STOP logs, raw final stats, each full 262144-byte UMEM
snapshot, the independent expected window and `result.json`. Root exports these
with raw guest console, exact kernel/config/BTF/source identity and complete
source/destination-image comparisons. Register the final scoped result in
`/root/xdev_ext/test-results/correctness/linux-kvm-and-driver-validation-on-6787p/`
under a new item, linking original evidence relatively and refreshing/checking
the catalog. A compile or oracle selfcheck is never a native PASS.
