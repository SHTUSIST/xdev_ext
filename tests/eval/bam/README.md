# BaM native correctness adapter

This directory supplies a build-only entry and a qualified, GPU-initiated NVMe
correctness adapter for [official BaM](https://github.com/ZaidQureshi/bam).
`native.lock.json` selects BaM `315fadfc5c5c018a64596157bfac94ecbb7d87a2`,
freestanding `6360203797a3601fa61f3580dc97b2535b2c232d` and its pinned libcxx.
`BaM-LICENSE` preserves the full upstream root license. Source files are fetched
from their official repositories; they are not silently substituted with the
historical archive.

`bench_native.cu` derives a minimal serial adapter from BaM's `ctrl.h`,
`queue.h`, `nvm_parallel_queue.h` and `page_cache.h`. A GPU kernel acquires a
CID, constructs an NVMe READ/WRITE with the exact LBA count, calls `sq_enqueue`,
`cq_poll` and `cq_dequeue`, and releases the CID only after a known completion.
It checks CQE CID, SQID, phase, SQ head and status. CQEs have no opcode; the
adapter checks the tracked submitted SQ opcode. Unlike `read_data()`, this
adapter has no software cache or `enqueue_second()` bookkeeping reads.
It is a **minimal native queue baseline**, not the complete BaM cache workload.
Queue depth is two with one outstanding command; correctness mode has no
performance metric and does not claim competitive throughput.

## Build only

```sh
git clone https://github.com/ZaidQureshi/bam.git /path/to/bam
git -C /path/to/bam checkout --detach 315fadfc5c5c018a64596157bfac94ecbb7d87a2
git -C /path/to/bam submodule update --init --recursive
python3 tests/eval/bam/build_native.py --upstream /path/to/bam \
  --cuda-root /usr/local/cuda --output /path/to/new-build --arch 80
```

The builder requires pristine exact Git trees and an official CUDA 12/13 SDK.
It builds the nine official Linux libnvm C++ sources, then compiles and links
our real CUDA kernel. GNU C++17 is used for libnvm's GNU `typeof` macro. CUDA
13 supports the provided sm80+ targets; use CUDA 12 for sm70/sm75. There is no
`--allow-unsupported-compiler`. Compilation failures exit 1; missing inputs exit
4 without a success record or binary. Commands, complete diagnostics, the exact
compatibility patch and final ELF identity are retained in the new output
folder. `build.json` says `built-not-run` and `physical_execution: false`.

The only native upstream edit is a whole-word private-template rename in
`include/freestanding/libcxx/include/type_traits` to avoid compiler built-in
name collisions. The builder applies it to an output copy. It never patches
the supplied upstream checkout, builds a module, installs packages, changes
sysfs, or runs upstream host/device scripts.

## Qualification and correctness

`native_contract.py` validates a receipt; it does not discover or certify P2P
hardware. A receipt must explicitly identify the exact upstream revision,
`/dev/libnvmN` controller, namespace capacity/LBA size, approved exclusive LBA
region, physical GPU UUID/capability, GPU initiation, Above 4G decoding, disabled
IOMMU/ACS, and direction. Write mode needs separate `allow_write: true`.
The runner qualifies before opening a controller. The native binary rechecks
GPU UUID/capability and actual namespace geometry before data commands.
Independent physical qualification must establish device ownership, correct
libnvm/NVIDIA mapping, topology and complete original-data preservation.
Those physical gates are separate from host tests and SDK compilation.

Correctness execution additionally requires an independently saved, exact
image of the **whole approved region** (`--original`), with a bounded maximum
of 64 MiB. `--bytes` selects an exact LBA-aligned prefix; write mode also needs
an exact `--seed`. No command extends outside the region or namespace. The
last command can transfer a partial page, using only its exact whole LBAs.
The GPU reads the entire region first and compares it byte-for-byte with the
independent original. The workload read/write uses only the requested prefix.
Write mode then reads back the entire region, checks the untouched region tail,
restores the original prefix and reads/verifies the whole original again.
All host seeding and post-run oracle CUDA copies are outside the native data
path and counted separately. The mapped GPU payload has exact 32-byte A5 guards
and full surrounding redzones. Every byte, including the last byte, is checked.

The terminal record reports workload `logical_operations`, all
`raw_native_commands`, and the additional
`verification_and_restoration_commands`; native verification/restoration reads
and writes are not hidden in a claim of one total command per workload I/O.
The adapter never reports timing or bandwidth. Performance mode is unavailable.

A receipt requesting any timeout/cancellation policy is rejected. Official
queue polling has no proven bounded cancel/drain operation. After uncertain
GPU submission/synchronization, unexpected completion identity, or uncertain
admin completion, the process retains the controller, queues, PRPs and GPU
memory indefinitely and prints an UNKNOWN diagnostic. SIGPIPE is ignored before
the first main diagnostic and again at the quarantine entry, so a disconnected
diagnostic pipe cannot terminate the UNKNOWN resource owner. A readable pipe
still receives the diagnostic. It ignores SIGINT,
SIGTERM and SIGHUP after physical setup begins. Do not wrap native execution
in a process-killing timeout. SIGKILL, machine reset, driver removal and other
external revocation remain physical hazards; process code cannot make them
safe. Accepted commands are never replayed as recovery.

Known terminal errors exit 1 and never produce success. If a write fails after
changing data, `original_restore_required: true` explicitly marks the need for
qualified recovery; a failed run does not claim original restoration. The
libnvm unmap/destroy APIs return void, so their internal release status cannot
be certified here. Queue deletion and all CUDA allocation/copy/free calls are
checked; cleanup failures are not retried. Complete device correctness,
module lifecycle, P2P, fault recovery and performance require physical testing.

## Host-only checks

```sh
make -C tests/eval/bam check
```

The C++ host fixture includes the production oracle/CQE helper. Host byte
mutation and boundary checks establish software behavior only; they do not
emulate an NVMe device and produce no performance number.

## Historical compatibility patch

`bam-linux6-gcc13-compat.patch`, `upstream.lock`, `find_upstream_commit.sh` and
`test_patch.py` retain the separate archived-copy contract. Its original Git
revision was unrecorded. Reconstructing three prepatch blobs did not identify
a matching official revision; the libcxx file also lives inside a submodule.
Do not apply that inference to the new native pin or call the old archive
byteequal to this revision. The historical Linux module patch is not part of
the native build and does not authorize loading or changing a physical device.
