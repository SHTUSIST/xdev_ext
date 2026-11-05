# COMP-1 actual deflate original capture

This is TESTS_READY source-only input for root's native correctness campaign. No compressed golden exists in this directory: the first unchanged-source guest run must create it. A four-stage session makes the intermediate compressed payload observable through the existing USER ABI while the real same-class inflater consumes it. Neither a CryptoAPI stub nor user-space compressor supplies bytes.

Retry2 repairs F1/F2 after root reported actual independent RED receipts. All ten v1 preimages and their original freeze are preserved under retry2/v1/. No compiler, guest or parser was executed by this source author. Original capture, RED/GREEN, current-kernel correctness, root source parity and independent spec/quality review remain unclaimed. Exact root commands and the actual existing-profile hook are below.

## Appendix A — root build

Root sets `capture_build` to a fresh output under its NVMe run directory, `native_build` to the matching existing strict-debug kernel build, and `source_id` to its independently verified complete source revision. These are environment inputs, not invented artifact paths. The author does not invoke these commands.

```bash
capture_source=/root/xdev_ext/staging/completion-20261101/compute-deflate-original-capture
product_source=/root/xdev_ext/staging/recovery-20261031/wt-integration
: "${capture_build:?Set a new private build-output path}"
: "${native_build:?Set the matching existing strict-debug kernel build}"
: "${source_id:?Set root-verified unchanged production source identity}"
CC=gcc-14 CLANG=/usr/bin/clang-21 bash "$capture_source/build.sh" \
  "$product_source" "$native_build" "$source_id" "$capture_build"
```

The C executable compiles directly against canonical UAPI with GCC. Clang only compiles mandatory BPF bytecode. Root preserves the entire build stdout/stderr and actual exit status. Source hashes are recorded before compilation and compared after it; identity JSON records kernel config/release/image hashes. Root must also reconcile that identity with the existing build's own source/config receipts: same release alone is insufficient.

## Appendix B — real existing profile hook and correctness execution

The real existing profile is `tests/integration/session/native/xdev_ext_mech_zc_kvm.sh`, specifically its generated `$SCRATCH/initroot` (`ROOT`) and `$SCRATCH/initramfs.cpio.gz` assembly. It already builds strict-debug when `--debug-locking` is selected and enables CPU for `--lifecycle`; IAA must also be present in the selected existing build; USER is included by CONFIG_XDEV_EXT_MECH and has no separate Kconfig symbol. Live USER support still must pass the existing BTF, load, USER_STAGE, CREATE and START gates. This test refuses their absence and does not request another profile or a device stand-in.

That runner has no public arbitrary guest-hook option. `stage-profile.sh` specializes only an already prepared root-owned generated initroot, preserves its original `init`, copies this test plus dynamic libraries, and installs a minimal guest entry using existing busybox/mount setup. It runs before any other class programs are attached, avoiding default-program conflicts. It does not patch the source runner or an existing oracle. Root selects a private copy of its prepared profile initroot so the ongoing profile is not overwritten.

```bash
: "${capture_initroot:?Set the private copy of an existing prepared profile initroot}"
: "${capture_initramfs:?Set the fresh capture initramfs path}"
: "${capture_log:?Set the fresh guest console log path}"
: "${capture_bytes:?Set the fresh extracted-original directory}"
bash "$capture_source/stage-profile.sh" "$capture_initroot" "$capture_build"
(cd "$capture_initroot" && find . | cpio -o -H newc --quiet | gzip -1) > "$capture_initramfs"
# Root uses its existing profile's verified QEMU executable and kernel.
# This payload uses registered host pages only: no disk or NIC is attached.
: "${QEMU:?Set the same actual QEMU executable as the verified existing profile}"
set +e
timeout 600 "$QEMU" -machine q35,accel=kvm -cpu host -smp 4 -m 4096 \
  -nographic -no-reboot -kernel "$native_build/arch/x86/boot/bzImage" \
  -initrd "$capture_initramfs" \
  -append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr' \
  -nic none </dev/null > "$capture_log" 2>&1
capture_status=$?
set -e
printf 'qemu_exit=%s\n' "$capture_status" >> "$capture_log"
# Extraction must run even after a failed QEMU/native capture, to retain diagnostics.
set +e
python3 -I "$capture_source/verify-capture.py" "$capture_log" "$capture_bytes"
extract_status=$?
set -e
[[ "$capture_status" == 0 && "$extract_status" == 0 ]]
```

Existing `compute_kvm.sh` tests BPF compute with NVMe; existing IAA transform guest tests software transform with a DMA stand-in and no exact-byte capture. Neither file is falsely described as already accepting a new capture flag. The hook above reuses the actual prepared profile kernel/initroot while running only native CPU/IAA/USER interfaces; nothing calls the DMA test driver. Root's existing diagnostics gate must separately reject kernel WARN/BUG/KASAN/locking failures in this exact log. The console extractor alone is not a diagnostics oracle.

## Appendix C — retained observations and review gates

The extractor always creates a receipt for a readable/partial log at a fresh output path. It retains every unambiguous, well-formed bounded record even when parse/content validation fails, the final marker is missing, or an earlier explicit failure/nonzero capture or guest exit is followed by PASS. Failure status is DIAGNOSTIC_FAILURE, diagnostic/errors are truthy, valid_original=false and source_of_compressed_expectations is exactly `diagnostic only; not a valid original`. Its CLI returns nonzero. Lengths describe only successfully retained actual bytes. Conflicting same-name records are explicitly ambiguous and cannot supply an original; all other valid records survive. No failed bytes become expected compressed output.

Native capture emits observed compressed/restored bytes before content/source/guard assertions. Case failure additionally emits fixed8192-byte frame records named `diag.CLASS.pool.fN`, `diag.CLASS.initial.fN`, `diag.CLASS.compressed_snapshot.fN`, with CLASS cpu/iaa and N0..5, before cleanup. Each initialized image has six frames; unavailable initial/snapshots are never emitted. Maximum18 records per failing case; each console line remains below100000 characters. Raw current pool bytes on an inflight-error path are diagnostic observations, not a stable/quiescent-original claim. The parser streams bounded chunks and never reads the whole log into memory. Any diagnostic namespace forces failure.

Successful C output contains full hex records for `input`, `cpu.deflate`, `cpu.inflate`, `iaa.deflate`, `iaa.inflate`; exact lengths; descriptors; source/guard results; source/kernel/config/build identities; full `/proc/crypto`; provider algorithm/type/masks/request flags and locked compression parameters. Extractor writes those five raw binaries and a length/equality receipt. Unequal valid compressed encodings are preserved separately, not replaced or forced equal.

No latency, throughput or advantage counter is measured. Session submitted/completed counters prove path traversal and termination only. Both exact reconstructions, full source-frame immutability, full compressed-source-frame immutability across inflate, all capacity-exterior guards, completion counters and STOP must pass. Absent classes/provider/no bytes/error/timeout/nonzero guest exit is failure. Root freezes resulting originals before any COMP-4 production author sees production work; root owns test-results registration and catalog write/check.

Fresh review should independently check the USER ring ownership/order, stage reservation and fd lifetime-token use, capacity-exterior guard accounting, actual BPF verifier attachment, and kernel/source receipt parity. Any source change after FREEZE.json is a new version and must be frozen before execution, retaining the old original.

## Appendix D — exact upstream reference originals

The current lock selects torvalds/linux commit `89be9a83ccf1f88522317ce02f854f30d6115c41` (v6.16-rc7). Primary originals were fetched once into `/root/xdev_ext/tmp/compute-comp1-deflate/`; read those saved bytes during review, not a second fetch. `manifest.tsv` records URLs, identities and HTTP receipts.

- Artifact `5a91af943337`, raw `5a91af943337-acompress.h.html`: `struct acomp_req` documents dlen as the size/output-byte count; `acomp_request_set_params()` documents source/destination and capacities; allocation takes algorithm/type/mask. Source URL: https://raw.githubusercontent.com/torvalds/linux/89be9a83ccf1f88522317ce02f854f30d6115c41/include/crypto/acompress.h
- Artifact `d3be71b65991`, raw `d3be71b65991-deflate.c.html`: exact deflate implementation uses default compression, windowBits -11, MAX_MEM_LEVEL/default strategy and registers driver deflate-generic. Source URL: https://raw.githubusercontent.com/torvalds/linux/89be9a83ccf1f88522317ce02f854f30d6115c41/crypto/deflate.c
- Artifact `1a31609e2e2b`, raw `1a31609e2e2b-architecture.rst.html`: the unique-driver selection discussion and /proc/crypto registry distinguish requested driver identity from generic-name priority selection. Source URL: https://raw.githubusercontent.com/torvalds/linux/89be9a83ccf1f88522317ce02f854f30d6115c41/Documentation/crypto/architecture.rst

These small files were sized before inspection. Root authorized this exact read-only primary-source fallback. No remote credentials or project Git operation was used.

## Appendix E — retry3 bounded retained parser state

Retry3 addresses only F2-R1. The active native C/BPF/build/guest/staging files stay byte-identical to retry2. Ten retry2 preimages and their exact freeze are in retry3/v2; retry3/PLAN.md precedes the repair, and retry3/HANDOFF.md/source.diff record it. This source author did not execute or import a parser, test or probe. Root reported the independent meaningful RED; root owns fresh replay and review.

Recognized CASE state now occupies two bits. Unknown/malformed CASE records create a fixed-category permanent error without preserving arbitrary names. Exact-final state saturates at2 (multiple); error_count saturates at65535 and explicit error_count_overflow marks additional errors. At most128 error messages are retained; error_messages_omitted is true when messages are omitted. The existing41-name byte/ambiguity dictionaries, two zero-exit strings,8192-byte buffer limit and100000-character line limit remain. EOF streaming and diagnostic artifact persistence remain mandatory; no total-log-size or parser-time cutoff is introduced. Later CASE/PASS cannot clear an earlier error.

## Appendix F — retry4 CASE status position

Retry4 addresses only F2-R2: the third whitespace-separated CASE token must be exactly uppercase `PASS` before a known cpu/iaa success bit can be set; the prior ` PASS ` space guard is also retained. A later `PASS` in the body cannot qualify `FAIL`, `PASSIVE`, lowercase or another non-PASS status. Unknown names and missing/non-PASS statuses enter the existing permanent fixed-category error path; later valid records cannot clear it. This checks the status position without defining new body fields or changing native output. All bounded state, EOF scanning and unambiguous diagnostic retention above remain binding.

The ten exact retry3 preimages and their prior FREEZE.json are preserved under retry4/v3 with a manifest; retry4/PLAN.md preceded the edit, and retry4/HANDOFF.md/source.diff record the source handoff. Native C/BPF/build/guest/staging and upstream claims remain unchanged. Root reported independent RED before GO; this author did not inspect independent tests or runtime artifacts and did not execute/import the parser. Fresh SPEC then QUALITY, root's independent parser controls and memory test, actual build/load/native capture, exact-log diagnostics and evidence registration remain root gates.
