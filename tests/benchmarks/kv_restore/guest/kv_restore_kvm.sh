#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# K-KV restore worker, local-verify role, in a private KVM guest: correctness
# only, never a performance run. Reuses a built kernel (O= directory with the
# system dma-buf heap and the xdev_ext dma-buf importer) and builds only the
# worker and its BPF object from the exact clean checkout. All writes stay in
# --scratch: the private NVMe image, the initramfs and the evidence.
#   bash kv_restore_kvm.sh --scratch DIR --source GIT_ROOT --view VIEW --build O_DIR [--viommu]
# VIEW is tools/layout.py's source view of GIT_ROOT. GIT_ROOT may differ from
# the kernel build's recorded commit only in files that do not enter the kernel.
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' VIEW='' BUILD='' VIOMMU=0
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc}
CLANG=${CLANG:-clang-21}
BPFTOOL=${BPFTOOL:-bpftool}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-900}
while (($#)); do
	case "$1" in
	--scratch) SCRATCH=$2; shift 2 ;;
	--source) SOURCE=$2; shift 2 ;;
	--view) VIEW=$2; shift 2 ;;
	--build) BUILD=$2; shift 2 ;;
	--viommu) VIOMMU=1; shift ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$VIEW" && -n "$BUILD" ]] || { echo 'missing option' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
	echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
TEST=$VIEW/tests/eval/kv_restore
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee -a "$EV/runner.log") 2>&1

# Identity: clean source, its own view, a prebuilt kernel whose inputs equal it.
SOURCE=$(git -C "$SOURCE" rev-parse --show-toplevel)
[[ -z $(git -C "$SOURCE" status --porcelain --untracked-files=all) ]] || { echo 'FAIL source checkout is dirty' >&2; exit 1; }
HEAD_SHA=$(git -C "$SOURCE" rev-parse --verify 'HEAD^{commit}')
BUILD_SHA=$(cat "$BUILD/xdev-ext-source.commit")
python3 -I - "$SOURCE" "$BUILD_SHA" "$HEAD_SHA" "$VIEW" >"$EV/source-delta.txt" <<'PYDELTA'
import json, subprocess, sys
from pathlib import Path
root, old, new, view = sys.argv[1:]
def git(*args):
    return subprocess.run(['git', '-C', root, *args], check=True, capture_output=True, text=True).stdout
subprocess.run(['git', '-C', root, 'merge-base', '--is-ancestor', old, new], check=True)
def native(revision):
    entries = json.loads(git('show', revision + ':source-layout.json'))['files']
    return {e['source']: e['native_path'] for e in entries if 'component' in e}
before, after = native(old), native(new)
changed = [n for n in git('diff', '--name-only', old, new).splitlines() if n]
for name in changed:
    if name in before or name in after:
        raise SystemExit('FAIL kernel-tree input changed since the prebuilt kernel: ' + name)
    if not (name.startswith('tests/') or name == 'source-layout.json'):
        raise SystemExit('FAIL change outside tests since the prebuilt kernel: ' + name)
if before != after:
    raise SystemExit('FAIL native overlay mapping changed since the prebuilt kernel')
receipt = json.loads((Path(view) / 'view.json').read_text())
if receipt.get('canonical_root') != str(Path(root).resolve()):
    raise SystemExit('FAIL view does not belong to the source checkout')
print('build_commit=' + old)
print('source_commit=' + new)
print('changed_since_build=' + ' '.join(changed))
PYDELTA
for f in kv_restore.c kv_plan.h kv_nvme_read.bpf.c kv_layout.py kv_protocol.py guest/validate.py; do
	cmp -s "$SOURCE/tests/benchmarks/kv_restore/$f" "$TEST/$f" || { echo "FAIL view differs from source: $f" >&2; exit 1; }
done
required=(DMABUF_HEAPS DMABUF_HEAPS_SYSTEM XDEV_EXT_PEER_DMABUF DMA_SHARED_BUFFER XDEV_EXT_MECH
	BLK_DEV_NVME BLK_DEV_INITRD DEVTMPFS IO_URING BPF_SYSCALL DEBUG_INFO_BTF PCI_MSI SERIAL_8250_CONSOLE)
if (( VIOMMU )); then required+=(INTEL_IOMMU); fi
for symbol in "${required[@]}"; do
	grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
done
sha256sum -c "$BUILD/xdev-ext-artifacts.sha256" >"$EV/prebuilt-artifacts-check.txt"
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
DEBUG_LOCKING=0
grep -Fxq CONFIG_PROVE_LOCKING=y "$BUILD/.config" && DEBUG_LOCKING=1
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; QEMU NVMe; system-heap dma-buf PEER pool; no XDOMAIN; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\nkernel_release=%s\nviommu=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$(cat "$BUILD/include/config/kernel.release")" "$VIOMMU"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|DETECT_HUNG_TASK|INTEL_IOMMU|XDEV_EXT_PEER_DMABUF|DMABUF_HEAPS_SYSTEM)=' "$BUILD/.config" || true
	"$CC" --version | head -1; "$CLANG" --version | head -1; "$BPFTOOL" version | head -1
} >"$EV/provenance.txt"
cp "$BUILD/.config" "$EV/kernel.config"
python3 -I "$SOURCE/tests/integration/session/native/xdev_ext_mech_zc_debug.py" config "$BUILD/.config" /dev/null "$DEBUG_LOCKING"

# Build the worker (with libxdev_ext) and the BPF object against this kernel's BTF.
mkdir -p "$OUT/build"
nice -n 10 make -s -C "$TEST" BUILD="$OUT/build" CC="$CC" "$OUT/build/kv_restore" >"$EV/worker-build.log" 2>&1
nice -n 10 make -s -C "$TEST" BUILD="$OUT/build" CLANG="$CLANG" BPFTOOL="$BPFTOOL" \
	VMLINUX_BTF="$BUILD/vmlinux" bpf >"$EV/bpf-build.log" 2>&1
sha256sum "$BUILD/arch/x86/boot/bzImage" "$OUT/build/kv_restore" "$OUT/build/kv_nvme_read.bpf.o" \
	"$SOURCE/tests/benchmarks/kv_restore/kv_restore.c" "$SOURCE/tests/benchmarks/kv_restore/kv_nvme_read.bpf.c" \
	"$SOURCE/tests/benchmarks/kv_restore/guest/validate.py" >"$EV/artifacts.sha256"

# Host-side plan and private source image.
python3 -I "$TEST/guest/validate.py" make-plan --output "$OUT/plan"
cp "$OUT/plan/plan.json" "$EV/plan.json"

# Minimal initramfs: busybox, the worker, its libraries, the object and GO scripts.
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/kv}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed basename readlink sync; do ln -sf busybox "$ROOT/bin/$app"; done
cp "$OUT/build/kv_restore" "$OUT/build/kv_nvme_read.bpf.o" "$OUT"/plan/go-*.txt "$OUT"/plan/args-*.txt "$ROOT/opt/kv/"
ldd "$OUT/build/kv_restore" | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' \
	| sort -u >"$EV/guest-libraries.txt"
while IFS= read -r lib; do mkdir -p "$ROOT$(dirname "$lib")"; cp -L "$lib" "$ROOT$lib"; done <"$EV/guest-libraries.txt"
cat >"$ROOT/init" <<'GUEST'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t bpf bpf /sys/fs/bpf
echo
echo KV_GUEST_BEGIN
src=
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	[ "$(sed 's/[[:space:]]*$//' "$f")" = KVSRC00001 ] && src=$c
done
if [ -n "$src" ]; then
	echo "KV_GUEST_FACT lba_bytes=$(cat /sys/block/${src}n1/queue/logical_block_size)"
	echo "KV_GUEST_FACT max_hw_sectors_kb=$(cat /sys/block/${src}n1/queue/max_hw_sectors_kb)"
	echo "KV_GUEST_FACT nvme_pci=$(basename "$(readlink -f /sys/class/nvme/$src/device)")"
	for run in A B C; do
		echo "KV_GUEST_RUN_BEGIN $run"
		/opt/kv/kv_restore local-verify --nvme "/dev/ng${src#nvme}n1" --nvme-prog /opt/kv/kv_nvme_read.bpf.o \
			$(cat /opt/kv/args-$run.txt) < /opt/kv/go-$run.txt
		echo "KV_GUEST_RUN_EXIT $run $?"
	done
else
	echo 'KV_GUEST_FAIL NVMe serial KVSRC00001 not found'
fi
echo KV_GUEST_DMESG_BEGIN
dmesg
echo KV_GUEST_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"

machine=q35,accel=kvm append='console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr'
viommu_args=()
if (( VIOMMU )); then
	machine+=,kernel-irqchip=split
	viommu_args=(-device intel-iommu,intremap=on,caching-mode=on)
	append+=' intel_iommu=on iommu.strict=1'
fi
args=(-machine "$machine" "${viommu_args[@]}" -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz" -append "$append" -nic none
	-drive "file=$OUT/plan/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=KVSRC00001)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
sha256sum "$OUT/plan/source.raw" >"$EV/source-before.sha256"
{ date -u +%FT%TZ; uptime; } >"$EV/host-before-guest.txt"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.raw.log" 2>&1 || qemu_status=$?
tr -d '\r' <"$EV/guest.raw.log" >"$EV/guest.log"
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
sha256sum "$OUT/plan/source.raw" >"$EV/source-after.sha256"
validator_status=0 console_status=0
python3 -I "$TEST/guest/validate.py" validate --plan "$OUT/plan/plan.json" --log "$EV/guest.log" \
	--result "$EV/result.json" | tee "$EV/host-validate.txt" || validator_status=$?
python3 -I "$SOURCE/tests/integration/session/native/xdev_ext_mech_zc_debug.py" console "$EV/guest.log" \
	"$EV/debug-console.json" "$DEBUG_LOCKING" | tee "$EV/debug-console.txt" || console_status=$?
cmp -s <(cut -d' ' -f1 "$EV/source-before.sha256") <(cut -d' ' -f1 "$EV/source-after.sha256") || {
	echo 'FAIL the read-only source image changed'; validator_status=1; }
# Emulated IOMMU: translated strict domain for the NVMe function, no remapping fault.
nvme_pci=$(sed -n 's/^KV_GUEST_FACT nvme_pci=\(.*\)$/\1/p' "$EV/guest.log" | head -1)
faults=$(grep -Eci 'DMAR: \[DMA (Read|Write)|fault addr|DMAR:.*fault' "$EV/guest.log" || true)
if (( VIOMMU )); then
	grep -q 'DMAR: IOMMU enabled' "$EV/guest.log" &&
	grep -q 'DMA domain TLB invalidation policy: strict mode' "$EV/guest.log" &&
	[[ -n "$nvme_pci" ]] && grep -q "pci $nvme_pci: Adding to iommu group" "$EV/guest.log" &&
	(( faults == 0 )) || { echo "FAIL vIOMMU checks (nvme=$nvme_pci faults=$faults)"; validator_status=1; }
elif grep -q 'DMAR: IOMMU enabled' "$EV/guest.log"; then
	echo 'FAIL DMAR enabled without --viommu'; validator_status=1
fi
printf 'nvme_pci=%s dmar_faults=%s\n' "$nvme_pci" "$faults" >>"$EV/provenance.txt"
if (( qemu_status == 0 && validator_status == 0 && console_status == 0 )); then
	echo "KV_RESTORE_LOCAL_VERIFY_KVM=PASS viommu=$VIOMMU" | tee "$EV/verdict.txt"
else
	echo "KV_RESTORE_LOCAL_VERIFY_KVM=FAIL viommu=$VIOMMU qemu_exit=$qemu_status validator_exit=$validator_status console_exit=$console_status" | tee "$EV/verdict.txt"
	exit 1
fi
