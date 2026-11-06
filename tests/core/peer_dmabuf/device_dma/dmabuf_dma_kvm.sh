#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused KVM correctness run of the dma-buf device-DMA guest test, never a
# performance benchmark. It reuses an already built kernel and its BTF-matched
# nvme_s0 BPF object, and builds only the guest test program. All writes stay
# in --scratch: private raw images, initramfs and evidence. No host module.
#   bash dmabuf_dma_kvm.sh --scratch DIR --source GIT_ROOT --build O_DIR --tools TOOLS_DIR [--viommu]
#        [--exporter system-heap|udmabuf]
# GIT_ROOT is a clean canonical product checkout whose HEAD differs from the
# build's recorded commit only in test inputs that do not enter the kernel or
# the BPF object. --viommu adds emulated Intel VT-d with strict guest IOMMU.
# --exporter udmabuf runs the same cases on udmabuf dma-bufs, whose exporter
# registers no xdev_ext descriptor (the undescribed import path).
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' BUILD='' TOOLS='' VIOMMU=0 EXPORTER=system-heap
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-1200}
while (($#)); do
	case "$1" in
	--scratch) SCRATCH=$2; shift 2 ;;
	--source) SOURCE=$2; shift 2 ;;
	--build) BUILD=$2; shift 2 ;;
	--tools) TOOLS=$2; shift 2 ;;
	--viommu) VIOMMU=1; shift ;;
	--exporter) EXPORTER=$2; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$BUILD" && -n "$TOOLS" ]] || { echo 'missing option' >&2; exit 2; }
[[ "$EXPORTER" == system-heap || "$EXPORTER" == udmabuf ]] || { echo 'exporter must be system-heap or udmabuf' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
	echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
TEST_REL=tests/core/peer_dmabuf/device_dma
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee -a "$EV/runner.log") 2>&1

# Identity: exact clean source and a prebuilt kernel/BPF object whose inputs equal it.
SOURCE=$(git -C "$SOURCE" rev-parse --show-toplevel)
[[ -z $(git -C "$SOURCE" status --porcelain --untracked-files=all) ]] || { echo 'FAIL source checkout is dirty' >&2; exit 1; }
HEAD_SHA=$(git -C "$SOURCE" rev-parse --verify 'HEAD^{commit}')
BUILD_SHA=$(cat "$BUILD/xdev-ext-source.commit")
python3 -I - "$SOURCE" "$BUILD_SHA" "$HEAD_SHA" >"$EV/source-delta.txt" <<'PYDELTA'
import json, subprocess, sys
root, old, new = sys.argv[1:]
def git(*args):
    return subprocess.run(['git', '-C', root, *args], check=True, capture_output=True, text=True).stdout
subprocess.run(['git', '-C', root, 'merge-base', '--is-ancestor', old, new], check=True)
def native(revision):
    entries = json.loads(git('show', revision + ':source-layout.json'))['files']
    return {e['source']: e['native_path'] for e in entries if 'component' in e}
before, after = native(old), native(new)
changed = [name for name in git('diff', '--name-only', old, new).splitlines() if name]
# Kernel and BPF-object inputs are native-mapped outside the selftest tree.
for name in changed:
    path = after.get(name, before.get(name))
    if path is None:
        if not (name.startswith('tests/') or name == 'source-layout.json'):
            raise SystemExit('FAIL change outside tests since the prebuilt kernel: ' + name)
    elif not path.startswith('tools/testing/selftests/'):
        raise SystemExit('FAIL kernel/tool input changed since the prebuilt kernel: ' + name)
for name in set(before) | set(after):
    if before.get(name) != after.get(name) and not (after.get(name) or before.get(name)).startswith('tools/testing/selftests/'):
        raise SystemExit('FAIL native overlay mapping changed outside selftests: ' + name)
print('build_commit=' + old)
print('source_commit=' + new)
print('changed_since_build=' + ' '.join(changed))
PYDELTA
required=(XDEV_EXT_PEER_DMABUF DMA_SHARED_BUFFER DEBUG_FS XDEV_EXT_MECH
	BLK_DEV_NVME BLK_DEV_INITRD DEVTMPFS IO_URING BPF_SYSCALL DEBUG_INFO_BTF PCI_MSI SERIAL_8250_CONSOLE)
# udmabuf mode also runs fenced-chain on the upstream sw_sync test timeline.
if [[ "$EXPORTER" == udmabuf ]]; then required+=(UDMABUF MEMFD_CREATE SYNC_FILE SW_SYNC)
else required+=(DMABUF_HEAPS DMABUF_HEAPS_SYSTEM); fi
if (( VIOMMU )); then required+=(INTEL_IOMMU); fi
for symbol in "${required[@]}"; do
	grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
done
sha256sum -c "$BUILD/xdev-ext-artifacts.sha256" >"$EV/prebuilt-artifacts-check.txt"
grep -Fq "$BUILD/arch/x86/boot/bzImage" "$BUILD/xdev-ext-artifacts.sha256"
grep -Fq "$TOOLS/nvme_s0.bpf.o" "$BUILD/xdev-ext-artifacts.sha256"
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
DEBUG_LOCKING=0
grep -Fxq CONFIG_PROVE_LOCKING=y "$BUILD/.config" && DEBUG_LOCKING=1
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; QEMU NVMe; %s dma-buf; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)" "$EXPORTER"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\ntools=%s\nkernel_release=%s\nviommu=%s\nexporter=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$TOOLS" "$(cat "$BUILD/include/config/kernel.release")" "$VIOMMU" "$EXPORTER"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|DETECT_HUNG_TASK|INTEL_IOMMU|IOMMU_DEFAULT_DMA_LAZY|XDEV_EXT_PEER_DMABUF|DMABUF_HEAPS_SYSTEM|UDMABUF)=' "$BUILD/.config" || true
} >"$EV/provenance.txt"
cp "$BUILD/.config" "$EV/kernel.config"
python3 -I "$SOURCE/tests/integration/session/native/xdev_ext_mech_zc_debug.py" config "$BUILD/.config" /dev/null "$DEBUG_LOCKING"

# Build only the guest test program, from the exact checkout.
mkdir -p "$OUT/build"
cp "$SOURCE/$TEST_REL/dmabuf_device_dma.c" "$OUT/build/"
nice -n 10 "$CC" -O2 -std=gnu11 -Wall -Wextra -Werror -iquote "$SOURCE/src/core/include/uapi" \
	"$OUT/build/dmabuf_device_dma.c" -o "$OUT/build/dmabuf_device_dma" -lbpf -lelf -lz >"$EV/test-build.log" 2>&1
sha256sum "$BUILD/arch/x86/boot/bzImage" "$TOOLS/nvme_s0.bpf.o" "$OUT/build/dmabuf_device_dma" \
	"$SOURCE/$TEST_REL/dmabuf_device_dma.c" "$SOURCE/$TEST_REL/validate.py" >"$EV/artifacts.sha256"

# Minimal initramfs: busybox, the test program, the BPF object and libraries.
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/dmabuf}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed basename readlink sync; do ln -sf busybox "$ROOT/bin/$app"; done
cp "$OUT/build/dmabuf_device_dma" "$TOOLS/nvme_s0.bpf.o" "$ROOT/opt/dmabuf/"
printf '%s\n' "$EXPORTER" >"$ROOT/opt/dmabuf/exporter"
ldd "$OUT/build/dmabuf_device_dma" | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' \
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
mount -t debugfs debugfs /sys/kernel/debug
code=1
src= dst=
echo
echo XDEV_EXT_DMABUF_GUEST_BEGIN
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	case "$(sed 's/[[:space:]]*$//' "$f")" in
	XDEVDSRC01) src=$c ;;
	XDEVDDST01) dst=$c ;;
	esac
done
if [ -n "$src" ] && [ -n "$dst" ]; then
	src_pci=$(basename "$(readlink -f "/sys/class/nvme/$src/device")")
	dst_pci=$(basename "$(readlink -f "/sys/class/nvme/$dst/device")")
	XDEV_EXT_DMABUF_GUEST=1 XDEV_EXT_DMABUF_EXPORTER="$(cat /opt/dmabuf/exporter)" \
		/opt/dmabuf/dmabuf_device_dma "/dev/${src}n1" "/dev/ng${src#nvme}n1" \
		"/dev/${dst}n1" "/dev/ng${dst#nvme}n1" "$src_pci" "$dst_pci" /opt/dmabuf
	code=$?
else
	echo 'FAIL NVMe serials XDEVDSRC01/XDEVDDST01 not found'
fi
echo "XDEV_EXT_DMABUF_GUEST_EXIT=$code"
echo XDEV_EXT_DMABUF_DMESG_BEGIN
dmesg
echo XDEV_EXT_DMABUF_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"

# Private disks: deterministic per-sector source, destination written by the guest.
python3 -I "$SOURCE/$TEST_REL/validate.py" make-source "$OUT/source.raw"
rm -f -- "$OUT/destination.raw"; truncate -s 32M "$OUT/destination.raw"
machine=q35,accel=kvm append='console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr'
viommu_args=()
if (( VIOMMU )); then
	machine+=,kernel-irqchip=split
	viommu_args=(-device intel-iommu,intremap=on,caching-mode=on)
	append+=' intel_iommu=on iommu.strict=1'
fi
args=(-machine "$machine" "${viommu_args[@]}" -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz" -append "$append" -nic none
	-drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=XDEVDSRC01
	-drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
	-device nvme,drive=dst,serial=XDEVDDST01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
{ date -u +%FT%TZ; uptime; ps -eo pid,etimes,args | grep -E 'qemu-system|normal8f' | grep -v grep | cut -c1-200 || true; } \
	>"$EV/host-before-guest.txt"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.raw.log" 2>&1 || qemu_status=$?
tr -d '\r' <"$EV/guest.raw.log" >"$EV/guest.log"
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
validator_status=0
viommu_flag=()
if (( VIOMMU )); then viommu_flag=(--viommu); fi
python3 -I "$SOURCE/$TEST_REL/validate.py" validate --source "$OUT/source.raw" --dest "$OUT/destination.raw" \
	--log "$EV/guest.log" --result "$EV/result.json" --exporter "$EXPORTER" "${viommu_flag[@]}" \
	| tee "$EV/host-validate.txt" || validator_status=$?
sha256sum "$OUT/source.raw" "$OUT/destination.raw" >"$EV/data.sha256"
if (( qemu_status == 0 && validator_status == 0 )); then
	echo "XDEV_EXT_DMABUF_DMA_KVM=PASS viommu=$VIOMMU exporter=$EXPORTER" | tee "$EV/verdict.txt"
else
	echo "XDEV_EXT_DMABUF_DMA_KVM=FAIL viommu=$VIOMMU exporter=$EXPORTER qemu_exit=$qemu_status validator_exit=$validator_status" | tee "$EV/verdict.txt"
	exit 1
fi
