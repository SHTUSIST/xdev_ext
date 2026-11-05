#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused KVM correctness run of the concurrent multi-page peer NVMe batch
# guest test (42-PEER-BATCH, 42-RANDOM), never a performance benchmark. It
# reuses an already built kernel and builds only the guest test program. All
# writes stay in --scratch: private raw images, initramfs and evidence.
#   bash peer_batch_kvm.sh --scratch DIR --source GIT_ROOT --build O_DIR
# GIT_ROOT is a clean canonical product checkout whose HEAD differs from the
# build's recorded commit only in test inputs that do not enter the kernel.
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' BUILD=''
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-1200}
while (($#)); do
	case "$1" in
	--scratch) SCRATCH=$2; shift 2 ;;
	--source) SOURCE=$2; shift 2 ;;
	--build) BUILD=$2; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$BUILD" ]] || { echo 'missing option' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
	echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
TEST_REL=tests/storage/nvme/peer_batch
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee -a "$EV/runner.log") 2>&1

# Identity: exact clean source and a prebuilt kernel whose inputs equal it.
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
# Kernel inputs are native-mapped outside the selftest tree.
for name in changed:
    path = after.get(name, before.get(name))
    if path is None:
        if not (name.startswith('tests/') or name == 'source-layout.json'):
            raise SystemExit('FAIL change outside tests since the prebuilt kernel: ' + name)
    elif not path.startswith('tools/testing/selftests/'):
        raise SystemExit('FAIL kernel input changed since the prebuilt kernel: ' + name)
for name in set(before) | set(after):
    if before.get(name) != after.get(name) and not (after.get(name) or before.get(name)).startswith('tools/testing/selftests/'):
        raise SystemExit('FAIL native overlay mapping changed outside selftests: ' + name)
print('build_commit=' + old)
print('source_commit=' + new)
print('changed_since_build=' + ' '.join(changed))
PYDELTA
required=(DMABUF_HEAPS DMABUF_HEAPS_SYSTEM XDEV_EXT_PEER_DMABUF DMA_SHARED_BUFFER DEBUG_FS XDEV_EXT_MECH
	BLK_DEV_NVME BLK_DEV_INITRD DEVTMPFS TRACING EVENT_TRACING PCI_MSI SERIAL_8250_CONSOLE)
for symbol in "${required[@]}"; do
	grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
done
sha256sum -c "$BUILD/xdev-ext-artifacts.sha256" >"$EV/prebuilt-artifacts-check.txt"
grep -Fq "$BUILD/arch/x86/boot/bzImage" "$BUILD/xdev-ext-artifacts.sha256"
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; QEMU NVMe; system-heap dma-buf; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\nkernel_release=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$(cat "$BUILD/include/config/kernel.release")"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|DETECT_HUNG_TASK|INTEL_IOMMU|XDEV_EXT_PEER_DMABUF|DMABUF_HEAPS_SYSTEM|CC_VERSION_TEXT)=' "$BUILD/.config" || true
} >"$EV/provenance.txt"
cp "$BUILD/.config" "$EV/kernel.config"

# Build only the guest test program, from the exact checkout.
mkdir -p "$OUT/build"
cp "$SOURCE/$TEST_REL/peer_batch_guest.c" "$OUT/build/"
nice -n 10 "$CC" -O2 -std=gnu11 -Wall -Wextra -Werror -iquote "$SOURCE/src/core/include/uapi" \
	"$OUT/build/peer_batch_guest.c" -o "$OUT/build/peer_batch_guest" >"$EV/test-build.log" 2>&1
sha256sum "$BUILD/arch/x86/boot/bzImage" "$OUT/build/peer_batch_guest" \
	"$SOURCE/$TEST_REL/peer_batch_guest.c" "$SOURCE/$TEST_REL/validate.py" >"$EV/artifacts.sha256"

# Minimal initramfs: busybox, the test program and its libraries.
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/peerbatch}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed basename readlink sync; do ln -sf busybox "$ROOT/bin/$app"; done
cp "$OUT/build/peer_batch_guest" "$ROOT/opt/peerbatch/"
ldd "$OUT/build/peer_batch_guest" | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' \
	| sort -u >"$EV/guest-libraries.txt"
while IFS= read -r lib; do mkdir -p "$ROOT$(dirname "$lib")"; cp -L "$lib" "$ROOT$lib"; done <"$EV/guest-libraries.txt"
cat >"$ROOT/init" <<'GUEST'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t debugfs debugfs /sys/kernel/debug
mount -t tracefs tracefs /sys/kernel/tracing
code=1
src= dst= err=
echo
echo XDEV_EXT_PEER_BATCH_GUEST_BEGIN
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	case "$(sed 's/[[:space:]]*$//' "$f")" in
	XDEVPBSRC01) src=$c ;;
	XDEVPBDST01) dst=$c ;;
	XDEVPBERR01) err=$c ;;
	esac
done
if [ -n "$src" ] && [ -n "$dst" ] && [ -n "$err" ]; then
	XDEV_EXT_PEER_BATCH_GUEST=1 /opt/peerbatch/peer_batch_guest "/dev/${src}n1" "/dev/ng${src#nvme}n1" \
		"/dev/${dst}n1" "/dev/ng${dst#nvme}n1" "/dev/${err}n1" "/dev/ng${err#nvme}n1" "$src" "$dst" "$err"
	code=$?
else
	echo 'FAIL NVMe serials XDEVPBSRC01/XDEVPBDST01/XDEVPBERR01 not found'
fi
echo "XDEV_EXT_PEER_BATCH_GUEST_EXIT=$code"
echo XDEV_EXT_PEER_BATCH_DMESG_BEGIN
dmesg
echo XDEV_EXT_PEER_BATCH_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"

# Private disks; ERR fails reads of one sector in QEMU's block layer (blkdebug).
python3 -I "$SOURCE/$TEST_REL/validate.py" make-images "$OUT"
printf '[inject-error]\nevent = "read_aio"\nerrno = "5"\nsector = "%s"\n' \
	"$(python3 -I "$SOURCE/$TEST_REL/validate.py" err-sector)" >"$OUT/blkdebug.conf"
cp "$OUT/blkdebug.conf" "$EV/blkdebug.conf"
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr' -nic none
	-drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=XDEVPBSRC01,mdts=8
	-drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
	-device nvme,drive=dst,serial=XDEVPBDST01,mdts=8
	-drive "file=blkdebug:$OUT/blkdebug.conf:$OUT/error.raw,if=none,id=err,format=raw,cache=none,aio=threads"
	-device nvme,drive=err,serial=XDEVPBERR01,mdts=8)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
{ date -u +%FT%TZ; uptime; ps -eo pid,etimes,args | grep -E 'qemu-system' | grep -v grep | cut -c1-200 || true; } \
	>"$EV/host-before-guest.txt"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.raw.log" 2>&1 || qemu_status=$?
tr -d '\r' <"$EV/guest.raw.log" >"$EV/guest.log"
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
validator_status=0
python3 -I "$SOURCE/$TEST_REL/validate.py" validate --images "$OUT" --log "$EV/guest.log" \
	--result "$EV/result.json" | tee "$EV/host-validate.txt" || validator_status=$?
sha256sum "$OUT/source.raw" "$OUT/destination.raw" "$OUT/error.raw" >"$EV/data.sha256"
if (( qemu_status == 0 && validator_status == 0 )); then
	echo "XDEV_EXT_PEER_BATCH_KVM=PASS" | tee "$EV/verdict.txt"
else
	echo "XDEV_EXT_PEER_BATCH_KVM=FAIL qemu_exit=$qemu_status validator_exit=$validator_status" | tee "$EV/verdict.txt"
	exit 1
fi
