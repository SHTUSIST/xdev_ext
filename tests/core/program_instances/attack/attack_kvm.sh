#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Attacker-brought program isolation on real QEMU NVMe PCI. Correctness only,
# nothing timed. The test adds no kernel code, so it runs against a prebuilt
# kernel the caller owns: --build is a kernel build directory (bzImage and a
# vmlinux BTF) and --native is the assembled native source tree that produced
# it (its UAPI headers and libxdev_ext). --source is the canonical Git root the
# test files come from. All disk writes and networking stay in private image
# files inside a private 0700 scratch; no host hardware is touched.
#
#   bash attack_kvm.sh --scratch DIR --source CANON --native LINUX --build BUILD
set -euo pipefail
umask 077
SCRATCH= SOURCE= NATIVE= BUILD=
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
CLANG=${CLANG:-/usr/bin/clang-21}
BPFTOOL=${BPFTOOL:-bpftool}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-1800}
while (($#)); do
    case "$1" in
    --scratch) SCRATCH=$2; shift 2;;
    --source) SOURCE=$2; shift 2;;
    --native) NATIVE=$2; shift 2;;
    --build) BUILD=$2; shift 2;;
    *) echo "unknown option: $1" >&2; exit 2;;
    esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$NATIVE" && -n "$BUILD" ]] || { echo 'missing option' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
    echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
SOURCE=$(cd "$SOURCE" && pwd -P)
NATIVE=$(cd "$NATIVE" && pwd -P)
BUILD=$(cd "$BUILD" && pwd -P)
[[ $(git -C "$SOURCE" rev-parse --show-toplevel) == "$SOURCE" ]] || {
    echo 'FAIL --source must be a canonical Git root' >&2; exit 1; }

EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee "$EV/runner.log") 2>&1
trap 'rc=$?; if (( rc )); then echo "XDEV_EXT_ATTACK_KVM=FAIL runner_exit=$rc"; fi' EXIT

git -C "$SOURCE" diff --quiet
git -C "$SOURCE" diff --cached --quiet
SHA=$(git -C "$SOURCE" rev-parse HEAD)
BUILD_SHA=$(cat "$BUILD/xdev-ext-source.commit")
# The test changes no kernel code, so the kernel binary need not be this exact
# commit. Record both; the kernel code at BUILD_SHA and at SHA must match (the
# branch only adds files under tests/).
printf 'test_source=%s\ntest_commit=%s\nkernel_build=%s\nkernel_commit=%s\nnative=%s\nscope=attacker-victim-isolation-software-correctness\ntiming=none\n' \
    "$SOURCE" "$SHA" "$BUILD" "$BUILD_SHA" "$NATIVE" >"$EV/provenance.txt"
for symbol in MODULES XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY BLK_DEV_NVME BLK_DEV_INITRD RD_GZIP \
    DEVTMPFS DEVTMPFS_MOUNT TMPFS PROC_FS SYSFS BLOCK PCI PCI_MSI IO_URING BPF BPF_SYSCALL \
    BPF_JIT DEBUG_INFO_BTF; do
    grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL requires CONFIG_$symbol=y"; exit 1; }
done
cp "$BUILD/.config" "$EV/kernel.config"
release=$(cat "$BUILD/include/config/kernel.release")
for artifact in "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux"; do
    [[ -s "$artifact" ]] || { echo "FAIL missing artifact $artifact"; exit 1; }
done

# Build the guest and BPF objects in a private native-shaped directory against
# the assembled native tree and the tested kernel's BTF. The canonical test
# sources are copied explicitly; nothing is written into the native view.
GUEST=$OUT/guest
mkdir -p "$GUEST"
for f in attack_guest.c attack.bpf.c attack_user.bpf.c Makefile; do
    cp "$SOURCE/tests/core/program_instances/attack/$f" "$GUEST/"
done
nice -n 10 make -C "$GUEST" KERNEL_SRC="$NATIVE" CC="$CC" CLANG="$CLANG" BPFTOOL="$BPFTOOL" \
    VMLINUX_BTF="$BUILD/vmlinux" >"$EV/test-build.log" 2>&1

# initramfs: busybox, the guest, the six BPF objects and the guest's libraries.
rm -rf -- "$ROOT"; mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/attack}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo printf poweroff dmesg sed grep sync; do ln -s busybox "$ROOT/bin/$app"; done
cp "$GUEST/attack_guest" "$ROOT/opt/attack/"
for o in attack_correct attack_reserved attack_outside attack_frame attack_verdict attack_user; do
    cp "$GUEST/$o.bpf.o" "$ROOT/opt/attack/"
done
: >"$EV/guest-libraries.txt"
elf=$(readelf -l -- "$GUEST/attack_guest") || { echo FAIL; exit 1; }
if grep -q INTERP <<<"$elf"; then
    deps=$(ldd "$GUEST/attack_guest" 2>&1) || { echo "FAIL ldd"; exit 1; }
    grep -q 'not found' <<<"$deps" && { printf '%s\n' "$deps" >&2; echo 'FAIL missing library'; exit 1; }
    awk '/=> \/|^[[:space:]]*\// {for(i=1;i<=NF;i++) if($i ~ /^\//) print $i}' <<<"$deps" >>"$EV/guest-libraries.txt"
fi
ldd /bin/busybox 2>/dev/null | awk '/=> \/|^[[:space:]]*\// {for(i=1;i<=NF;i++) if($i ~ /^\//) print $i}' >>"$EV/guest-libraries.txt" || true
sort -u -o "$EV/guest-libraries.txt" "$EV/guest-libraries.txt"
while IFS= read -r library; do
    [[ -n "$library" ]] || continue
    mkdir -p "$ROOT$(dirname "$library")"; cp -L "$library" "$ROOT$library"
done <"$EV/guest-libraries.txt"

cat >"$ROOT/init" <<'GUEST'
#!/bin/sh
export PATH=/bin
export XDEV_EXT_ATTACK_GUEST=1
main() {
    mount -t proc proc /proc && mount -t sysfs sysfs /sys &&
    mount -t devtmpfs devtmpfs /dev && mount -t tmpfs tmpfs /tmp &&
    mount -t bpf bpf /sys/fs/bpf || return 1
    src= dst=
    for serial in /sys/class/nvme/nvme*/serial; do
        [ -f "$serial" ] || continue
        case "$(sed 's/[[:space:]]*$//' "$serial")" in
        XDEVATKSRC01) c=${serial%/serial}; src=${c##*/} ;;
        XDEVATKDST01) c=${serial%/serial}; dst=${c##*/} ;;
        esac
    done
    [ -n "$src" ] && [ -n "$dst" ] || { echo 'FAIL NVMe serials not found'; return 1; }
    echo "XDEV_EXT_ATTACK_ROLES source=$src destination=$dst"
    /opt/attack/attack_guest "/dev/${src}n1" "/dev/ng${src#nvme}n1" \
        "/dev/${dst}n1" "/dev/ng${dst#nvme}n1" /opt/attack
}
echo
main
rc=$?
echo "XDEV_EXT_ATTACK_C_EXIT=$rc"
echo XDEV_EXT_ATTACK_DMESG_BEGIN
dmesg || rc=1
echo XDEV_EXT_ATTACK_DMESG_END
sync || rc=1
echo "XDEV_EXT_ATTACK_GUEST_EXIT=$rc"
poweroff -f
GUEST
chmod 755 "$ROOT/init"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"

# Disk images, independent of QEMU: a deterministic nonuniform source and a
# guard destination. The source pattern matches attack_validate.py's reads.
python3 -I - "$OUT" <<'PY'
from pathlib import Path
import sys
out = Path(sys.argv[1])
span = 4 << 20
source = bytes((i * 31 + 7) & 0xff for i in range(span))
(out / 'source.raw').write_bytes(source)
(out / 'source-before.raw').write_bytes(source)
(out / 'destination.raw').write_bytes(bytes([0x6b]) * span)
PY
sha256sum "$BUILD/.config" "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux" \
    "$GUEST/attack_guest" "$GUEST"/attack_*.bpf.o "$OUT/source-before.raw" >"$EV/artifacts.sha256"

[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]] || { echo 'FAIL KVM/QEMU unavailable'; exit 1; }
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
    -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
    -append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr' -nic none
    -drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
    -device nvme,drive=src,serial=XDEVATKSRC01
    -drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
    -device nvme,drive=dst,serial=XDEVATKDST01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
[[ "$qemu_status" == 0 ]] || { echo "FAIL qemu exit $qemu_status"; exit 1; }

# Required guest terminal markers, no kernel warning, and a clean C exit.
grep -q 'XDEV_EXT_ATTACK_ISOLATION=PASS' "$EV/guest.log" || { echo 'FAIL guest did not report isolation PASS'; exit 1; }
grep -q 'XDEV_EXT_ATTACK_C_EXIT=0' "$EV/guest.log" || { echo 'FAIL nonzero guest C exit'; exit 1; }
grep -q 'XDEV_EXT_ATTACK_GUEST_EXIT=0' "$EV/guest.log" || { echo 'FAIL nonzero guest exit'; exit 1; }
if sed -n '/XDEV_EXT_ATTACK_DMESG_BEGIN/,/XDEV_EXT_ATTACK_DMESG_END/p' "$EV/guest.log" | \
    grep -E 'WARNING:|BUG:|Oops|KASAN|UBSAN|circular locking|inconsistent lock|RCU stall|soft lockup|hung task|blocked for more than|quarantined|deferred drain'; then
    echo 'FAIL kernel log shows a warning, debug report, stall or quarantine'; exit 1
fi

# Independent host whole-disk oracle.
python3 -I "$SOURCE/tests/core/program_instances/attack/attack_validate.py" \
    "$OUT/source-before.raw" "$OUT/destination.raw" >"$EV/whole-disk.json"
grep -q '"state": "PASS"' "$EV/whole-disk.json" || { echo 'FAIL host whole-disk oracle rejected the run'; exit 1; }

cat >"$EV/result.json" <<JSON
{"scope":"attacker-victim program isolation, real QEMU NVMe, software correctness only",
 "test_commit":"$SHA","kernel_commit":"$BUILD_SHA","kernel_release":"$release",
 "qemu_exit":0,"timing":"none","hardware":false,"performance":false}
JSON
echo 'XDEV_EXT_ATTACK_KVM=PASS' | tee "$EV/verdict.txt"
trap - EXIT
