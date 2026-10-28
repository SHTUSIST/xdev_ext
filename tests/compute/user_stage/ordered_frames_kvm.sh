#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Exclusive software correctness run of the existing raw USER ordered guest.
# Invoked by user_kvm.sh --ordered-frames. No performance measurement.
set -euo pipefail
umask 077
SCRATCH= SOURCE= BUILD= TOOLS=
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
CLANG=${CLANG:-/usr/bin/clang-21}
BPFTOOL=${BPFTOOL:-bpftool}
while (($#)); do
    case "$1" in
    --scratch) SCRATCH=$2; shift 2;;
    --source) SOURCE=$2; shift 2;;
    --build) BUILD=$2; shift 2;;
    --tools) TOOLS=$2; shift 2;;
    *) echo "unknown option: $1" >&2; exit 2;;
    esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$BUILD" && -n "$TOOLS" ]] || { echo 'missing option' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
    echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
SOURCE=$(cd "$SOURCE" && pwd -P)
BUILD=$(cd "$BUILD" && pwd -P)
TOOLS=$(cd "$TOOLS" && pwd -P)
[[ $(git -C "$SOURCE" rev-parse --show-toplevel) == "$SOURCE" ]] || {
    echo 'FAIL --source must be canonical Git root' >&2; exit 1; }
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee "$EV/runner.log") 2>&1
trap 'rc=$?; if (( rc )); then echo "XDEV_EXT_ORDERED_KVM=FAIL runner_exit=$rc"; fi' EXIT
git -C "$SOURCE" diff --quiet
git -C "$SOURCE" diff --cached --quiet
[[ -z $(git -C "$SOURCE" ls-files --others --exclude-standard) ]]
SHA=$(git -C "$SOURCE" rev-parse HEAD)
CONTRACT=$SOURCE/tests/integration/build/kvm_layout/contracts.py
NATIVE=$SOURCE/build/source-view/kernel
python3 -I "$CONTRACT" roots "$SOURCE" "$SHA" "$BUILD" "$EV/roots.json"
[[ $(cat "$BUILD/xdev-ext-source.commit") == "$SHA" ]]
python3 -I "$CONTRACT" artifacts "$BUILD/xdev-ext-xdomain-build.sha256" "$EV/bound-artifacts.json" \
    "$BUILD/.config" "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux" "$BUILD/Module.symvers" \
    "$TOOLS/user_plan.bpf.o" "$TOOLS/peer-guest/xdev_ext_peer_sw.ko"
sha256sum -c "$BUILD/xdev-ext-xdomain-build.sha256" >"$EV/build-identity-check.log" 2>&1
for symbol in MODULES MODULE_UNLOAD XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY BLK_DEV_NVME BLK_DEV_INITRD RD_GZIP \
    DEVTMPFS DEVTMPFS_MOUNT TMPFS PROC_FS SYSFS BLOCK PCI PCI_MSI ACPI SERIAL_8250 SERIAL_8250_CONSOLE \
    IO_URING BPF BPF_SYSCALL BPF_JIT DEBUG_INFO_BTF; do
    grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL requires CONFIG_$symbol=y"; exit 1; }
done
DEBUG=$SOURCE/tests/integration/session/native/xdev_ext_mech_zc_debug.py
python3 -I "$DEBUG" config "$BUILD/.config" "$EV/debug-profile.json" 1
release=$(cat "$BUILD/include/config/kernel.release")
for artifact in "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux" "$BUILD/Module.symvers" \
    "$TOOLS/user_plan.bpf.o" "$TOOLS/peer-guest/xdev_ext_peer_sw.ko"; do
    [[ -s "$artifact" ]] || { echo "FAIL missing artifact $artifact"; exit 1; }
done
printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\nnative_source=%s\nassembled_source=%s\ntools=%s\nkernel_release=%s\nscope=ordered-frames-software-correctness\ntiming=none\n' \
    "$SOURCE" "$SHA" "$BUILD" "$SHA" "$NATIVE" "$SOURCE/build/assembled/linux" "$TOOLS" "$release" >"$EV/provenance.txt"
cp "$BUILD/.config" "$EV/kernel.config"

# Preserve the existing C include ../../../xdev_ext_peer/guest/... in a
# private native-shaped build tree. Never write a generated binary into view.
SELF=$OUT/build/tools/testing/selftests
GUEST=$SELF/xdev_ext_mech/user_stage/guest
mkdir -p "$SELF/xdev_ext_mech/user_stage" "$SELF/xdev_ext_peer/guest"
cp -a "$NATIVE/tools/testing/selftests/xdev_ext_mech/user_stage/guest/." "$GUEST/"
cp "$NATIVE/tools/testing/selftests/xdev_ext_peer/guest/sw_provider_uapi.h" "$SELF/xdev_ext_peer/guest/"
# This test policy is logical-only: copy its canonical source explicitly.
cp "$SOURCE/tests/compute/user_stage/guest/ordered_frames_nvme.bpf.c" "$GUEST/"
nice -n 10 make -C "$GUEST" KERNEL_SRC="$NATIVE" CC="$CC" VMLINUX_BTF="$BUILD/vmlinux" \
    CLANG="$CLANG" BPFTOOL="$BPFTOOL" ordered_frames_guest ordered_frames_nvme.bpf.o >"$EV/test-build.log" 2>&1
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/user}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo printf poweroff dmesg sed grep sync sleep insmod rmmod; do
    ln -s busybox "$ROOT/bin/$app"
done
cp "$GUEST/ordered_frames_guest" "$GUEST/ordered_frames_nvme.bpf.o" "$TOOLS/user_plan.bpf.o" \
    "$TOOLS/peer-guest/xdev_ext_peer_sw.ko" "$ROOT/opt/user/"
: >"$EV/guest-libraries.txt"
collect_libraries() {
    local binary=$1 elf dependencies
    elf=$(readelf -l -- "$binary") || return 1
    if ! grep -q INTERP <<<"$elf"; then return 0; fi
    dependencies=$(ldd "$binary" 2>&1) || return 1
    if grep -q 'not found' <<<"$dependencies"; then
        printf '%s\n' "$dependencies" >&2; return 1
    fi
    awk '/=> \/|^[[:space:]]*\// {for(i=1;i<=NF;i++) if($i ~ /^\//) print $i}' <<<"$dependencies" >>"$EV/guest-libraries.txt"
}
for binary in "$GUEST/ordered_frames_guest" /bin/busybox; do collect_libraries "$binary"; done
sort -u -o "$EV/guest-libraries.txt" "$EV/guest-libraries.txt"
while IFS= read -r library; do
    mkdir -p "$ROOT$(dirname "$library")"; cp -L "$library" "$ROOT$library"
done <"$EV/guest-libraries.txt"
cat >"$ROOT/init" <<'GUEST'
#!/bin/sh
export PATH=/bin
guest_main() {
    mount -t proc proc /proc && mount -t sysfs sysfs /sys &&
    mount -t devtmpfs devtmpfs /dev && mount -t tmpfs tmpfs /tmp &&
    mount -t bpf bpf /sys/fs/bpf || return 1
    destination= matches=0
    for serial in /sys/class/nvme/nvme*/serial; do
        [ -f "$serial" ] || continue
        [ "$(sed 's/[[:space:]]*$//' "$serial")" = XDEVORDERED01 ] || continue
        destination=${serial%/serial}; destination=${destination##*/}
        matches=$((matches + 1))
    done
    [ "$matches" = 1 ] || return 1
    block=/dev/${destination}n1
    ng=/dev/ng${destination#nvme}n1
    [ -b "$block" ] && [ -c "$ng" ] || return 1
    insmod /opt/user/xdev_ext_peer_sw.ko guest_only=1
    load_rc=$?
    echo "XDEV_EXT_ORDERED_PROVIDER_LOAD=$load_rc"
    [ "$load_rc" = 0 ] || return 1
    /opt/user/ordered_frames_guest "$block" "$ng" /opt/user 2048
    c_rc=$?
    echo "XDEV_EXT_ORDERED_C_EXIT=$c_rc"
    rmmod xdev_ext_peer_sw
    unload_rc=$?
    echo "XDEV_EXT_ORDERED_PROVIDER_UNLOAD=$unload_rc"
    [ "$c_rc" = 0 ] && [ "$unload_rc" = 0 ]
}
# Keep complete diagnostics even on C/setup failure. The host rejects every
# missing terminal record and any nonzero C, guest, or QEMU status.
echo
guest_main
guest_rc=$?
echo XDEV_EXT_ORDERED_DMESG_BEGIN
dmesg || guest_rc=1
echo XDEV_EXT_ORDERED_DMESG_END
sync || guest_rc=1
echo "XDEV_EXT_ORDERED_GUEST_EXIT=$guest_rc"
poweroff -f
GUEST
chmod 755 "$ROOT/init"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"

# The baseline is generated independently before QEMU and is never inferred
# from its output. Separate files, not hardlinks; the whole disk is checked.
python3 -I - "$OUT" <<'PY'
from pathlib import Path
import sys
out = Path(sys.argv[1])
chunk = bytes((i * 29 + 0xA5) % 256 for i in range(4096)) * 256
for name in ('destination-before.raw', 'destination.raw'):
    with (out / name).open('wb') as stream:
        for _ in range(16):
            stream.write(chunk)
PY
sha256sum "$BUILD/.config" "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux" "$BUILD/Module.symvers" \
    "$GUEST/ordered_frames_guest" "$GUEST/ordered_frames_nvme.bpf.o" "$TOOLS/user_plan.bpf.o" \
    "$TOOLS/peer-guest/xdev_ext_peer_sw.ko" "$OUT/destination-before.raw" >"$EV/artifacts.sha256"
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]] || { echo 'FAIL KVM/QEMU unavailable'; exit 1; }
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
    -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
    -append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr' -nic none
    -drive "file=$OUT/destination.raw,if=none,id=private,format=raw,cache=none,aio=threads"
    -device nvme,drive=private,serial=XDEVORDERED01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "${TIMEOUT_SECONDS:-1800}" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
[[ "$qemu_status" == 0 ]]
python3 -I "$CONTRACT" ordered-log "$EV/guest.log" "$EV/terminal.json"
python3 -I "$DEBUG" console "$EV/guest.log" "$EV/debug.json" 1
python3 -I "$SOURCE/tests/compute/user_stage/ordered_frames_validate.py" \
    "$OUT/destination-before.raw" "$OUT/destination.raw" 2048 >"$EV/whole-disk.json"
cp "$EV/terminal.json" "$EV/result.json"
echo 'XDEV_EXT_ORDERED_KVM=PASS' | tee "$EV/verdict.txt"
