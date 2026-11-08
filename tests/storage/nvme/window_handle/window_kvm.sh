#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# NVMe LBA window handles on real QEMU NVMe PCI.
# Correctness only, nothing timed. --build is a kernel build directory
# (bzImage, vmlinux with BTF, .config, xdev-ext-source.commit), --native the
# assembled native tree of the commit under test (its UAPI headers and BPF
# program headers), --source the canonical Git root the test files come from.
# All disk writes stay in private image files inside a private 0700 scratch;
# no host hardware is touched. A kernel built from another commit is allowed
# only to show the test failing there (RED); the result records both commits.
# --mode multi runs window_multi.h instead: four tenants per round share one
# namespace of a two-namespace DST controller while one of them fails; it
# needs CONFIG_FAULT_INJECTION_DEBUG_FS and CONFIG_FAIL_IO_TIMEOUT (the faults
# are the kernel's own, on the faulty tenant's private namespace only).
# --mode multi-reset runs on the same devices: a DST controller reset while
# innocent tenants may have commands in flight. It reports what they end with
# (XDEV_EXT_WINDOW_RESET_DIAG lines) and gates on each innocent STOPping with
# 0 and its exact window or being released after the reset's DMA-stop proof,
# on every range being free, on each quarantined session leaving quarantine,
# and on the whole-disk oracle (window_validate.py --reset).
#
#   bash window_kvm.sh --scratch DIR --source CANON --native LINUX --build BUILD [--mode multi|multi-reset]
set -euo pipefail
umask 077
SCRATCH= SOURCE= NATIVE= BUILD= MODE=window
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
CLANG=${CLANG:-/usr/bin/clang-21}
BPFTOOL=${BPFTOOL:-bpftool}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-900}
while (($#)); do
    case "$1" in
    --scratch) SCRATCH=$2; shift 2;;
    --source) SOURCE=$2; shift 2;;
    --native) NATIVE=$2; shift 2;;
    --build) BUILD=$2; shift 2;;
    --mode) MODE=$2; shift 2;;
    *) echo "unknown option: $1" >&2; exit 2;;
    esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$NATIVE" && -n "$BUILD" ]] || { echo 'missing option' >&2; exit 2; }
[[ "$MODE" == window || "$MODE" == multi || "$MODE" == multi-reset ]] || { echo "unknown mode: $MODE" >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
    echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
SOURCE=$(cd "$SOURCE" && pwd -P)
NATIVE=$(cd "$NATIVE" && pwd -P)
BUILD=$(cd "$BUILD" && pwd -P)
[[ $(git -C "$SOURCE" rev-parse --show-toplevel) == "$SOURCE" ]] || {
    echo 'FAIL --source must be a canonical Git root' >&2; exit 1; }
TEST_DIR=$SOURCE/tests/storage/nvme/window_handle

EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee "$EV/runner.log") 2>&1
trap 'rc=$?; if (( rc )); then echo "XDEV_EXT_WINDOW_KVM=FAIL runner_exit=$rc"; fi' EXIT

git -C "$SOURCE" diff --quiet
git -C "$SOURCE" diff --cached --quiet
SHA=$(git -C "$SOURCE" rev-parse HEAD)
BUILD_SHA=$(cat "$BUILD/xdev-ext-source.commit")
# The assembly records the canonical checkout it was prepared from.
NATIVE_ROOT=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("canonical_root", ""))' \
    "$NATIVE/.xdev-ext-source.json" 2>/dev/null || true)
NATIVE_SHA=
[[ -n "$NATIVE_ROOT" && -d "$NATIVE_ROOT" ]] && NATIVE_SHA=$(git -C "$NATIVE_ROOT" rev-parse HEAD 2>/dev/null || true)
same=no; [[ "$BUILD_SHA" == "$SHA" ]] && same=yes
# Whether the kernel sources (src/) of the build commit equal the test commit's.
src_same=unknown
if git -C "$SOURCE" cat-file -e "$BUILD_SHA^{commit}" 2>/dev/null; then
    src_same=no; git -C "$SOURCE" diff --quiet "$BUILD_SHA" HEAD -- src && src_same=yes
fi
printf 'test_source=%s\ntest_commit=%s\nnative=%s\nnative_commit=%s\nkernel_build=%s\nkernel_commit=%s\nkernel_is_test_commit=%s\nkernel_src_equals_test_src=%s\nmode=%s\nscope=nvme-lba-window-handle-software-correctness\ntiming=none\n' \
    "$SOURCE" "$SHA" "$NATIVE" "$NATIVE_SHA" "$BUILD" "$BUILD_SHA" "$same" "$src_same" "$MODE" >"$EV/provenance.txt"
extra_symbols=
[[ "$MODE" == multi* ]] && extra_symbols='DEBUG_FS FAULT_INJECTION FAULT_INJECTION_DEBUG_FS FAIL_IO_TIMEOUT'
for symbol in MODULES XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY BLK_DEV_NVME BLK_DEV_INITRD RD_GZIP \
    DEVTMPFS DEVTMPFS_MOUNT TMPFS PROC_FS SYSFS BLOCK PCI PCI_MSI IO_URING BPF BPF_SYSCALL \
    BPF_JIT DEBUG_INFO_BTF UNIX $extra_symbols; do
    grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL requires CONFIG_$symbol=y"; exit 1; }
done
cp "$BUILD/.config" "$EV/kernel.config"
release=$(cat "$BUILD/include/config/kernel.release")
for artifact in "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux"; do
    [[ -s "$artifact" ]] || { echo "FAIL missing artifact $artifact"; exit 1; }
done

# Guest program and BPF object, built in a private directory against the
# native tree and the tested kernel's BTF; nothing is written into the view.
GUEST=$OUT/guest
rm -rf -- "$GUEST"; mkdir -p "$GUEST"
for f in window_guest.c window_multi.h window_nvme.bpf.c Makefile; do cp "$TEST_DIR/$f" "$GUEST/"; done
nice -n 10 make -C "$GUEST" KERNEL_SRC="$NATIVE" CC="$CC" CLANG="$CLANG" BPFTOOL="$BPFTOOL" \
    VMLINUX_BTF="$BUILD/vmlinux" >"$EV/test-build.log" 2>&1

rm -rf -- "$ROOT"; mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/window}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo printf poweroff dmesg sed grep sync ls; do ln -s busybox "$ROOT/bin/$app"; done
cp "$GUEST/window_guest" "$GUEST/window_nvme.bpf.o" "$ROOT/opt/window/"
case "$MODE" in multi) verb=multi;; multi-reset) verb=reset;; *) verb=window;; esac
printf '%s\n' "$verb" >"$ROOT/opt/window/mode"
: >"$EV/guest-libraries.txt"
elf=$(readelf -l -- "$GUEST/window_guest") || { echo FAIL; exit 1; }
if grep -q INTERP <<<"$elf"; then
    deps=$(ldd "$GUEST/window_guest" 2>&1) || { echo "FAIL ldd"; exit 1; }
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
export XDEV_EXT_WINDOW_GUEST=1
main() {
    mount -t proc proc /proc && mount -t sysfs sysfs /sys &&
    mount -t devtmpfs devtmpfs /dev && mount -t tmpfs tmpfs /tmp &&
    mount -t bpf bpf /sys/fs/bpf || return 1
    src= dst=
    for serial in /sys/class/nvme/nvme*/serial; do
        [ -f "$serial" ] || continue
        case "$(sed 's/[[:space:]]*$//' "$serial")" in
        XDEVWINSRC01) c=${serial%/serial}; src=${c##*/} ;;
        XDEVWINDST01) c=${serial%/serial}; dst=${c##*/} ;;
        esac
    done
    [ -n "$src" ] && [ -n "$dst" ] || { echo 'FAIL NVMe serials not found'; return 1; }
    echo "XDEV_EXT_WINDOW_ROLES source=$src destination=$dst"
    ls -l "/dev/${src}n1" "/dev/ng${src#nvme}n1" "/dev/${dst}n1" "/dev/ng${dst#nvme}n1"
    verb=$(cat /opt/window/mode)
    if [ "$verb" = multi ] || [ "$verb" = reset ]; then
        mount -t debugfs debugfs /sys/kernel/debug || return 1
        ls -l "/dev/${dst}n2" "/dev/ng${dst#nvme}n2" || return 1
        /opt/window/window_guest "/dev/${src}n1" "/dev/ng${src#nvme}n1" \
            "/dev/${dst}n1" "/dev/ng${dst#nvme}n1" /opt/window "$verb" \
            "/dev/${dst}n2" "/dev/ng${dst#nvme}n2"
        return
    fi
    /opt/window/window_guest "/dev/${src}n1" "/dev/ng${src#nvme}n1" \
        "/dev/${dst}n1" "/dev/ng${dst#nvme}n1" /opt/window
}
echo
main
rc=$?
echo "XDEV_EXT_WINDOW_C_EXIT=$rc"
echo XDEV_EXT_WINDOW_DMESG_BEGIN
dmesg || rc=1
echo XDEV_EXT_WINDOW_DMESG_END
sync || rc=1
echo "XDEV_EXT_WINDOW_GUEST_EXIT=$rc"
poweroff -f
GUEST
chmod 755 "$ROOT/init"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"

# The oracle checks itself first.
TMPDIR=$OUT python3 -I "$TEST_DIR/window_validate_test.py" >"$EV/oracle-selftest.log" 2>&1 || {
    cat "$EV/oracle-selftest.log"; echo 'FAIL oracle self-test'; exit 1; }

# Disk images: a position-unique source with a random per-run seed and a guard
# destination; window_validate.py regenerates the source from the seed.
python3 -I - "$OUT" "$EV/source-seed.txt" "$MODE" <<'PY'
from pathlib import Path
import os
import struct
import sys
out = Path(sys.argv[1])
span = 4 << 20
seed = 0x6b6b6b6b
while seed == 0x6b6b6b6b:
    seed = int.from_bytes(os.urandom(4), 'little')
source = bytearray(span)
for o in range(0, span, 8):
    struct.pack_into('<II', source, o, ((o // 512) << 7) | (((o % 512) // 8) << 1) | 1, seed)
(out / 'source.raw').write_bytes(source)
(out / 'source-before.raw').write_bytes(source)
(out / 'destination.raw').write_bytes(bytes([0x6b]) * span)
if sys.argv[3].startswith('multi'):
    (out / 'aux.raw').write_bytes(bytes([0x3c]) * span)
Path(sys.argv[2]).write_text('seed=0x%08x\n' % seed)
PY
sha256sum "$BUILD/.config" "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux" \
    "$GUEST/window_guest" "$GUEST/window_nvme.bpf.o" "$OUT/source-before.raw" \
    "$TEST_DIR/window_validate.py" >"$EV/artifacts.sha256"

[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]] || { echo 'FAIL KVM/QEMU unavailable'; exit 1; }
append='console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr'
# multi: no command timeout may fire on its own during the run (the timeout
# round swallows completions on purpose), so the passthrough timeout is long.
[[ "$MODE" == multi* ]] && append+=' nvme_core.io_timeout=600'
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
    -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
    -append "$append" -nic none
    -drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
    -device nvme,drive=src,serial=XDEVWINSRC01
    -drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads,throttling.bps-write=131072")
if [[ "$MODE" == multi* ]]; then
    # One DST controller, two namespaces: ns1 shared, ns2 the faulty tenant's.
    args+=(-drive "file=$OUT/aux.raw,if=none,id=aux,format=raw,cache=none,aio=threads"
        -device nvme,id=dstctl,serial=XDEVWINDST01
        -device nvme-ns,drive=dst,bus=dstctl,nsid=1
        -device nvme-ns,drive=aux,bus=dstctl,nsid=2)
else
    args+=(-device nvme,drive=dst,serial=XDEVWINDST01)
fi
# QEMU's own write throttle on the destination backing file (128 KiB/s): a
# session is still writing when victim2 closes its handle fds right after
# START. It changes no device model and nothing is timed.
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
[[ "$qemu_status" == 0 ]] || { echo "FAIL qemu exit $qemu_status"; exit 1; }

marker=XDEV_EXT_WINDOW_HANDLE=PASS
[[ "$MODE" == multi ]] && marker=XDEV_EXT_WINDOW_MULTI=PASS
[[ "$MODE" == multi-reset ]] && marker=XDEV_EXT_WINDOW_RESET_DIAG=DONE
grep -q "$marker" "$EV/guest.log" || { echo "FAIL guest did not report $marker"; exit 1; }
grep -q 'XDEV_EXT_WINDOW_C_EXIT=0' "$EV/guest.log" || { echo 'FAIL nonzero guest C exit'; exit 1; }
grep -q 'XDEV_EXT_WINDOW_GUEST_EXIT=0' "$EV/guest.log" || { echo 'FAIL nonzero guest exit'; exit 1; }
if grep -q '^not ok' "$EV/guest.log"; then echo 'FAIL a guest check reported not ok'; exit 1; fi
sed -n '/XDEV_EXT_WINDOW_DMESG_BEGIN/,/XDEV_EXT_WINDOW_DMESG_END/p' "$EV/guest.log" >"$EV/dmesg.txt"
# multi: exactly the one expected quarantine (the unknown round's session at
# STOP) and one deferred release (the timeout round's session, released after
# the closing reset); anything else fails as in window mode. multi-reset
# allows them, but every quarantined session must leave quarantine.
allowed='^$'
[[ "$MODE" == multi-reset ]] && allowed='xdev_ext_mech: (session [0-9]+ quarantined, |drain bound passed )'
if [[ "$MODE" == multi ]]; then
    allowed='xdev_ext_mech: session [0-9]+ quarantined, '
    n=$(grep -cE "$allowed" "$EV/dmesg.txt" || true)
    [[ "$n" == 1 ]] || { echo "FAIL expected 1 quarantined session, saw $n"; exit 1; }
    n=$(grep -c 'drain bound passed with [0-9]* batches in flight' "$EV/dmesg.txt" || true)
    [[ "$n" == 1 ]] || { echo "FAIL expected 1 deferred release, saw $n"; exit 1; }
fi
if [[ "$MODE" == multi || "$MODE" == multi-reset ]]; then
    # The DST controller resets prove the quarantined sessions' commands stopped.
    q=$(grep -cE 'xdev_ext_mech: session [0-9]+ quarantined, ' "$EV/dmesg.txt" || true)
    l=$(grep -cE 'xdev_ext_mech: session [0-9]+ leaves quarantine: ' "$EV/dmesg.txt" || true)
    printf 'quarantined=%s left_quarantine=%s\n' "$q" "$l" >"$EV/quarantine-counts.txt"
    [[ "$q" == "$l" ]] || { echo "FAIL $q sessions quarantined but $l left quarantine"; exit 1; }
fi
if grep -E 'WARNING:|BUG:|Oops|KASAN|UBSAN|circular locking|inconsistent lock|RCU stall|soft lockup|hung task|blocked for more than|quarantined|deferred drain' "$EV/dmesg.txt" | \
    grep -v 'KernelAddressSanitizer initialized' | grep -vE "$allowed"; then
    echo 'FAIL kernel log shows a warning, debug report, stall or quarantine'; exit 1
fi

if [[ "$MODE" == multi ]]; then
    kill_min=$(sed -n 's/^XDEV_EXT_WINDOW_MULTI_KILL done_at_kill=\([0-9]*\) .*/\1/p' "$EV/guest.log" | tail -1)
    [[ -n "$kill_min" ]] || { echo 'FAIL no kill point reported'; exit 1; }
    python3 -I "$TEST_DIR/window_validate.py" --multi "$OUT/source-before.raw" "$OUT/destination.raw" \
        "$OUT/aux.raw" "$kill_min" >"$EV/whole-disk.json" || true
elif [[ "$MODE" == multi-reset ]]; then
    # Per-tenant end states; innocents that STOPped cleanly must be exact.
    grep '^XDEV_EXT_WINDOW_RESET_DIAG' "$EV/guest.log" >"$EV/reset-diagnostic.txt"
    exact=$(sed -n 's/^XDEV_EXT_WINDOW_RESET_EXACT tenants=\([-0-9,]*\)$/\1/p' "$EV/guest.log" | tail -1)
    [[ -n "$exact" ]] || { echo 'FAIL no exact-tenant list reported'; exit 1; }
    python3 -I "$TEST_DIR/window_validate.py" --reset "$OUT/source-before.raw" "$OUT/destination.raw" \
        "$OUT/aux.raw" "$exact" >"$EV/whole-disk.json" || true
else
    python3 -I "$TEST_DIR/window_validate.py" "$OUT/source-before.raw" "$OUT/destination.raw" >"$EV/whole-disk.json" || true
fi
grep -q '"state": "PASS"' "$EV/whole-disk.json" || { cat "$EV/whole-disk.json"; echo 'FAIL host whole-disk oracle rejected the run'; exit 1; }

seed=$(sed -n 's/^seed=//p' "$EV/source-seed.txt")
oks=$(grep -c '^ok ' "$EV/guest.log" || true)
cat >"$EV/result.json" <<JSON
{"scope":"NVMe LBA window handles, real QEMU NVMe, software correctness only",
 "test_commit":"$SHA","kernel_commit":"$BUILD_SHA","kernel_is_test_commit":"$same",
 "kernel_src_equals_test_src":"$src_same","kernel_release":"$release","mode":"$MODE",
 "guest_ok":$oks,"source_seed":"$seed","qemu_exit":0,"timing":"none","hardware":false,"performance":false}
JSON
echo "XDEV_EXT_WINDOW_KVM=PASS mode=$MODE" | tee "$EV/verdict.txt"
trap - EXIT
