#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# KVM correctness run of the BPF compute examples
# (tools/xdev_ext_mech/examples/compute) against the fixed CPU transforms;
# never a performance benchmark: nothing is timed. It boots a kernel and
# tools built from an ancestor commit (bzImage, xdev_ext_mech_ctl and the
# vmlinux.h of tools/xdev_ext_mech) that differs from the checkout only in the
# examples, this test directory, .gitignore and the host CI workflow, and builds only the example
# objects (clang, BPF bytecode only) and the guest tool (gcc). The kernel needs
# CONFIG_XDEV_EXT_MECH_CPU with the strict debug options. All writes stay in
# --scratch: initramfs, a private results disk and evidence. No host module is
# loaded and no host NIC, route or disk is touched; the guest has no network
# device.
#   bash examples_kvm.sh --scratch DIR --source GIT_ROOT --build O_DIR --tools TOOLS_DIR
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' BUILD='' TOOLS=''
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
CLANG=${CLANG:-/usr/bin/clang-21}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-2400}
while (($#)); do
	case "$1" in
	--scratch) SCRATCH=$2; shift 2 ;;
	--source) SOURCE=$2; shift 2 ;;
	--build) BUILD=$2; shift 2 ;;
	--tools) TOOLS=$2; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$BUILD" && -n "$TOOLS" ]] || { echo 'missing option' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
	echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
REL=kernel/tools/testing/selftests/xdev_ext_mech/compute_examples
EXD=kernel/tools/xdev_ext_mech/examples/compute
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee -a "$EV/runner.log") 2>&1
stage=identity
trap 'echo "XDEV_EXT_COMPUTE_EXAMPLES_KVM=FAIL stage=$stage" | tee "$EV/verdict.txt"' ERR

# Identity: an exact clean checkout, and a prebuilt kernel/tools of an ancestor.
SOURCE=$(git -C "$SOURCE" rev-parse --show-toplevel)
git -C "$SOURCE" diff --quiet && git -C "$SOURCE" diff --cached --quiet
[[ -z $(git -C "$SOURCE" ls-files --others --exclude-standard) ]] || { echo 'FAIL untracked source files' >&2; false; }
HEAD_SHA=$(git -C "$SOURCE" rev-parse --verify 'HEAD^{commit}')
BUILD_SHA=$(cat "$BUILD/xdev-ext-source.commit")
git -C "$SOURCE" cat-file -e "$BUILD_SHA^{commit}"
git -C "$SOURCE" merge-base --is-ancestor "$BUILD_SHA" "$HEAD_SHA"
changed=$(git -C "$SOURCE" diff --name-only "$BUILD_SHA" "$HEAD_SHA" || true)
# None of these is part of the prebuilt kernel or tools.
if [[ -n "$changed" ]] && grep -v -e "^$REL/" -e "^$EXD/" -e '^\.gitignore$' \
	-e '^\.github/workflows/host\.yml$' <<<"$changed"; then
	echo 'FAIL source differs from the prebuilt kernel/tools outside the example and test files' >&2; false
fi
for symbol in XDEV_EXT_MECH XDEV_EXT_MECH_CPU DEBUG_KERNEL PROVE_LOCKING DEBUG_ATOMIC_SLEEP KASAN \
	DETECT_HUNG_TASK BLK_DEV_NVME BLK_DEV_INITRD DEVTMPFS IO_URING BPF_SYSCALL DEBUG_INFO_BTF \
	SERIAL_8250_CONSOLE; do
	grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; false; }
done
release=$(cat "$BUILD/include/config/kernel.release")
for artifact in "$BUILD/arch/x86/boot/bzImage" "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/vmlinux.h"; do
	[[ -s "$artifact" ]] || { echo "FAIL missing prebuilt artifact $artifact" >&2; false; }
done
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; CPU class fixed transforms vs BPF compute examples; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\ntools=%s\nkernel_release=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$TOOLS" "$release"
	printf 'changed_since_build=%s\n' "$(tr '\n' ' ' <<<"$changed")"
	printf 'clang=%s\ncc=%s\n' "$("$CLANG" --version | head -1)" "$("$CC" --version | head -1)"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|DETECT_HUNG_TASK|XDEV_EXT_MECH_CPU|DEBUG_INFO_COMPRESSED[A-Z_]*|PREEMPT[A-Z_]*)=' "$BUILD/.config" || true
} >"$EV/provenance.txt"

# The example objects (vmlinux.h of the prebuilt tools) and the guest tool.
stage=build-examples
mkdir -p "$OUT/obj"
nice -n 10 make -C "$SOURCE/$EXD" OUT="$OUT/obj" VMLINUX_DIR="$TOOLS" CLANG="$CLANG" all \
	>"$EV/test-build.log" 2>&1
stage=build-guest-tool
"$CC" -std=gnu11 -O2 -g -Wall -Wextra -Werror -I"$SOURCE/kernel" \
	-I"$SOURCE/kernel/tools/testing/selftests/xdev_ext_mech" \
	"$SOURCE/$REL/guest/compute_examples_guest.c" -o "$OUT/compute_examples_guest" \
	-lbpf -lelf -lz >>"$EV/test-build.log" 2>&1

# Minimal initramfs: busybox, the guest programs and their libraries.
stage=initramfs
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/examples/obj}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo printf poweroff dmesg sed mkdir mktemp sync ls wc tar dd rm cut grep \
	true sleep; do
	ln -sf busybox "$ROOT/bin/$app"
done
cp "$OUT/compute_examples_guest" "$TOOLS/xdev_ext_mech_ctl" "$SOURCE/$REL/guest/run-guest.sh" \
	"$ROOT/opt/examples/"
cp "$OUT/obj/"*.bpf.o "$ROOT/opt/examples/obj/"
: >"$EV/guest-libraries.txt"
for binary in "$OUT/compute_examples_guest" "$TOOLS/xdev_ext_mech_ctl"; do
	ldd "$binary" | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' \
		>>"$EV/guest-libraries.txt"
done
sort -u -o "$EV/guest-libraries.txt" "$EV/guest-libraries.txt"
while IFS= read -r lib; do
	mkdir -p "$ROOT$(dirname "$lib")"; cp -L "$lib" "$ROOT$lib"
done <"$EV/guest-libraries.txt"
cat >"$ROOT/init" <<'GUEST'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t bpf bpf /sys/fs/bpf
# Firmware leaves escape sequences on the console line; start a clean one.
echo
echo XDEV_EXT_EXAMPLES_GUEST_BEGIN
XDEV_EXT_EXAMPLES_GUEST=1 sh /opt/examples/run-guest.sh /opt/examples
code=$?
echo "XDEV_EXT_EXAMPLES_GUEST_EXIT=$code"
echo XDEV_EXT_EXAMPLES_DMESG_BEGIN
dmesg
echo XDEV_EXT_EXAMPLES_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init" "$ROOT/opt/examples/run-guest.sh"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"
sha256sum "$BUILD/arch/x86/boot/bzImage" "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/vmlinux.h" \
	"$OUT/compute_examples_guest" "$OUT/obj/"*.bpf.o >"$EV/artifacts.sha256"

# A private results disk; nothing else is attached.
stage=guest
python3 -I "$SOURCE/$REL/examples_validate.py" make-images "$OUT"
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr'
	-nic none
	-drive "file=$OUT/results.raw,if=none,id=res,format=raw,cache=none,aio=threads"
	-device nvme,drive=res,serial=XDEVXRES01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
stage=validate
validator_status=0
python3 -I "$SOURCE/$REL/examples_validate.py" validate --dir "$OUT" --log "$EV/guest.log" \
	--result "$EV/result.json" || validator_status=$?
grep '^XDEV_EXT_EXAMPLE_VERIFIER ' "$EV/guest.log" | tr -d '\r' >"$EV/verifier-insns.txt" || true
trap - ERR
if (( qemu_status == 0 && validator_status == 0 )); then
	echo 'XDEV_EXT_COMPUTE_EXAMPLES_KVM=PASS' | tee "$EV/verdict.txt"
else
	echo "XDEV_EXT_COMPUTE_EXAMPLES_KVM=FAIL qemu_exit=$qemu_status validator_exit=$validator_status" |
		tee "$EV/verdict.txt"
	exit 1
fi
