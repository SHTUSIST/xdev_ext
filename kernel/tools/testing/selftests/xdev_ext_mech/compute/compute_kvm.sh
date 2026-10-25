#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused KVM correctness run of the CPU class BPF compute callback
# (Documentation/userspace-api/xdev_ext-compute.rst), never a performance
# benchmark: nothing is timed. It boots a kernel and tools built from the same
# checkout (bzImage, xdev_ext_mech_ctl, nxp_mech.bpf.o and the verifier objects
# of tools/testing/selftests/xdev_ext_integration/verifier) and builds only the
# guest BPF objects and the layout helper. The kernel needs CONFIG_XDEV_EXT_MECH_CPU
# (xdev_ext_mech_zc_kvm.sh --lifecycle enables it). All writes stay in --scratch:
# private raw images, initramfs and evidence. No host module is loaded and no
# host NIC, route or disk is touched; the guest has no network device.
#   bash compute_kvm.sh --scratch DIR --source GIT_ROOT --build O_DIR --tools TOOLS_DIR
# --red boots an older kernel (O_DIR of a commit without compute) with the same
# guest programs and passes only if attaching the compute program is refused:
# the guest test's RED baseline. Identity checks of the build are recorded, not
# enforced, in that mode.
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' BUILD='' TOOLS='' RED=0
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
CLANG=${CLANG:-/usr/bin/clang-21}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-1500}
while (($#)); do
	case "$1" in
	--scratch) SCRATCH=$2; shift 2 ;;
	--source) SOURCE=$2; shift 2 ;;
	--build) BUILD=$2; shift 2 ;;
	--tools) TOOLS=$2; shift 2 ;;
	--red) RED=1; shift ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$BUILD" && -n "$TOOLS" ]] || { echo 'missing option' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
	echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
REL=kernel/tools/testing/selftests/xdev_ext_mech/compute
VER=kernel/tools/testing/selftests/xdev_ext_integration/verifier
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee -a "$EV/runner.log") 2>&1

# Identity: an exact clean checkout, and a prebuilt kernel/tools of that commit.
SOURCE=$(git -C "$SOURCE" rev-parse --show-toplevel)
git -C "$SOURCE" diff --quiet && git -C "$SOURCE" diff --cached --quiet
[[ -z $(git -C "$SOURCE" ls-files --others --exclude-standard) ]] || { echo 'FAIL untracked source files' >&2; exit 1; }
HEAD_SHA=$(git -C "$SOURCE" rev-parse --verify 'HEAD^{commit}')
BUILD_SHA=$(cat "$BUILD/xdev-ext-source.commit")
if (( RED )); then
	changed="red baseline kernel $BUILD_SHA, guest programs of $HEAD_SHA"
else
	git -C "$SOURCE" cat-file -e "$BUILD_SHA^{commit}"
	git -C "$SOURCE" merge-base --is-ancestor "$BUILD_SHA" "$HEAD_SHA"
	changed=$(git -C "$SOURCE" diff --name-only "$BUILD_SHA" "$HEAD_SHA" || true)
	# Only this test directory and its specification may differ: neither is
	# part of the prebuilt kernel or tools.
	if [[ -n "$changed" ]] && grep -v -e "^$REL/" -e '^kernel/Documentation/userspace-api/xdev_ext-compute.rst$' <<<"$changed"; then
		echo 'FAIL source differs from the prebuilt kernel/tools outside the compute test files' >&2; exit 1
	fi
	for symbol in XDEV_EXT_MECH_CPU DEBUG_KERNEL PROVE_LOCKING DEBUG_ATOMIC_SLEEP KASAN DETECT_HUNG_TASK; do
		grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
	done
fi
for symbol in XDEV_EXT_MECH BLK_DEV_NVME BLK_DEV_INITRD DEVTMPFS IO_URING BPF_SYSCALL DEBUG_INFO_BTF \
	SERIAL_8250_CONSOLE; do
	grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
done
release=$(cat "$BUILD/include/config/kernel.release")
for artifact in "$BUILD/arch/x86/boot/bzImage" "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/nxp_mech.bpf.o"; do
	[[ -s "$artifact" ]] || { echo "FAIL missing prebuilt artifact $artifact" >&2; exit 1; }
done
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; QEMU NVMe; CPU class BPF compute; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\ntools=%s\nkernel_release=%s\nred=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$TOOLS" "$release" "$RED"
	printf 'changed_since_build=%s\n' "$(tr '\n' ' ' <<<"$changed")"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|DETECT_HUNG_TASK|XDEV_EXT_MECH_CPU|DEBUG_INFO_COMPRESSED[A-Z_]*|PREEMPT[A-Z_]*)=' "$BUILD/.config" || true
} >"$EV/provenance.txt"

# Guest BPF objects and the verifier objects of this commit; the layout helper.
mkdir -p "$OUT/build/verifier"
nice -n 10 make -C "$SOURCE/$REL/guest" OUT="$OUT/build" KERNEL_SRC="$SOURCE/kernel" CLANG="$CLANG" \
	HOSTCC="$CC" all >"$EV/test-build.log" 2>&1
nice -n 10 make -C "$SOURCE/$VER" BUILD_DIR="$OUT/build/verifier" CLANG="$CLANG" HOSTCC="$CC" \
	all >>"$EV/test-build.log" 2>&1
"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -I"$SOURCE/kernel" "$SOURCE/$REL/compute_layout.c" \
	-o "$OUT/build/compute_layout" >>"$EV/test-build.log" 2>&1
"$OUT/build/compute_layout" >"$EV/layout.txt"
capacity=$(sed -n 's/.*capacity=\([0-9]*\).*/\1/p' "$EV/layout.txt")
seg_len=$(sed -n 's/.*seg_len=\([0-9]*\).*/\1/p' "$EV/layout.txt")
[[ -n "$capacity" && -n "$seg_len" ]]

# Minimal initramfs: busybox, the guest programs and their libraries.
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/compute/verifier}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo printf poweroff dmesg sed cut basename dirname mkdir rmdir mktemp sync \
	awk grep seq sleep cmp dd ls tr wc head tail readlink true; do
	ln -sf busybox "$ROOT/bin/$app"
done
cp "$OUT/build/compute_test.bpf.o" "$OUT/build/compute_old_layout.bpf.o" "$TOOLS/xdev_ext_mech_ctl" \
	"$TOOLS/nxp_mech.bpf.o" "$SOURCE/$REL/guest/run-guest.sh" "$ROOT/opt/compute/"
cp "$OUT/build/verifier/"*.bpf.o "$SOURCE/$VER/run_compute.sh" "$SOURCE/$VER/run.sh" \
	"$SOURCE/$VER/run_state.sh" "$ROOT/opt/compute/verifier/"
printf 'capacity=%s\nseg_len=%s\n' "$capacity" "$seg_len" >"$ROOT/opt/compute/layout.env"
: >"$EV/guest-libraries.txt"
ldd "$TOOLS/xdev_ext_mech_ctl" | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' \
	>>"$EV/guest-libraries.txt"
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
echo XDEV_EXT_COMPUTE_GUEST_BEGIN
XDEV_EXT_COMPUTE_GUEST=1 sh /opt/compute/run-guest.sh /opt/compute
code=$?
echo "XDEV_EXT_COMPUTE_GUEST_EXIT=$code"
echo XDEV_EXT_COMPUTE_DMESG_BEGIN
dmesg
echo XDEV_EXT_COMPUTE_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init" "$ROOT/opt/compute/run-guest.sh"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"
sha256sum "$BUILD/arch/x86/boot/bzImage" "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/nxp_mech.bpf.o" \
	"$OUT/build/compute_test.bpf.o" "$OUT/build/compute_old_layout.bpf.o" \
	"$OUT/build/verifier/"*.bpf.o >"$EV/artifacts.sha256"

# Private disks; nothing else is attached.
python3 -I "$SOURCE/$REL/compute_validate.py" make-images "$OUT"
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr'
	-nic none
	-drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=XDEVCSRC01
	-drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
	-device nvme,drive=dst,serial=XDEVCDST01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
validate=(python3 -I "$SOURCE/$REL/compute_validate.py" validate --dir "$OUT" --log "$EV/guest.log"
	--layout "$EV/layout.txt" --result "$EV/result.json")
validator_status=0
if (( RED )); then
	"${validate[@]}" --red || validator_status=$?
	if (( qemu_status == 0 && validator_status == 0 )); then
		echo 'XDEV_EXT_COMPUTE_KVM=RED_CONFIRMED first_failure=attach-compute' | tee "$EV/verdict.txt"
		exit 0
	fi
	echo "XDEV_EXT_COMPUTE_KVM=RED_UNEXPECTED qemu_exit=$qemu_status validator_exit=$validator_status" |
		tee "$EV/verdict.txt"
	exit 1
fi
"${validate[@]}" || validator_status=$?
if (( qemu_status == 0 && validator_status == 0 )); then
	echo 'XDEV_EXT_COMPUTE_KVM=PASS' | tee "$EV/verdict.txt"
else
	echo "XDEV_EXT_COMPUTE_KVM=FAIL qemu_exit=$qemu_status validator_exit=$validator_status" | tee "$EV/verdict.txt"
	exit 1
fi
