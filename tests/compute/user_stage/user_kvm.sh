#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused KVM correctness run of the USER stage class, never a performance
# benchmark: nothing is timed. It reuses a kernel and tools built by
# xdev_ext_mech_zc_kvm.sh --lifecycle (XDEV_EXT_MECH_CPU) from the same checkout
# (bzImage, nvme_s0/user_plan/cpu_plan BPF) and builds only
# guest/user_stage_e2e. All writes stay in --scratch: private raw images,
# initramfs and evidence. No host module is loaded and no host NIC, route or
# disk is touched; the guest has no network.
#   bash user_kvm.sh --scratch DIR --source GIT_ROOT --build O_DIR --tools TOOLS_DIR
# --red boots an older kernel (O_DIR of a commit before the USER stage) with the
# same guest program and BPF objects of TOOLS_DIR and passes only if the first
# USER step is refused (its program type does not exist): the guest test's RED
# baseline. Identity checks of the build are recorded, not enforced, then.
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' BUILD='' TOOLS='' RED=0
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-1800}
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
REL=kernel/tools/testing/selftests/xdev_ext_mech/user_stage
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
	changed="red baseline kernel $BUILD_SHA, guest program and BPF objects of $HEAD_SHA"
else
	git -C "$SOURCE" cat-file -e "$BUILD_SHA^{commit}"
	git -C "$SOURCE" merge-base --is-ancestor "$BUILD_SHA" "$HEAD_SHA"
	changed=$(git -C "$SOURCE" diff --name-only "$BUILD_SHA" "$HEAD_SHA" || true)
	# Only this test directory and its specification may differ: neither is
	# part of the prebuilt kernel or tools.
	if [[ -n "$changed" ]] && grep -v -e "^$REL/" -e '^kernel/Documentation/userspace-api/xdev_ext-user-stage.rst$' <<<"$changed"; then
		echo 'FAIL source differs from the prebuilt kernel/tools outside the USER stage test files' >&2; exit 1
	fi
	for symbol in XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY XDEV_EXT_MECH_CPU BLK_DEV_NVME BLK_DEV_INITRD DEVTMPFS \
		IO_URING BPF_SYSCALL DEBUG_INFO_BTF SERIAL_8250_CONSOLE PCI_MSI; do
		grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
	done
fi
release=$(cat "$BUILD/include/config/kernel.release")
for artifact in "$BUILD/arch/x86/boot/bzImage" "$TOOLS/nvme_s0.bpf.o" "$TOOLS/user_plan.bpf.o" "$TOOLS/cpu_plan.bpf.o"; do
	[[ -s "$artifact" ]] || { echo "FAIL missing prebuilt artifact $artifact" >&2; exit 1; }
done
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; QEMU NVMe; user thread in the guest; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\ntools=%s\nkernel_release=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$TOOLS" "$release"
	printf 'changed_since_build=%s\n' "$(tr '\n' ' ' <<<"$changed")"
	grep -E '^CONFIG_(KASAN|KASAN_GENERIC|PROVE_LOCKING|LOCKDEP|DEBUG_ATOMIC_SLEEP|DETECT_HUNG_TASK|XDEV_EXT_MECH_CPU|PREEMPT[A-Z_]*)=' \
		"$BUILD/.config" || true
} >"$EV/provenance.txt"

# Build only the guest test program, from the exact checkout.
mkdir -p "$OUT/build"
cp "$SOURCE/$REL/guest/"{Makefile,user_stage_e2e.c} "$OUT/build/"
nice -n 10 make -C "$OUT/build" KERNEL_SRC="$SOURCE/kernel" CC="$CC" user_stage_e2e >"$EV/test-build.log" 2>&1

# Minimal initramfs: busybox, the guest program and its libraries, the programs.
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/user}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed grep sync sleep ls tr wc head tail; do
	ln -sf busybox "$ROOT/bin/$app"
done
cp "$OUT/build/user_stage_e2e" "$TOOLS/nvme_s0.bpf.o" "$TOOLS/user_plan.bpf.o" "$TOOLS/cpu_plan.bpf.o" \
	"$SOURCE/$REL/guest/run-guest.sh" "$ROOT/opt/user/"
ldd "$OUT/build/user_stage_e2e" | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' |
	sort -u >"$EV/guest-libraries.txt"
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
echo XDEV_EXT_USER_GUEST_BEGIN
XDEV_EXT_USER_GUEST=1 sh /opt/user/run-guest.sh /opt/user
code=$?
echo "XDEV_EXT_USER_GUEST_EXIT=$code"
echo XDEV_EXT_USER_DMESG_BEGIN
dmesg
echo XDEV_EXT_USER_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init" "$ROOT/opt/user/run-guest.sh"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"
sha256sum "$BUILD/arch/x86/boot/bzImage" "$OUT/build/user_stage_e2e" "$TOOLS/nvme_s0.bpf.o" \
	"$TOOLS/user_plan.bpf.o" "$TOOLS/cpu_plan.bpf.o" >"$EV/artifacts.sha256"

# Private disks; no network device.
python3 -I "$SOURCE/$REL/user_validate.py" make-images "$OUT"
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr'
	-nic none
	-drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=XDEVUSRC01
	-drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
	-device nvme,drive=dst,serial=XDEVUDST01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
if (( RED )); then
	# Expected: the kernel without the USER stage has no USER program type.
	if (( qemu_status == 0 )) && tr -d '\r' <"$EV/guest.log" |
		grep -Eq '^not ok [0-9]+ - load and attach user_plan struct_ops$' &&
		! grep -q 'XDEV_EXT_USER_STAGE_E2E=PASS' "$EV/guest.log"; then
		echo 'XDEV_EXT_USER_KVM=RED_CONFIRMED first_failure=user_plan-attach' | tee "$EV/verdict.txt"
		exit 0
	fi
	echo "XDEV_EXT_USER_KVM=RED_UNEXPECTED qemu_exit=$qemu_status" | tee "$EV/verdict.txt"
	exit 1
fi
validator_status=0
python3 -I "$SOURCE/$REL/user_validate.py" validate --dir "$OUT" --log "$EV/guest.log" \
	--result "$EV/result.json" || validator_status=$?
if (( qemu_status == 0 && validator_status == 0 )); then
	echo 'XDEV_EXT_USER_KVM=PASS' | tee "$EV/verdict.txt"
else
	echo "XDEV_EXT_USER_KVM=FAIL qemu_exit=$qemu_status validator_exit=$validator_status" | tee "$EV/verdict.txt"
	exit 1
fi
