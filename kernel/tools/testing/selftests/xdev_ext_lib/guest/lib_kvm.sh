#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused KVM correctness run of libxdev_ext, never a performance benchmark.
# It reuses an already built kernel and its BTF-matched mechanism BPF
# objects, builds the library, its host unit tests and the guest programs
# from the exact checkout, and boots a private QEMU guest with two NVMe
# images, two virtio-net NICs on a private QEMU hub, and the guest-only CE
# stand-in module built against that kernel.  All writes stay in
# --scratch.  No host module, NIC, route or disk is touched.
#   bash lib_kvm.sh --scratch DIR --source GIT_ROOT --build O_DIR --tools TOOLS_DIR
# GIT_ROOT is a clean product checkout whose HEAD differs from the build's
# recorded commit only in the library, this test and build/CI wiring.
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' BUILD='' TOOLS=''
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-1200}
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
TEST_REL=kernel/tools/testing/selftests/xdev_ext_lib
LIB_REL=kernel/tools/xdev_ext_mech/lib
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee -a "$EV/runner.log") 2>&1

# Identity: exact clean source; prebuilt kernel/BPF objects whose inputs equal it.
SOURCE=$(git -C "$SOURCE" rev-parse --show-toplevel)
git -C "$SOURCE" diff --quiet
git -C "$SOURCE" diff --cached --quiet
[[ -z $(git -C "$SOURCE" ls-files --others --exclude-standard) ]] || { echo 'FAIL untracked source files' >&2; exit 1; }
HEAD_SHA=$(git -C "$SOURCE" rev-parse --verify 'HEAD^{commit}')
BUILD_SHA=$(cat "$BUILD/xdev-ext-source.commit")
git -C "$SOURCE" cat-file -e "$BUILD_SHA^{commit}"
git -C "$SOURCE" merge-base --is-ancestor "$BUILD_SHA" "$HEAD_SHA"
changed=$(git -C "$SOURCE" diff --name-only "$BUILD_SHA" "$HEAD_SHA")
if [[ -n "$changed" ]] && grep -v -e "^$TEST_REL/" -e "^$LIB_REL/" -e '^\.gitignore$' \
	-e '^kernel/tools/testing/selftests/xdev_ext_peer/guest/' \
	-e '^kernel/tools/xdev_ext_mech/Makefile$' -e '^\.github/workflows/host\.yml$' <<<"$changed"; then
	echo 'FAIL source differs from the prebuilt kernel/BPF objects outside the library and allowed tests' >&2; exit 1
fi
for symbol in MODULES XDEV_EXT_MECH XDEV_EXT_MECH_CE XDEV_EXT_MECH_ZEROCOPY BLK_DEV_NVME BLK_DEV_INITRD DEVTMPFS IO_URING \
	BPF_SYSCALL DEBUG_INFO_BTF XDP_SOCKETS PACKET VIRTIO_NET PCI_MSI SERIAL_8250_CONSOLE; do
	grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
done
release=$(cat "$BUILD/include/config/kernel.release")
CE_SIM=$TOOLS/ce-sim/xdev_ext_ce_sim.ko
for artifact in "$BUILD/arch/x86/boot/bzImage" "$TOOLS/nxp_mech.bpf.o" "$TOOLS/ce_plan.bpf.o" "$CE_SIM"; do
	[[ -s "$artifact" ]]
done
[[ $(modinfo -F vermagic "$CE_SIM" | cut -d' ' -f1) == "$release" ]]
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; virtio-net and QEMU NVMe; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\ntools=%s\nkernel_release=%s\ncc=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$TOOLS" "$release" "$("$CC" --version | head -1)"
	printf 'changed_since_build=%s\n' "$(tr '\n' ' ' <<<"$changed")"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|DETECT_HUNG_TASK)=' "$BUILD/.config" || true
} >"$EV/provenance.txt"

# Host unit tests of the library, from the exact checkout (TAP).
host_status=0
nice -n 10 make -C "$SOURCE/$TEST_REL" CC="$CC" OUTPUT="$OUT/host-tests" run >"$EV/host-unit-tests.log" 2>&1 || host_status=$?
printf 'host_unit_tests_exit=%s\n' "$host_status" >>"$EV/provenance.txt"
(( host_status == 0 )) || { echo "FAIL host unit tests exit=$host_status" >&2; exit 1; }
# The library archive and the guest programs.
nice -n 10 make -C "$SOURCE/kernel/tools/xdev_ext_mech" lib CC="$CC" BUILD_DIR="$OUT/mech" >"$EV/lib-build.log" 2>&1
nice -n 10 make -C "$SOURCE/$TEST_REL/guest" CC="$CC" KSRC="$SOURCE/kernel" LIBXDEV_EXT="$OUT/mech/lib" \
	OUTPUT="$OUT" >"$EV/guest-build.log" 2>&1
sha256sum "$BUILD/arch/x86/boot/bzImage" "$TOOLS/nxp_mech.bpf.o" "$TOOLS/ce_plan.bpf.o" "$CE_SIM" \
	"$OUT/xdev_ext_lib_nvme_nic" "$OUT/xdev_ext_lib_iou" "$OUT/xdev_ext_lib_rx" >"$EV/artifacts.sha256"

# Minimal initramfs: busybox, the guest programs, the BPF object, libraries.
G=/opt/xdev_ext_lib
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp} "$ROOT$G"
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed sleep rm ip sync insmod; do ln -sf busybox "$ROOT/bin/$app"; done
cp "$OUT/xdev_ext_lib_nvme_nic" "$OUT/xdev_ext_lib_iou" "$OUT/xdev_ext_lib_rx" "$TOOLS/nxp_mech.bpf.o" \
	"$TOOLS/ce_plan.bpf.o" "$CE_SIM" "$SOURCE/$TEST_REL/guest/run-guest.sh" "$ROOT$G/"
python3 -I "$SOURCE/$TEST_REL/guest/lib_validate.py" plan >"$ROOT$G/plan.txt"
cp "$ROOT$G/plan.txt" "$EV/plan.txt"
python3 -I "$SOURCE/$TEST_REL/guest/lib_validate.py" plan-iou >"$ROOT$G/plan-iou.txt"
cp "$ROOT$G/plan-iou.txt" "$EV/plan-iou.txt"
: >"$EV/guest-libraries.txt"
for program in "$OUT/xdev_ext_lib_nvme_nic" "$OUT/xdev_ext_lib_iou" "$OUT/xdev_ext_lib_rx"; do
	ldd "$program" | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' >>"$EV/guest-libraries.txt"
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
code=1
src= dst=
echo
echo XDEV_EXT_LIB_GUEST_BEGIN
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	case "$(sed 's/[[:space:]]*$//' "$f")" in
	XDEVLIBSRC1) src=$c ;;
	XDEVLIBDST1) dst=$c ;;
	esac
done
if [ -n "$src" ] && [ -n "$dst" ]; then
	sh /opt/xdev_ext_lib/run-guest.sh "/dev/ng${src#nvme}n1" "/dev/${dst}n1" "/dev/ng${dst#nvme}n1"
	code=$?
else
	echo 'FAIL NVMe serials XDEVLIBSRC1/XDEVLIBDST1 not found'
fi
echo "XDEV_EXT_LIB_GUEST_EXIT=$code"
echo XDEV_EXT_LIB_DMESG_BEGIN
dmesg
echo XDEV_EXT_LIB_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init" "$ROOT$G/run-guest.sh"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"

# Private disks: deterministic nonuniform source, guard-filled destination.
python3 -I "$SOURCE/$TEST_REL/guest/lib_validate.py" make-source "$OUT/source.raw"
python3 -I "$SOURCE/$TEST_REL/guest/lib_validate.py" make-dest "$OUT/destination.raw"
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr ipv6.disable=1'
	-nic none -netdev hubport,id=wire0,hubid=0 -netdev hubport,id=wire1,hubid=0
	-device virtio-net-pci,netdev=wire0,mac=02:00:00:00:00:01,iommu_platform=on,disable-legacy=on,rx_queue_size=1024
	-device virtio-net-pci,netdev=wire1,mac=02:00:00:00:00:02,iommu_platform=on,disable-legacy=on,rx_queue_size=1024
	-drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=XDEVLIBSRC1
	-drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
	-device nvme,drive=dst,serial=XDEVLIBDST1)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
validator_status=0
python3 -I "$SOURCE/$TEST_REL/guest/lib_validate.py" validate --source "$OUT/source.raw" \
	--dest "$OUT/destination.raw" --log "$EV/guest.log" --result "$EV/result.json" || validator_status=$?
if (( qemu_status == 0 && validator_status == 0 )); then
	echo 'XDEV_EXT_LIB_KVM=PASS' | tee "$EV/verdict.txt"
else
	echo "XDEV_EXT_LIB_KVM=FAIL qemu_exit=$qemu_status validator_exit=$validator_status" | tee "$EV/verdict.txt"
	exit 1
fi
