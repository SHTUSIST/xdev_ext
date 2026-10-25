#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused KVM correctness run of stage polling (XDEV_EXT_MECH_STAGE_F_POLL),
# never a performance benchmark: nothing is timed.  It reuses a kernel and
# tools built by xdev_ext_mech_zc_kvm.sh --ce-sim from the same checkout
# (bzImage, xdev_ext_mech_ctl, nvme_s0/nxp_mech BPF, the DMA selftest provider
# and dma_poll_runtime) and builds only guest/nvme_poll_e2e.  All writes stay in
# --scratch: private raw images, initramfs and evidence.  No host module is
# loaded and no host NIC, route or disk is touched; the guest's two virtio-net
# devices meet on a QEMU hub.
#   bash poll_kvm.sh --scratch DIR --source GIT_ROOT --build O_DIR --tools TOOLS_DIR
# --red boots an older kernel (O_DIR of a commit before stage polling) with the
# same guest programs and passes only if the first polled CREATE is refused:
# the guest test's RED baseline.  Identity checks of the build are recorded,
# not enforced, in that mode.
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' BUILD='' TOOLS='' RED=0
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-1200}
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
REL=kernel/tools/testing/selftests/xdev_ext_mech/poll
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
	# part of the prebuilt kernel, modules or tools.
	if [[ -n "$changed" ]] && grep -v -e "^$REL/" -e '^kernel/Documentation/userspace-api/xdev_ext-poll.rst$' <<<"$changed"; then
		echo 'FAIL source differs from the prebuilt kernel/tools outside the stage-polling test files' >&2; exit 1
	fi
fi
for symbol in MODULES MODULE_UNLOAD XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY XDEV_EXT_MECH_DMA BLK_DEV_NVME \
	BLK_DEV_INITRD DEVTMPFS IO_URING BPF_SYSCALL DEBUG_INFO_BTF XDP_SOCKETS VIRTIO_NET NET_RX_BUSY_POLL \
	PCI_MSI SERIAL_8250_CONSOLE DEBUG_FS; do
	grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
done
release=$(cat "$BUILD/include/config/kernel.release")
DMA=$TOOLS/dma-provider
for artifact in "$BUILD/arch/x86/boot/bzImage" "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/nvme_s0.bpf.o" \
	"$TOOLS/nxp_mech.bpf.o" "$DMA/xdev_ext_dma_provider_sim.ko" "$DMA/dma_poll_runtime" \
	"$DMA/dma_provider_pair.bpf.o"; do
	[[ -s "$artifact" ]] || { echo "FAIL missing prebuilt artifact $artifact" >&2; exit 1; }
done
[[ $(modinfo -F vermagic "$DMA/xdev_ext_dma_provider_sim.ko" | cut -d' ' -f1) == "$release" ]] || (( RED ))
cmp "$SOURCE/kernel/tools/testing/selftests/xdev_ext_mech/provider/dma_poll_runtime.c" "$DMA/dma_poll_runtime.c"
cmp "$SOURCE/kernel/tools/testing/selftests/xdev_ext_mech/provider/xdev_ext_dma_provider_sim.c" "$DMA/xdev_ext_dma_provider_sim.c"
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; QEMU NVMe and virtio-net; DMA provider is CPU memcpy; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\ntools=%s\nkernel_release=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$TOOLS" "$release"
	printf 'changed_since_build=%s\n' "$(tr '\n' ' ' <<<"$changed")"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|NET_RX_BUSY_POLL|PREEMPT[A-Z_]*)=' "$BUILD/.config" || true
} >"$EV/provenance.txt"

# Build only the guest test program, from the exact checkout.
mkdir -p "$OUT/build"
cp "$SOURCE/$REL/guest/"{Makefile,nvme_poll_e2e.c} "$OUT/build/"
nice -n 10 make -C "$OUT/build" KERNEL_SRC="$SOURCE/kernel" CC="$CC" nvme_poll_e2e >"$EV/test-build.log" 2>&1

# Minimal initramfs: busybox, the guest programs and their libraries.
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/poll}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed cut basename dirname mknod insmod rmmod sync awk grep \
	seq sleep kill cmp dd blockdev ip ls tr wc head tail readlink; do
	ln -sf busybox "$ROOT/bin/$app"
done
cp "$OUT/build/nvme_poll_e2e" "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/nvme_s0.bpf.o" "$TOOLS/nxp_mech.bpf.o" \
	"$DMA/xdev_ext_dma_provider_sim.ko" "$DMA/dma_poll_runtime" "$DMA/dma_provider_pair.bpf.o" \
	"$SOURCE/$REL/guest/run-guest.sh" "$ROOT/opt/poll/"
: >"$EV/guest-libraries.txt"
for program in "$OUT/build/nvme_poll_e2e" "$TOOLS/xdev_ext_mech_ctl" "$DMA/dma_poll_runtime"; do
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
# Firmware leaves escape sequences on the console line; start a clean one.
echo
echo XDEV_EXT_POLL_GUEST_BEGIN
XDEV_EXT_POLL_GUEST=1 sh /opt/poll/run-guest.sh /opt/poll
code=$?
echo "XDEV_EXT_POLL_GUEST_EXIT=$code"
echo XDEV_EXT_POLL_DMESG_BEGIN
dmesg
echo XDEV_EXT_POLL_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init" "$ROOT/opt/poll/run-guest.sh"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"
sha256sum "$BUILD/arch/x86/boot/bzImage" "$OUT/build/nvme_poll_e2e" "$TOOLS/xdev_ext_mech_ctl" \
	"$TOOLS/nvme_s0.bpf.o" "$TOOLS/nxp_mech.bpf.o" "$DMA/xdev_ext_dma_provider_sim.ko" \
	"$DMA/dma_poll_runtime" "$DMA/dma_provider_pair.bpf.o" >"$EV/artifacts.sha256"

# Private disks and a private two-port hub; the kernel gets two poll queues.
python3 -I "$SOURCE/$REL/poll_validate.py" make-images "$OUT"
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr ipv6.disable=1 nvme.poll_queues=2'
	-nic none -netdev hubport,id=wire0,hubid=0 -netdev hubport,id=wire1,hubid=0
	-device virtio-net-pci,netdev=wire0,mac=02:00:00:00:00:01,iommu_platform=on,disable-legacy=on,rx_queue_size=1024
	-device virtio-net-pci,netdev=wire1,mac=02:00:00:00:00:02,iommu_platform=on,disable-legacy=on,rx_queue_size=1024
	-drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=XDEVPSRC01
	-drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
	-device nvme,drive=dst,serial=XDEVPDST01
	-drive "file=$OUT/spare.raw,if=none,id=spare,format=raw,cache=none,aio=threads"
	-device nvme,drive=spare,serial=XDEVPSPR01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
if (( RED )); then
	# Expected: the kernel without stage polling refuses the bit at CREATE.
	if (( qemu_status == 0 )) && tr -d '\r' <"$EV/guest.log" |
		grep -Eq '^not ok [0-9]+ - polled-copy: CREATE with POLL on NVMe READ and WRITE$' &&
		! grep -q 'XDEV_EXT_POLL_NVME=PASS' "$EV/guest.log"; then
		echo 'XDEV_EXT_POLL_KVM=RED_CONFIRMED first_failure=polled-copy-CREATE' | tee "$EV/verdict.txt"
		exit 0
	fi
	echo "XDEV_EXT_POLL_KVM=RED_UNEXPECTED qemu_exit=$qemu_status" | tee "$EV/verdict.txt"
	exit 1
fi
validator_status=0
python3 -I "$SOURCE/$REL/poll_validate.py" validate --dir "$OUT" --log "$EV/guest.log" \
	--result "$EV/result.json" || validator_status=$?
if (( qemu_status == 0 && validator_status == 0 )); then
	echo 'XDEV_EXT_POLL_KVM=PASS' | tee "$EV/verdict.txt"
else
	echo "XDEV_EXT_POLL_KVM=FAIL qemu_exit=$qemu_status validator_exit=$validator_status" | tee "$EV/verdict.txt"
	exit 1
fi
