#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused KVM correctness run of the reset-recovery guest tests (fd path and
# mechanism-session path), never a performance benchmark. QEMU NVMe performs
# the DMA into host RAM standing in for device memory; the UNKNOWN outcomes
# come from the kernel's own fault injection. It reuses a prebuilt kernel O=
# directory, the provider module built against it and the nvme_s0.bpf.o built
# against its BTF (--tools), and builds only the two guest test programs from
# an assembled Linux tree. All writes stay in --scratch (private 0700 directory).
#   bash reset_kvm.sh --scratch DIR --linux ASSEMBLED_TREE --build O_DIR --module KO --tools DIR
# The kernel needs CONFIG_FAULT_INJECTION_DEBUG_FS and CONFIG_FAIL_IO_TIMEOUT.
set -euo pipefail
umask 077
SCRATCH='' LINUX='' BUILD='' MODULE='' TOOLS=''
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-900}
while (($#)); do
	case "$1" in
	--scratch) SCRATCH=$2; shift 2 ;;
	--linux) LINUX=$2; shift 2 ;;
	--build) BUILD=$2; shift 2 ;;
	--module) MODULE=$2; shift 2 ;;
	--tools) TOOLS=$2; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[[ -n "$SCRATCH" && -n "$LINUX" && -n "$BUILD" && -n "$MODULE" && -n "$TOOLS" ]] || { echo 'missing option' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
	echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
GUEST=$LINUX/tools/testing/selftests/xdev_ext_peer/guest
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee -a "$EV/runner.log") 2>&1

for symbol in MODULES MODULE_UNLOAD XDEV_EXT_MECH BLK_DEV_NVME BLK_DEV_INITRD DEVTMPFS DEBUG_FS \
	FAULT_INJECTION FAULT_INJECTION_DEBUG_FS FAIL_IO_TIMEOUT PCI_MSI SERIAL_8250_CONSOLE \
	IO_URING BPF_SYSCALL DEBUG_INFO_BTF; do
	grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
done
release=$(cat "$BUILD/include/config/kernel.release")
[[ $(modinfo -F vermagic "$MODULE" | cut -d' ' -f1) == "$release" ]]
for artifact in "$BUILD/arch/x86/boot/bzImage" "$MODULE" "$GUEST/peer_reset_e2e.c" "$GUEST/run-reset-guest.sh" \
	"$GUEST/peer_reset_session_e2e.c" "$TOOLS/nvme_s0.bpf.o" "$GUEST/reset_validate.py"; do [[ -s "$artifact" ]]; done
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; QEMU NVMe; host RAM stands in for device memory; no timing; no physical DMA claim\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	canonical=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["canonical_root"])' \
		"$LINUX/.xdev-ext-source.json" 2>/dev/null || echo unknown)
	printf 'linux=%s\nlinux_canonical_root=%s\nlinux_canonical_commit=%s\n' "$LINUX" "$canonical" \
		"$(git -C "$canonical" rev-parse HEAD 2>/dev/null || echo unknown)"
	printf 'build=%s\nbuild_commit=%s\nmodule=%s\ntools=%s\nkernel_release=%s\n' \
		"$BUILD" "$(cat "$BUILD/xdev-ext-source.commit" 2>/dev/null || echo unknown)" "$MODULE" "$TOOLS" "$release"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|DETECT_HUNG_TASK|FAULT_INJECTION|FAULT_INJECTION_DEBUG_FS|FAIL_IO_TIMEOUT|IOMMU_DEFAULT_DMA_LAZY)=' "$BUILD/.config" || true
} >"$EV/provenance.txt"

# Only the two guest programs are built here: fd path static, session path
# dynamic (libbpf), with its libraries copied into the initramfs below.
mkdir -p "$OUT/build"
cp "$GUEST/"{Makefile,peer_reset_e2e.c,peer_reset_session_e2e.c,sw_provider_uapi.h} "$OUT/build/"
nice -n 10 make -C "$OUT/build" KERNEL_SRC="$LINUX" CC="$CC" LDFLAGS=-static peer_reset_e2e >"$EV/test-build.log" 2>&1
nice -n 10 make -C "$OUT/build" KERNEL_SRC="$LINUX" CC="$CC" peer_reset_session_e2e >>"$EV/test-build.log" 2>&1
sha256sum "$BUILD/.config" "$BUILD/arch/x86/boot/bzImage" "$MODULE" "$TOOLS/nvme_s0.bpf.o" \
	"$OUT/build/peer_reset_e2e" "$OUT/build/peer_reset_session_e2e" "$GUEST/peer_reset_e2e.c" \
	"$GUEST/peer_reset_session_e2e.c" "$GUEST/run-reset-guest.sh" "$GUEST/reset_validate.py" >"$EV/artifacts.sha256"

rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/peer_reset}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed cut basename mknod insmod rmmod sync test [; do
	ln -sf busybox "$ROOT/bin/$app"
done
cp "$OUT/build/peer_reset_e2e" "$OUT/build/peer_reset_session_e2e" "$TOOLS/nvme_s0.bpf.o" "$MODULE" \
	"$GUEST/run-reset-guest.sh" "$ROOT/opt/peer_reset/"
ldd "$OUT/build/peer_reset_session_e2e" | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' |
	sort -u >"$EV/guest-libraries.txt"
while IFS= read -r lib; do
	mkdir -p "$ROOT$(dirname "$lib")"; cp -L "$lib" "$ROOT$lib"
done <"$EV/guest-libraries.txt"
cat >"$ROOT/init" <<'GUESTINIT'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
code=1
src= other=
echo
echo XDEV_EXT_RESET_GUEST_BEGIN
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	case "$(sed 's/[[:space:]]*$//' "$f")" in
	XDEVSSRC01) src=$c ;;
	XDEVPEER01) other=$c ;;
	esac
done
if [ -n "$src" ] && [ -n "$other" ]; then
	XDEV_EXT_PEER_GUEST=1 sh /opt/peer_reset/run-reset-guest.sh "$src" "$other" \
		"/dev/ng${src#nvme}n1" "${src}n1"
	code=$?
else
	echo 'FAIL NVMe serials XDEVSSRC01/XDEVPEER01 not found'
fi
echo "XDEV_EXT_RESET_GUEST_EXIT=$code"
echo XDEV_EXT_RESET_DMESG_BEGIN
dmesg
echo XDEV_EXT_RESET_DMESG_END
sync
poweroff -f
GUESTINIT
chmod 755 "$ROOT/init" "$ROOT/opt/peer_reset/run-reset-guest.sh"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"

rm -f -- "$OUT/source.raw" "$OUT/other.raw"
truncate -s 16M "$OUT/source.raw"; truncate -s 16M "$OUT/other.raw"
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=4 nokaslr'
	-nic none
	-drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=XDEVSSRC01
	-drive "file=$OUT/other.raw,if=none,id=other,format=raw,cache=none,aio=threads"
	-device nvme,drive=other,serial=XDEVPEER01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
validator_status=0
python3 -I "$GUEST/reset_validate.py" --log "$EV/guest.log" --result "$EV/result.json" || validator_status=$?
if (( qemu_status == 0 && validator_status == 0 )); then
	echo 'XDEV_EXT_PEER_RESET_KVM=PASS' | tee "$EV/verdict.txt"
else
	echo "XDEV_EXT_PEER_RESET_KVM=FAIL qemu_exit=$qemu_status validator_exit=$validator_status" | tee "$EV/verdict.txt"
	exit 1
fi
