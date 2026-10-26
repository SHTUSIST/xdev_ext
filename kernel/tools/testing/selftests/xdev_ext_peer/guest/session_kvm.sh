#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused KVM correctness run of the POOL_PEER session test, never a
# performance benchmark.  It reuses an already built kernel, its BTF-matched
# mechanism tools, and the guest provider module built against that kernel;
# it builds only the session test program.  All writes stay in --scratch:
# private raw images, initramfs, and evidence.  No host module is loaded.
#   bash session_kvm.sh --scratch DIR --source GIT_ROOT --build O_DIR --tools TOOLS_DIR
# GIT_ROOT is a clean product checkout whose HEAD differs from the build's
# recorded commit only inside this guest test or the library selftests.
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
GUEST_REL=kernel/tools/testing/selftests/xdev_ext_peer/guest
EPOCH_REL=tests/eval/xdomain
# Only these SDK-free production helper inputs may differ from the kernel
# build. Kernel/provider changes still require matching rebuilt artifacts.
EPOCH_INPUTS=(epoch_control.c epoch_control.h check_contract.c check_contract.h)
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee -a "$EV/runner.log") 2>&1

# Identity: exact clean source, and a prebuilt kernel/tools whose inputs equal it.
SOURCE=$(git -C "$SOURCE" rev-parse --show-toplevel)
git -C "$SOURCE" diff --quiet
git -C "$SOURCE" diff --cached --quiet
[[ -z $(git -C "$SOURCE" ls-files --others --exclude-standard) ]] || { echo 'FAIL untracked source files' >&2; exit 1; }
HEAD_SHA=$(git -C "$SOURCE" rev-parse --verify 'HEAD^{commit}')
BUILD_SHA=$(cat "$BUILD/xdev-ext-source.commit")
git -C "$SOURCE" cat-file -e "$BUILD_SHA^{commit}"
git -C "$SOURCE" merge-base --is-ancestor "$BUILD_SHA" "$HEAD_SHA"
changed=$(git -C "$SOURCE" diff --name-only "$BUILD_SHA" "$HEAD_SHA" | grep -v '^\.gitignore$' || true)
if [[ -n "$changed" ]] && grep -v -e "^$GUEST_REL/" \
	-e '^kernel/tools/testing/selftests/xdev_ext_lib/' \
	-e '^tests/eval/xdomain/epoch_control\.c$' \
	-e '^tests/eval/xdomain/epoch_control\.h$' \
	-e '^tests/eval/xdomain/check_contract\.c$' \
	-e '^tests/eval/xdomain/check_contract\.h$' \
	-e '^\.github/workflows/host\.yml$' <<<"$changed"; then
	echo 'FAIL source differs from the prebuilt kernel/tools outside the allowed tests' >&2; exit 1
fi
if grep -Fxq -e "$GUEST_REL/xdev_ext_peer_sw.c" -e "$GUEST_REL/sw_provider_uapi.h" <<<"$changed"; then
	echo 'FAIL provider module source changed since the prebuilt module' >&2; exit 1
fi
for f in xdev_ext_peer_sw.c sw_provider_uapi.h; do
	cmp "$SOURCE/$GUEST_REL/$f" "$TOOLS/peer-guest/$f"
done
for symbol in MODULES MODULE_UNLOAD XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY BLK_DEV_NVME BLK_DEV_INITRD \
	DEVTMPFS IO_URING BPF_SYSCALL DEBUG_INFO_BTF PCI_MSI SERIAL_8250_CONSOLE; do
	grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
done
release=$(cat "$BUILD/include/config/kernel.release")
[[ $(modinfo -F vermagic "$TOOLS/peer-guest/xdev_ext_peer_sw.ko" | cut -d' ' -f1) == "$release" ]]
for artifact in "$BUILD/arch/x86/boot/bzImage" "$TOOLS/xdev_ext_peer_chain" "$TOOLS/nvme_s0.bpf.o" \
	"$TOOLS/peer-guest/xdev_ext_peer_sw.ko"; do [[ -s "$artifact" ]]; done
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; host RAM stands in for device memory; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\ntools=%s\nkernel_release=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$TOOLS" "$release"
	printf 'changed_since_build=%s\n' "$(tr '\n' ' ' <<<"$changed")"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|DETECT_HUNG_TASK)=' "$BUILD/.config" || true
} >"$EV/provenance.txt"

# Build only the session test program, from the exact checkout.
mkdir -p "$OUT/build/xdomain"
cp "$SOURCE/$GUEST_REL/"{Makefile,peer_session_e2e.c,sw_provider_uapi.h} "$OUT/build/"
for f in "${EPOCH_INPUTS[@]}"; do
	cp "$SOURCE/$EPOCH_REL/$f" "$OUT/build/xdomain/$f"
	cmp "$SOURCE/$EPOCH_REL/$f" "$OUT/build/xdomain/$f"
done
# The fixed source receipt identifies exactly the helper bytes compiled into
# this guest binary, rather than whitelisting an entire eval directory.
(
	cd "$SOURCE"
	printf 'source_commit=%s\nhelper_copy=%s\n' "$HEAD_SHA" "$OUT/build/xdomain"
	for f in "${EPOCH_INPUTS[@]}"; do sha256sum "$EPOCH_REL/$f"; done
) >"$EV/epoch-helper-sources.txt"
nice -n 10 make -C "$OUT/build" KERNEL_SRC="$SOURCE/kernel" \
	EPOCH_HELPER_DIR="$OUT/build/xdomain" CC="$CC" peer_session_e2e >"$EV/test-build.log" 2>&1
# The artifacts the guest runs, recorded once for this fixed test version.
sha256sum "$BUILD/arch/x86/boot/bzImage" "$TOOLS/xdev_ext_peer_chain" "$TOOLS/nvme_s0.bpf.o" \
	"$TOOLS/peer-guest/xdev_ext_peer_sw.ko" "$OUT/build/peer_session_e2e" >"$EV/artifacts.sha256"

# Minimal initramfs: busybox, the four test artifacts, and their libraries.
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/peer_session}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed cut basename mknod insmod rmmod sync; do
	ln -sf busybox "$ROOT/bin/$app"
done
cp "$OUT/build/peer_session_e2e" "$TOOLS/xdev_ext_peer_chain" "$TOOLS/nvme_s0.bpf.o" \
	"$TOOLS/peer-guest/xdev_ext_peer_sw.ko" "$SOURCE/$GUEST_REL/run-session-guest.sh" "$ROOT/opt/peer_session/"
: >"$EV/guest-libraries.txt"
for program in "$OUT/build/peer_session_e2e" "$TOOLS/xdev_ext_peer_chain"; do
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
# Firmware leaves escape sequences on the console line; start a clean one.
echo
echo XDEV_EXT_SESSION_GUEST_BEGIN
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	case "$(sed 's/[[:space:]]*$//' "$f")" in
	XDEVSSRC01) src=$c ;;
	XDEVPEER01) dst=$c ;;
	esac
done
if [ -n "$src" ] && [ -n "$dst" ]; then
	XDEV_EXT_PEER_GUEST=1 sh /opt/peer_session/run-session-guest.sh \
		"/dev/${src}n1" "/dev/ng${src#nvme}n1" "/dev/${dst}n1" "/dev/ng${dst#nvme}n1"
	code=$?
else
	echo 'FAIL NVMe serials XDEVSSRC01/XDEVPEER01 not found'
fi
echo "XDEV_EXT_SESSION_GUEST_EXIT=$code"
echo XDEV_EXT_SESSION_DMESG_BEGIN
dmesg
echo XDEV_EXT_SESSION_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init" "$ROOT/opt/peer_session/run-session-guest.sh"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"

# Private disks: deterministic nonuniform source, zeroed destination.
python3 -I "$SOURCE/$GUEST_REL/session_validate.py" make-source "$OUT/source.raw"
rm -f -- "$OUT/destination.raw"; truncate -s 16M "$OUT/destination.raw"
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=1 nokaslr'
	-nic none
	-drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=XDEVSSRC01
	-drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
	-device nvme,drive=dst,serial=XDEVPEER01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
validator_status=0
python3 -I "$SOURCE/$GUEST_REL/session_validate.py" validate --source "$OUT/source.raw" \
	--dest "$OUT/destination.raw" --log "$EV/guest.log" --result "$EV/result.json" || validator_status=$?
if (( qemu_status == 0 && validator_status == 0 )); then
	echo 'XDEV_EXT_PEER_SESSION_KVM=PASS' | tee "$EV/verdict.txt"
else
	echo "XDEV_EXT_PEER_SESSION_KVM=FAIL qemu_exit=$qemu_status validator_exit=$validator_status" | tee "$EV/verdict.txt"
	exit 1
fi
