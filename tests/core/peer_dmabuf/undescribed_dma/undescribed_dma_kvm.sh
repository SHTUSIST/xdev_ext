#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused KVM correctness run of the undescribed-exporter guest test
# (prototype for ASK.70), never a performance benchmark. It reuses an already
# built kernel and builds only the guest test program. All writes stay in
# --scratch: private raw images, initramfs and evidence. No host module, no
# device model beyond QEMU's own NVMe controllers.
#   bash undescribed_dma_kvm.sh --scratch DIR --source GIT_ROOT --build O_DIR \
#        [--mode normal|refuse] [--viommu] [--baseline-kernel]
# GIT_ROOT is a clean canonical checkout. Normally its HEAD may differ from the
# build's recorded commit only in test inputs. --baseline-kernel instead allows
# a kernel built from an ancestor commit, to observe the pre-feature behaviour
# (a RED run); its verdict is labelled BASELINE and never counts as a pass.
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' BUILD='' MODE=normal VIOMMU=0 BASELINE=0
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-900}
while (($#)); do
	case "$1" in
	--scratch) SCRATCH=$2; shift 2 ;;
	--source) SOURCE=$2; shift 2 ;;
	--build) BUILD=$2; shift 2 ;;
	--mode) MODE=$2; shift 2 ;;
	--viommu) VIOMMU=1; shift ;;
	--baseline-kernel) BASELINE=1; shift ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$BUILD" ]] || { echo 'missing option' >&2; exit 2; }
[[ "$MODE" == normal || "$MODE" == refuse ]] || { echo 'mode must be normal or refuse' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
	echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
TEST_REL=tests/core/peer_dmabuf/undescribed_dma
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee -a "$EV/runner.log") 2>&1

# Identity: exact clean source and a prebuilt kernel whose inputs equal it.
SOURCE=$(git -C "$SOURCE" rev-parse --show-toplevel)
[[ -z $(git -C "$SOURCE" status --porcelain --untracked-files=all) ]] || { echo 'FAIL source checkout is dirty' >&2; exit 1; }
HEAD_SHA=$(git -C "$SOURCE" rev-parse --verify 'HEAD^{commit}')
BUILD_SHA=$(cat "$BUILD/xdev-ext-source.commit")
python3 -I - "$SOURCE" "$BUILD_SHA" "$HEAD_SHA" "$BASELINE" >"$EV/source-delta.txt" <<'PYDELTA'
import json, subprocess, sys
root, old, new, baseline = sys.argv[1:]
def git(*args):
    return subprocess.run(['git', '-C', root, *args], check=True, capture_output=True, text=True).stdout
subprocess.run(['git', '-C', root, 'merge-base', '--is-ancestor', old, new], check=True)
changed = [name for name in git('diff', '--name-only', old, new).splitlines() if name]
print('build_commit=' + old)
print('source_commit=' + new)
print('changed_since_build=' + ' '.join(changed))
if baseline == '1':
    print('baseline_kernel=1 (kernel inputs may differ; never a pass)')
    raise SystemExit(0)
def native(revision):
    entries = json.loads(git('show', revision + ':source-layout.json'))['files']
    return {e['source']: e['native_path'] for e in entries if 'component' in e}
before, after = native(old), native(new)
for name in changed:
    path = after.get(name, before.get(name))
    if path is None:
        if not (name.startswith('tests/') or name == 'source-layout.json'):
            raise SystemExit('FAIL change outside tests since the prebuilt kernel: ' + name)
    elif not path.startswith('tools/testing/selftests/'):
        raise SystemExit('FAIL kernel/tool input changed since the prebuilt kernel: ' + name)
for name in set(before) | set(after):
    if before.get(name) != after.get(name) and not (after.get(name) or before.get(name)).startswith('tools/testing/selftests/'):
        raise SystemExit('FAIL native overlay mapping changed outside selftests: ' + name)
PYDELTA
required=(UDMABUF XDEV_EXT_PEER_DMABUF DMA_SHARED_BUFFER DEBUG_FS XDEV_EXT_MECH BLK_DEV_NVME
	BLK_DEV_INITRD DEVTMPFS MEMFD_CREATE PCI_MSI SERIAL_8250_CONSOLE SWIOTLB)
if (( VIOMMU )); then required+=(INTEL_IOMMU); fi
for symbol in "${required[@]}"; do
	grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || { echo "FAIL kernel requires CONFIG_$symbol=y" >&2; exit 1; }
done
sha256sum -c "$BUILD/xdev-ext-artifacts.sha256" >"$EV/prebuilt-artifacts-check.txt"
grep -Fq "$BUILD/arch/x86/boot/bzImage" "$BUILD/xdev-ext-artifacts.sha256"
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
DEBUG_LOCKING=0
grep -Fxq CONFIG_PROVE_LOCKING=y "$BUILD/.config" && DEBUG_LOCKING=1
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; QEMU NVMe; udmabuf dma-buf without descriptor; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\nkernel_release=%s\nmode=%s\nviommu=%s\nbaseline_kernel=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$(cat "$BUILD/include/config/kernel.release")" \
		"$MODE" "$VIOMMU" "$BASELINE"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|DETECT_HUNG_TASK|INTEL_IOMMU|UDMABUF|XDEV_EXT_PEER_DMABUF|SWIOTLB)=' "$BUILD/.config" || true
} >"$EV/provenance.txt"
cp "$BUILD/.config" "$EV/kernel.config"
python3 -I "$SOURCE/tests/integration/session/native/xdev_ext_mech_zc_debug.py" config "$BUILD/.config" /dev/null "$DEBUG_LOCKING"

# Build only the guest test program, from the exact checkout.
mkdir -p "$OUT/build"
cp "$SOURCE/$TEST_REL/undescribed_dma.c" "$OUT/build/"
nice -n 10 "$CC" -O2 -std=gnu11 -Wall -Wextra -Werror -static -iquote "$SOURCE/src/core/include/uapi" \
	"$OUT/build/undescribed_dma.c" -o "$OUT/build/undescribed_dma" >"$EV/test-build.log" 2>&1
sha256sum "$BUILD/arch/x86/boot/bzImage" "$OUT/build/undescribed_dma" \
	"$SOURCE/$TEST_REL/undescribed_dma.c" "$SOURCE/$TEST_REL/validate.py" >"$EV/artifacts.sha256"

# Minimal initramfs: busybox and the statically linked test program.
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/undescribed}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed basename readlink sync; do ln -sf busybox "$ROOT/bin/$app"; done
cp "$OUT/build/undescribed_dma" "$ROOT/opt/undescribed/"
cat >"$ROOT/init" <<GUEST
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t debugfs debugfs /sys/kernel/debug
code=1
src= dst=
echo
echo XDEV_EXT_UNDESCRIBED_GUEST_BEGIN
echo "XDEV_EXT_UNDESCRIBED_CMDLINE=\$(cat /proc/cmdline)"
for f in /sys/class/nvme/nvme*/serial; do
	c=\${f%/serial}; c=\${c##*/}
	case "\$(sed 's/[[:space:]]*\$//' "\$f")" in
	XDEVUSRC01) src=\$c ;;
	XDEVUDST01) dst=\$c ;;
	esac
done
if [ -n "\$src" ] && [ -n "\$dst" ]; then
	src_pci=\$(basename "\$(readlink -f "/sys/class/nvme/\$src/device")")
	dst_pci=\$(basename "\$(readlink -f "/sys/class/nvme/\$dst/device")")
	for p in "\$src_pci" "\$dst_pci"; do
		g=none
		[ -e "/sys/bus/pci/devices/\$p/iommu_group" ] && g=\$(basename "\$(readlink -f "/sys/bus/pci/devices/\$p/iommu_group")")
		echo "XDEV_EXT_UNDESCRIBED_IOMMU_GROUP \$p \$g"
	done
	/opt/undescribed/undescribed_dma $MODE "/dev/ng\${src#nvme}n1" "/dev/ng\${dst#nvme}n1" "\$src_pci" "\$dst_pci"
	code=\$?
else
	echo 'FAIL NVMe serials XDEVUSRC01/XDEVUDST01 not found'
fi
echo "XDEV_EXT_UNDESCRIBED_GUEST_EXIT=\$code"
echo XDEV_EXT_UNDESCRIBED_DMESG_BEGIN
dmesg
echo XDEV_EXT_UNDESCRIBED_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"

# Private disks: deterministic source, destination written only by the guest.
python3 -I "$SOURCE/$TEST_REL/validate.py" make-source "$OUT/source.raw"
rm -f -- "$OUT/destination.raw"; truncate -s 8M "$OUT/destination.raw"
machine=q35,accel=kvm append='console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr'
[[ "$MODE" == refuse ]] && append+=' swiotlb=force'
viommu_args=()
if (( VIOMMU )); then
	machine+=,kernel-irqchip=split
	viommu_args=(-device intel-iommu,intremap=on,caching-mode=on)
	append+=' intel_iommu=on iommu.strict=1'
fi
args=(-machine "$machine" "${viommu_args[@]}" -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz" -append "$append" -nic none
	-drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=XDEVUSRC01
	-drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
	-device nvme,drive=dst,serial=XDEVUDST01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
host_state() { date -u +%FT%TZ; uptime; ps -eo pid,user,etimes,args | grep -E 'qemu-system' | grep -v grep | cut -c1-220 || true; }
host_state >"$EV/host-before-guest.txt"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.raw.log" 2>&1 || qemu_status=$?
host_state >"$EV/host-after-guest.txt"
tr -d '\r' <"$EV/guest.raw.log" >"$EV/guest.log"
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
validator_status=0
viommu_flag=()
if (( VIOMMU )); then viommu_flag=(--viommu); fi
python3 -I "$SOURCE/$TEST_REL/validate.py" validate --mode "$MODE" --source "$OUT/source.raw" \
	--dest "$OUT/destination.raw" --log "$EV/guest.log" --result "$EV/result.json" "${viommu_flag[@]}" \
	| tee "$EV/host-validate.txt" || validator_status=$?
sha256sum "$OUT/source.raw" "$OUT/destination.raw" >"$EV/data.sha256"
label=XDEV_EXT_UNDESCRIBED_DMA_KVM
(( BASELINE )) && label=XDEV_EXT_UNDESCRIBED_DMA_KVM_BASELINE
if (( qemu_status == 0 && validator_status == 0 && ! BASELINE )); then
	echo "$label=PASS mode=$MODE viommu=$VIOMMU" | tee "$EV/verdict.txt"
else
	echo "$label=FAIL mode=$MODE viommu=$VIOMMU qemu_exit=$qemu_status validator_exit=$validator_status" | tee "$EV/verdict.txt"
	exit 1
fi
