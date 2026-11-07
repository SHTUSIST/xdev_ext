#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Host side of the libcuda capability-gate probe (see guest.sh).
#
#   launch.sh --run DIR --base-initroot DIR --kernel BZIMAGE \
#       --libcuda OFFICIAL_LIBCUDA --scanner PATCH_SCANNER.py \
#       --probe CUDA_ATTR_PROBE --gpu PCI_BDF [--memory-mb N] [--limit-s N]
#
# The official libcuda is only read.  The scanner (a third-party script that
# locates the one immediate byte gating GPUDirect RDMA/DMA-BUF in libcuda
# 590.48.01) must report exactly one candidate whose current byte is 0x40 at
# file offset 0x42d69b; it then writes a patched copy into DIR/patched.  The
# copy must differ from the official file in exactly that one byte (0x40 ->
# 0x60).  The base initroot is copied, never modified.  One VFIO GPU guest;
# the harness never binds, unbinds or resets a host device.
set -euo pipefail
RUN= BASE= KERNEL= LIBCUDA= SCANNER= PROBE= GPU= MEMORY_MB=8192 LIMIT_S=2700
while (($#)); do
	case $1 in
	--run) RUN=$2 ;; --base-initroot) BASE=$2 ;; --kernel) KERNEL=$2 ;;
	--libcuda) LIBCUDA=$2 ;; --scanner) SCANNER=$2 ;; --probe) PROBE=$2 ;;
	--gpu) GPU=$2 ;; --memory-mb) MEMORY_MB=$2 ;; --limit-s) LIMIT_S=$2 ;;
	*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
	shift 2
done
for v in RUN BASE KERNEL LIBCUDA SCANNER PROBE GPU; do
	[[ -n ${!v} ]] || { echo "missing --${v,,}" >&2; exit 2; }
done
HERE=$(cd "$(dirname "$0")" && pwd)
OFFSET=$((0x42d69b))
mkdir "$RUN"
cd "$RUN"
exec > >(tee -a launch.log) 2>&1
echo "launch_begin_utc=$(date -u +%FT%TZ)"

# --- preflight: GPU group free, memory -------------------------------------
group=$(basename "$(readlink -f "/sys/bus/pci/devices/$GPU/iommu_group")")
driver=$(basename "$(readlink -f "/sys/bus/pci/devices/$GPU/driver")")
[[ $driver == vfio-pci ]] || { echo "FAIL $GPU driver=$driver, expected vfio-pci" >&2; exit 1; }
if fuser "/dev/vfio/$group" >/dev/null 2>&1; then
	echo "FAIL /dev/vfio/$group is held:" >&2; fuser -v "/dev/vfio/$group" >&2; exit 1
fi
avail_kib=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
(( avail_kib / 1024 > MEMORY_MB * 3 )) || { echo "FAIL MemAvailable ${avail_kib}KiB too small for ${MEMORY_MB}MiB" >&2; exit 1; }
printf 'gpu=%s\niommu_group=%s\ndriver=%s\nmem_available_kib=%s\nguest_memory_mb=%s\n' \
	"$GPU" "$group" "$driver" "$avail_kib" "$MEMORY_MB" >preflight.txt
lspci -vvv -s "$GPU" >lspci-before.txt 2>&1 || true
cat "/sys/bus/pci/devices/$GPU/power_state" >power-before.txt 2>&1 || true

# --- patched copy of libcuda --------------------------------------------------
sha256sum "$LIBCUDA" "$SCANNER" "$PROBE" "$KERNEL" >inputs.sha256
python3 -I "$SCANNER" --src "$LIBCUDA" --dry-run >scan-dry-run.log 2>&1
cat scan-dry-run.log
[[ $(grep -c '^candidate\[' scan-dry-run.log) == 1 ]] || { echo 'FAIL scanner candidates != 1' >&2; exit 1; }
grep -Eq "patch byte file offset: +0x42d69b$" scan-dry-run.log || { echo 'FAIL candidate offset' >&2; exit 1; }
grep -Eq 'immediate: +0x40 -> 0x60$' scan-dry-run.log || { echo 'FAIL candidate immediate' >&2; exit 1; }
grep -Eq 'classification: +known-layout$' scan-dry-run.log || { echo 'FAIL layout drift' >&2; exit 1; }
byte=$(dd if="$LIBCUDA" bs=1 skip="$OFFSET" count=1 2>/dev/null | od -An -tx1 | tr -d ' ')
[[ $byte == 40 ]] || { echo "FAIL original byte $byte != 40" >&2; exit 1; }
python3 -I "$SCANNER" --src "$LIBCUDA" --out-dir "$RUN/patched" >scan-patch.log 2>&1
cat scan-patch.log
cmp -l "$LIBCUDA" patched/libcuda.so.590.48.01 >patch-diff.txt || true
cat patch-diff.txt
# cmp -l: 1-based decimal offset, octal bytes.
[[ $(wc -l <patch-diff.txt) == 1 ]] &&
	[[ $(awk '{print $1, $2, $3}' patch-diff.txt) == "$((OFFSET + 1)) 100 140" ]] ||
	{ echo 'FAIL patched copy differs in more or other than one byte' >&2; exit 1; }
sha256sum "$LIBCUDA" patched/libcuda.so.590.48.01 | tee libcuda.sha256
sha256sum -c inputs.sha256 >inputs-after-patch.check

# --- initramfs ----------------------------------------------------------------
cp -a "$BASE" initroot
mkdir -p initroot/opt/gate/patched capture
cp "$HERE/guest.sh" initroot/opt/gate/guest.sh
cp "$PROBE" initroot/opt/gate/cuda_attr_probe
cp patched/libcuda.so.590.48.01 initroot/opt/gate/patched/
ln -s libcuda.so.590.48.01 initroot/opt/gate/patched/libcuda.so.1
ln -s libcuda.so.1 initroot/opt/gate/patched/libcuda.so
printf '#!/bin/sh\nexec /bin/sh /opt/gate/guest.sh\n' >initroot/init
chmod 0755 initroot/init initroot/opt/gate/guest.sh initroot/opt/gate/cuda_attr_probe
cmp "$LIBCUDA" initroot/usr/lib/x86_64-linux-gnu/libcuda.so.590.48.01
(cd initroot && find . | cpio -o -H newc 2>../cpio.log | gzip -1) >initramfs.cpio.gz

# --- NVMe images: random source window, zero destination ---------------------
head -c $((16 << 20)) /dev/urandom >source.raw
truncate -s $((16 << 20)) destination.raw
dd if=source.raw bs=512 skip=2048 count=64 2>/dev/null | sha256sum | tee source-window.sha256

# --- one VFIO GPU guest ----------------------------------------------------------
qemu=(/usr/bin/qemu-system-x86_64 -machine q35,accel=kvm -cpu host,host-phys-bits=on
	-smp 4 -m "$MEMORY_MB" -nographic -nic none -no-reboot
	-qmp "unix:$RUN/qmp.sock,server=on,wait=off"
	-kernel "$KERNEL" -initrd "$RUN/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr ipv6.disable=1'
	-global q35-pcihost.pci-hole64-size=128G
	-device pcie-root-port,id=gpu_rp,chassis=17,slot=17,bus=pcie.0
	-device "vfio-pci,host=$GPU,bus=gpu_rp"
	-drive "file=$RUN/source.raw,if=none,id=src,format=raw"
	-device nvme,drive=src,serial=GATESRC01
	-drive "file=$RUN/destination.raw,if=none,id=dst,format=raw"
	-device nvme,drive=dst,serial=GATEDST01
	-fsdev "local,id=capture,path=$RUN/capture,security_model=none"
	-device virtio-9p-pci,fsdev=capture,mount_tag=gatecapture)
printf '%s\n' "${qemu[@]}" >qemu-command.txt
"${qemu[@]}" </dev/null >guest-console.log 2>&1 &
qemu_pid=$!
echo "$qemu_pid" >qemu.pid
echo "qemu_pid=$qemu_pid started_utc=$(date -u +%FT%TZ)"
waited=0
while kill -0 "$qemu_pid" 2>/dev/null && ((waited < LIMIT_S)); do
	sleep 5; waited=$((waited + 5))
done
if kill -0 "$qemu_pid" 2>/dev/null; then
	echo "HOLD qemu pid $qemu_pid still running after ${LIMIT_S}s; not killed" | tee HOLD.txt
	exit 3
fi
rc=0
wait "$qemu_pid" || rc=$?
echo "$rc" >qemu.exit
echo "qemu_exit=$rc finished_utc=$(date -u +%FT%TZ)"
lspci -vvv -s "$GPU" >lspci-after.txt 2>&1 || true
cat "/sys/bus/pci/devices/$GPU/power_state" >power-after.txt 2>&1 || true
basename "$(readlink -f "/sys/bus/pci/devices/$GPU/driver")" >driver-after.txt
sha256sum -c inputs.sha256 >inputs-after-run.check
exit 0
