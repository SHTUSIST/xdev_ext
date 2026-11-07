#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Rebuild an existing guest kernel configuration with upstream PCI P2PDMA
# enabled, plus the NVIDIA open modules against it, into a new directory.
# Without CONFIG_PCI_P2PDMA, pci_p2pdma_distance() is the header stub that
# returns -1, so PEER admission of a VRAM BAR backing always reports no P2P
# path.  The base build directory is only read (copied).
#
#   build_p2pdma_kernel.sh --linux-src DIR --base-build DIR --nvidia-src DIR --out DIR
set -euo pipefail
LINUX= BASE= NVSRC= OUT= JOBS=${JOBS:-8}
while (($#)); do
	case $1 in
	--linux-src) LINUX=$2 ;; --base-build) BASE=$2 ;; --nvidia-src) NVSRC=$2 ;;
	--out) OUT=$2 ;; *) echo "unknown argument $1" >&2; exit 2 ;;
	esac
	shift 2
done
[[ -n $LINUX && -n $BASE && -n $NVSRC && -n $OUT ]] || { echo 'missing argument' >&2; exit 2; }
mkdir "$OUT"
exec > >(tee -a "$OUT/build.log") 2>&1
lowprio() { nice -n 10 ionice -c 3 "$@"; }
echo "begin_utc=$(date -u +%FT%TZ)"
lowprio cp -a "$BASE" "$OUT/build"
cp "$OUT/build/.config" "$OUT/config.base"
"$LINUX/scripts/config" --file "$OUT/build/.config" -e MEMORY_HOTPLUG -e MEMORY_HOTREMOVE \
	-e ZONE_DEVICE -e PCI_P2PDMA
lowprio make -C "$LINUX" O="$OUT/build" CC=gcc-14 HOSTCC=gcc-14 olddefconfig
for symbol in PCI_P2PDMA ZONE_DEVICE; do
	grep -Fxq "CONFIG_$symbol=y" "$OUT/build/.config" || { echo "FAIL CONFIG_$symbol not set" >&2; exit 1; }
done
diff "$OUT/config.base" "$OUT/build/.config" >"$OUT/config.diff" || true
cat "$OUT/config.diff"
lowprio make -C "$LINUX" O="$OUT/build" -j"$JOBS" CC=gcc-14 HOSTCC=gcc-14 bzImage modules
echo "kernel_done_utc=$(date -u +%FT%TZ)"
mkdir "$OUT/gpu"
lowprio cp -a "$NVSRC" "$OUT/nvidia-build"
lowprio make -C "$OUT/nvidia-build" modules -j"$JOBS" SYSSRC="$LINUX" SYSOUT="$OUT/build" \
	XDEV_EXT_ENABLE_GPU_CE_DMA=1 CC=gcc-14 >"$OUT/nvidia-build.log" 2>&1
cp "$OUT/nvidia-build/kernel-open/"{nvidia.ko,nvidia-uvm.ko} "$OUT/gpu/"
[[ $(modinfo -F vermagic "$OUT/gpu/nvidia.ko" | cut -d' ' -f1) == "$(cat "$OUT/build/include/config/kernel.release")" ]]
sha256sum "$OUT/build/arch/x86/boot/bzImage" "$OUT/gpu/"*.ko | tee "$OUT/artifacts.sha256"
echo "end_utc=$(date -u +%FT%TZ)"
