#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Real-GPU correctness cases inside an xdev_ext KVM guest whose GPU is a
# VFIO-assigned physical device.  No timing here is performance data.
#
#   xdev_ext_gpu_guest.sh run DIR CTL SRC_BLOCK SRC_NG DST_BLOCK DST_NG \
#       SOURCE_SLBA TARGET_SLBA GROUPS DEPTH CE_LEN TIMEOUT_MS
#   xdev_ext_gpu_guest.sh unload
#
# DIR holds nvidia.ko, nvidia-uvm.ko, release, ce_plan.bpf.o, nvme_s0.bpf.o,
# net_peer.bpf.o, xdev_ext_peer_chain and xdev_ext_gpu_dmabuf.  The NVMe
# struct_ops program of the main guest (nxp_nvme_ops) is attached by the
# caller.  TARGET_SLBA starts a destination window that only these cases use.
# Every case prints one XDEV_EXT_GPU_CASE line; raw tool output is prefixed
# with XDEV_EXT_GPU_LOG so the main console validator never parses it.
set -u
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu

log_file() {
	sed "s/^/XDEV_EXT_GPU_LOG $1: /" "$2" 2>/dev/null
}

if [ "${1:-}" = unload ]; then
	# Modules must leave cleanly so the host driver can take the GPU back
	# without a reset: a GSP left running blocks the host re-probe.
	for module in nvidia_uvm nvidia; do
		[ -d "/sys/module/$module" ] || continue
		if ! rmmod "$module" 2>/tmp/rmmod-$module.err; then
			echo "XDEV_EXT_GPU_UNLOAD=FAIL module=$module refcnt=$(cat /sys/module/$module/refcnt 2>/dev/null) holders=$(ls /sys/module/$module/holders 2>/dev/null | tr '\n' ',') error=$(tr '\n' ' ' </tmp/rmmod-$module.err)"
			exit 1
		fi
	done
	[ ! -d /sys/module/nvidia ] && echo XDEV_EXT_GPU_UNLOAD=PASS
	exit 0
fi

[ "${1:-}" = run ] && [ $# -eq 13 ] || { echo 'usage: xdev_ext_gpu_guest.sh run ...' >&2; exit 2; }
dir=$2 ctl=$3 source_block=$4 source_ng=$5 destination_block=$6 destination_ng=$7
source_slba=$8 target_slba=$9 groups=${10} depth=${11} ce_len=${12} timeout_ms=${13}
release=$(cat "$dir/release")
window_nlb=$((groups * 16))
failed=0 unsupported=0
case_result() {
	# name result detail...
	name=$1 result=$2
	shift 2
	echo "XDEV_EXT_GPU_CASE name=$name result=$result $*"
	case $result in
	PASS) ;;
	UNSUPPORTED) unsupported=$((unsupported + 1)) ;;
	*) failed=$((failed + 1)) ;;
	esac
}

# --- G0: our NVIDIA modules on the physical GPU --------------------------
# The CE mechanism backend registers only with NVreg_EnableXdevExtCeDma=1
# (nv-xdev_ext-ce-backend.c); without it every CE stage bind is ENODEV.
if ! insmod "$dir/nvidia.ko" NVreg_EnableXdevExtCeDma=1 >/tmp/insmod-nvidia.log 2>&1; then
	log_file insmod /tmp/insmod-nvidia.log
	echo "XDEV_EXT_GPU_MODULES=FAIL step=insmod-nvidia release=$release"
	exit 1
fi
if ! insmod "$dir/nvidia-uvm.ko" >/tmp/insmod-uvm.log 2>&1; then
	log_file insmod /tmp/insmod-uvm.log
	echo "XDEV_EXT_GPU_MODULES=FAIL step=insmod-uvm release=$release"
	exit 1
fi
gpu_bdf=
for link in /sys/bus/pci/drivers/nvidia/????:??:??.?; do
	[ -e "$link" ] || continue
	[ -z "$gpu_bdf" ] || { echo 'XDEV_EXT_GPU_MODULES=FAIL step=bind reason=multiple-gpus'; exit 1; }
	gpu_bdf=${link##*/}
done
[ -n "$gpu_bdf" ] || { echo 'XDEV_EXT_GPU_MODULES=FAIL step=bind reason=no-gpu-bound'; exit 1; }
vendor=$(cat "/sys/bus/pci/devices/$gpu_bdf/vendor") device=$(cat "/sys/bus/pci/devices/$gpu_bdf/device")
uvm_major=$(sed -n 's/^\([0-9]*\) nvidia-uvm$/\1/p' /proc/devices)
[ -n "$uvm_major" ] || { echo 'XDEV_EXT_GPU_MODULES=FAIL step=uvm-major'; exit 1; }
# The usual nvidia-modprobe helper is absent; create the fixed nodes.
mknod -m 666 /dev/nvidiactl c 195 255
mknod -m 666 /dev/nvidia0 c 195 0
mknod -m 666 /dev/nvidia-uvm c "$uvm_major" 0
mknod -m 666 /dev/nvidia-uvm-tools c "$uvm_major" 1
if nvidia-smi --query-gpu=name,pci.bus_id,driver_version,vbios_version,memory.total --format=csv,noheader >/tmp/smi.log 2>&1; then
	log_file nvidia-smi /tmp/smi.log
	smi_version=$(cut -d, -f3 /tmp/smi.log | tr -d ' ')
else
	log_file nvidia-smi /tmp/smi.log
	smi_version=none
fi
[ "$smi_version" = "$release" ] || {
	echo "XDEV_EXT_GPU_MODULES=FAIL step=nvidia-smi driver=$smi_version release=$release"
	exit 1
}
grep -h '' /proc/driver/nvidia/version 2>/dev/null | sed 's/^/XDEV_EXT_GPU_LOG version: /'
echo "XDEV_EXT_GPU_MODULES=PASS release=$release device=${vendor#0x}:${device#0x} bdf=$gpu_bdf"

# --- CUDA's own report on this GPU: the only evidence for UNSUPPORTED ------
caps=
if "$dir/xdev_ext_gpu_dmabuf" --caps --bdf "$gpu_bdf" >/tmp/gpu-caps.log 2>&1; then
	caps=$(grep '^XDEV_EXT_GPU_CAPS ' /tmp/gpu-caps.log | head -n 1)
fi
log_file caps /tmp/gpu-caps.log
[ -n "$caps" ] || caps="XDEV_EXT_GPU_CAPS bdf=$gpu_bdf probe=failed"
echo "$caps"
caps_have() {
	for want in "$@"; do
		case " $caps " in *" $want "*) ;; *) return 1 ;; esac
	done
}

drop_caches() { sync; echo 3 >/proc/sys/vm/drop_caches; }
# Byte oracle through the block devices: the case wrote with NVMe
# passthrough commands, so caches are dropped before reading back.
compare_window() {
	drop_caches
	dd if="$source_block" of=/tmp/gpu-src.bin bs=512 skip="$source_slba" count="$window_nlb" 2>/dev/null &&
	dd if="$destination_block" of=/tmp/gpu-dst.bin bs=512 skip="$target_slba" count="$window_nlb" 2>/dev/null &&
	cmp /tmp/gpu-src.bin /tmp/gpu-dst.bin >/dev/null
}
clear_window() {
	dd if=/dev/zero of="$destination_block" bs=512 seek="$target_slba" count="$window_nlb" conv=notrunc,fsync 2>/dev/null
	drop_caches
	dd if="$destination_block" of=/tmp/gpu-dst.bin bs=512 skip="$target_slba" count="$window_nlb" 2>/dev/null
	! cmp /tmp/gpu-src.bin /tmp/gpu-dst.bin >/dev/null 2>&1
}
# The CE window: CUDA resolves a cuMemAlloc address for a CE stage only
# through its GPUDirect RDMA (third-party P2P) registrations.  Where CUDA
# reports none, the window is a VMM allocation whose POSIX file descriptor
# export the tool attaches to both CE stage fds.
if caps_have gpu_direct_rdma=1; then ce_mode=native ce_alloc=--ce-alloc
else ce_mode=vmm ce_alloc=--ce-vmm; fi
ce_ok() {
	grep -Fxq "XDEV_EXT_MECH_CE_GPU=PASS chain=$2" "$1" &&
	grep -Eq "^XDEV_EXT_MECH_STATS .* last_err=0 batches_done=$groups batches_abort=0 rejects=0 .* sequestered=0 timeouts=0 inflight=0 " "$1" &&
	grep -Fxq "CUDA allocation=$ce_mode released=yes" "$1" || return 1
	[ "$ce_mode" = native ] ||
		grep -Eq '^CUDA allocation=vmm bdf=[^ ]+ va=0x[0-9a-f]+ bytes=[0-9]+ mapped=[0-9]+ export=posix-fd attached=2$' "$1"
}
# The --diagnostics CREATE report: which phase and stage refused, and why.
create_diag() {
	sed -n 's/^diagnostics result=\(-\{0,1\}[0-9]*\) .* phase=\([0-9]*\) stage=\([0-9]*\) .*$/create_result=\1 phase=\2 stage=\3/p' "$1" | head -n 1
}

"$ctl" attach --obj "$dir/ce_plan.bpf.o" --map ce_plan_ops --pin /sys/fs/bpf/gpu-ce >/tmp/gpu-attach.log 2>&1 || {
	log_file attach /tmp/gpu-attach.log
	echo 'XDEV_EXT_GPU_MODULES=FAIL step=attach-ce-plan'
	exit 1
}

# --- G1: CE chain d (real GPU copy engines only) -------------------------
"$ctl" ce-chain --chain d --ce-dev /dev/nvidia0 "$ce_alloc" --ce-len "$ce_len" \
	--groups "$groups" --depth "$depth" --group-bytes 8192 \
	--timeout-ms "$timeout_ms" --diagnostics >/tmp/gpu-d.log 2>&1
rc=$?
log_file ce-chain-d /tmp/gpu-d.log
if [ "$rc" = 0 ] && ce_ok /tmp/gpu-d.log d; then
	case_result ce-chain-d PASS groups="$groups" allocation="$ce_mode"
else case_result ce-chain-d FAIL rc="$rc" allocation="$ce_mode" $(create_diag /tmp/gpu-d.log); fi

# --- G2: CE chain a (NVMe -> host UMEM -> VRAM -> host UMEM -> NVMe) ------
drop_caches
dd if="$source_block" of=/tmp/gpu-src.bin bs=512 skip="$source_slba" count="$window_nlb" 2>/dev/null
if clear_window; then
	"$ctl" ce-chain --chain a --ce-dev /dev/nvidia0 "$ce_alloc" --ce-len "$ce_len" \
		--src-ng "$source_ng" --slba "$source_slba" --nlb "$window_nlb" \
		--dst-ng "$destination_ng" --dst-slba "$target_slba" --dst-nlb "$window_nlb" \
		--groups "$groups" --depth "$depth" --group-bytes 8192 \
		--timeout-ms "$timeout_ms" --diagnostics >/tmp/gpu-a.log 2>&1
	rc=$?
	log_file ce-chain-a /tmp/gpu-a.log
	if [ "$rc" = 0 ] && ce_ok /tmp/gpu-a.log a && compare_window; then
		case_result ce-chain-a PASS bytes=$((window_nlb * 512)) allocation="$ce_mode" compare=equal
	else
		case_result ce-chain-a FAIL rc="$rc" allocation="$ce_mode" $(create_diag /tmp/gpu-a.log) \
			compare=$(compare_window && echo equal || echo differs)
	fi
else
	case_result ce-chain-a FAIL reason=window-not-cleared
fi
"$ctl" detach --pin /sys/fs/bpf/gpu-ce >/dev/null 2>&1

# --- G3: PEER pool in VRAM (NVMe READ into VRAM, NVMe WRITE from VRAM) ---
# The NVMe struct_ops of the main guest is detached for the peer tool,
# which attaches its own nvme_s0 program, and re-attached afterwards.
"$ctl" detach --pin /sys/fs/bpf/zc-nvme >/tmp/gpu-detach.log 2>&1
if clear_window; then
	"$dir/xdev_ext_peer_chain" --cuda "$gpu_bdf" /dev/nvidia0 "$source_ng" "$destination_ng" \
		"$groups" 8192 9 "$source_slba" "$target_slba" "$dir" >/tmp/gpu-peer.log 2>&1
	rc=$?
	log_file peer-nvme /tmp/gpu-peer.log
	if [ "$rc" = 0 ] && grep -Eq "^peer chain: done=$groups abort=0 inflight=0 sequestered=0 status=0$" /tmp/gpu-peer.log && compare_window; then
		case_result peer-nvme PASS bytes=$((window_nlb * 512))
	elif [ "$rc" != 0 ] && grep -Eq '^peer chain failed at register: .* \(-22\)$' /tmp/gpu-peer.log &&
	     dmesg | grep -Fq 'NVRM: XDEV_EXT peer pin: nvidia_p2p_get_pages_persistent failed: -22' &&
	     caps_have gpu_direct_rdma=0 pointer_rdma=0; then
		# CUDA supports no GPUDirect RDMA on this GPU and marks the block
		# unusable with it, and NVIDIA's persistent pin itself refused the
		# VA (no third-party P2P registration to resolve it: EINVAL), not
		# one of the provider's own checks.
		case_result peer-nvme UNSUPPORTED reason=cuda-no-gpudirect-rdma step=register errno=-22 \
			gpu_direct_rdma=0 pointer_rdma=0
	else
		case_result peer-nvme FAIL rc="$rc" compare=$(compare_window && echo equal || echo differs)
	fi
else
	case_result peer-nvme FAIL reason=window-not-cleared
fi

# --- G4: VRAM exported as DMA-BUF, imported as the PEER pool --------------
if clear_window; then
	"$dir/xdev_ext_gpu_dmabuf" --bdf "$gpu_bdf" --bytes 2097152 --expect /tmp/gpu-src.bin \
		--group-bytes 8192 --frame-bytes 65536 -- \
		"$dir/xdev_ext_peer_chain" --allocation-fd '{fd}' "$source_ng" "$destination_ng" \
		"$groups" 8192 9 "$source_slba" "$target_slba" "$dir" >/tmp/gpu-dmabuf.log 2>&1
	rc=$?
	log_file dmabuf-peer /tmp/gpu-dmabuf.log
	if [ "$rc" = 0 ] && grep -Eq "^peer chain: done=$groups abort=0 inflight=0 sequestered=0 status=0$" /tmp/gpu-dmabuf.log &&
	   grep -Fq 'XDEV_EXT_GPU_DMABUF vram_holds_last_group=yes' /tmp/gpu-dmabuf.log && compare_window; then
		case_result dmabuf-peer PASS bytes=$((window_nlb * 512))
	elif [ "$rc" != 0 ] && grep -Eq '^XDEV_EXT_GPU_DMABUF device=[^ ]+ dma_buf_supported=0$' /tmp/gpu-dmabuf.log &&
	     caps_have dma_buf=0; then
		# CUDA refuses DMA-BUF export of device memory on this GPU; the
		# helper stops before any allocation or PEER registration.
		case_result dmabuf-peer UNSUPPORTED reason=cuda-no-dma-buf dma_buf_supported=0
	else
		case_result dmabuf-peer FAIL rc="$rc" compare=$(compare_window && echo equal || echo differs)
	fi
else
	case_result dmabuf-peer FAIL reason=window-not-cleared
fi
"$ctl" attach --obj /opt/xdev_ext/nxp_mech.bpf.o --map nxp_nvme_ops \
	--pin /sys/fs/bpf/zc-nvme --set nvme_mode=0 >/tmp/gpu-reattach.log 2>&1 || {
	log_file reattach /tmp/gpu-reattach.log
	case_result reattach-nvme FAIL
}

# The window ends with the source bytes, which the host image oracle checks.
# UNSUPPORTED is never PASS: the host verdict and the harness stay nonzero.
if [ "$failed" != 0 ]; then summary=FAIL
elif [ "$unsupported" != 0 ]; then summary=UNSUPPORTED
else summary=PASS; fi
echo "XDEV_EXT_GPU_GUEST=$summary failed=$failed unsupported=$unsupported"
exit 0
