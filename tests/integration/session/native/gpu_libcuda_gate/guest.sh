#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Guest init for the libcuda capability-gate probe on a VFIO-assigned GPU.
# It compares the official libcuda with a separately patched copy that only
# the probe commands load (LD_LIBRARY_PATH per command; the system library
# under /usr/lib/x86_64-linux-gnu stays the official file).  Correctness only:
# both NVMe controllers are QEMU-emulated, so no step proves physical
# peer-to-peer DMA between devices.
#
# Layout inside the initramfs:
#   /opt/xdev_ext/gpu/        nvidia.ko, nvidia-uvm.ko, release,
#                             xdev_ext_gpu_dmabuf, xdev_ext_peer_chain,
#                             ce_plan.bpf.o, nvme_s0.bpf.o, net_peer.bpf.o
#   /opt/xdev_ext/xdev_ext_mech_ctl, /opt/xdev_ext/nxp_mech.bpf.o
#   /opt/gate/cuda_attr_probe, /opt/gate/patched/libcuda.so.1 (-> patched copy)
#   /opt/gate/patched.sha256, /opt/gate/original.sha256
# The host shares a 9p directory with mount tag "gatecapture".
#
# Steps run in order; a step past its time limit, or RM lock assertions,
# skip every later GPU step (the unload still runs, bounded).
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
SYSLIB=/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu
PATCHED=/opt/gate/patched
export LD_LIBRARY_PATH=$SYSLIB
set -u

# The initramfs busybox lacks some applet links used below.
for applet in cp od uname ln; do
	command -v "$applet" >/dev/null 2>&1 || /bin/busybox ln -s busybox "/bin/$applet"
done
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mkdir -p /capture /sys/fs/bpf
mount -t bpf bpf /sys/fs/bpf
capture=/tmp
if mount -t 9p -o trans=virtio,version=9p2000.L gatecapture /capture; then
	capture=/capture
fi
exec >"$capture/guest-probe.log" 2>&1

finish() {
	trap - EXIT
	echo "GATE_FINISH problem=${gpu_problem:-none}"
	dmesg >"$capture/dmesg-final.log" 2>&1
	sync
	echo GATE_POWEROFF >/dev/console
	poweroff -f
}
trap finish EXIT

# bounded LIMIT_S LOG COMMAND...: status, or 124 after SIGKILL past LIMIT_S.
bounded() {
	bounded_limit=$1 bounded_log=$2
	shift 2
	"$@" >"$bounded_log" 2>&1 &
	bounded_pid=$!
	bounded_waited=0
	while kill -0 "$bounded_pid" 2>/dev/null &&
	      [ "$bounded_waited" -lt "$((bounded_limit * 10))" ]; do
		sleep 0.1
		bounded_waited=$((bounded_waited + 1))
	done
	if kill -0 "$bounded_pid" 2>/dev/null; then
		kill -KILL "$bounded_pid" 2>/dev/null
		return 124
	fi
	wait "$bounded_pid"
}
gpu_problem=
# The CLI's own deadline (debug profile: 240 s) plus CUDA start-up.
limit_s=300
# step NAME LOG COMMAND...: run bounded, copy its log, print one result line.
step() {
	step_name=$1 step_log=$2
	shift 2
	if [ -n "$gpu_problem" ]; then
		echo "GATE_STEP name=$step_name result=SKIPPED reason=after-$gpu_problem"
		return 125
	fi
	bounded "$limit_s" "$step_log" "$@"
	step_rc=$?
	cp "$step_log" "$capture/" 2>/dev/null
	sed "s/^/GATE_LOG $step_name: /" "$step_log"
	if [ "$step_rc" = 124 ]; then
		gpu_problem=timeout-$step_name
		echo "GATE_PROBLEM step=$step_name reason=timeout limit_s=$limit_s"
	elif dmesg | grep -Eq 'GPU lock already acquired by this thread|rmGpuLocksGetOwnedMask\(\) == 0'; then
		gpu_problem=rm-lock-state-$step_name
		echo "GATE_PROBLEM step=$step_name reason=rm-lock-state"
	fi
	echo "GATE_STEP name=$step_name rc=$step_rc"
	return "$step_rc"
}
dmesg_mark() { echo "GATE_DMESG_MARK $1" >/dev/kmsg; }

echo GATE_BEGIN
cat /proc/cmdline
uname -a
echo "GATE_SHA original:"; sha256sum /usr/lib/x86_64-linux-gnu/libcuda.so.590.48.01
echo "GATE_SHA patched:"; sha256sum "$PATCHED/libcuda.so.590.48.01"
ls -l "$PATCHED" /usr/lib/x86_64-linux-gnu/libcuda.so*
echo "GATE_BYTE original: $(dd if=/usr/lib/x86_64-linux-gnu/libcuda.so.590.48.01 bs=1 skip=$((0x42d69b)) count=1 2>/dev/null | od -An -tx1 | tr -d ' ')"
echo "GATE_BYTE patched: $(dd if="$PATCHED/libcuda.so.590.48.01" bs=1 skip=$((0x42d69b)) count=1 2>/dev/null | od -An -tx1 | tr -d ' ')"

# --- NVMe: two emulated controllers, mapped by serial --------------------
src_ng= dst_ng= src_blk= dst_blk=
# Controllers probe asynchronously after boot.
for _ in $(seq 1 200); do
	[ "$(cat /sys/class/nvme/nvme*/serial 2>/dev/null | grep -c 'GATE...01')" = 2 ] &&
		[ -b /dev/nvme0n1 ] && [ -b /dev/nvme1n1 ] && break
	sleep 0.1
done
for c in /sys/class/nvme/nvme*; do
	[ -e "$c/serial" ] || continue
	n=${c##*/}
	case $(tr -d ' ' <"$c/serial") in
	GATESRC01) src_ng=/dev/ng${n#nvme}n1 src_blk=/dev/${n}n1 ;;
	GATEDST01) dst_ng=/dev/ng${n#nvme}n1 dst_blk=/dev/${n}n1 ;;
	esac
done
echo "GATE_NVME src=$src_ng,$src_blk dst=$dst_ng,$dst_blk"
[ -c "$src_ng" ] && [ -c "$dst_ng" ] && [ -b "$src_blk" ] && [ -b "$dst_blk" ] || {
	echo 'GATE_STEP name=nvme result=FAIL reason=devices'; exit 1; }
source_slba=2048 target_slba=4096 groups=4
window_nlb=$((groups * 16))
drop_caches() { sync; echo 3 >/proc/sys/vm/drop_caches; }
dd if="$src_blk" of=/tmp/src.bin bs=512 skip="$source_slba" count="$window_nlb" 2>/dev/null
echo "GATE_SRC_WINDOW sha256=$(sha256sum /tmp/src.bin | cut -d' ' -f1)"
clear_window() {
	dd if=/dev/zero of="$dst_blk" bs=512 seek="$target_slba" count="$window_nlb" conv=notrunc,fsync 2>/dev/null
	drop_caches
	dd if="$dst_blk" of=/tmp/dst.bin bs=512 skip="$target_slba" count="$window_nlb" 2>/dev/null
	! cmp /tmp/src.bin /tmp/dst.bin >/dev/null 2>&1
}
compare_window() {
	drop_caches
	dd if="$dst_blk" of=/tmp/dst.bin bs=512 skip="$target_slba" count="$window_nlb" 2>/dev/null
	cmp /tmp/src.bin /tmp/dst.bin >/dev/null && echo equal || echo differs
}

# --- G0: our NVIDIA modules --------------------------------------------------
G=/opt/xdev_ext/gpu
release=$(cat "$G/release")
step insmod-nvidia /tmp/insmod-nvidia.log insmod "$G/nvidia.ko" NVreg_EnableXdevExtCeDma=1 || exit 1
step insmod-uvm /tmp/insmod-uvm.log insmod "$G/nvidia-uvm.ko" || exit 1
gpu_bdf=
for link in /sys/bus/pci/drivers/nvidia/????:??:??.?; do
	[ -e "$link" ] && gpu_bdf=${link##*/}
done
uvm_major=$(sed -n 's/^\([0-9]*\) nvidia-uvm$/\1/p' /proc/devices)
mknod -m 666 /dev/nvidiactl c 195 255
mknod -m 666 /dev/nvidia0 c 195 0
mknod -m 666 /dev/nvidia-uvm c "$uvm_major" 0
mknod -m 666 /dev/nvidia-uvm-tools c "$uvm_major" 1
step nvidia-smi /tmp/smi.log nvidia-smi \
	--query-gpu=name,pci.bus_id,driver_version,vbios_version,memory.total --format=csv,noheader
echo "GATE_GPU bdf=$gpu_bdf release=$release"

# --- (i) capability attributes: official, then patched copy -----------------
step attrs-original /tmp/attrs-original.log /opt/gate/cuda_attr_probe "$gpu_bdf"
step caps-original /tmp/caps-original.log "$G/xdev_ext_gpu_dmabuf" --caps --bdf "$gpu_bdf"
step attrs-patched /tmp/attrs-patched.log env LD_LIBRARY_PATH="$PATCHED:$SYSLIB" \
	/opt/gate/cuda_attr_probe "$gpu_bdf"
step caps-patched /tmp/caps-patched.log env LD_LIBRARY_PATH="$PATCHED:$SYSLIB" \
	"$G/xdev_ext_gpu_dmabuf" --caps --bdf "$gpu_bdf"

# --- (ii) dma-buf export (patched) imported as the PEER pool, NVMe I/O ------
# Same command as the product G4 case: NVMe READ into the imported VRAM
# dma-buf, NVMe WRITE back from it to the destination window.
if clear_window; then
	dmesg_mark dmabuf-patched-begin
	step dmabuf-patched /tmp/dmabuf-patched.log env LD_LIBRARY_PATH="$PATCHED:$SYSLIB" \
		"$G/xdev_ext_gpu_dmabuf" --bdf "$gpu_bdf" --bytes 2097152 --expect /tmp/src.bin \
		--group-bytes 8192 --frame-bytes 65536 -- \
		"$G/xdev_ext_peer_chain" --allocation-fd '{fd}' "$src_ng" "$dst_ng" \
		"$groups" 8192 9 "$source_slba" "$target_slba" "$G"
	echo "GATE_RESULT step=dmabuf-patched compare=$(compare_window)"
	dmesg_mark dmabuf-patched-end
else
	echo 'GATE_RESULT step=dmabuf-patched result=FAIL reason=window-not-cleared'
fi

# --- (iii) persistent P2P pin of a cuMemAlloc buffer (patched) -------------
if clear_window; then
	dmesg_mark peer-patched-begin
	step peer-patched /tmp/peer-patched.log env LD_LIBRARY_PATH="$PATCHED:$SYSLIB" \
		"$G/xdev_ext_peer_chain" --cuda "$gpu_bdf" /dev/nvidia0 "$src_ng" "$dst_ng" \
		"$groups" 8192 9 "$source_slba" "$target_slba" "$G"
	peer_rc=$?
	echo "GATE_RESULT step=peer-patched rc=$peer_rc compare=$(compare_window)"
	dmesg_mark peer-patched-end
else
	echo 'GATE_RESULT step=peer-patched result=FAIL reason=window-not-cleared'
fi
dmesg | grep -E 'GATE_DMESG_MARK|XDEV_EXT peer|nvidia_p2p|NVRM: .*(p2p|P2P|dma-buf|dmabuf)' |
	sed 's/^/GATE_DMESG: /'

# --- regression: CE chains d/a with the official libcuda ---------------------
# As in the product harness: NVMe struct_ops attached, CE plan attached, the
# VMM allocation path (the official libcuda reports no GPUDirect RDMA);
# groups 4, depth 4, CE length 4 x 8192 and the debug-profile CLI timeout.
ctl=/opt/xdev_ext/xdev_ext_mech_ctl
step attach-nvme /tmp/attach-nvme.log "$ctl" attach --obj /opt/xdev_ext/nxp_mech.bpf.o \
	--map nxp_nvme_ops --pin /sys/fs/bpf/zc-nvme --set nvme_mode=0
step attach-ce /tmp/attach-ce.log "$ctl" attach --obj "$G/ce_plan.bpf.o" --map ce_plan_ops \
	--pin /sys/fs/bpf/gpu-ce
step ce-chain-d /tmp/ce-chain-d.log "$ctl" ce-chain --chain d --ce-dev /dev/nvidia0 --ce-vmm \
	--ce-len 32768 --groups "$groups" --depth 4 --group-bytes 8192 --timeout-ms 240000 --diagnostics
if clear_window; then
	step ce-chain-a /tmp/ce-chain-a.log "$ctl" ce-chain --chain a --ce-dev /dev/nvidia0 --ce-vmm \
		--ce-len 32768 --src-ng "$src_ng" --slba "$source_slba" --nlb "$window_nlb" \
		--dst-ng "$dst_ng" --dst-slba "$target_slba" --dst-nlb "$window_nlb" \
		--groups "$groups" --depth 4 --group-bytes 8192 --timeout-ms 240000 --diagnostics
	echo "GATE_RESULT step=ce-chain-a compare=$(compare_window)"
fi
limit_s=30
step detach-ce /tmp/detach-ce.log "$ctl" detach --pin /sys/fs/bpf/gpu-ce
step detach-nvme /tmp/detach-nvme.log "$ctl" detach --pin /sys/fs/bpf/zc-nvme

# --- unload: modules must leave cleanly so the GPU returns without reset ----
gpu_problem_before_unload=$gpu_problem
gpu_problem=
limit_s=60
step rmmod-uvm /tmp/rmmod-uvm.log rmmod nvidia_uvm
step rmmod-nvidia /tmp/rmmod-nvidia.log rmmod nvidia
[ -d /sys/module/nvidia ] && echo GATE_UNLOAD=FAIL || echo GATE_UNLOAD=PASS
[ -z "$gpu_problem" ] && gpu_problem=$gpu_problem_before_unload
exit 0
