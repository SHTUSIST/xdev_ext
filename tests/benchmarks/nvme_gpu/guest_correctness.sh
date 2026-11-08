#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Correctness of the NVMe<->GPU session arm inside an xdev_ext KVM guest, with
# the CPU copy-engine stand-in.  No timing from this script is performance
# data.  Not run by the host suite; the guest harness calls it.
#
#   guest_correctness.sh DIR BLOCK NG SLBA
#
# DIR holds xdev_ext_mech_ctl, nxp_mech.bpf.o, nvme_rand.bpf.o, ce_plan.bpf.o,
# xdev_ext_ce_sim.ko
# and session_nvme_ce.  BLOCK is the scratch namespace's block device and NG
# its generic character device; SLBA starts a scratch LBA window of at least
# 1 MiB that nothing else uses.  No struct_ops program may be attached yet.
set -eu

dir=$1
block=$2
ng=$3
slba=$4
ctl=$dir/xdev_ext_mech_ctl
lba=$(cat "/sys/block/$(basename "$block")/queue/logical_block_size")
offset=$((slba * lba))

insmod "$dir/xdev_ext_ce_sim.ko" fail_mode=none
test -c /dev/xdev_ext_ce_sim
"$ctl" attach --obj "$dir/nxp_mech.bpf.o" --map nxp_nvme_ops --pin /sys/fs/bpf/eval-nvme \
	--set nvme_mode=0
"$ctl" attach --obj "$dir/ce_plan.bpf.o" --map ce_plan_ops --pin /sys/fs/bpf/eval-ce

check() {
	grep -Eq '"status":"pass"' "$1"
	grep -Eq '"execution":"kvm-ce-sim","performance_claim":"none"' "$1"
}

# As many blocks as slots, twice and four times as many; both directions,
# two passes.  Every arm needs at least qd blocks (xg_geometry_check).
for case in "8192 4 32768" "8192 8 131072" "65536 4 1048576"; do
	set -- $case
	for direction in load save; do
		out=/tmp/eval-nvme-gpu-$direction-$1-$2-$3.json
		"$dir/session_nvme_ce" --direction "$direction" --ng "$ng" --slba "$slba" \
			--lba-size "$lba" --file "$block" --file-offset "$offset" \
			--ce-dev /dev/xdev_ext_ce_sim --ce-va 0 --size "$1" --qd "$2" \
			--window-bytes "$3" --passes 2 --timeout-ms 60000 >"$out"
		check "$out"
		echo "XDEV_EVAL_NVME_GPU_CASE=PASS direction=$direction size=$1 qd=$2 window=$3"
	done
done

# rand: nvme_rand_ops replaces nxp_nvme_ops, rand_seed = the arm's --seed (1).
# At qd 1 the load oracle names the last batch's block in the rand order.
"$ctl" detach --pin /sys/fs/bpf/eval-nvme
"$ctl" attach --obj "$dir/nvme_rand.bpf.o" --map nvme_rand_ops --pin /sys/fs/bpf/eval-nvme \
	--set rand_seed=1
for case in "8192 1 65536" "8192 4 131072" "65536 4 1048576"; do
	set -- $case
	for direction in load save; do
		out=/tmp/eval-nvme-gpu-rand-$direction-$1-$2-$3.json
		"$dir/session_nvme_ce" --direction "$direction" --ng "$ng" --slba "$slba" \
			--lba-size "$lba" --file "$block" --file-offset "$offset" \
			--ce-dev /dev/xdev_ext_ce_sim --ce-va 0 --size "$1" --qd "$2" \
			--window-bytes "$3" --passes 2 --pattern rand --seed 1 --timeout-ms 60000 >"$out"
		check "$out"
		grep -q '"pattern":"rand"' "$out"
		echo "XDEV_EVAL_NVME_GPU_CASE=PASS pattern=rand direction=$direction size=$1 qd=$2 window=$3"
	done
done

"$ctl" detach --pin /sys/fs/bpf/eval-ce
"$ctl" detach --pin /sys/fs/bpf/eval-nvme
for i in $(seq 1 200); do
	[ "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" = 0 ] && break
	sleep 0.05
done
test "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" = 0
rmmod xdev_ext_ce_sim
echo 'XDEV_EVAL_NVME_GPU_SESSION_GUEST=PASS backend=CPU-memcpy-standin gpu=none performance_claim=none'
