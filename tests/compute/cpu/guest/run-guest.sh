#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Guest only (compute_kvm.sh boots it): the CPU class BPF compute callback over
# two QEMU NVMe namespaces, NVMe READ -> CPU -> NVMe WRITE. Correctness only,
# nothing is timed. Every case prints XDEV_EXT_COMPUTE_CASE=PASS|FAIL name=...;
# the host validator compares the destination with an independent oracle.
# The plan below is duplicated, not shared, with compute_validate.py.
set -u
dir=${1:-/opt/compute}
[ "${XDEV_EXT_COMPUTE_GUEST:-}" = 1 ] || { echo 'FAIL guest only: set XDEV_EXT_COMPUTE_GUEST=1'; exit 1; }
. "$dir/layout.env"
ctl=$dir/xdev_ext_mech_ctl
logs=$(mktemp -d /tmp/xdev-ext-compute.XXXXXX)
pin=/sys/fs/bpf/compute-cpu
nvme_pin=/sys/fs/bpf/compute-nvme
groups=16 depth=16 group_bytes=8192 src_slba=2048
nlb=$((groups * group_bytes / 512))

src= dst=
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	case "$(sed 's/[[:space:]]*$//' "$f")" in
	XDEVCSRC01) src=$c ;;
	XDEVCDST01) dst=$c ;;
	esac
done
[ -n "$src" ] && [ -n "$dst" ] || { echo 'XDEV_EXT_COMPUTE_CASE=FAIL name=nvme-roles'; exit 1; }
src_ng=/dev/ng${src#nvme}n1 dst_ng=/dev/ng${dst#nvme}n1
echo "XDEV_EXT_COMPUTE_ROLES source=$src destination=$dst capacity=$capacity seg_len=$seg_len"

fail() { echo "XDEV_EXT_COMPUTE_CASE=FAIL name=$1 ${2:-}"; for l in "$logs"/*.log; do echo "== $l"; cat "$l"; done; exit 1; }
pass() { echo "XDEV_EXT_COMPUTE_CASE=PASS name=$1 ${2:-}"; }
attach() { # name object map [--set ...]
	name=$1 obj=$2 map=$3; shift 3
	"$ctl" detach --pin "$pin" >/dev/null 2>&1 || :
	"$ctl" attach --obj "$dir/$obj" --map "$map" --pin "$pin" "$@" >"$logs/$name.log" 2>&1 ||
		fail "$name" "reason=attach-failed"
	cat "$logs/$name.log"
}
chain() { # name xform arg dst_slba: sets rc
	name=$1
	rc=0
	echo "XDEV_EXT_COMPUTE_BEGIN name=$name"
	"$ctl" cpu-chain --xform "$2" --xform-arg "$3" --src-ng "$src_ng" --slba "$src_slba" \
		--nlb "$nlb" --dst-ng "$dst_ng" --dst-slba "$4" --dst-nlb "$nlb" \
		--groups "$groups" --depth "$depth" --group-bytes "$group_bytes" \
		--timeout-ms 240000 >"$logs/$name.log" 2>&1 || rc=$?
	cat "$logs/$name.log"
	echo "XDEV_EXT_COMPUTE_EXIT name=$name rc=$rc"
}
expect_pass() {
	[ "$rc" = 0 ] && grep -q 'XDEV_EXT_MECH_CPU_CHAIN=PASS' "$logs/$1.log" || fail "$1" "rc=$rc"
	pass "$1" "${2:-}"
}
# ctl exits 3 (setup) when CREATE is refused before any batch starts.
expect_refused() {
	[ "$rc" = 3 ] && grep -q 'Operation not supported' "$logs/$1.log" || fail "$1" "rc=$rc"
	pass "$1" "create=-EOPNOTSUPP"
}
# ctl exits 1 when batches started and failed; the stats line says how.
expect_failed() {
	name=$1 want=$2
	[ "$rc" = 1 ] || fail "$name" "rc=$rc"
	grep -q "XDEV_EXT_MECH_STATS .*batches_done=0 " "$logs/$name.log" || fail "$name" "reason=batch-completed"
	grep -Eq "$want" "$logs/$name.log" || fail "$name" "reason=wrong-error"
	pass "$name" "rc=1"
}

"$ctl" attach --obj "$dir/nxp_mech.bpf.o" --map nxp_nvme_ops --pin "$nvme_pin" --set nvme_mode=0 ||
	fail nvme-program

# 1. A compute program loads and runs: XOR + seal, once per batch.
attach attach-compute compute_test.bpf.o compute_test_ops --set mode=0
pass attach-compute
chain compute-xor-seal bpf-compute 0 2048
expect_pass compute-xor-seal "region=2048"
# 2. A declared length change cannot feed the fixed NVMe group.
chain delta-before-nvme bpf-compute 4 7168
expect_refused delta-before-nvme
# 3. Context and view bounds inside a running program.
attach attach-probe compute_test.bpf.o compute_test_ops --set mode=3 --set probe_cap="$capacity"
chain compute-probe bpf-compute 0 3072
expect_pass compute-probe "region=3072 capacity=$capacity"
# 4. A length other than L + D: kfunc misuse fails every batch.
attach attach-bad-len compute_test.bpf.o compute_test_ops --set mode=1
chain bad-set-len bpf-compute 0 4096
expect_failed bad-set-len 'last_err=-EPROTO .*protocol_err=[1-9]'
# 5. The program's own error completes the batch with it.
attach attach-prog-error compute_test.bpf.o compute_test_ops --set mode=2
chain program-error bpf-compute 0 5120
expect_failed program-error 'last_err=-74 '
# 6. These programs load, then copy only the scalar ctx. Each ignores one
#    kfunc refusal and returns 0; the real call still fails with -EPROTO.
#    All three destination ranges are disjoint from the original cases.
attach attach-copy-len compute_test.bpf.o compute_test_ops --set mode=4
chain copied-ctx-frame-len bpf-compute 0 256
expect_failed copied-ctx-frame-len 'last_err=-EPROTO .*protocol_err=[1-9]'
attach attach-copy-rw compute_test.bpf.o compute_test_ops --set mode=5
chain copied-ctx-frame-rw bpf-compute 0 1536
expect_failed copied-ctx-frame-rw 'last_err=-EPROTO .*protocol_err=[1-9]'
attach attach-copy-set-len compute_test.bpf.o compute_test_ops --set mode=6
chain copied-ctx-set-len bpf-compute 0 2560
expect_failed copied-ctx-set-len 'last_err=-EPROTO .*protocol_err=[1-9]'
# 7. An object built without compute still loads and runs fixed transforms,
#    and the BPF transform is refused at CREATE without a compute program.
attach attach-old-layout compute_old_layout.bpf.o old_layout_ops
pass attach-old-layout
chain old-layout-seal crc32c-seal 0 1024
expect_pass old-layout-seal "region=1024"
chain no-compute-program bpf-compute 0 6144
expect_refused no-compute-program
"$ctl" detach --pin "$pin" >/dev/null 2>&1 || fail detach
"$ctl" detach --pin "$nvme_pin" >/dev/null 2>&1 || fail detach-nvme
sync

# 8. Verifier rejections; the shared negatives use the updated test header.
for suite in run_compute run run_state; do
	LOG_DIR=$logs/verifier-$suite CTL=$ctl OBJECT_DIR=$dir/verifier sh "$dir/verifier/$suite.sh" ||
		fail "verifier-$suite"
	pass "verifier-$suite"
done
echo 'XDEV_EXT_COMPUTE_GUEST=PASS'
