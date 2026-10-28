#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# BPF compute callback negatives (Documentation/userspace-api/xdev_ext-compute.rst).
# Run inside the disposable guest with the target kernel's live BTF. Every
# case must fail inside the kernel verifier log with its exact reason.
set -eu
CTL=${CTL:-/opt/xdev_ext/xdev_ext_mech_ctl}
OBJECT_DIR=${OBJECT_DIR:-/opt/xdev_ext/verifier}
LOG_DIR=${LOG_DIR:-$(mktemp -d /tmp/xdev_ext-verifier-compute.XXXXXXXX)}
PIN_DIR=/sys/fs/bpf/xdev_ext-verifier-compute-$$

fail()
{
	printf 'XDEV_EXT_MECH_VERIFIER_COMPUTE=FAIL case=%s reason=%s logs=%s\n' \
		"${case_name:-setup}" "$1" "$LOG_DIR" >&2
	exit 1
}

test -x "$CTL" || fail missing-ctl
test -r /sys/kernel/btf/vmlinux || fail missing-live-kernel-btf
mkdir -p "$LOG_DIR"
mkdir "$PIN_DIR" || fail pin-directory
trap 'rmdir "$PIN_DIR" 2>/dev/null || :' EXIT

count=0
run_case()
{
	case_name=$1
	map_name=$2
	expected=$3
	object=$OBJECT_DIR/xdev_ext_mech_fail_$case_name.bpf.o
	log=$LOG_DIR/$case_name.log
	pin=$PIN_DIR/$case_name
	test -s "$object" || fail missing-object
	status=0
	"$CTL" attach --obj "$object" --map "$map_name" --pin "$pin" \
		>"$log" 2>&1 || status=$?
	printf '%s\n' "$status" >"$LOG_DIR/$case_name.exit"
	if test "$status" -eq 0; then
		"$CTL" detach --pin "$pin" >>"$log" 2>&1 || :
		fail unexpected-attach-success
	fi
	sed -n '/-- BEGIN PROG LOAD LOG --/,/-- END PROG LOAD LOG --/p' \
		"$log" >"$LOG_DIR/$case_name.verifier.log"
	grep -F -- '-- BEGIN PROG LOAD LOG --' "$LOG_DIR/$case_name.verifier.log" \
		>/dev/null || fail missing-verifier-log
	grep -F -- '-- END PROG LOAD LOG --' "$LOG_DIR/$case_name.verifier.log" \
		>/dev/null || fail incomplete-verifier-log
	grep -F -- "$expected" "$LOG_DIR/$case_name.verifier.log" \
		>/dev/null || fail wrong-verifier-rejection
	test ! -e "$pin" || fail unexpected-pinned-link
	count=$((count + 1))
	printf 'XDEV_EXT_MECH_VERIFIER_COMPUTE=PASS case=%s exit=%s reason=%s\n' \
		"$case_name" "$status" "$expected"
}

run_case compute_rw_build compute_rw_build_ops \
	'calling kernel function bpf_xdev_ext_frame_rw is not allowed'
run_case compute_set_len_complete compute_set_len_complete_ops \
	'calling kernel function bpf_xdev_ext_frame_set_len is not allowed'
run_case compute_view_size compute_view_size_ops 'R4 is not a const'
run_case compute_view_past compute_view_past_ops \
	'invalid access to memory, mem_size=4 off=4 size=1'
run_case compute_wrong_class compute_wrong_class_ops \
	'attach to unsupported member compute of struct xdev_ext_nvme_mech_ops'
run_case compute_sleepable compute_sleepable_ops \
	'attach to unsupported member compute of struct xdev_ext_cpu_mech_ops'
run_case compute_desc compute_desc_ops \
	'calling kernel function bpf_xdev_ext_desc is not allowed'
printf 'XDEV_EXT_MECH_VERIFIER_COMPUTES=PASS cases=%s logs=%s\n' "$count" "$LOG_DIR"
