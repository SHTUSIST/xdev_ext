#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Run inside the disposable guest with the target kernel's live BTF.
set -eu

CTL=${CTL:-/opt/xdev_ext/xdev_ext_mech_ctl}
OBJECT_DIR=${OBJECT_DIR:-/opt/xdev_ext/verifier}
LOG_DIR=${LOG_DIR:-$(mktemp -d /tmp/xdev_ext-verifier-negative.XXXXXXXX)}
PIN_DIR=/sys/fs/bpf/xdev_ext-verifier-negative-$$

fail()
{
	printf 'XDEV_EXT_MECH_VERIFIER_NEGATIVE=FAIL case=%s reason=%s logs=%s\n' \
		"${case_name:-setup}" "$1" "$LOG_DIR" >&2
	exit 1
}

test -x "$CTL" || fail missing-ctl
test -r /sys/kernel/btf/vmlinux || fail missing-live-kernel-btf
test -d /sys/fs/bpf || fail missing-bpffs-directory
mkdir -p "$LOG_DIR"
mkdir "$PIN_DIR" || fail pin-directory
trap 'rmdir "$PIN_DIR" 2>/dev/null || :' EXIT

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
	# Reject setup-only failures: the exact reason must be within an actual
	# kernel verifier log, not an ELF/BTF relocation or map attach diagnostic.
	sed -n '/-- BEGIN PROG LOAD LOG --/,/-- END PROG LOAD LOG --/p' \
		"$log" >"$LOG_DIR/$case_name.verifier.log"
	grep -F -- '-- BEGIN PROG LOAD LOG --' "$LOG_DIR/$case_name.verifier.log" \
		>/dev/null || fail missing-verifier-log
	grep -F -- '-- END PROG LOAD LOG --' "$LOG_DIR/$case_name.verifier.log" \
		>/dev/null || fail incomplete-verifier-log
	grep -F -- "$expected" "$LOG_DIR/$case_name.verifier.log" \
		>/dev/null || fail wrong-verifier-rejection
	test ! -e "$pin" || fail unexpected-pinned-link
	printf 'XDEV_EXT_MECH_VERIFIER_NEGATIVE=PASS case=%s exit=%s reason=%s\n' \
		"$case_name" "$status" "$expected"
}

run_case wrong_class_hold wrong_class_hold_ops \
	'calling kernel function bpf_xdev_ext_afxdp_hold is not allowed'
run_case desc_complete desc_complete_ops \
	'calling kernel function bpf_xdev_ext_desc is not allowed'
run_case sleepable_build sleepable_build_ops \
	'attach to unsupported member build of struct xdev_ext_nvme_mech_ops'
run_case forged_ctx forged_ctx_ops 'R1 must be referenced or trusted'
run_case frame_write frame_write_ops 'cannot write into rdonly_mem'
run_case dma_wrong_class_hold dma_wrong_class_hold_ops \
	'calling kernel function bpf_xdev_ext_afxdp_hold is not allowed'
run_case dma_desc_complete dma_desc_complete_ops \
	'calling kernel function bpf_xdev_ext_desc is not allowed'
printf 'XDEV_EXT_MECH_VERIFIER_NEGATIVES=PASS cases=7 logs=%s\n' "$LOG_DIR"
