#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Additional new-interface negatives; run after the five shared-kfunc cases.
set -eu
CTL=${CTL:-/opt/xdev_ext/xdev_ext_mech_ctl}
OBJECT_DIR=${OBJECT_DIR:-/opt/xdev_ext/verifier}
LOG_DIR=${LOG_DIR:-$(mktemp -d /tmp/xdev_ext-verifier-reliable.XXXXXXXX)}
PIN_DIR=/sys/fs/bpf/xdev_ext-verifier-reliable-$$

test -x "$CTL"
test -r /sys/kernel/btf/vmlinux
mkdir -p "$LOG_DIR"
mkdir "$PIN_DIR"
trap 'rmdir "$PIN_DIR" 2>/dev/null || :' EXIT

for case_name in rel_view_write rel_view_complete; do
	case "$case_name" in
	rel_view_write) map=rel_view_write_ops; expected='cannot write into rdonly_mem' ;;
	rel_view_complete) map=rel_view_complete_ops; expected='calling kernel function bpf_xdev_ext_rel_tx_view is not allowed' ;;
	esac
	object=$OBJECT_DIR/xdev_ext_mech_fail_$case_name.bpf.o
	log=$LOG_DIR/$case_name.log
	pin=$PIN_DIR/$case_name
	test -s "$object"
	status=0
	"$CTL" attach --obj "$object" --map "$map" --pin "$pin" \
		>"$log" 2>&1 || status=$?
	printf '%s\n' "$status" >"$LOG_DIR/$case_name.exit"
	if test "$status" -eq 0; then
		"$CTL" detach --pin "$pin" >>"$log" 2>&1 || :
		printf 'XDEV_EXT_MECH_VERIFIER_REL=FAIL case=%s reason=unexpected-attach-success\n' "$case_name"
		exit 1
	fi
	sed -n '/-- BEGIN PROG LOAD LOG --/,/-- END PROG LOAD LOG --/p' \
		"$log" >"$LOG_DIR/$case_name.verifier.log"
	if ! grep -F -- '-- BEGIN PROG LOAD LOG --' "$LOG_DIR/$case_name.verifier.log" >/dev/null ||
	   ! grep -F -- '-- END PROG LOAD LOG --' "$LOG_DIR/$case_name.verifier.log" >/dev/null ||
	   ! grep -F -- "$expected" "$LOG_DIR/$case_name.verifier.log" >/dev/null ||
	   test -e "$pin"; then
		printf 'XDEV_EXT_MECH_VERIFIER_REL=FAIL case=%s reason=wrong-verifier-rejection logs=%s\n' \
			"$case_name" "$LOG_DIR"
		exit 1
	fi
	printf 'XDEV_EXT_MECH_VERIFIER_REL=PASS case=%s exit=%s reason=%s\n' \
		"$case_name" "$status" "$expected"
done
printf 'XDEV_EXT_MECH_VERIFIER_RELS=PASS cases=2 logs=%s\n' "$LOG_DIR"
