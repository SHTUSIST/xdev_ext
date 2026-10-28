#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Exact matching-kernel helper probes; optional argument selects one case.
set -eu
CTL=${CTL:-/opt/xdev_ext/xdev_ext_mech_ctl}
OBJECT_DIR=${OBJECT_DIR:-/opt/xdev_ext/verifier}
LOG_DIR=${LOG_DIR:-$(mktemp -d /tmp/xdev-ext-verifier-helpers.XXXXXXXX)}
PIN_DIR=/sys/fs/bpf/xdev-ext-verifier-helpers-$$
selection=${1:-all}
count=0
pin=
case_name=setup

fail()
{
	printf 'XDEV_EXT_MECH_HELPER=FAIL case=%s reason=%s logs=%s\n' \
		"$case_name" "$1" "$LOG_DIR" >&2
	exit 1
}

cleanup()
{
	if [ -n "$pin" ] && [ -e "$pin" ]; then
		"$CTL" detach --pin "$pin" >/dev/null 2>&1 || :
	fi
	rmdir "$PIN_DIR" 2>/dev/null || :
}

[ "$#" -le 1 ] || fail argument-count
[ -x "$CTL" ] || fail missing-ctl
[ -r /sys/kernel/btf/vmlinux ] || fail missing-live-kernel-btf
[ -d /sys/fs/bpf ] || fail missing-bpffs
mkdir -p "$LOG_DIR"
mkdir "$PIN_DIR" || fail pin-directory
trap cleanup EXIT INT TERM

run_case()
{
	case_name=$1
	helper=$2
	id=$3
	expected=$4
	[ "$selection" = all ] || [ "$selection" = "$case_name" ] || return 0
	object=$OBJECT_DIR/helper_$case_name.bpf.o
	log=$LOG_DIR/$case_name.log
	pin=$PIN_DIR/$case_name
	[ -s "$object" ] || fail missing-object
	status=0
	"$CTL" attach --obj "$object" --map helper_probe_ops --pin "$pin" \
		>"$log" 2>&1 || status=$?
	printf '%s\n' "$status" >"$LOG_DIR/$case_name.exit"
	cat "$log"
	if [ "$expected" = ALLOW ]; then
		[ "$status" -eq 0 ] || fail allow-load-failed
		[ -e "$pin" ] || fail allow-link-not-pinned
		"$CTL" detach --pin "$pin" >>"$log" 2>&1 || fail allow-detach-failed
	else
		# CLI cmd_attach reports verifier load failures as CTL_SETUP (3).
		# Only the exact helper log below distinguishes the intended denial.
		[ "$status" -eq 3 ] || fail unexpected-loader-exit
		if grep -Eiq 'XDOMAIN_SETUP_FAIL|failed to open|failed to find|invalid ELF|not found in kernel BTF|relocation.*failed' "$log"; then
			fail setup-error
		fi
		# A matched diagnostic counts only once its own complete region closes.
		# Never accept generic errors, another helper ID, or outside-log text.
		awk -v wanted="program of this type cannot use helper $helper#$id" '
		/-- BEGIN PROG LOAD LOG --$/ { if (inside) bad=1; inside=1; matched=0; next }
		$0 == "-- END PROG LOAD LOG --" {
			if (!inside) bad=1;
			if (inside && matched) found=1;
			inside=0; matched=0; next
		}
		inside && $0 == wanted { matched=1 }
		END { exit !(found && !inside && !bad) }
		' "$log" || fail wrong-verifier-rejection
	fi
	[ ! -e "$pin" ] || fail unexpected-pinned-link
	count=$((count + 1))
	printf 'XDEV_EXT_MECH_HELPER=PASS case=%s expected=%s helper=%s id=%s\n' \
		"$case_name" "$expected" "$helper" "$id"
}

run_case map_lookup_elem bpf_map_lookup_elem 1 ALLOW
run_case ktime_get_ns bpf_ktime_get_ns 5 ALLOW
run_case probe_read_kernel bpf_probe_read_kernel 113 DENY
run_case probe_read_kernel_str bpf_probe_read_kernel_str 115 DENY
run_case probe_read_user bpf_probe_read_user 112 DENY
run_case probe_read_user_str bpf_probe_read_user_str 114 DENY
run_case get_current_task bpf_get_current_task 35 DENY
run_case get_current_task_btf bpf_get_current_task_btf 158 DENY
run_case trace_printk bpf_trace_printk 6 DENY
run_case trace_vprintk bpf_trace_vprintk 177 DENY
run_case timer_init bpf_timer_init 169 DENY
run_case tail_call bpf_tail_call 12 DENY
run_case ringbuf_output bpf_ringbuf_output 130 DENY
run_case map_update_elem bpf_map_update_elem 2 DENY
[ "$count" -gt 0 ] || fail unknown-selection
[ "$selection" != all ] || [ "$count" -eq 14 ] || fail incomplete-inventory
printf 'XDEV_EXT_MECH_HELPERS=PASS cases=%s logs=%s\n' "$count" "$LOG_DIR"
