#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# A database-style positional O_DIRECT workload must be indistinguishable from
# libc when it runs through the transparent front end: identical return values
# and errno for every call (folded into the workload's trace digest), and
# byte-identical file contents.  Non-qualifying calls must stay in libc.
#
# A stock host cannot execute the custom opcode.  The test-only kernel model
# library (xdev_ext_preload_kernel_model.c) supplies STATX_DIOALIGN and completes
# READ_COMPAT/WRITE_COMPAT in userspace, so the front end's takeover path runs
# here too.  The "rejected" configurations have the model refuse the XDEV_EXT_UMEM
# registration itself, so they also hold on a kernel that would accept it.
# Proof that the real opcode executed belongs to the KVM harness.
set -eu

ksft_skip=4
# The programs and libraries below are built into the selftest OUTPUT
# directory.  lib.mk runs this script from the source directory, so the
# Makefile's run_tests passes OUTPUT in XDEV_EXT_PRELOAD_TEST_DIR; an installed
# copy finds them next to itself.
dir=${XDEV_EXT_PRELOAD_TEST_DIR:-$(cd "$(dirname "$0")" && pwd)}
workload="$dir/xdev_ext_preload_db_workload"
front_end="$dir/libio_uring_unified.so"
model="$dir/libxdev_ext_preload_kernel_model.so"
cancel_wait="$dir/xdev_ext_preload_cancel_wait"
fortify="$dir/xdev_ext_preload_fortify"
buffered_cost="$dir/xdev_ext_preload_buffered_cost"

fail()
{
	echo "not ok - $*"
	exit 1
}

for artifact in "$workload" "$front_end" "$model" "$cancel_wait" "$fortify" \
	"$buffered_cost"; do
	[ -e "$artifact" ] || fail "missing build artifact: $artifact"
done

# The sanitizer target prepends its runtime so that it loads first.
prefix=${XDEV_EXT_PRELOAD_TEST_LD_PREFIX:+$XDEV_EXT_PRELOAD_TEST_LD_PREFIX:}
base=${XDEV_EXT_DB_WORKLOAD_DIR:-$dir}
work=$(mktemp -d "$base/xdev_ext-db-equivalence.XXXXXX")
# Arm 9's scratch directory lives outside $work.
nodirect=
trap 'rm -rf "$work" ${nodirect:+"$nodirect"}' EXIT
# A shell killed by a signal runs no EXIT trap (dash); exit so that it does.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
fs_type=$(stat -f -c %T "$work")
if ! dd if=/dev/zero of="$work/probe" bs=4096 count=1 oflag=direct \
	status=none 2>/dev/null; then
	echo "SKIP: $fs_type at $work does not accept O_DIRECT"
	exit "$ksft_skip"
fi
# The model reports the smallest alignment this filesystem accepts.
model_align=4096:4096
if dd if=/dev/zero of="$work/probe" bs=512 count=1 oflag=direct \
	status=none 2>/dev/null; then
	model_align=512:512
fi
rm -f "$work/probe"
echo "# filesystem=$fs_type model_dioalign=$model_align"

summary_of()
{
	grep '^XDEV_EXT_DB_WORKLOAD_RESULT=' "$work/$1.out"
}

field()
{
	# field <line> <name>
	printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p"
}

# run <name> <mode> [VAR=value ...]: one workload process on a fresh file.
run()
{
	name=$1
	mode=$2
	shift 2
	file="$work/$name.db"
	: > "$file"
	if ! env "$@" XDEV_EXT_PRELOAD_PATHS="$file" "$workload" "$file" "$mode" \
		> "$work/$name.out" 2> "$work/$name.err"; then
		sed 's/^/# /' "$work/$name.out" "$work/$name.err"
		fail "$name: workload exited non-zero"
	fi
	line=$(summary_of "$name") || fail "$name: no summary line"
	case "$line" in
	XDEV_EXT_DB_WORKLOAD_RESULT=PASS\ *) ;;
	*) fail "$name: $line" ;;
	esac
	digest=$(sha256sum "$file" | cut -d' ' -f1)
	[ "$(field "$line" sha256)" = "$digest" ] ||
		fail "$name: summary sha256 differs from sha256sum $digest"
	echo "# $name: $line"
}

same_summary()
{
	[ "$(summary_of "$1")" = "$(summary_of "$2")" ] ||
		fail "$2 summary differs from $1"
	cmp -s "$work/$1.db" "$work/$2.db" || fail "$2 file bytes differ from $1"
}

# Sum one key over every XDEV_EXT_PRELOAD_REPORT or XDEV_EXT_MODEL_SUMMARY line.
sum_key()
{
	awk -v prefix="$2" -v key="$3" '
		$1 == prefix {
			for (i = 2; i <= NF; i++) {
				split($i, kv, "=")
				if (kv[1] == key)
					total += kv[2]
			}
		}
		END { print total + 0 }' "$work/$1.err"
}

# Stock host, no model: everything must fall back exactly.
run libc-stock full ${prefix:+LD_PRELOAD="${prefix%:}"}
run frontend-disabled-stock full LD_PRELOAD="$prefix$front_end"
same_summary libc-stock frontend-disabled-stock
run frontend-enabled-stock full LD_PRELOAD="$prefix$front_end" \
	XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_REPORT=1
same_summary libc-stock frontend-enabled-stock
echo "ok 1 - stock host: disabled and enabled front end match libc"

# Model supplies DIOALIGN and rejects the XDEV_EXT_UMEM registration itself
# (XDEV_EXT_MODEL_REJECT_UMEM=1), whatever the host kernel would answer: admission
# succeeds, and every call must still fall back before publication.
run libc-model full LD_PRELOAD="$prefix$model" XDEV_EXT_MODEL_DIOALIGN="$model_align"
cmp -s "$work/libc-stock.db" "$work/libc-model.db" ||
	fail "libc runs with and without the model wrote different bytes"
reads=$(field "$(summary_of libc-model)" eligible_reads)
writes=$(field "$(summary_of libc-model)" eligible_writes)
read_errors=$(field "$(summary_of libc-model)" eligible_read_errors)
write_errors=$(field "$(summary_of libc-model)" eligible_write_errors)
fallbacks=$(field "$(summary_of libc-model)" fallback_calls)
[ "$reads" -gt 0 ] && [ "$writes" -gt 0 ] && [ "$fallbacks" -gt 0 ] ||
	fail "model classification admitted no calls"
run frontend-rejected full LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_REJECT_UMEM=1 \
	XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_REPORT=1
same_summary libc-model frontend-rejected
! grep -q '^XDEV_EXT_PRELOAD_REPORT ' "$work/frontend-rejected.err" ||
	fail "a rejected registration produced a reportable ring"
# The rejection also holds where the registration would otherwise be accepted
# (XDEV_EXT_MODEL_UMEM=1 stands for a matching kernel).
run frontend-rejected-umem full LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_UMEM=1 \
	XDEV_EXT_MODEL_REJECT_UMEM=1 XDEV_EXT_MODEL_SUMMARY=1 XDEV_EXT_PRELOAD_ENABLED=1 \
	XDEV_EXT_PRELOAD_REPORT=1
same_summary libc-model frontend-rejected-umem
! grep -q '^XDEV_EXT_PRELOAD_REPORT ' "$work/frontend-rejected-umem.err" ||
	fail "a rejected registration produced a reportable ring" \
		"(XDEV_EXT_MODEL_UMEM=1)"
[ "$(sum_key frontend-rejected-umem XDEV_EXT_MODEL_SUMMARY read_sqes)" -eq 0 ] &&
[ "$(sum_key frontend-rejected-umem XDEV_EXT_MODEL_SUMMARY write_sqes)" -eq 0 ] ||
	fail "a rejected registration published an SQE"
echo "ok 2 - rejected registration falls back after admission"

# Modelled takeover: every eligible call is one SQE, no other call is.
# check_takeover <libc run> <front-end run>
check_takeover()
{
	ref=$(summary_of "$1")
	name=$2
	ref_reads=$(field "$ref" eligible_reads)
	ref_writes=$(field "$ref" eligible_writes)
	ref_read_errors=$(field "$ref" eligible_read_errors)
	ref_write_errors=$(field "$ref" eligible_write_errors)
	same_summary "$1" "$name"
	[ "$(sum_key "$name" XDEV_EXT_PRELOAD_REPORT read_count)" -eq \
	  $((ref_reads - ref_read_errors)) ] ||
		fail "$name: read_count mismatch"
	[ "$(sum_key "$name" XDEV_EXT_PRELOAD_REPORT read_errors)" -eq \
	  "$ref_read_errors" ] || fail "$name: read_errors mismatch"
	[ "$(sum_key "$name" XDEV_EXT_PRELOAD_REPORT write_count)" -eq \
	  $((ref_writes - ref_write_errors)) ] ||
		fail "$name: write_count mismatch"
	[ "$(sum_key "$name" XDEV_EXT_PRELOAD_REPORT write_errors)" -eq \
	  "$ref_write_errors" ] || fail "$name: write_errors mismatch"
	[ "$(sum_key "$name" XDEV_EXT_MODEL_SUMMARY read_sqes)" -eq "$ref_reads" ] ||
		fail "$name: READ_COMPAT SQE count differs from eligible_reads"
	[ "$(sum_key "$name" XDEV_EXT_MODEL_SUMMARY write_sqes)" -eq \
	  "$ref_writes" ] ||
		fail "$name: WRITE_COMPAT SQE count differs from" \
			"eligible_writes"
	[ "$(sum_key "$name" XDEV_EXT_MODEL_SUMMARY other_sqes)" -eq 0 ] ||
		fail "$name: unexpected SQE kinds"
}
run frontend-takeover full LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_UMEM=1 \
	XDEV_EXT_MODEL_SUMMARY=1 XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_REPORT=1
check_takeover libc-model frontend-takeover
echo "ok 3 - modelled takeover matches libc; SQEs equal eligible calls"

run frontend-takeover-eintr full LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_UMEM=1 XDEV_EXT_MODEL_EINTR=1 \
	XDEV_EXT_MODEL_SUMMARY=1 XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_REPORT=1
check_takeover libc-model frontend-takeover-eintr
[ "$(sum_key frontend-takeover-eintr XDEV_EXT_MODEL_SUMMARY eintr_returned)" -eq \
  $((reads + writes)) ] || fail "EINTR was not returned once per request"
echo "ok 4 - EINTR after acceptance drains without replay"

run libc-fallback-only fallback-only LD_PRELOAD="$prefix$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align"
run frontend-fallback-only fallback-only LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_UMEM=1 \
	XDEV_EXT_MODEL_SUMMARY=1 XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_REPORT=1
same_summary libc-fallback-only frontend-fallback-only
[ "$(field "$(summary_of frontend-fallback-only)" eligible_reads)" -eq 0 ] &&
[ "$(field "$(summary_of frontend-fallback-only)" eligible_writes)" -eq 0 ] ||
	fail "fallback-only mode classified a call as eligible"
[ "$(sum_key frontend-fallback-only XDEV_EXT_MODEL_SUMMARY read_sqes)" -eq 0 ] &&
[ "$(sum_key frontend-fallback-only XDEV_EXT_MODEL_SUMMARY write_sqes)" -eq 0 ] ||
	fail "a non-qualifying call published an SQE"
echo "ok 5 - non-qualifying calls publish no SQE"

# cancel_wait_run <name> <mode> [VAR=value ...]: one fixture run, fresh file.
cancel_wait_run()
{
	name=$1
	mode=$2
	shift 2
	file="$work/$name.db"
	: > "$file"
	if ! env "$@" XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_PATHS="$file" \
		"$cancel_wait" "$file" "$mode" > "$work/$name.out" 2>&1; then
		sed 's/^/# /' "$work/$name.out"
		fail "$name: cancellation fixture failed"
	fi
	grep -q "^XDEV_EXT_PRELOAD_CANCEL_WAIT=PASS mode=$mode" "$work/$name.out" ||
		fail "$name: PASS marker missing"
}
cancel_wait_run cancel-wait wait LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_UMEM=1
echo "ok 6 - cancellation waits for the published request's completion"

# Taken over, rejected at registration, or ineligible: the caller's
# cancellation state is unchanged after every positional call.
cancel_wait_run cancel-state-takeover state \
	LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_UMEM=1
cancel_wait_run cancel-state-rejected state \
	LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_REJECT_UMEM=1
echo "ok 7 - positional calls keep the caller's cancellation state"

# Fortified callers reach __pread_chk/__pread64_chk, not pread/pread64.
symbols=$(nm -D "$fortify")
case "$symbols" in
*" U __pread_chk"*" U __pread64_chk"* | *" U __pread64_chk"*" U __pread_chk"*) ;;
*) fail "fortify fixture does not reference __pread_chk and __pread64_chk" ;;
esac
for mode in libc takeover; do
	file="$work/fortify-$mode.db"
	: > "$file"
	if [ "$mode" = libc ]; then
		preload="$prefix$model"
	else
		preload="$prefix$front_end:$model"
	fi
	if ! env LD_PRELOAD="$preload" XDEV_EXT_MODEL_DIOALIGN="$model_align" \
		XDEV_EXT_MODEL_UMEM=1 XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_PATHS="$file" \
		"$fortify" "$file" "$mode" > "$work/fortify.out" 2>&1; then
		sed 's/^/# /' "$work/fortify.out"
		fail "fortified positional reads ($mode)"
	fi
	grep -q "^XDEV_EXT_PRELOAD_FORTIFY=PASS mode=$mode" "$work/fortify.out" ||
		fail "fortify PASS marker missing ($mode)"
done
echo "ok 8 - fortified reads are taken over and keep the overflow abort"

# A file system that rejects O_DIRECT is reported with exit status 4, also
# when the workload cannot write its message (stderr closed).
nodirect_base=${XDEV_EXT_DB_NODIRECT_DIR:-/dev/shm}
if [ -d "$nodirect_base" ]; then
	nodirect=$(mktemp -d "$nodirect_base/xdev_ext-db-nodirect.XXXXXX" \
		2>/dev/null) || nodirect=
fi
if [ -z "$nodirect" ]; then
	echo "ok 9 - # SKIP no scratch directory under $nodirect_base"
elif dd if=/dev/zero of="$nodirect/probe" bs=4096 count=1 oflag=direct \
	status=none 2>/dev/null; then
	rm -f "$nodirect/probe"
	rmdir "$nodirect"
	nodirect=
	echo "ok 9 - # SKIP $nodirect_base accepts O_DIRECT"
else
	: > "$nodirect/nodirect.db"
	rc=0
	"$workload" "$nodirect/nodirect.db" full > /dev/null 2>&- || rc=$?
	rm -f "$nodirect/nodirect.db" "$nodirect/probe"
	rmdir "$nodirect"
	nodirect=
	[ "$rc" -eq 4 ] ||
		fail "workload on a file system without O_DIRECT exited" \
			"$rc, want 4"
	echo "ok 9 - a file system without O_DIRECT is reported with exit" \
		"status 4"
fi

# A device with a 4096-byte logical block reports a DIO offset alignment of
# 4096.  The workload's own I/O must stay eligible there and pass on such a
# device, so only the deliberate probes fall back at either alignment.  The
# model replaces a less strict alignment that the host kernel reports itself
# (Linux 6.1 and later), so both runs must see 4096.
align_4096=
if [ "$model_align" != 4096:4096 ]; then
	run libc-model-4096 full LD_PRELOAD="$prefix$model" \
		XDEV_EXT_MODEL_DIOALIGN=4096:4096
	align_4096=$(field "$(summary_of libc-model-4096)" dio_offset_align)
fi
if [ "$model_align" = 4096:4096 ]; then
	echo "ok 10 - # SKIP arms 2-8 already ran at DIO alignment 4096"
elif [ "$align_4096" != 4096 ]; then
	echo "ok 10 - # SKIP the workload saw DIO offset alignment" \
		"'$align_4096', not 4096"
else
	fallbacks_4096=$(field "$(summary_of libc-model-4096)" fallback_calls)
	[ "$fallbacks_4096" -eq "$fallbacks" ] ||
		fail "fallback_calls=$fallbacks_4096 at alignment 4096," \
			"$fallbacks at $model_align"
	run frontend-takeover-4096 full LD_PRELOAD="$prefix$front_end:$model" \
		XDEV_EXT_MODEL_DIOALIGN=4096:4096 XDEV_EXT_MODEL_UMEM=1 \
		XDEV_EXT_MODEL_SUMMARY=1 XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_REPORT=1
	align_4096=$(field "$(summary_of frontend-takeover-4096)" \
		dio_offset_align)
	[ "$align_4096" = 4096 ] ||
		fail "frontend-takeover-4096: DIO offset alignment $align_4096"
	check_takeover libc-model-4096 frontend-takeover-4096
	echo "ok 10 - at DIO alignment 4096 only the deliberate probes fall" \
		"back"
fi

# io_uring unavailable (EPERM: kernel.io_uring_disabled=2 or a seccomp filter;
# ENOSYS: a kernel without io_uring).  The workload still passes, and the
# front end, which cannot create its ring, falls back for every call.
for setup_errno in 1 38; do
	run "libc-no-io-uring-$setup_errno" full LD_PRELOAD="$prefix$model" \
		XDEV_EXT_MODEL_DIOALIGN="$model_align" \
		XDEV_EXT_MODEL_IO_URING_SETUP_ERRNO="$setup_errno"
	run "frontend-no-io-uring-$setup_errno" full \
		LD_PRELOAD="$prefix$front_end:$model" \
		XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_UMEM=1 \
		XDEV_EXT_MODEL_SUMMARY=1 \
		XDEV_EXT_MODEL_IO_URING_SETUP_ERRNO="$setup_errno" \
		XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_REPORT=1
	same_summary "libc-no-io-uring-$setup_errno" \
		"frontend-no-io-uring-$setup_errno"
	! grep -q '^XDEV_EXT_PRELOAD_REPORT ' \
		"$work/frontend-no-io-uring-$setup_errno.err" ||
		fail "io_uring_setup errno $setup_errno: a ring was reported"
	[ "$(sum_key "frontend-no-io-uring-$setup_errno" XDEV_EXT_MODEL_SUMMARY \
	     read_sqes)" -eq 0 ] &&
	[ "$(sum_key "frontend-no-io-uring-$setup_errno" XDEV_EXT_MODEL_SUMMARY \
	     write_sqes)" -eq 0 ] ||
		fail "io_uring_setup errno $setup_errno: an SQE was published"
done
echo "ok 11 - without io_uring the workload passes and every call falls back"

# A buffered descriptor on the allowlisted file stays tracked (F_SETFL may set
# O_DIRECT later), but each of its calls costs at most one descriptor call.
file="$work/buffered-cost.db"
: > "$file"
if ! env LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_UMEM=1 \
	XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_PATHS="$file" \
	"$buffered_cost" "$file" > "$work/buffered-cost.out" 2>&1; then
	sed 's/^/# /' "$work/buffered-cost.out"
	fail "buffered descriptor cost"
fi
grep -q '^XDEV_EXT_PRELOAD_BUFFERED_COST=PASS' "$work/buffered-cost.out" ||
	fail "buffered-cost PASS marker missing"
sed -n 's/^\([0-9]* .* descriptor calls\)$/# \1/p' "$work/buffered-cost.out"
echo "ok 12 - a buffered descriptor costs at most one call per positional call"

# send, sendto and sendmsg are cancellation points too.  With socket takeover
# enabled, a cancellation pending at entry acts there, one that arrives while
# the front end holds its duplicate descriptor never leaks it, and the caller's
# cancellation state is unchanged on every path and is the state the libc send
# on the duplicate runs in.
for mode in send-entry send-blocked send-state; do
	cancel_wait_run "$mode-libc" "$mode" LD_PRELOAD="$prefix$model"
	cancel_wait_run "$mode-disabled" "$mode" \
		LD_PRELOAD="$prefix$front_end:$model"
	cancel_wait_run "$mode-rejected" "$mode" \
		LD_PRELOAD="$prefix$front_end:$model" \
		XDEV_EXT_MODEL_REJECT_UMEM=1 XDEV_EXT_PRELOAD_SOCKET_ENABLED=1
	cancel_wait_run "$mode-takeover" "$mode" \
		LD_PRELOAD="$prefix$front_end:$model" XDEV_EXT_MODEL_UMEM=1 \
		XDEV_EXT_PRELOAD_SOCKET_ENABLED=1
done
cancel_wait_run send-wait send-wait LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_UMEM=1 XDEV_EXT_PRELOAD_SOCKET_ENABLED=1
# Publication refused (busy SQ): the taken-over send uses libc on the front
# end's duplicate, which is then where a cancellation acts.
cancel_wait_run send-seam send-seam LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_UMEM=1 XDEV_EXT_MODEL_SQ_BUSY=1 XDEV_EXT_PRELOAD_SOCKET_ENABLED=1
cancel_wait_run send-state-busy send-state \
	LD_PRELOAD="$prefix$front_end:$model" XDEV_EXT_MODEL_UMEM=1 \
	XDEV_EXT_MODEL_SQ_BUSY=1 XDEV_EXT_PRELOAD_SOCKET_ENABLED=1
# Registration rejected (XDEV_EXT_MODEL_REJECT_UMEM=1): a cancellation that arrives
# during ring setup must not act inside it; it acts in the libc send on the
# duplicate.
cancel_wait_run send-seam-rejected send-seam \
	LD_PRELOAD="$prefix$front_end:$model" XDEV_EXT_MODEL_REJECT_UMEM=1 \
	XDEV_EXT_PRELOAD_SOCKET_ENABLED=1
# A cancellation that arrives after the send returned, while the front end
# closes its duplicate, must not act inside that close().
cancel_wait_run send-close-rejected send-close \
	LD_PRELOAD="$prefix$front_end:$model" XDEV_EXT_MODEL_REJECT_UMEM=1 \
	XDEV_EXT_PRELOAD_SOCKET_ENABLED=1
cancel_wait_run send-close-takeover send-close \
	LD_PRELOAD="$prefix$front_end:$model" XDEV_EXT_MODEL_UMEM=1 \
	XDEV_EXT_PRELOAD_SOCKET_ENABLED=1
cancel_wait_run send-close-busy send-close \
	LD_PRELOAD="$prefix$front_end:$model" XDEV_EXT_MODEL_UMEM=1 \
	XDEV_EXT_MODEL_SQ_BUSY=1 XDEV_EXT_PRELOAD_SOCKET_ENABLED=1
echo "ok 13 - sends act on cancellation without leaking a descriptor"

# Every exported positional entry point acts on a cancellation pending at
# entry, whether the call would be taken over, rejected at registration, or
# handled by libc alone.
cancel_wait_run entry-libc entry LD_PRELOAD="$prefix$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align"
cancel_wait_run entry-rejected entry LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_REJECT_UMEM=1
cancel_wait_run entry-takeover entry LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_UMEM=1
echo "ok 14 - every positional entry point acts on a pending cancellation"

# A thread that returns normally with a cancellation request pending: the
# front end's teardown of its ring must not act on the request, so
# pthread_join() gets the returned value and no descriptor is left open.
cancel_wait_run return-pending-libc return-pending LD_PRELOAD="$prefix$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align"
cancel_wait_run return-pending-rejected return-pending \
	LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_REJECT_UMEM=1
cancel_wait_run return-pending-takeover return-pending \
	LD_PRELOAD="$prefix$front_end:$model" \
	XDEV_EXT_MODEL_DIOALIGN="$model_align" XDEV_EXT_MODEL_UMEM=1
echo "ok 15 - a thread that returns with a cancellation pending keeps its" \
	"value and leaks no descriptor"

echo "PASS: database-style workload is libc-equivalent through the front end"
