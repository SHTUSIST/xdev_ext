#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Guest only (examples_kvm.sh boots it): the BPF compute examples of
# tools/xdev_ext_mech/examples/compute against the fixed CPU transforms.
# Correctness only, nothing is timed. For every case the same inputs run once
# through the fixed transform and once through the example (CPU stage with
# XDEV_EXT_CPU_XFORM_BPF), in sessions over IOU UMEM user frames; the records
# go to the results disk as one tar archive and the host validator
# (examples_validate.py) compares both runs with each other and with an
# independent oracle. The case plan is duplicated, not shared, with
# examples_validate.py: a guest that drifts from it fails there.
set -u
dir=${1:-/opt/examples}
[ "${XDEV_EXT_EXAMPLES_GUEST:-}" = 1 ] || { echo 'FAIL guest only: set XDEV_EXT_EXAMPLES_GUEST=1'; exit 1; }
ctl=$dir/xdev_ext_mech_ctl
tool=$dir/compute_examples_guest
obj=$dir/obj
out=/tmp/examples-out
logs=$(mktemp -d /tmp/xdev-ext-examples.XXXXXX)
pin=/sys/fs/bpf/examples-cpu
mkdir -p "$out"

res=
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	[ "$(sed 's/[[:space:]]*$//' "$f")" = XDEVXRES01 ] && res=/dev/${c}n1
done
[ -n "$res" ] || { echo 'XDEV_EXT_EXAMPLES_CASE=FAIL name=results-disk'; exit 1; }

# A failure still leaves what was recorded (and verifier logs) on the results disk.
save() {
	(cd "$out" && tar -cf /tmp/examples-results.tar .) &&
		dd if=/tmp/examples-results.tar of="$res" bs=1M conv=fsync 2>"$logs/dd.log" && sync
}
fail() {
	echo "XDEV_EXT_EXAMPLES_CASE=FAIL name=$1 ${2:-}"
	for l in "$logs"/*.log; do echo "== $l"; cat "$l"; done
	save || echo 'XDEV_EXT_EXAMPLES_RESULTS=FAIL'
	exit 1
}
pass() { echo "XDEV_EXT_EXAMPLES_CASE=PASS name=$1 ${2:-}"; }

# 1. Every example object passes the verifier; record its processed insns.
XDEV_EXT_EXAMPLES_LOG_DIR=$out "$tool" verify "$obj"/*.bpf.o >"$out/verifier.txt" 2>"$logs/verify.log"
rc=$?
cat "$out/verifier.txt"
[ "$rc" = 0 ] || fail verifier "rc=$rc"
pass verifier

# Spans: one frame per batch, lengths 1..300 and the edges up to SEG, at
# header room 0 and 360 (capacity exactly L + D at the largest length).
# Frames: session-shaped groups, SEG-byte frames and a shorter last one.
FRAMES='--frames 1432:8192:360:3 --frames 300:8192:360:3 --frames 7:200:0:3 --frames 16:512:0:3 --frames 4064:8192:0:3'

# case NAME OBJECT MAP SET FIXED_STAGES BPF_STAGES INPUT LAYOUTS...
case_run() {
	name=$1 object=$2 map=$3 set=$4 fixed=$5 bpf=$6 input=$7 seed=$8
	shift 8
	"$ctl" detach --pin "$pin" >/dev/null 2>&1 || :
	# shellcheck disable=SC2086
	"$ctl" attach --obj "$obj/$object" --map "$map" --pin "$pin" $set >"$logs/$name.attach.log" 2>&1 ||
		fail "$name" reason=attach-failed
	for mode in fixed bpf; do
		stages=$fixed
		[ "$mode" = bpf ] && stages=$bpf
		# shellcheck disable=SC2086
		"$tool" run --out "$out/$name.$mode.bin" --seed "$seed" --input "$input" $stages "$@" \
			>"$logs/$name.$mode.log" 2>&1 || fail "$name" "mode=$mode reason=run-failed"
		cat "$logs/$name.$mode.log"
	done
	rm -f "$logs/$name".*.log
	pass "$name"
}

NEG=--negatives
case_run crc32c_check_bytewise crc32c_check_bytewise.bpf.o crc32c_check_ops '--set strip=0' \
	'--stage 4:0' '--stage 10:0' sealed 11 $NEG --spans 4096:0 --spans 3736:360 $FRAMES
case_run crc32c_check_slice8 crc32c_check_slice8.bpf.o crc32c_check_ops '--set strip=0' \
	'--stage 4:0' '--stage 10:0' sealed 12 $NEG --spans 4096:0 --spans 3736:360 $FRAMES
case_run crc32c_strip_slice8 crc32c_check_slice8.bpf.o crc32c_check_ops '--set strip=1' \
	'--stage 2:0' '--stage 10:-4' sealed 13 $NEG --spans 4096:0 --spans 3736:360 $FRAMES
case_run crc32c_append_bytewise crc32c_append_bytewise.bpf.o crc32c_append_ops '' \
	'--stage 1:0' '--stage 10:4' random 14 --spans 4092:0 --spans 3732:360 $FRAMES
case_run crc32c_append_slice8 crc32c_append_slice8.bpf.o crc32c_append_ops '' \
	'--stage 1:0' '--stage 10:4' random 15 --spans 4092:0 --spans 3732:360 $FRAMES
case_run xxh64_append_seed0 xxh64_append.bpf.o xxh64_append_ops '--set seed=0' \
	'--stage 6:0' '--stage 10:8' random 16 --spans 4088:0 --spans 3728:360 $FRAMES
case_run xxh64_append_seed xxh64_append.bpf.o xxh64_append_ops '--set seed=0x9E3779B185EBCA87' \
	'--stage 6:0x9E3779B185EBCA87' '--stage 10:8' random 17 --spans 4088:0 --spans 3728:360 $FRAMES
# The check alone against the fixed strip (outputs differ by the strip) ...
case_run parse_check_h16 parse_check.bpf.o parse_check_ops '--set hdr=16' \
	'--stage 5:16' '--stage 10:0' parse:16 18 $NEG --spans 4096:0 $FRAMES
case_run parse_check_h4 parse_check.bpf.o parse_check_ops '--set hdr=4' \
	'--stage 5:4' '--stage 10:0' parse:4 19 $NEG --spans 4096:0 $FRAMES
# ... and the check followed by the kernel's strip, byte-identical to the strip.
case_run parse_compose_h16 parse_check.bpf.o parse_check_ops '--set hdr=16' \
	'--stage 5:16' '--stage 10:0 --stage 5:16' parse:16 20 $NEG --spans 4096:0 $FRAMES
case_run sha256_append sha256_append.bpf.o sha256_append_ops '' \
	'--stage 7:0' '--stage 10:32' random 21 --spans 4064:0 --spans 3704:360 $FRAMES
"$ctl" detach --pin "$pin" >/dev/null 2>&1 || fail detach

# The records leave through the results disk.
save || { echo 'XDEV_EXT_EXAMPLES_CASE=FAIL name=results-write'; exit 1; }
echo "XDEV_EXT_EXAMPLES_RESULTS bytes=$(wc -c </tmp/examples-results.tar) files=$(ls "$out" | wc -l)"
echo 'XDEV_EXT_EXAMPLES_GUEST=PASS'
