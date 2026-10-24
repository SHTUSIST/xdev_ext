#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Matching disposable guest only. Busybox sh; correctness checks without clocks.
set -eu
[ "$#" = 3 ] || { echo 'usage: fence_guest MODULE NONCE_PREFIX ITERATIONS' >&2; exit 2; }
module=$1 prefix=$2 iterations=$3
case "$prefix" in ''|*[!0-9a-f]*) exit 2;; esac
[ "${#prefix}" = 31 ] && [ "$iterations" = 8 ] || exit 2
sys=/sys/module/lifecycle_bench
debug=/sys/kernel/debug/xdev_lifecycle_bench
absent() { [ ! -e "$sys" ] && [ ! -e "$debug" ] && [ ! -e "$debug/result" ]; }
absent || { echo 'FAIL preexisting fence producer' >&2; exit 1; }
# No implicit mount: harness must provide an actual debugfs mount.
grep -q ' /sys/kernel/debug debugfs ' /proc/mounts
set -- $(sha256sum "$module")
echo "XDEV_EXT_FENCE_IDENTITY kernel_release=$(uname -r) module_sha256=$1"
# Save all observations before emitting the protocol so loader stdout/dmesg
# cannot split the contiguous raw-report and case record sequence.
logdir=$(mktemp -d /tmp/xdev-ext-fence.XXXXXX)
nonce=${prefix}0
insmod "$module" mode=check iterations="$iterations" run_nonce="$nonce" >"$logdir/check-load" 2>&1 || { cat "$logdir/check-load" >&2; exit 1; }
# Unverified ownership must never cause removal of someone else's producer.
[ "$(cat "$sys/parameters/run_nonce")" = "$nonce" ] || exit 1
owned=1
cleanup() {
 if [ "$owned" = 1 ]; then rmmod lifecycle_bench || :; fi
}
trap cleanup EXIT HUP INT TERM
sys_mode=$(cat "$sys/parameters/mode")
sys_iterations=$(cat "$sys/parameters/iterations")
sys_nonce=$(cat "$sys/parameters/run_nonce")
[ "$sys_mode" = check ] && [ "$sys_iterations" = "$iterations" ] && [ "$sys_nonce" = "$nonce" ]
cat "$debug/result" >"$logdir/raw-report.json"
rmmod lifecycle_bench
owned=0
absent
negative() {
 name=$1 suffix=$2 parameter=$3
 absent
 rc=0
 insmod "$module" mode=check iterations="$iterations" run_nonce="${prefix}${suffix}" "$parameter" >"$logdir/$name-load" 2>&1 || rc=$?
 cat "$logdir/$name-load"
 if [ "$rc" = 0 ]; then
  # Unexpected successful negative: retain failure and only clean our own nonce.
  if [ "$(cat "$sys/parameters/run_nonce")" = "${prefix}${suffix}" ]; then rmmod lifecycle_bench || :; fi
  echo "FAIL negative unexpectedly loaded: $name" >&2
  return 1
 fi
 absent || { echo "FAIL negative leaked producer: $name" >&2; return 1; }
 echo "XDEV_EXT_FENCE_CASE=$name nonce=${prefix}${suffix} mode=check iterations=$iterations load_rc=$rc unload_rc=not-loaded module=absent debugfs=absent" >"$logdir/$name-receipt"
}
negative alloc1 1 fail_alloc_at=1
negative alloc2 2 fail_alloc_at=2
negative callback1 3 fail_callback_at=1
negative callback2 4 fail_callback_at=2
echo "XDEV_EXT_FENCE_BEGIN nonce=$nonce mode=check iterations=$iterations sysfs_nonce=$sys_nonce sysfs_mode=$sys_mode sysfs_iterations=$sys_iterations"
echo XDEV_EXT_FENCE_JSON_BEGIN
cat "$logdir/raw-report.json"
echo XDEV_EXT_FENCE_JSON_END
echo "XDEV_EXT_FENCE_CASE=check nonce=$nonce mode=check iterations=$iterations load_rc=0 unload_rc=0 module=absent debugfs=absent"
for name in alloc1 alloc2 callback1 callback2; do cat "$logdir/$name-receipt"; done
echo 'XDEV_EXT_FENCE_DONE=5/5 performance_claim=none'
