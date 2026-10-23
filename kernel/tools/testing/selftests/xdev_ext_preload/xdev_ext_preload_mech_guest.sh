#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Run inside the matching private VM, after socket_sink and optional ce_plan
# struct_ops have been attached. Third arg is a disposable file on guest ext4.
set -eu
bin=${1:?binary directory}
logs=${2:?private evidence directory}
file=${3:?disposable ext4 file}
mkdir -p "$logs"
lib="$bin/libio_uring_unified.so"

# A failed application or content check must not leave its redirected evidence
# only in the guest's tmpfs. Publish each existing component once on every exit
# and keep the original failure status for the enclosing lifecycle test.
step=setup
publish_logs() {
	result=$?
	trap - EXIT
	set +e
	for name in compat-udp.log compat-dio-off.log compat-dio-on.log compat-ordinary-fork.log \
		mech-socket-base.log mech-socket-lifecycle.log \
		mech-ce-socket-base.log mech-ce-socket-lifecycle.log \
		mech-socket-threads.log mech-ce-socket-threads.log \
		mech-socket-processes.log mech-ce-socket-processes.log; do
		log="$logs/$name"
		[ -f "$log" ] || continue
		printf 'XDEV_EXT_PRELOAD_LOG_BEGIN name=%s\n' "$name"
		cat "$log"
		publish_result=$?
		if [ "$result" -eq 0 ] && [ "$publish_result" -ne 0 ]; then
			result=$publish_result
			step=publish-log:$name
		fi
		# A crashed workload may leave a partial last line.
		printf '\nXDEV_EXT_PRELOAD_LOG_END name=%s\n' "$name"
	done
	if [ "$result" -ne 0 ]; then
		printf 'XDEV_EXT_PRELOAD_STEP=FAIL name=%s exit=%s\n' "$step" "$result"
	else
		echo 'XDEV_EXT_PRELOAD_GUEST_EXECUTION=PASS requires_host_counter_validation=1'
	fi
	exit "$result"
}
trap publish_logs EXIT

step=compat-udp.log
XDEV_EXT_PRELOAD_SOCKET_ENABLED=1 XDEV_EXT_PRELOAD_SOCKET_MECH=0 \
XDEV_EXT_PRELOAD_REPORT=1 LD_PRELOAD="$lib" \
	"$bin/xdev_ext_preload_socket_smoke" >"$logs/compat-udp.log" 2>&1
grep -q '^XDEV_EXT_TRANSPARENT_SOCKET_PAYLOAD=PASS sends=3 bytes=25$' "$logs/compat-udp.log"
grep -Eq 'XDEV_EXT_PRELOAD_REPORT .*custom_send_count=3 custom_send_bytes=25 custom_send_errors=0$' "$logs/compat-udp.log"

for mode in base lifecycle; do
	step=mech-socket-$mode.log
	env -u XDEV_EXT_PRELOAD_SOCKET_CE_DEVICE -u XDEV_EXT_PRELOAD_SOCKET_CE_ADDR \
	-u XDEV_EXT_PRELOAD_SOCKET_CE_LEN XDEV_EXT_PRELOAD_SOCKET_ENABLED=1 \
	XDEV_EXT_PRELOAD_SOCKET_MECH=1 XDEV_EXT_PRELOAD_REPORT=1 LD_PRELOAD="$lib" \
		"$bin/xdev_ext_preload_mech_workload" "$mode" >"$logs/mech-socket-$mode.log" 2>&1
	if [ -n "${XDEV_EXT_PRELOAD_SOCKET_CE_DEVICE:-}" ]; then
		step=mech-ce-socket-$mode.log
		XDEV_EXT_PRELOAD_SOCKET_ENABLED=1 XDEV_EXT_PRELOAD_SOCKET_MECH=1 \
		XDEV_EXT_PRELOAD_REPORT=1 LD_PRELOAD="$lib" \
			"$bin/xdev_ext_preload_mech_workload" "$mode" >"$logs/mech-ce-socket-$mode.log" 2>&1
	fi
done

for mode in threads processes; do
	if [ "$mode" = threads ]; then threads=4; processes=1; else threads=2; processes=4; fi
	step=mech-socket-$mode.log
	env -u XDEV_EXT_PRELOAD_SOCKET_CE_DEVICE -u XDEV_EXT_PRELOAD_SOCKET_CE_ADDR \
	-u XDEV_EXT_PRELOAD_SOCKET_CE_LEN XDEV_EXT_PRELOAD_SOCKET_ENABLED=1 \
	XDEV_EXT_PRELOAD_SOCKET_MECH=1 XDEV_EXT_PRELOAD_REPORT=1 LD_PRELOAD="$lib" \
		"$bin/xdev_ext_preload_mech_workload" concurrency "$threads" "$processes" 65 \
		>"$logs/mech-socket-$mode.log" 2>&1
	if [ -n "${XDEV_EXT_PRELOAD_SOCKET_CE_DEVICE:-}" ]; then
		step=mech-ce-socket-$mode.log
		XDEV_EXT_PRELOAD_SOCKET_ENABLED=1 XDEV_EXT_PRELOAD_SOCKET_MECH=1 \
		XDEV_EXT_PRELOAD_REPORT=1 LD_PRELOAD="$lib" \
			"$bin/xdev_ext_preload_mech_workload" concurrency "$threads" "$processes" 65 \
			>"$logs/mech-ce-socket-$mode.log" 2>&1
	fi
done

for mode in off on; do
	step=compat-dio-$mode.log
	: > "$file"
	if [ "$mode" = on ]; then enabled=1; else enabled=0; fi
	XDEV_EXT_PRELOAD_ENABLED="$enabled" XDEV_EXT_PRELOAD_SOCKET_ENABLED=0 \
	XDEV_EXT_PRELOAD_PATHS="$file" XDEV_EXT_PRELOAD_FRAME_SIZE=4096 \
	XDEV_EXT_PRELOAD_REPORT=1 LD_PRELOAD="$lib" \
		"$bin/xdev_ext_preload_db_workload" "$file" full >"$logs/compat-dio-$mode.log" 2>&1
	grep '^XDEV_EXT_DB_WORKLOAD_RESULT=PASS ' "$logs/compat-dio-$mode.log" >"$logs/compat-dio-$mode.result"
	[ "$(wc -l < "$logs/compat-dio-$mode.result")" -eq 1 ]
done
step=compat-dio-compare
cmp "$logs/compat-dio-off.result" "$logs/compat-dio-on.result"

step=compat-ordinary-fork.log
ordinary_file="$file.ordinary-fork"
: > "$ordinary_file"
XDEV_EXT_PRELOAD_ENABLED=1 XDEV_EXT_PRELOAD_SOCKET_ENABLED=0 \
XDEV_EXT_PRELOAD_SOCKET_MECH=0 XDEV_EXT_PRELOAD_PATHS="$ordinary_file" \
XDEV_EXT_PRELOAD_FRAME_SIZE=4096 XDEV_EXT_PRELOAD_REPORT=1 LD_PRELOAD="$lib" \
    "$bin/xdev_ext_preload_ordinary_fork_guest" "$ordinary_file" \
    >"$logs/compat-ordinary-fork.log" 2>&1
grep -q '^XDEV_EXT_ORDINARY_FORK=PASS ' "$logs/compat-ordinary-fork.log"
