#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Guest only: UNKNOWN peer DMA outcomes and their release by a proven NVMe
# Controller Reset, on the fd path and on the mechanism-session path. Every
# case runs as its own process; the provider module must unload at the end,
# after every reference drained.
set -eu
cd "$(dirname "$0")"
if [ "${XDEV_EXT_PEER_GUEST:-}" != 1 ]; then
	echo 'Guest only: harness must set XDEV_EXT_PEER_GUEST=1' >&2
	exit 1
fi
if [ "$#" -ne 4 ]; then
	echo 'usage: run-reset-guest.sh SOURCE_CTRL OTHER_CTRL SOURCE_NG SOURCE_DISK' >&2
	exit 2
fi
src=$1 other=$2 ng=$3 disk=$4
if [ "$src" = "$other" ]; then echo 'source and other controller must differ' >&2; exit 1; fi
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
for f in "/sys/kernel/debug/$disk/fault_inject/times" /sys/kernel/debug/fail_io_timeout/times \
	"/sys/block/$disk/io-timeout-fail" /sys/module/nvme_core/parameters/io_timeout \
	"/sys/class/nvme/$src/reset_controller" "/sys/class/nvme/$other/reset_controller"; do
	if [ ! -e "$f" ]; then echo "not ok - kernel interface missing: $f"; exit 1; fi
done
insmod ./xdev_ext_peer_sw.ko guest_only=1
if [ ! -c /dev/xdev_ext_peer_sw ]; then
	minor=$(cut -d: -f2 /sys/class/misc/xdev_ext_peer_sw/dev)
	mknod /dev/xdev_ext_peer_sw c 10 "$minor"
fi
status=0
for c in control error-status timeout-cancel owner-open; do
	./peer_reset_e2e "$c" "$ng" "$src" "$other" "$disk" || status=1
done
./peer_reset_session_e2e session-error-status "$ng" "$src" "$other" "$disk" "$PWD" || status=1
if rmmod xdev_ext_peer_sw; then
	echo 'XDEV_EXT_PEER_RESET_UNLOAD=PASS module=xdev_ext_peer_sw'
else
	echo 'not ok - provider module still held after every case'
	status=1
fi
exit "$status"
