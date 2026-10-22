#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu
cd "$(dirname "$0")"
if [ "${XDEV_EXT_PEER_GUEST:-}" != 1 ]; then
	echo 'Guest only: harness must set XDEV_EXT_PEER_GUEST=1' >&2
	exit 1
fi
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
	echo 'usage: run-guest.sh SOURCE_BLOCK SOURCE_NG PRIVATE_DEST_BLOCK PRIVATE_DEST_NG [SOURCE_SLBA]' >&2
	exit 2
fi
# Enforce the harness-provisioned disposable third disk, before any writes.
target=$(basename "$3")
source=$(basename "$1")
if [ "$(basename "$2")" != "ng${source#nvme}" ] || \
   [ "$(basename "$4")" != "ng${target#nvme}" ] || [ "$source" = "$target" ]; then
	echo 'Block and generic namespace names must match distinct NVMe controllers' >&2
	exit 1
fi
serial=$(cat "/sys/class/block/$target/device/serial" 2>/dev/null || cat "/sys/class/block/$target/device/../serial")
case "$serial" in *XDEVPEER01*) ;; *) echo 'Destination must have QEMU serial XDEVPEER01' >&2; exit 1 ;; esac
insmod ./xdev_ext_peer_sw.ko guest_only=1
cleanup() { rmmod xdev_ext_peer_sw; }
trap cleanup EXIT HUP INT TERM
if [ ! -c /dev/xdev_ext_peer_sw ]; then
	minor=$(cut -d: -f2 /sys/class/misc/xdev_ext_peer_sw/dev)
	mknod /dev/xdev_ext_peer_sw c 10 "$minor"
fi
./peer_nvme_e2e "$@"
rmmod xdev_ext_peer_sw
trap - EXIT HUP INT TERM
if [ -e /sys/module/xdev_ext_peer_sw ]; then
	echo 'not ok - software provider module still loaded' >&2
	exit 1
fi
echo '# software provider cleanly unloaded after exact reference drain'
