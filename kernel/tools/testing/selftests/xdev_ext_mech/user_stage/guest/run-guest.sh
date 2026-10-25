#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Guest only (user_kvm.sh boots it): the USER stage over real QEMU NVMe.
# Correctness only, nothing is timed. Prints XDEV_EXT_USER_* markers; the
# host validator requires them and checks both disk images itself.
set -eu
dir=${1:-/opt/user}
[ "${XDEV_EXT_USER_GUEST:-}" = 1 ] || { echo 'FAIL guest only: set XDEV_EXT_USER_GUEST=1'; exit 1; }
src= dst=
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	case "$(sed 's/[[:space:]]*$//' "$f")" in
	XDEVUSRC01) src=$c ;;
	XDEVUDST01) dst=$c ;;
	esac
done
[ -n "$src" ] && [ -n "$dst" ] || { echo 'FAIL NVMe serials not found'; exit 1; }
echo "XDEV_EXT_USER_ROLES source=$src destination=$dst"
XDEV_EXT_USER_GUEST=1 "$dir/user_stage_e2e" "/dev/${src}n1" "/dev/ng${src#nvme}n1" \
	"/dev/${dst}n1" "/dev/ng${dst#nvme}n1" "$dir"
echo 'XDEV_EXT_USER_E2E=PASS'
dmesg >/tmp/dmesg.txt
if grep -E 'quarantined|drain bound passed|WARNING:|BUG:|Oops|KASAN|circular locking|inconsistent lock|blocked for more than' /tmp/dmesg.txt; then
	echo 'FAIL kernel log shows a quarantine, deferred drain, warning or debug report'; exit 1
fi
echo 'XDEV_EXT_USER_DMESG=PASS no_quarantine=1 no_deferred_drain=1 no_warning=1'
echo 'XDEV_EXT_USER_GUEST=PASS'
