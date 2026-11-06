#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Physical Thunderbolt/USB4 host interface (NHI) assigned to an xdev_ext KVM
# guest through VFIO.  Nothing needs to be connected: probing the host router
# runs the control channel (ring setup, doorbells, MSI-X interrupts and
# interrupt throttling of drivers/thunderbolt/nhi.c) on the real controller.
# CYCLES unbind/bind cycles repeat ring teardown and re-initialisation.
#
#   xdev_ext_tb_nhi_guest.sh CYCLES
#
# Prints XDEV_EXT_TB_NHI_STATE per pass, XDEV_EXT_TB_NHI_CYCLE per cycle and
# one XDEV_EXT_TB_NHI verdict; raw kernel lines are prefixed XDEV_EXT_TB_NHI_LOG.
set -u
cycles=$1
nhi=
for device in /sys/bus/pci/devices/*; do
	[ "$(cat "$device/class")" = 0x0c0340 ] || continue
	[ -z "$nhi" ] || { echo 'XDEV_EXT_TB_NHI=FAIL reason=multiple-nhi'; exit 0; }
	nhi=${device##*/}
done
[ -n "$nhi" ] || { echo 'XDEV_EXT_TB_NHI=FAIL reason=no-nhi'; exit 0; }

router=/sys/bus/thunderbolt/devices/0-0
wait_router() {
	for i in $(seq 1 200); do
		[ -r "$router/unique_id" ] && return 0
		sleep 0.1
	done
	return 1
}
state() {
	echo "XDEV_EXT_TB_NHI_STATE pass=$1 nhi=$nhi driver=$(basename "$(readlink /sys/bus/pci/devices/$nhi/driver 2>/dev/null)" 2>/dev/null)" \
		"security=$(cat /sys/bus/thunderbolt/devices/domain0/security 2>/dev/null)" \
		"vendor=$(cat $router/vendor_name 2>/dev/null | tr ' ' _)" \
		"device=$(cat $router/device_name 2>/dev/null | tr ' ' _)" \
		"generation=$(cat $router/generation 2>/dev/null)" \
		"nvm=$(cat $router/nvm_version 2>/dev/null)" \
		"unique_id=$(cat $router/unique_id 2>/dev/null)"
}
errors() {
	dmesg | grep -iE 'thunderbolt.*(timeout|timed out|failed|error|not ready)|nhi.*(timeout|failed)' |
		grep -v 'XDEV_EXT' | sed 's/^/XDEV_EXT_TB_NHI_LOG error: /'
}

result=PASS
if wait_router; then
	state 0
else
	state 0
	echo 'XDEV_EXT_TB_NHI_CYCLE=FAIL cycle=0 reason=no-host-router'
	result=FAIL
fi
first_id=$(cat "$router/unique_id" 2>/dev/null)
cycle=1
while [ "$result" = PASS ] && [ "$cycle" -le "$cycles" ]; do
	reason=
	echo "$nhi" >/sys/bus/pci/drivers/thunderbolt/unbind || reason=unbind
	[ -z "$reason" ] && [ -e /sys/bus/thunderbolt/devices/domain0 ] && reason=domain-left
	[ -z "$reason" ] && { echo "$nhi" >/sys/bus/pci/drivers/thunderbolt/bind || reason=bind; }
	[ -z "$reason" ] && { wait_router || reason=no-host-router; }
	[ -z "$reason" ] && [ "$(cat "$router/unique_id" 2>/dev/null)" != "$first_id" ] && reason=router-identity
	state "$cycle"
	if [ -z "$reason" ]; then
		echo "XDEV_EXT_TB_NHI_CYCLE=PASS cycle=$cycle"
	else
		echo "XDEV_EXT_TB_NHI_CYCLE=FAIL cycle=$cycle reason=$reason"
		result=FAIL
	fi
	cycle=$((cycle + 1))
done
dmesg | grep -iE 'thunderbolt|nhi' | sed 's/^/XDEV_EXT_TB_NHI_LOG dmesg: /'
if [ -n "$(errors)" ]; then
	errors
	result=FAIL
fi
echo "XDEV_EXT_TB_NHI=$result cycles=$cycles"
exit 0
