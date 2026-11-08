#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Physical Thunderbolt/USB4 host interface (NHI) assigned to an xdev_ext KVM
# guest through VFIO.  Nothing needs to be connected: probing the host router
# runs the control channel (ring setup, doorbells, MSI-X interrupts and
# interrupt throttling of drivers/thunderbolt/nhi.c) on the real controller.
# CYCLES unbind/bind cycles repeat ring teardown and re-initialisation.
#
#   xdev_ext_tb_nhi_guest.sh CYCLES [ENUMERATE [POLL]]
#
# Prints XDEV_EXT_TB_NHI_STATE per pass, XDEV_EXT_TB_NHI_CYCLE per cycle and
# one XDEV_EXT_TB_NHI verdict; raw kernel lines are prefixed XDEV_EXT_TB_NHI_LOG.
# ENUMERATE=1 first reports, read-only, the topology the guest sees
# (XDEV_EXT_TB_NHI_ENUM lines): bus devices, USB4 port links, any XDomain
# and whether it carries the host router's own UUID (a cable between two
# ports of this host), and the host router adapters' registers.
# POLL=N (with ENUMERATE=1) then samples, once per second for N seconds and
# read-only, what could reveal a cable: XDEV_EXT_TB_NHI_POLL lines.
set -u
cycles=$1
enumerate_mode=${2:-0}
poll_seconds=${3:-0}
case $poll_seconds in
''|*[!0-9]*) echo 'XDEV_EXT_TB_NHI=FAIL reason=bad-poll'; exit 0 ;;
esac
sysfs=/sys
# Link training and the XDomain UUID/property exchange finish after the host
# router appears; wait until the topology has not changed for a while.
settle_max=30
settle_stable=6
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

# One line naming every bus device and each USB4 port's link type.
topology() {
	for device in "$sysfs"/bus/thunderbolt/devices/*; do
		[ -e "$device" ] || continue
		printf '%s' "${device##*/}"
		for port in "$device"/usb4_port*; do
			[ -r "$port/link" ] && printf ':%s=%s' "${port##*/}" "$(cat "$port/link" 2>/dev/null)"
		done
		printf ' '
	done
}
# Reads sysfs and debugfs only; never writes authorized, forcepower or any
# other attribute.
enumerate() {
	previous=$(topology)
	stable=0
	waited=0
	while [ "$waited" -lt "$settle_max" ] && [ "$stable" -lt "$settle_stable" ]; do
		sleep 1
		waited=$((waited + 1))
		current=$(topology)
		if [ "$current" = "$previous" ]; then
			stable=$((stable + 1))
		else
			stable=0
			previous=$current
		fi
	done
	echo "XDEV_EXT_TB_NHI_ENUM settle waited=$waited stable=$stable"
	host_uuid=$(cat "$sysfs/bus/thunderbolt/devices/0-0/unique_id" 2>/dev/null)
	routers=0
	xdomains=0
	same=0
	for device in "$sysfs"/bus/thunderbolt/devices/*; do
		[ -e "$device" ] || continue
		type=$(sed -n 's/^DEVTYPE=//p' "$device/uevent" 2>/dev/null)
		line="XDEV_EXT_TB_NHI_ENUM device=${device##*/} type=${type:-unknown}"
		for attribute in security iommu_dma_protection vendor vendor_name device device_name \
			unique_id generation nvm_version rx_speed rx_lanes tx_speed tx_lanes maxhopid; do
			[ -r "$device/$attribute" ] || continue
			line="$line $attribute=$(cat "$device/$attribute" 2>/dev/null | tr ' ' _)"
		done
		case "$type" in
		thunderbolt_device)
			routers=$((routers + 1)) ;;
		thunderbolt_xdomain)
			xdomains=$((xdomains + 1))
			if [ -n "$host_uuid" ] && [ "$(cat "$device/unique_id" 2>/dev/null)" = "$host_uuid" ]; then
				line="$line same_uuid_as_host=yes"
				same=$((same + 1))
			else
				line="$line same_uuid_as_host=no"
			fi ;;
		esac
		echo "$line"
		for port in "$device"/usb4_port*; do
			[ -r "$port/link" ] || continue
			echo "XDEV_EXT_TB_NHI_ENUM port=${device##*/}/${port##*/} link=$(cat "$port/link" 2>/dev/null)"
		done
	done
	debug=$sysfs/kernel/debug
	[ -d "$debug/thunderbolt" ] || mount -t debugfs debugfs "$debug" 2>/dev/null
	for regs in "$debug"/thunderbolt/0-0/port*/regs; do
		[ -r "$regs" ] || continue
		port=${regs%/regs}
		port=${port##*/}
		sed "s|^|XDEV_EXT_TB_NHI_ENUM regs 0-0 $port |" "$regs" 2>/dev/null
	done
	echo "XDEV_EXT_TB_NHI_ENUM summary routers=$routers xdomains=$xdomains same_uuid_xdomains=$same"
}

# One NHI PCI config dword at byte OFFSET, as hex.
config_dword() {
	od -An -tx4 -j "$2" -N 4 "$1/config" 2>/dev/null | tr -d ' '
}
# Reads only, once per second for poll_seconds: the NHI runtime PM state,
# the Intel vendor-specific config dwords that the ICL-family nhi_ops use
# (VS_CAP_9 at 0xc8, bit 31 FW ready; VS_CAP_22 at 0xfc, bit 1 force power),
# the bus devices with their USB4 port links, and the host router's lane
# adapter (cap 0x01) and USB4 port (cap 0x06) capability rows from debugfs.
# The config reads come first because a debugfs read resumes the router.
# A sample whose full adapter dump differs from the previous one is counted.
poll() {
	nhi_path=$sysfs/bus/pci/devices/$nhi
	debug=$sysfs/kernel/debug
	[ -d "$debug/thunderbolt" ] || mount -t debugfs debugfs "$debug" 2>/dev/null
	previous=
	changed=0
	sample=0
	while [ "$sample" -lt "$poll_seconds" ]; do
		sample=$((sample + 1))
		echo "XDEV_EXT_TB_NHI_POLL t=$sample nhi_runtime=$(cat "$nhi_path/power/runtime_status" 2>/dev/null)" \
			"vs_cap_9=0x$(config_dword "$nhi_path" 200) vs_cap_22=0x$(config_dword "$nhi_path" 252)" \
			"topology=$(topology | tr ' ' ',')"
		full=
		for regs in "$debug"/thunderbolt/0-0/port*/regs; do
			[ -r "$regs" ] || continue
			port=${regs%/regs}
			port=${port##*/}
			dump=$(cat "$regs" 2>/dev/null)
			full="$full
$port
$dump"
			printf '%s\n' "$dump" | grep -E '^0x[0-9a-f]+ +[0-9]+ 0x0[16] ' |
				sed "s|^|XDEV_EXT_TB_NHI_POLL t=$sample regs 0-0 $port |"
		done
		if [ "$sample" -gt 1 ] && [ "$full" != "$previous" ]; then
			changed=$((changed + 1))
			echo "XDEV_EXT_TB_NHI_POLL t=$sample adapter_dump_changed=1"
		fi
		previous=$full
		[ "$sample" -lt "$poll_seconds" ] && sleep 1
	done
	echo "XDEV_EXT_TB_NHI_POLL summary samples=$sample changed_samples=$changed"
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
if [ "$enumerate_mode" = 1 ] && [ "$result" = PASS ]; then
	enumerate
	[ "$poll_seconds" -gt 0 ] && poll
fi
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
