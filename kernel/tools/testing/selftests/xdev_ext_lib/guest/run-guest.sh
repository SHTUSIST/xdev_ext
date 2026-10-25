#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Inside the KVM guest: run each plan line (lib_validate.py plan) through
# the libxdev_ext driver on eth0 while the independent AF_PACKET receiver
# reassembles the payload from eth1 and writes it to the destination disk.
#   sh run-guest.sh SOURCE_NG DESTINATION_BLOCK
set -u
dir=/opt/xdev_ext_lib
src_ng=$1
dst=$2
ip link set lo up
ip link set eth0 up
ip link set eth1 up
echo 67108864 >/proc/sys/net/core/rmem_max
mac0=$(cat /sys/class/net/eth0/address)
mac1=$(cat /sys/class/net/eth1/address)
echo "XDEV_EXT_LIB_LINKS eth0=$mac0 eth1=$mac1 mtu0=$(cat /sys/class/net/eth0/mtu) mtu1=$(cat /sys/class/net/eth1/mtu)"
while IFS=: read -r name api mode slba nlb groups depth bytes wire sport dport off expect; do
	echo "XDEV_EXT_LIB_PLAN name=$name api=$api mode=$mode slba=$slba nlb=$nlb groups=$groups depth=$depth group_bytes=$bytes wire=$wire expect=$expect"
	rx_exit=none
	rx=
	if [ "$expect" = pass ]; then
		rm -f /tmp/rx.ready
		"$dir/xdev_ext_lib_rx" --ifname eth1 --dst "$dst" --dst-offset "$off" \
			--session "$wire" --groups "$groups" --group-bytes "$bytes" --mtu 1500 \
			--src-mac "$mac0" --dst-mac "$mac1" --src-ip 192.0.2.1 --dst-ip 192.0.2.2 \
			--src-port "$sport" --dst-port "$dport" --timeout-ms 60000 \
			--ready /tmp/rx.ready >"/tmp/rx-$name.log" 2>&1 &
		rx=$!
		i=0
		while [ ! -e /tmp/rx.ready ] && [ "$i" -lt 200 ]; do sleep 0.05; i=$((i + 1)); done
	fi
	copy=
	if [ "$mode" = copy ]; then copy=--copy; fi
	# shellcheck disable=SC2086
	"$dir/xdev_ext_lib_nvme_nic" --api "$api" --obj "$dir/nxp_mech.bpf.o" --ng "$src_ng" \
		--slba "$slba" --nlb "$nlb" --ifname eth0 $copy --peer-mac "$mac1" \
		--local-ip 192.0.2.1 --peer-ip 192.0.2.2 --local-port "$sport" --peer-port "$dport" \
		--wire-session "$wire" --groups "$groups" --depth "$depth" --group-bytes "$bytes" \
		--timeout-ms 60000 >"/tmp/tx-$name.log" 2>&1
	tx_exit=$?
	if [ -n "$rx" ]; then
		wait "$rx"
		rx_exit=$?
	fi
	cat "/tmp/tx-$name.log"
	if [ -f "/tmp/rx-$name.log" ]; then cat "/tmp/rx-$name.log"; fi
	echo "XDEV_EXT_LIB_SCENARIO name=$name tx_exit=$tx_exit rx_exit=$rx_exit"
done <"$dir/plan.txt"
sync
