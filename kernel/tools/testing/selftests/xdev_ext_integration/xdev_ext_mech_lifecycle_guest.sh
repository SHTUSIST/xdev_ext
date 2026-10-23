#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Correctness-only extension for the private ZC guest. Call after the harness
# resolved its own NVMe roles and attached its NVMe/NXP struct_ops programs.
# Arguments identify exclusively guest-owned scratch ranges; no host devices.
set -eu
if [ "$#" != 10 ]; then
 echo "usage: $0 CTL SOURCE_NG SOURCE_BLOCK DEST_NG DEST_BLOCK SOURCE_SLBA DEST_SLBA GROUPS DEPTH CPU_BPF" >&2
 exit 2
fi
ctl=$1 source_ng=$2 source_block=$3 destination_ng=$4 destination_block=$5
source_slba=$6 dest_slba=$7 groups=$8 depth=$9
shift 9
cpu_bpf=$1
bytes=$((groups * 8192))
nlb=$((bytes / 512))
fanout_slba=$dest_slba
rx_slba=$((dest_slba + nlb))
cpu_slba=$((rx_slba + nlb))
cpu_rx_slba=$((cpu_slba + nlb))
logdir=$(mktemp -d /tmp/xdev-ext-lifecycle.XXXXXX)
rx_pid=
cpu_pin=/sys/fs/bpf/xdev-ext-lifecycle-cpu
cleanup() {
 if [ -n "$rx_pid" ]; then kill "$rx_pid" 2>/dev/null || :; wait "$rx_pid" 2>/dev/null || :; fi
 "$ctl" detach --pin "$cpu_pin" >/dev/null 2>&1 || :
}
trap cleanup EXIT HUP INT TERM
start_rx() {
 "$ctl" nic-nvme --ifname eth1 --dst-ng "$destination_ng" --slba "$1" --nlb "$nlb" \
  --peer-mac 02:00:00:00:00:01 --local-ip 192.0.2.2 --peer-ip 192.0.2.1 \
  --local-port 12345 --peer-port 54321 --groups "$groups" --depth "$depth" \
  --group-bytes 8192 --timeout-ms 60000 >"$logdir/rx.log" 2>&1 &
 rx_pid=$!
 ready=0
 for i in $(seq 1 200); do
  if grep -q 'XDEV_EXT_MECH_READY mode=nic-nvme .* xsk=zc' "$logdir/rx.log"; then ready=1; break; fi
  kill -0 "$rx_pid" 2>/dev/null || break
  sleep 0.05
 done
 [ "$ready" = 1 ] || { cat "$logdir/rx.log"; return 1; }
}
finish_rx() {
 wait "$rx_pid" || { cat "$logdir/rx.log"; return 1; }
 rx_pid=
 cat "$logdir/rx.log"
 grep -q 'XDEV_EXT_MECH_NIC_NVME_E2E=PASS' "$logdir/rx.log"
}
verify() {
 "$ctl" verify-xform --xform "$1" --seg-len "$2" --src "$source_block" \
  --src-off "$((source_slba * 512))" --dst "$destination_block" \
  --dst-off "$(($3 * 512))" --bytes "$bytes" --group-bytes 8192
}
start_rx "$rx_slba"
"$ctl" fanout --src-ng "$source_ng" --slba "$source_slba" --nlb "$nlb" \
 --dst-ng "$destination_ng" --dst-slba "$fanout_slba" --dst-nlb "$nlb" \
 --ifname eth0 --peer-mac 02:00:00:00:00:02 --local-ip 192.0.2.1 --peer-ip 192.0.2.2 \
 --local-port 54321 --peer-port 12345 --groups "$groups" --depth "$depth" \
 --group-bytes 8192 --timeout-ms 60000
finish_rx
verify none 1432 "$fanout_slba"
verify none 1432 "$rx_slba"
"$ctl" attach --obj "$cpu_bpf" --map cpu_plan_ops --pin "$cpu_pin"
"$ctl" cpu-chain --xform crc32c-seal --src-ng "$source_ng" --slba "$source_slba" --nlb "$nlb" \
 --dst-ng "$destination_ng" --dst-slba "$cpu_slba" --dst-nlb "$nlb" \
 --groups "$groups" --depth "$depth" --group-bytes 8192 --timeout-ms 60000
# ctl_layout uses MTU 1500 geometry for both IOU and XSK pools.
verify crc32c-seal 1432 "$cpu_slba"
start_rx "$cpu_rx_slba"
"$ctl" cpu-chain --xform crc32c-seal --src-ng "$source_ng" --slba "$source_slba" --nlb "$nlb" \
 --ifname eth0 --peer-mac 02:00:00:00:00:02 --local-ip 192.0.2.1 --peer-ip 192.0.2.2 \
 --local-port 54321 --peer-port 12345 --groups "$groups" --depth "$depth" \
 --group-bytes 8192 --timeout-ms 60000
finish_rx
verify crc32c-seal 1432 "$cpu_rx_slba"
echo XDEV_EXT_MECH_LIFECYCLE_GUEST=PASS
