#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Called after actual serial-based private-NVMe role resolution; E2 only.
set -eu
[ "$#" = 2 ] || exit 2
source_block=$1 source_ng=$2
bin=/opt/xdev_ext/e2
out=/tmp/e2-capture
export E2_PRIVATE_GUEST=yes
export E2_EXPORT_TRANSPORT=virtio
finish_e2() {
    status=$?
    trap - EXIT
    set +e
    if [ -d "$out" ]; then
        cp /tmp/e2-source-window.bin "$out/source-window.bin"
        cat "/sys/block/${source_block##*/}/queue/logical_block_size" > "$out/source-lba-size.txt"
        cp "$bin/nvme_reverse.bpf.o" "$out/reverse.bpf.o"
        cp "$bin/nvme_gray.bpf.o" "$out/gray.bpf.o"
        cp "$bin/nxp_mech.bpf.o" "$out/nxp_mech.bpf.o"
        cp "$bin/nvme_s0.bpf.o" "$out/nvme_s0.bpf.o"
        for file in "$out"/*.umem.before "$out"/*.umem.after; do
            [ ! -f "$file" ] || gzip -1 "$file" || status=1
        done
        sh "$bin/export_artifacts.sh" "$out"
        exported=$?
        [ "$exported" = 0 ] || status=1
    else
        status=1
    fi
    echo "E2_GUEST_CAPTURE_EXIT=$status"
    exit "$status"
}
trap finish_e2 EXIT
[ -b "$source_block" ] && [ -c "$source_ng" ]
# Ordinary UDP receives on the existing peer NIC; native TX stays AF_XDP ZC.
# These settings affect this private guest only, accepting its other local IP.
ip addr add 192.0.2.1/32 dev eth0
ip addr add 192.0.2.2/32 dev eth1
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/eth1/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/eth1/accept_local
dd if="$source_block" of=/tmp/e2-source-window.bin bs=512 skip=2048 count=64
sh "$bin/guest_run.sh" "$bin" "$source_ng" eth0 192.0.2.2 02:00:00:00:00:02 "$out" "$bin/trace_ctl.sh"
echo 'E2_EXECUTION_COMPLETE=PASS scope=guest-correctness performance_claim=none'
