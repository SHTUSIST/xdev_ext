#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Guest only (poll_kvm.sh boots it with nvme.poll_queues=2): stage polling
# over real QEMU NVMe, the DMA selftest provider (CPU memcpy) and AF_XDP on two
# virtio-net devices joined by a QEMU hub. Correctness only, nothing is timed.
# Every case prints a XDEV_EXT_POLL_* marker; the host validator requires them.
set -eu
dir=${1:-/opt/poll}
[ "${XDEV_EXT_POLL_GUEST:-}" = 1 ] || { echo 'FAIL guest only: set XDEV_EXT_POLL_GUEST=1'; exit 1; }
ctl=$dir/xdev_ext_mech_ctl

src= dst= spare=
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	case "$(sed 's/[[:space:]]*$//' "$f")" in
	XDEVPSRC01) src=$c ;;
	XDEVPDST01) dst=$c ;;
	XDEVPSPR01) spare=$c ;;
	esac
done
[ -n "$src" ] && [ -n "$dst" ] && [ -n "$spare" ] || { echo 'FAIL NVMe serials not found'; exit 1; }
echo "XDEV_EXT_POLL_ROLES source=$src destination=$dst spare=$spare"
for c in "$src" "$dst" "$spare"; do
	echo "XDEV_EXT_POLL_IO_POLL controller=$c io_poll=$(cat /sys/block/${c}n1/queue/io_poll)"
done
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || :
for t in /sys/kernel/debug/block/${src}n1/hctx*/type; do
	[ -r "$t" ] && echo "XDEV_EXT_POLL_HCTX $(basename "$(dirname "$t")") type=$(cat "$t")"
done

nvme_e2e() {
	XDEV_EXT_POLL_GUEST=1 "$dir/nvme_poll_e2e" "/dev/${src}n1" "/dev/ng${src#nvme}n1" \
		"/dev/${dst}n1" "/dev/ng${dst#nvme}n1" "/dev/${spare}n1" "/dev/ng${spare#nvme}n1" "$dir" "$1"
}
# 1. NVMe: polled copy, interrupt control, STOP with polled commands in flight.
nvme_e2e main
echo 'XDEV_EXT_POLL_NVME=PASS'

# 2. DMA provider route: the same bit drives a provider ->poll.
insmod "$dir/xdev_ext_dma_provider_sim.ko"
if [ ! -c /dev/xdev_ext_dma_provider_sim ]; then
	minor=$(cut -d: -f2 /sys/class/misc/xdev_ext_dma_provider_sim/dev)
	mknod /dev/xdev_ext_dma_provider_sim c 10 "$minor"
fi
"$dir/dma_poll_runtime" "$dir/dma_provider_pair.bpf.o" poll 257 8
"$dir/dma_poll_runtime" "$dir/dma_provider_pair.bpf.o" plain 257 8
"$dir/dma_poll_runtime" "$dir/dma_provider_pair.bpf.o" stop 64 8
"$dir/dma_poll_runtime" "$dir/dma_provider_pair.bpf.o" refuse-provider 1 1
"$dir/dma_poll_runtime" "$dir/dma_provider_pair.bpf.o" refuse-class 1 1
rmmod xdev_ext_dma_provider_sim
[ ! -d /sys/module/xdev_ext_dma_provider_sim ]
echo 'XDEV_EXT_POLL_DMA=PASS cases=poll,plain,stop,refuse-provider,refuse-class backend=CPU-memcpy'

# 3. AF_XDP: NVMe READ -> AF_XDP TX on eth0, AF_XDP RX -> NVMe WRITE on eth1.
groups=16 depth=16 nlb=$((16 * 16)) src_slba=32768 rx_slba=32768
ip link set lo up
ip link set eth0 up
ip link set eth1 up
$ctl attach --obj "$dir/nxp_mech.bpf.o" --map nxp_afxdp_ops --pin /sys/fs/bpf/poll-afxdp --set nxp_session=270019
$ctl attach --obj "$dir/nxp_mech.bpf.o" --map nxp_nvme_ops --pin /sys/fs/bpf/poll-nvme --set nvme_mode=0
busy_poll_packets() {
	awk '/^TcpExt:/ { if (!n) { for (i = 1; i <= NF; i++) h[i] = $i; n = 1 } else
		for (i = 1; i <= NF; i++) if (h[i] == "BusyPollRxPackets") print $i }' /proc/net/netstat
}
irqs() {
	awk -v pat="$1" '$NF ~ pat { for (i = 2; i <= NF; i++) if ($i ~ /^[0-9]+$/) s += $i; else break }
		END { print s + 0 }' /proc/interrupts
}
defer() {
	for d in eth0 eth1; do
		echo "$1" >"/sys/class/net/$d/napi_defer_hard_irqs"
		echo "$2" >"/sys/class/net/$d/gro_flush_timeout"
	done
}
# The sessions write through NVMe passthrough, beside the page cache: flush
# and drop cached pages around every buffered access.
clear_window() {
	dd if=/dev/zero of="/dev/${dst}n1" bs=512 seek="$rx_slba" count="$nlb" conv=fsync 2>/dev/null
	blockdev --flushbufs "/dev/${dst}n1"
}
same_window() {
	blockdev --flushbufs "/dev/${src}n1"
	blockdev --flushbufs "/dev/${dst}n1"
	dd if="/dev/${src}n1" of=/tmp/a bs=512 skip="$src_slba" count="$nlb" 2>/dev/null
	dd if="/dev/${dst}n1" of=/tmp/b bs=512 skip="$rx_slba" count="$nlb" 2>/dev/null
	cmp /tmp/a /tmp/b
}
nic_pair() {
	label=$1; shift
	rx_ok=0
	$ctl nic-nvme "$@" --ifname eth1 --dst-ng "/dev/ng${dst#nvme}n1" --slba "$rx_slba" --nlb "$nlb" \
		--peer-mac 02:00:00:00:00:01 --local-ip 192.0.2.2 --peer-ip 192.0.2.1 \
		--local-port 12345 --peer-port 54321 --groups "$groups" --depth "$depth" \
		--group-bytes 8192 --timeout-ms 60000 >/tmp/rx.log 2>&1 &
	rx=$!
	for i in $(seq 1 400); do
		if grep -q 'XDEV_EXT_MECH_READY mode=nic-nvme .* xsk=zc' /tmp/rx.log; then rx_ok=1; break; fi
		kill -0 "$rx" 2>/dev/null || break
		sleep 0.05
	done
	if [ "$rx_ok" != 1 ]; then cat /tmp/rx.log; echo "FAIL $label receiver not ready"; return 1; fi
	set +e
	$ctl nvme-nic "$@" --ifname eth0 --src-ng "/dev/ng${src#nvme}n1" --slba "$src_slba" --nlb "$nlb" \
		--peer-mac 02:00:00:00:00:02 --local-ip 192.0.2.1 --peer-ip 192.0.2.2 \
		--local-port 54321 --peer-port 12345 --groups "$groups" --depth "$depth" \
		--group-bytes 8192 --timeout-ms 60000 >/tmp/tx.log 2>&1
	tx_exit=$?
	wait "$rx"
	rx_exit=$?
	set -e
	sed "s/^/# $label rx: /" /tmp/rx.log
	sed "s/^/# $label tx: /" /tmp/tx.log
	[ "$tx_exit" = 0 ] && [ "$rx_exit" = 0 ] || { echo "FAIL $label tx_exit=$tx_exit rx_exit=$rx_exit"; return 1; }
	grep -q 'XDEV_EXT_MECH_READY mode=source .* xsk=zc' /tmp/tx.log || { echo "FAIL $label sender not zero-copy"; return 1; }
}

# Refusals: no NAPI interrupt deferral, or a copy-mode sender with nothing to poll.
defer 0 0
if $ctl nvme-nic --poll --ifname eth0 --src-ng "/dev/ng${src#nvme}n1" --slba "$src_slba" --nlb "$nlb" \
	--peer-mac 02:00:00:00:00:02 --local-ip 192.0.2.1 --peer-ip 192.0.2.2 --local-port 54321 \
	--peer-port 12345 --groups "$groups" --depth "$depth" --group-bytes 8192 --timeout-ms 5000 >/tmp/refuse.log 2>&1; then
	cat /tmp/refuse.log; echo 'FAIL AF_XDP polling accepted without interrupt deferral'; exit 1
fi
grep -q 'Operation not supported' /tmp/refuse.log || { cat /tmp/refuse.log; echo 'FAIL wrong refusal'; exit 1; }
echo 'XDEV_EXT_POLL_NIC_REFUSE=PASS reason=no-napi-deferral create=-EOPNOTSUPP'
defer 2 200000
if $ctl nvme-nic --poll --copy --ifname eth0 --src-ng "/dev/ng${src#nvme}n1" --slba "$src_slba" --nlb "$nlb" \
	--peer-mac 02:00:00:00:00:02 --local-ip 192.0.2.1 --peer-ip 192.0.2.2 --local-port 54321 \
	--peer-port 12345 --groups "$groups" --depth "$depth" --group-bytes 8192 --timeout-ms 5000 >/tmp/refuse.log 2>&1; then
	cat /tmp/refuse.log; echo 'FAIL copy-mode AF_XDP transmit accepted for polling'; exit 1
fi
grep -q 'Operation not supported' /tmp/refuse.log || { cat /tmp/refuse.log; echo 'FAIL wrong copy refusal'; exit 1; }
echo 'XDEV_EXT_POLL_NIC_REFUSE=PASS reason=copy-transmit create=-EOPNOTSUPP'

# Control without the bit: the busy-poll counter must not move.
clear_window
before=$(busy_poll_packets)
nic_pair interrupt
after=$(busy_poll_packets)
same_window || { echo 'FAIL interrupt NIC chain data'; exit 1; }
echo "XDEV_EXT_POLL_NIC_CONTROL busy_poll_rx_packets_delta=$((after - before))"
[ "$((after - before))" = 0 ] || { echo 'FAIL busy polling without the bit'; exit 1; }

# Polled: every stage of both sessions carries the bit.
clear_window
before=$(busy_poll_packets)
nvme_before=$(irqs "^${src}q[1-9]")
nvme_dst_before=$(irqs "^${dst}q[1-9]")
nic_in=$(irqs '^virtio[0-9]+-input')
nic_out=$(irqs '^virtio[0-9]+-output')
nic_pair polled --poll
after=$(busy_poll_packets)
nvme_after=$(irqs "^${src}q[1-9]")
nvme_dst_after=$(irqs "^${dst}q[1-9]")
same_window || { echo 'FAIL polled NIC chain data'; exit 1; }
grep -q '^XDEV_EXT_MECH_POLL stages=2$' /tmp/rx.log && grep -q '^XDEV_EXT_MECH_POLL stages=2$' /tmp/tx.log
echo "XDEV_EXT_POLL_NIC_POLLED busy_poll_rx_packets_delta=$((after - before)) source_nvme_io_irq_delta=$((nvme_after - nvme_before)) destination_nvme_io_irq_delta=$((nvme_dst_after - nvme_dst_before)) virtio_input_irq_delta=$(( $(irqs '^virtio[0-9]+-input') - nic_in )) virtio_output_irq_delta=$(( $(irqs '^virtio[0-9]+-output') - nic_out ))"
[ "$((after - before))" -gt 0 ] || { echo 'FAIL no NAPI work done by the session workers'; exit 1; }
[ "$((nvme_after - nvme_before))" = 0 ] || { echo 'FAIL polled NVMe READ raised I/O-queue interrupts'; exit 1; }
[ "$((nvme_dst_after - nvme_dst_before))" = 0 ] || { echo 'FAIL polled NVMe WRITE raised I/O-queue interrupts'; exit 1; }
$ctl detach --pin /sys/fs/bpf/poll-nvme
$ctl detach --pin /sys/fs/bpf/poll-afxdp
echo 'XDEV_EXT_POLL_NIC=PASS chain=nvme-read,afxdp-tx-zc,afxdp-rx,nvme-write data=identical'

dmesg >/tmp/dmesg.txt
if grep -E 'completion polled|drain bound passed|quarantined|WARNING:|BUG:|Oops' /tmp/dmesg.txt; then
	echo 'FAIL kernel log shows a polling timeout, deferred drain, quarantine or warning'; exit 1
fi
echo 'XDEV_EXT_POLL_DMESG=PASS no_completion_polled_timeout=1 no_deferred_drain=1 no_warning=1'

# 4. Last: reset the spare controller to zero poll queues under a polled session.
lines=$(wc -l </tmp/dmesg.txt)
nvme_e2e reset
echo 'XDEV_EXT_POLL_NVME_RESET=PASS'
dmesg | tail -n +"$((lines + 1))" >/tmp/dmesg-reset.txt
if grep -E 'completion polled|drain bound passed|quarantined|BUG:|Oops' /tmp/dmesg-reset.txt; then
	echo 'FAIL kernel log after the reset shows a polling timeout, deferred drain or quarantine'; exit 1
fi
# nvme-pci reset with fewer poll queues asks for more interrupt groups than
# CPUs; upstream lib/group_cpus.c WARN_ON(nr_present + nr_others < numgrps).
warnings=$(grep -c 'WARNING:' /tmp/dmesg-reset.txt || :)
known=$(grep -c 'WARNING: .* at lib/group_cpus.c:[0-9]* group_cpus_evenly' /tmp/dmesg-reset.txt || :)
[ "$warnings" = "$known" ] || { echo 'FAIL unexpected warning after the reset'; exit 1; }
echo "XDEV_EXT_POLL_DMESG_RESET=PASS no_completion_polled_timeout=1 no_deferred_drain=1 upstream_group_cpus_warnings=$known other_warnings=0"
echo 'XDEV_EXT_POLL_GUEST=PASS'
