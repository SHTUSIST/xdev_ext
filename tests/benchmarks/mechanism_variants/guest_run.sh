#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Execute inside the integrator's private QEMU guest only. No image writes.
# Usage: guest_run.sh BIN_DIR SOURCE_NG TX_IF SINK_IP PEER_MAC CAPTURE_DIR TRACE_CTL
# TRACE_CTL begin NAME OUT / end NAME OUT owns tracefs collection and writes
# OUT/NAME.trace. It must collect real hooks; this runner never creates events.
set -eu
[ "$#" = 7 ] || { echo 'usage: guest_run.sh BIN_DIR SOURCE_NG TX_IF SINK_IP PEER_MAC CAPTURE_DIR TRACE_CTL' >&2; exit 2; }
bin=$1
ng=$2
iface=$3
sink_ip=$4
peer_mac=$5
out=$6
trace_ctl=$7
[ "${E2_PRIVATE_GUEST:-}" = yes ] || { echo 'E2_PRIVATE_GUEST=yes is required for the private test guest' >&2; exit 2; }
[ -c "$ng" ]
[ -e "/sys/class/net/$iface" ]
[ -x "$trace_ctl" ]
[ ! -e "$out" ] || { echo 'capture directory must be new' >&2; exit 2; }
mkdir -m 700 "$out"
ctl=$bin/mv_ctl
pin=/sys/fs/bpf/e2-nvme
netpin=/sys/fs/bpf/e2-net
[ ! -e "$pin" ] && [ ! -e "$netpin" ]
net_attached=0
nvme_attached=0
sink_pid=
cleanup() {
    if [ -n "$sink_pid" ]; then kill "$sink_pid" 2>/dev/null || :; wait "$sink_pid" 2>/dev/null || :; fi
    if [ "$nvme_attached" = 1 ]; then "$ctl" detach --pin "$pin"; fi
    if [ "$net_attached" = 1 ]; then "$ctl" detach --pin "$netpin"; fi
}
trap cleanup EXIT
# Resource specifications used by both sessions; retain this command verbatim.
# Actual callback batch IDs start at 1 in this core, independent of first_seq.
printf '%s\n' "ng=$ng" "iface=$iface" "sink_ip=$sink_ip" "peer_mac=$peer_mac" \
    'window_slba=2048' 'window_nlb=64' 'group_bytes=4096' 'groups=16' 'depth=1' \
    'pool=AF_XDP-zero-copy' 'nvme_direction=read' 'first_seq=1' \
    'expected_callback_request_id_origin=1; must confirm from actual trace' > "$out/setup.txt"
uname -a > "$out/uname.txt"
cat /proc/cmdline > "$out/cmdline.txt"
cat "/sys/class/net/$iface/mtu" > "$out/mtu.txt"
cat "/sys/class/net/$iface/address" > "$out/local_mac.txt"
sha256sum "$bin/nvme_reverse.bpf.o" "$bin/nvme_gray.bpf.o" "$bin/nxp_mech.bpf.o" > "$out/objects.sha256"
E2_POLICY_CAPTURE="$out/net-policy" "$ctl" attach --obj "$bin/nxp_mech.bpf.o" --map nxp_afxdp_ops \
    --set nxp_session=270019 --set key_base=1 --pin "$netpin" > "$out/net-attach.log" 2>&1
net_attached=1
for variant in reverse gray; do
    E2_VERIFIER_LOG="$out/$variant-verifier" "$ctl" attach --obj "$bin/nvme_$variant.bpf.o" --map mv_nvme_ops --pin "$pin" > "$out/$variant-attach.log" 2>&1
    nvme_attached=1
    # Archive actual loaded-program metadata; no hand-written acceptance bool.
    bpftool -j prog show > "$out/$variant-programs.json"
    bpftool -j link show > "$out/$variant-links.json"
    bpftool -j map show > "$out/$variant-maps.json"
    "$bin/mv_sink" "$sink_ip" 12345 "$out/$variant-sink.bin" > "$out/$variant-sink.log" 2>&1 &
    sink_pid=$!
    ready=0
    for i in $(seq 1 200); do
        if grep -Fxq E2_SINK_READY "$out/$variant-sink.log"; then ready=1; break; fi
        kill -0 "$sink_pid" 2>/dev/null || break
        sleep 0.01
    done
    [ "$ready" = 1 ]
    "$trace_ctl" begin "$variant" "$out"
    # This same invocation creates a new session on each A/B iteration. The
    # previous process closes its ring before detach/recreate of the object.
    set +e
    E2_UMEM_CAPTURE="$out/$variant-guards" E2_CREATE_CAPTURE="$out/$variant-create" "$ctl" nvme-nic --src-ng "$ng" --ifname "$iface" --slba 2048 --nlb 64 \
        --peer-mac "$peer_mac" --local-ip 192.0.2.1 --peer-ip "$sink_ip" \
        --local-port 54321 --peer-port 12345 --groups 16 --depth 1 \
        --group-bytes 4096 --timeout-ms 60000 > "$out/$variant-run.log" 2>&1
    run_status=$?
    set -e
    "$trace_ctl" end "$variant" "$out"
    test "$run_status" = 0
    test -s "$out/$variant.trace"
    wait "$sink_pid"
    sink_pid=
    test "$(wc -c < "$out/$variant-sink.bin")" = 65536
    "$ctl" detach --pin "$pin" > "$out/$variant-detach.log" 2>&1
    nvme_attached=0
    echo "E2_VARIANT_EXECUTED=$variant sink_bytes=65536 capture=$out performance_claim=none"
done
# The pre-existing invalid-plan source writes actual scratch which must enter
# the same full class boundary. Nonzero CLI exit alone is not a rejection
# verdict: the independent trace gate must check errno and zero native accepts.
for negative in outside_window reserved_cdw2; do
    if [ "$negative" = outside_window ]; then mode=1; else mode=2; fi
    "$ctl" attach --obj "$bin/nvme_s0.bpf.o" --map nvme_s0_ops --set mode="$mode" --pin "$pin" > "$out/$negative-attach.log" 2>&1
    nvme_attached=1
    "$trace_ctl" begin "$negative" "$out"
    set +e
    E2_CREATE_CAPTURE="$out/$negative-create" "$ctl" nvme-nic --src-ng "$ng" --ifname "$iface" --slba 2048 --nlb 64 \
        --peer-mac "$peer_mac" --local-ip 192.0.2.1 --peer-ip "$sink_ip" \
        --local-port 54321 --peer-port 12345 --groups 1 --depth 1 \
        --group-bytes 4096 --timeout-ms 60000 > "$out/$negative-run.log" 2>&1
    run_status=$?
    set -e
    printf '%s\n' "$run_status" > "$out/$negative-exit.txt"
    "$trace_ctl" end "$negative" "$out"
    test -s "$out/$negative.trace"
    test "$run_status" != 0
    "$ctl" detach --pin "$pin" > "$out/$negative-detach.log" 2>&1
    nvme_attached=0
    echo "E2_NEGATIVE_EXECUTED=$negative verification=raw-class-trace-required"
done
"$ctl" detach --pin "$netpin" > "$out/net-detach.log" 2>&1
net_attached=0
echo 'E2_GUEST_RUNS=CAPTURED validation=independent-oracle-and-trace-gate-required performance_claim=none'
