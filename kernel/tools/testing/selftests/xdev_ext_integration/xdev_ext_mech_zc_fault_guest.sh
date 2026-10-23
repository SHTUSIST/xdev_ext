#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Run only inside the private QEMU initramfs. Values come from the host's
# frozen expectation table. No fixture log is used as an observation.
set -eu
. /opt/xdev_ext/zc.env
. /opt/xdev_ext/fault.env
ctl=/opt/xdev_ext/xdev_ext_mech_ctl
trace=/sys/kernel/tracing
ce_params=/sys/module/xdev_ext_ce_sim/parameters
work=/tmp/fault-observations
mkdir -p "$work"
roles=''
case "$fault_expectation" in
'XDEV_EXT_ZC_FAULT_EXPECT campaign='*) ;;
*) echo 'FAIL missing campaign expectation' >&2; exit 2 ;;
esac
echo "$fault_expectation"
echo "XDEV_EXT_ZC_FAULT_ENV campaign=$fault_campaign groups=$groups depth=$depth"
finish_fault() {
    finish_status=$?
    trap - EXIT
    set +e
    # On a harness error expose the incomplete raw observations, never a PASS.
    if [ "$finish_status" != 0 ]; then
        for fault_log in "$work"/*.log; do
            [ -f "$fault_log" ] && cat "$fault_log"
        done
    fi
    echo "XDEV_EXT_ZC_FAULT_GUEST_EXIT=$finish_status"
    exit "$finish_status"
}
trap finish_fault EXIT

pins() {
    pin_a= pin_r= pin_m=
    while read -r pin_key pin_value pin_rest; do
        case "$pin_key" in
        nr_foll_pin_acquired) pin_a=$pin_value ;;
        nr_foll_pin_released) pin_r=$pin_value ;;
        esac
    done </proc/vmstat
    while read -r pin_key pin_value pin_rest; do
        [ "$pin_key" != Mlocked: ] || pin_m=$pin_value
    done </proc/meminfo
    [ -n "$pin_a" ] && [ -n "$pin_r" ] && [ -n "$pin_m" ]
    echo "XDEV_EXT_ZC_FAULT_PINS phase=$1 acquired=$pin_a released=$pin_r mlocked_kb=$pin_m"
}
ce_config() {
    echo "XDEV_EXT_ZC_FAULT_CE_CONFIG phase=$1 fail_mode=$(cat "$ce_params/fail_mode") delay_us=$(cat "$ce_params/delay_us")"
}
attach_nvme() {
    "$ctl" attach --obj /opt/xdev_ext/nxp_mech.bpf.o --map nxp_nvme_ops \
        --pin /sys/fs/bpf/zc-nvme --set "nvme_mode=$1"
}
spawn() {
    spawn_role=$1
    shift
    # The PID is the executable itself, not a shell wrapping a child process.
    "$@" >"$work/$spawn_role.log" 2>&1 &
    echo "$!" >"$work/$spawn_role.pid"
    roles="$roles $spawn_role"
}
run_logged() {
    run_role=$1
    shift
    set +e
    "$@" >"$work/$run_role.log" 2>&1
    run_status=$?
    set -e
    echo "$run_status" >"$work/$run_role.exit"
    show_log "$run_role"
}
show_log() {
    echo "XDEV_EXT_ZC_FAULT_LOG_BEGIN role=$1 exit=$(cat "$work/$1.exit")"
    cat "$work/$1.log"
    echo "XDEV_EXT_ZC_FAULT_LOG_END role=$1"
}
join_role() {
    set +e
    wait "$(cat "$work/$1.pid")"
    join_status=$?
    set -e
    echo "$join_status" >"$work/$1.exit"
    show_log "$1"
}
session_id() {
    sed -n 's/^XDEV_EXT_MECH_READY .*session=\([0-9][0-9]*\).*/\1/p' "$work/$1.log" | head -n 1
}
ready() {
    ready_count=0
    while [ "$ready_count" -lt 500 ]; do
        [ -z "$(session_id "$1")" ] || return 0
        kill -0 "$(cat "$work/$1.pid")" 2>/dev/null || return 1
        sleep 0.01
        ready_count=$((ready_count + 1))
    done
    return 1
}
stat_field() {
    sed -n "s/^XDEV_EXT_MECH_STATS .* $2=\([^ ]*\).*/\1/p" "$1" | tail -n 1
}
observe_inflight() {
    observed=0
    observed_n=0
    observe_count=0
    observe_session=$(session_id "$1")
    while [ -n "$observe_session" ] && [ "$observe_count" -lt 500 ]; do
        if "$ctl" stats --session "$observe_session" >"$work/$1.observed" 2>&1; then
            observed_n=$(stat_field "$work/$1.observed" inflight)
            [ -n "$observed_n" ] || return 1
            if [ "$observed_n" -gt 0 ]; then observed=1; break; fi
        fi
        kill -0 "$(cat "$work/$1.pid")" 2>/dev/null || break
        sleep 0.001
        observe_count=$((observe_count + 1))
    done
    echo "XDEV_EXT_ZC_FAULT_INFLIGHT_SEEN role=$1 seen=$observed inflight=$observed_n"
}
kill_role() {
    observe_inflight "$1"
    kill -KILL "$(cat "$work/$1.pid")" 2>/dev/null || true
    echo "XDEV_EXT_ZC_FAULT_KILL role=$1 signal=9"
}
settle() {
    settle_role=$1
    settle_session=$(session_id "$settle_role")
    if [ -z "$settle_session" ]; then
        echo "XDEV_EXT_ZC_FAULT_SESSION role=$settle_role session=0 state=NOT_CREATED"
        return
    fi
    settle_count=0
    while [ "$settle_count" -lt 1000 ]; do
        set +e
        "$ctl" stats --session "$settle_session" >"$work/$settle_role.settle" 2>&1
        settle_rc=$?
        set -e
        if [ "$settle_rc" = 3 ] && grep -q 'No such file or directory' "$work/$settle_role.settle"; then
            echo "XDEV_EXT_ZC_FAULT_SESSION role=$settle_role session=$settle_session state=FREED"
            return
        fi
        settle_state=$(stat_field "$work/$settle_role.settle" state)
        settle_inflight=$(stat_field "$work/$settle_role.settle" inflight)
        settle_quarantine=$(stat_field "$work/$settle_role.settle" sequestered)
        if [ "$settle_rc" = 0 ] && [ "$settle_state" = ZOMBIE ] && [ "$settle_inflight" = 0 ]; then
            echo "XDEV_EXT_ZC_FAULT_SESSION role=$settle_role session=$settle_session state=ZOMBIE inflight=$settle_inflight sequestered=$settle_quarantine"
            return
        fi
        sleep 0.01
        settle_count=$((settle_count + 1))
    done
    cat "$work/$settle_role.settle"
    echo "FAIL session did not settle role=$settle_role" >&2
    return 1
}
chain() {
    chain_role=$1 chain_kind=$2 chain_groups=$3 chain_src=$4 chain_dst=$5 chain_va=$6
    set -- "$ctl" ce-chain --chain "$chain_kind" --groups "$chain_groups" --depth "$depth" \
        --ce-dev /dev/xdev_ext_ce_sim --ce-va "$chain_va" --ce-len 65536 \
        --timeout-ms "$cli_timeout_ms"
    if [ "$chain_kind" != d ]; then
        set -- "$@" --src-ng "$source_ng" --slba "$chain_src" --nlb "$((chain_groups * 16))"
    fi
    if [ "$chain_kind" = a ]; then
        set -- "$@" --dst-ng "$destination_ng" --dst-slba "$chain_dst" --dst-nlb "$((chain_groups * 16))"
    elif [ "$chain_kind" = b ]; then
        set -- "$@" --ifname eth0 --local-ip 10.0.0.1 --peer-ip 10.0.0.2 \
            --local-port 4000 --peer-port 4001 --peer-mac 02:00:00:00:00:02
    fi
    spawn "$chain_role" "$@"
}
network() {
    network_rx=$1 network_tx=$2 network_mode=$3
    set -- "$ctl" nic-nvme --ifname eth1 --dst-ng "$destination_ng" \
        --slba "$rx_slba" --nlb "$window_nlb" --groups "$groups" --depth "$depth" \
        --local-ip 10.0.0.2 --peer-ip 10.0.0.1 --local-port 4001 --peer-port 4000 \
        --peer-mac 02:00:00:00:00:01 --timeout-ms "$rx_timeout_ms"
    case "$network_mode" in
    ring-exit-rx|exit-rx|detach-nvme-under-load|netdev-remove-rx)
        set -- "$@" --ce-dev /dev/xdev_ext_ce_sim --ce-va 1048576 --ce-len 65536 ;;
    esac
    case "$network_mode" in
    ring-exit-rx) set -- "$@" --close-inflight ;;
    detach-afxdp-mid-run) set -- "$@" --detach-mid-run /sys/fs/bpf/zc-afxdp ;;
    detach-nvme-under-load) set -- "$@" --detach-mid-run /sys/fs/bpf/zc-nvme ;;
    fq-dup) set -- "$@" --fq-dup ;;
    afxdp-copy) set -- "$@" --copy ;;
    afxdp-drv-copy) set -- "$@" --copy --drv-mode ;;
    esac
    spawn "$network_rx" "$@"
    ready "$network_rx"
    set -- "$ctl" nvme-nic --ifname eth0 --src-ng "$source_ng" \
        --slba "$source_slba" --nlb "$window_nlb" --groups "$groups" --depth "$depth" \
        --local-ip 10.0.0.1 --peer-ip 10.0.0.2 --local-port 4000 --peer-port 4001 \
        --peer-mac 02:00:00:00:00:02 --timeout-ms "$cli_timeout_ms"
    [ "$network_mode" != afxdp-copy ] || set -- "$@" --copy
    spawn "$network_tx" "$@"
}
remove_netdev() {
    remove_dev=$(readlink -f "/sys/class/net/$1/device")
    # These are the guest's virtio devices, never a host network interface.
    [ -n "$remove_dev" ] && [ -e "$remove_dev/driver/unbind" ]
    echo "${remove_dev##*/}" >"$remove_dev/driver/unbind"
    remove_count=0
    while [ -e "/sys/class/net/$1" ] && [ "$remove_count" -lt 500 ]; do
        sleep 0.01
        remove_count=$((remove_count + 1))
    done
    [ ! -e "/sys/class/net/$1" ]
    echo "XDEV_EXT_ZC_FAULT_NETDEV_REMOVED ifname=$1 present=0"
}

pins before
insmod /opt/xdev_ext/xdev_ext_ce_sim.ko window_size=4194304 \
    "fail_mode=$ce_fail_mode" "delay_us=$ce_fault_delay_us"
ce_config campaign
if [ "$fault_campaign" = cross-session-isolation ]; then
    # A class has one registered program. Its positive ABI attach must run
    # before ce_plan_ops owns that slot; the malformed ABI is retried while
    # VICTIM is active below. Replacing VICTIM's mechanism would revoke it.
    sh /opt/xdev_ext/verifier/run_abi.sh >"$work/AGG_VERIFIER_ABI.log" 2>&1
fi
"$ctl" attach --obj /opt/xdev_ext/ce_plan.bpf.o --map ce_plan_ops --pin /sys/fs/bpf/zc-ce
"$ctl" attach --obj /opt/xdev_ext/nxp_mech.bpf.o --map nxp_afxdp_ops \
    --pin /sys/fs/bpf/zc-afxdp --set nxp_session=270019
attach_nvme "$nvme_mode"
echo 0 >"$trace/tracing_on"
echo >"$trace/set_ftrace_filter"
for fn in xsk_kernel_xmit __xsk_rcv xsk_xdev_ext_mech_tx_complete xsk_xdev_ext_mech_rx; do
    grep -Eq "^$fn([[:space:]]|$)" "$trace/available_filter_functions"
    echo "$fn" >>"$trace/set_ftrace_filter"
done
echo function >"$trace/current_tracer"
echo >"$trace/trace"
echo 1 >"$trace/tracing_on"
case "$fault_campaign" in
ring-exit-rx|exit-rx|detach-afxdp-mid-run|detach-nvme-under-load|netdev-remove-rx|fq-dup|afxdp-copy|afxdp-drv-copy)
    network RX TX "$fault_campaign"
    case "$fault_campaign" in
    exit-rx) kill_role RX ;;
    netdev-remove-rx) observe_inflight RX; remove_netdev eth1 ;;
    esac
    join_role RX
    join_role TX
    case "$fault_campaign" in
    detach-afxdp-mid-run) [ ! -e /sys/fs/bpf/zc-afxdp ]; echo 'XDEV_EXT_ZC_FAULT_PIN_GONE pin=zc-afxdp gone=1' ;;
    detach-nvme-under-load) [ ! -e /sys/fs/bpf/zc-nvme ]; echo 'XDEV_EXT_ZC_FAULT_PIN_GONE pin=zc-nvme gone=1' ;;
    esac ;;
exit-source|window-reject|nvme-readonly-dest|nvme-reset-mid-run)
    chain SRC a "$groups" "$source_slba" "$ce_slba" 0
    case "$fault_campaign" in
    exit-source) ready SRC; kill_role SRC ;;
    nvme-reset-mid-run)
        ready SRC
        observe_inflight SRC
        echo 1 >"/sys/class/nvme/$nvme_destination/reset_controller"
        reset_count=0
        while [ "$(cat "/sys/class/nvme/$nvme_destination/state")" != live ] && [ "$reset_count" -lt 1000 ]; do
            sleep 0.01
            reset_count=$((reset_count + 1))
        done
        echo "XDEV_EXT_ZC_FAULT_RESET controller=$nvme_destination state=$(cat "/sys/class/nvme/$nvme_destination/state")" ;;
    esac
    join_role SRC ;;
netdev-remove-tx|ce-presubmit)
    chain SRC b "$groups" "$source_slba" "$ce_slba" 0
    if [ "$fault_campaign" = netdev-remove-tx ]; then
        ready SRC
        observe_inflight SRC
        remove_netdev eth0
    fi
    join_role SRC ;;
ce-ambiguous-multi)
    chain SRC d "$groups" "$source_slba" "$ce_slba" 0
    join_role SRC ;;
concurrent-ce-disjoint|concurrent-ce-overlap)
    chain A a "$groups" "$source_slba" "$ce_slba" 0
    secondary_va=2097152
    [ "$fault_campaign" != concurrent-ce-overlap ] || secondary_va=0
    chain B a "$groups" "$alt_source_slba" "$alt_slba" "$secondary_va"
    both_ready=0
    if ready A && ready B && kill -0 "$(cat "$work/A.pid")" 2>/dev/null && kill -0 "$(cat "$work/B.pid")" 2>/dev/null; then both_ready=1; fi
    echo "XDEV_EXT_ZC_FAULT_CONCURRENT both_ready=$both_ready"
    join_role A
    join_role B ;;
cross-session-isolation)
    chain VICTIM a 512 "$source_slba" "$ce_slba" 0
    ready VICTIM
    chain AGG_CEVA a "$groups" "$source_slba" "$alt_slba" 4194304
    join_role AGG_CEVA
    chain AGG_LBA a "$groups" "$image_sectors" "$alt_slba" 2097152
    join_role AGG_LBA
    run_logged AGG_STATS /opt/xdev_ext/fault_uid "$(session_id VICTIM)"
    run_logged AGG_VERIFIER_NEG sh /opt/xdev_ext/verifier/run.sh /opt/xdev_ext/verifier "$ctl"
    run_logged AGG_VERIFIER_STATE sh /opt/xdev_ext/verifier/run_state.sh /opt/xdev_ext/verifier "$ctl"
    abi_status=0
    "$ctl" attach --obj /opt/xdev_ext/verifier/ce_abi_old.bpf.o --map ce_abi_ops \
        --pin /sys/fs/bpf/fault-bad-abi >"$work/abi-active.log" 2>&1 || abi_status=$?
    [ "$abi_status" != 0 ]
    grep -F 'attach ce_abi_ops: Invalid argument' "$work/abi-active.log"
    [ ! -e /sys/fs/bpf/fault-bad-abi ]
    cat "$work/abi-active.log" >>"$work/AGG_VERIFIER_ABI.log"
    echo 'ABI negative rechecked while victim active' >>"$work/AGG_VERIFIER_ABI.log"
    echo 0 >"$work/AGG_VERIFIER_ABI.exit"
    show_log AGG_VERIFIER_ABI
    network AGG_FQDUP_RX AGG_FQDUP_TX fq-dup
    join_role AGG_FQDUP_RX
    join_role AGG_FQDUP_TX
    victim_alive=0
    kill -0 "$(cat "$work/VICTIM.pid")" 2>/dev/null && victim_alive=1
    echo "XDEV_EXT_ZC_FAULT_VICTIM_ALIVE alive=$victim_alive"
    join_role VICTIM ;;
*) echo 'FAIL unknown fault campaign' >&2; exit 2 ;;
esac
for role in $roles; do
    case "$role" in AGG_CEVA|AGG_LBA) continue ;; esac
    settle "$role"
done
if [ "$fault_after" = 1 ]; then
    echo none >"$ce_params/fail_mode"
    echo 0 >"$ce_params/delay_us"
    ce_config after
    # Existing sessions have settled. Re-register the normal NVMe program if
    # the campaign revoked it or selected a rejecting descriptor mechanism.
    if [ "$nvme_mode" != 0 ] || [ ! -e /sys/fs/bpf/zc-nvme ]; then
        [ ! -e /sys/fs/bpf/zc-nvme ] || "$ctl" detach --pin /sys/fs/bpf/zc-nvme
        attach_nvme 0
    fi
    chain AFTER a "$groups" "$source_slba" "$after_slba" 3145728
    join_role AFTER
    settle AFTER
fi
echo 0 >"$trace/tracing_on"
copy_calls=$(grep -cE ' (xsk_kernel_xmit|__xsk_rcv) <-' "$trace/trace" || true)
zc_calls=$(grep -cE ' (xsk_xdev_ext_mech_tx_complete|xsk_xdev_ext_mech_rx) <-' "$trace/trace" || true)
echo "XDEV_EXT_ZC_FAULT_TRACE copy_calls=$copy_calls zc_calls=$zc_calls"
echo XDEV_EXT_ZC_FAULT_TRACE_RAW_BEGIN
cat "$trace/trace"
echo XDEV_EXT_ZC_FAULT_TRACE_RAW_END
ref_wait=0
while [ "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" != 0 ] && [ "$ref_wait" -lt 100 ]; do
    sleep 0.01
    ref_wait=$((ref_wait + 1))
done
ce_refs=$(cat /sys/module/xdev_ext_ce_sim/refcnt)
ce_settled=0
[ "$ce_refs" != 0 ] || ce_settled=1
echo "XDEV_EXT_ZC_FAULT_CE_SIM_STATS accepted=$(cat "$ce_params/accepted") completed=$(cat "$ce_params/completed") pending=$(cat "$ce_params/pending") peak_pending=$(cat "$ce_params/peak_pending") submit_before_first_complete=$(cat "$ce_params/submit_before_first_complete")"
echo "XDEV_EXT_ZC_FAULT_CE_REFS refcnt=$ce_refs settled=$ce_settled"
if rmmod xdev_ext_ce_sim; then ce_unload=unloaded; else ce_unload=refused; fi
echo "XDEV_EXT_ZC_FAULT_CE_UNLOAD result=$ce_unload"
pins after
echo "XDEV_EXT_ZC_FAULT_CAMPAIGN_DONE campaign=$fault_campaign"
