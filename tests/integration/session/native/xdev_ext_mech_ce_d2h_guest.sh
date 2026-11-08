#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Four isolated software diagnostics. No CPU timing or physical DMA claim.
set -eu
ctl=$1
module=$2
program=$3
source_ng=$4
source_block=$5
destination_ng=$6
destination_block=$7
source_slba=$8
destination_slba=$9
delay_us=${10}
timeout_ms=${11}
sysfs=${D2H_SYSFS_ROOT:-/sys/module/xdev_ext_ce_sim}
logdir=${D2H_LOG_DIR:-/tmp/ce-d2h}
rounds=${D2H_POLL_ROUNDS:-200}
insmod_cmd=${D2H_INSMOD:-/bin/insmod}
rmmod_cmd=${D2H_RMMOD:-/bin/rmmod}
mkdir -p "$logdir"

raw_log() {
    /bin/busybox awk -v name="$case_id" -v stream="$1" \
        '{ print "XDEV_EXT_ZC_D2H_RAW case=" name " stream=" stream " " $0 }' "$2"
}
module_log() {
    phase=$1
    mode_read=$(cat "$sysfs/parameters/fail_mode")
    poison_read=$(cat "$sysfs/parameters/poison_after_h2d")
    delay_read=$(cat "$sysfs/parameters/delay_us")
    accepted=$(cat "$sysfs/parameters/accepted")
    completed=$(cat "$sysfs/parameters/completed")
    pending=$(cat "$sysfs/parameters/pending")
    refs=$(cat "$sysfs/refcnt")
    echo "XDEV_EXT_ZC_D2H_MODULE case=$case_id phase=$phase accepted=$accepted completed=$completed pending=$pending refcnt=$refs mode=$mode_read poison=$poison_read delay_us=$delay_read"
    test "$mode_read" = "$mode" && test "$poison_read" = Y && test "$delay_read" = "$delay_us" || return 1
    test "$pending" = 0 && test "$refs" = 0 || return 1
    if [ "$phase" = before ]; then
        test "$accepted" = 0 && test "$completed" = 0 || return 1
    else
        test "$accepted" = 2 && test "$completed" = 2 || return 1
    fi
}
check_cli() {
    # Parse the unchanged CLI records, including exact one-record counts.
    /bin/busybox awk -v chain="$chain" -v bad="$bad" '
      function scan(  i,p) {
        delete f
        for(i=2;i<=NF;i++) { split($i,p,"="); if(p[1] in f || p[2]=="") exit 1; f[p[1]]=p[2] }
      }
      function need(keys,  names,n,k) {
        n=split(keys,names," ");for(k=1;k<=n;k++)if(!(names[k] in f))exit 1
      }
      /^XDEV_EXT_MECH_NOTIFY / {scan();need("mode eventfd_reads stats_reads");n++; if(f["mode"]!="terminal" || f["eventfd_reads"]!=1 || f["stats_reads"]!=1) exit 1}
      /^XDEV_EXT_MECH_STATS / {
        scan();need("state last_err batches_done batches_abort rejects sequestered timeouts inflight native_publish protocol_err submitted completed");s++;v=chain=="a"?"1,1,1,1":"1,1,0,0"
        if(f["state"]!="ACTIVE" || f["last_err"]!=0 || f["batches_done"]!=1 || f["batches_abort"]!=0 || f["rejects"]!=0 || f["sequestered"]!=0 || f["timeouts"]!=0 || f["inflight"]!=0 || f["native_publish"]!=0 || f["protocol_err"]!=0 || f["submitted"]!=v || f["completed"]!=v) exit 1
      }
      /^XDEV_EXT_MECH_CE_WINDOW=/ {
        scan();need("chain written depth error poison reference");w++;ref=chain=="d"?"frames":"none"
        if($1!="XDEV_EXT_MECH_CE_WINDOW=PASS" || f["chain"]!=chain || f["written"]!=1 || f["depth"]!=1 || f["error"]!=0 || f["poison"]!="0xc3" || f["reference"]!=ref) exit 1
      }
      /^XDEV_EXT_MECH_CE_SIM=/ {
        scan();need("chain");c++;v=chain=="d" && bad?"FAIL":"PASS"
        if($1!="XDEV_EXT_MECH_CE_SIM=" v || f["chain"]!=chain) exit 1
      }
      /^XDEV_EXT_MECH_CE_HOST_DATA / {
        scan();need("chain payload_bytes mismatches guard_mismatches checked_bytes");h++; if(chain!="d" || f["chain"]!="d" || f["payload_bytes"]!=8192 || f["mismatches"]!=bad || f["guard_mismatches"]!=0 || f["checked_bytes"]<8192) exit 1
      }
      END {if(n!=1 || s!=1 || w!=1 || c!=1 || h!=(chain=="d")) exit 1}
    ' "$1"
}
for mode in none skip_d2h; do
    for chain in a d; do
        case_id=$chain-$mode
        bad=0
        [ "$mode" = none ] || bad=8192
        echo "XDEV_EXT_ZC_D2H_BEGIN case=$case_id"
        "$insmod_cmd" "$module" fail_mode="$mode" poison_after_h2d=1 delay_us="$delay_us"
        module_log before
        "$ctl" attach --obj "$program" --map ce_plan_ops --pin /sys/fs/bpf/ce-d2h
        if [ "$chain" = a ]; then
            set -- --src-ng "$source_ng" --slba "$source_slba" --nlb 16 \
                --dst-ng "$destination_ng" --dst-slba "$destination_slba" --dst-nlb 16
        else
            set --
        fi
        cli_log=$logdir/$case_id-cli.log
        verify_log=$logdir/$case_id-verify.log
        set +e
        "$ctl" ce-chain --chain "$chain" --ce-dev /dev/xdev_ext_ce_sim --ce-len 8192 \
            --groups 1 --depth 1 --group-bytes 8192 --timeout-ms "$timeout_ms" "$@" >"$cli_log" 2>&1
        cli_exit=$?
        set -e
        raw_log cli "$cli_log"
        verify_exit=-1
        if [ "$chain" = a ]; then
            set +e
            "$ctl" verify-xform --xform none --seg-len 4096 --group-bytes 8192 \
                --src "$source_block" --src-off "$((source_slba*512))" \
                --dst "$destination_block" --dst-off "$((destination_slba*512))" \
                --bytes 8192 >"$verify_log" 2>&1
            verify_exit=$?
            set -e
            raw_log verify "$verify_log"
        fi
        echo "XDEV_EXT_ZC_D2H_EXIT case=$case_id cli=$cli_exit verify=$verify_exit"
        if [ "$chain" = d ] && [ "$mode" = skip_d2h ]; then
            test "$cli_exit" = 1
        else
            test "$cli_exit" = 0
        fi
        check_cli "$cli_log"
        if [ "$chain" = a ]; then
            verdict=PASS
            expected_exit=0
            if [ "$mode" = skip_d2h ]; then verdict=FAIL;expected_exit=1;fi
            test "$verify_exit" = "$expected_exit"
            test "$(cat "$verify_log")" = "XDEV_EXT_MECH_VERIFY_XFORM=$verdict xform=none bytes=8192 mismatches=$bad"
        fi
        "$ctl" detach --pin /sys/fs/bpf/ce-d2h
        for attempt in $(/bin/busybox seq 1 "$rounds"); do
            if [ "$(cat "$sysfs/parameters/pending")" = 0 ] && [ "$(cat "$sysfs/refcnt")" = 0 ];then break;fi
            sleep 0.05
        done
        module_log after
        set +e
        "$rmmod_cmd" xdev_ext_ce_sim
        unload_exit=$?
        set -e
        echo "XDEV_EXT_ZC_D2H_UNLOAD case=$case_id status=$unload_exit"
        test "$unload_exit" = 0
        echo "XDEV_EXT_ZC_D2H_END case=$case_id"
    done
done
echo 'XDEV_EXT_ZC_CE_D2H_DIAGNOSTIC=PASS cases=4 groups=1 depth=1 group_bytes=8192 backend=CPU-memcpy-standin'
