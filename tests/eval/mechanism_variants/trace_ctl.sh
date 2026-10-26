#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Real tracefs instance lifecycle for guest_run.sh; never creates event rows.
set -eu
[ "$#" = 3 ] || { echo 'usage: trace_ctl.sh begin|end NAME CAPTURE_DIR' >&2; exit 2; }
[ "${E2_PRIVATE_GUEST:-}" = yes ] || { echo 'explicit private guest is required' >&2; exit 2; }
action=$1
name=$2
out=$3
case "$name" in reverse|gray|outside_window|reserved_cdw2) ;; *) exit 2;; esac
tracefs=${E2_TRACEFS_ROOT:-/sys/kernel/tracing}
state=$out/.$name.trace-instance
case "$action" in
begin)
    [ -d "$out" ] && [ ! -e "$state" ]
    test -r "$tracefs/events/xdev_ext/native_event/format"
    test -d "$tracefs/instances"
    instance=$tracefs/instances/e2-$name-$$
    mkdir "$instance"
    # Keep the owned instance path even if a later setup step fails, so the
    # integrator can preserve diagnostics and remove this exact instance.
    printf '%s\n' "$instance" > "$state"
    echo 0 > "$instance/tracing_on"
    # 8,806 records * 256 bytes fits even if all records land on one CPU.
    # Keep all mapping/registration rows: this is a bounded 4 MiB per CPU.
    echo 4096 > "$instance/buffer_size_kb"
    echo nop > "$instance/current_tracer"
    echo mono > "$instance/trace_clock"
    : > "$instance/trace"
    echo 1 > "$instance/events/xdev_ext/native_event/enable"
    for control in buffer_size_kb current_tracer trace_clock; do
        printf '%s=' "$control"
        cat "$instance/$control"
    done > "$out/$name-trace-config.txt"
    cat "$instance/events/xdev_ext/native_event/format" > "$out/$name-event-format.txt"
    echo 1 > "$instance/tracing_on"
    printf 'E2_BEGIN_%s\n' "$name" > "$instance/trace_marker"
    ;;
end)
    test -s "$state"
    instance=$(cat "$state")
    case "$instance" in "$tracefs"/instances/e2-"$name"-*) ;; *) exit 2;; esac
    printf 'E2_END_%s\n' "$name" > "$instance/trace_marker"
    echo 0 > "$instance/tracing_on"
    cat "$instance/trace" > "$out/$name.trace"
    : > "$out/$name-trace-stats.txt"
    for stats in "$instance"/per_cpu/cpu*/stats; do
        printf '%s\n' "$stats" >> "$out/$name-trace-stats.txt"
        cat "$stats" >> "$out/$name-trace-stats.txt"
    done
    echo 0 > "$instance/events/xdev_ext/native_event/enable"
    rmdir "$instance"
    rm "$state"
    # A non-empty trace of only markers is not native evidence.
    grep -q 'native_event:' "$out/$name.trace"
    if grep -Eq '^(overrun|commit overrun|dropped events):[[:space:]]*[1-9]' "$out/$name-trace-stats.txt"; then
        echo 'E2 trace capture lost events' >&2
        exit 1
    fi
    ;;
*) exit 2;;
esac
