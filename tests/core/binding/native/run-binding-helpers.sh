#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu
if [ "$#" -ne 4 ]; then
    echo "usage: $0 LOADER OBJECT FRESH_LOG_DIR EXPECTED_KERNEL_RELEASE" >&2
    exit 2
fi
loader=$1
object=$2
logs=$3
expected_release=$4
actual_release=$(uname -r)
if [ "$actual_release" != "$expected_release" ]; then
    echo "kernel release mismatch: actual=$actual_release expected=$expected_release" >&2
    exit 2
fi
if [ ! -r /sys/kernel/btf/vmlinux ]; then
    echo "matching running-kernel BTF is required at /sys/kernel/btf/vmlinux" >&2
    exit 2
fi
if [ -e "$logs" ]; then
    echo "fresh log directory required: $logs" >&2
    exit 2
fi
# The loader creates logs exclusively; preserve its status through stdout capture.
status=0
"$loader" "$object" "$logs" || status=$?
if [ -d "$logs" ]; then
    {
        echo "expected_kernel_release=$expected_release"
        echo "actual_kernel_release=$actual_release"
        echo "loader_exit=$status"
        echo "running_kernel_btf=/sys/kernel/btf/vmlinux"
    } > "$logs/runner.txt"
fi
exit "$status"
