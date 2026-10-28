#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Actual live-BTF CE ABI positive attach and old-ABI attach rejection.
set -eu
CTL=${CTL:-/opt/xdev_ext/xdev_ext_mech_ctl}
OBJECT_DIR=${OBJECT_DIR:-/opt/xdev_ext/verifier}
LOG_DIR=${LOG_DIR:-$(mktemp -d /tmp/xdev-ext-verifier-abi.XXXXXXXX)}
PIN=/sys/fs/bpf/xdev-ext-verifier-abi-$$
test -x "$CTL"
test -r /sys/kernel/btf/vmlinux
mkdir -p "$LOG_DIR"
cleanup() { "$CTL" detach --pin "$PIN" >/dev/null 2>&1 || :; }
trap cleanup EXIT INT TERM
"$CTL" attach --obj "$OBJECT_DIR/ce_abi_good.bpf.o" --map ce_abi_ops --pin "$PIN" \
 >"$LOG_DIR/ce_abi_good.log" 2>&1
test -e "$PIN"
"$CTL" detach --pin "$PIN" >>"$LOG_DIR/ce_abi_good.log" 2>&1
test ! -e "$PIN"
status=0
"$CTL" attach --obj "$OBJECT_DIR/ce_abi_old.bpf.o" --map ce_abi_ops --pin "$PIN" \
 >"$LOG_DIR/ce_abi_old.log" 2>&1 || status=$?
printf '%s\n' "$status" >"$LOG_DIR/ce_abi_old.exit"
test "$status" != 0
# A relocation or verifier-load failure cannot stand in for ABI admission.
grep -F 'attach ce_abi_ops: Invalid argument' "$LOG_DIR/ce_abi_old.log"
test ! -e "$PIN"
echo 'XDEV_EXT_MECH_CE_ABI=PASS current=accepted old=attach-rejected'
