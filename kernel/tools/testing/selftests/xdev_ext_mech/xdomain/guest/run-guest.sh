#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu
[ "${XDEV_EXT_XDOMAIN_GUEST:-}" = 1 ] || exit 3
dir=${1:-/opt/xdomain}
cd "$dir"
pass() { echo "XDEV_EXT_XDOMAIN_CASE=PASS name=$1"; }
fail() { echo "XDEV_EXT_XDOMAIN_CASE=FAIL name=$1"; exit 1; }
setup() { echo "XDOMAIN_SETUP_FAIL $*"; exit 3; }
modprobe thunderbolt || setup thunderbolt
modprobe xdev_ext_xdomain || setup xdomain
lsmod | grep -q '^thunderbolt ' || setup thunderbolt-presence
lsmod | grep -q '^xdev_ext_xdomain ' || setup xdomain-presence
insmod ./xdev_ext_peer_sw.ko guest_only=1 || setup software-provider
[ -s /sys/kernel/btf/vmlinux ] || setup BTF
pass module-load
# Real registry KUnit rows are prerequisites, not substitute named cases.
dmesg > /tmp/xdomain-kunit.log
for name in active_unregister next_unregister data_lifetime callback_registration reregister return_semantics; do
    grep -Eq "ok [0-9]+ .*tb_test_protocol_${name}([[:space:]]|$)" /tmp/xdomain-kunit.log || setup "KUnit-$name"
done
pin=/sys/fs/bpf/xdomain-reference
./xdev_ext_mech_ctl attach --obj ./xdomain_peer.bpf.o --map xdomain_peer_ops --pin "$pin" > /tmp/reference.log 2>&1 || { cat /tmp/reference.log; fail reference-attach; }
cat /tmp/reference.log
pass reference-attach
./xdev_ext_mech_ctl attach --obj ./nvme_s0.bpf.o --map nvme_s0_ops --pin /sys/fs/bpf/xdomain-nvme > /tmp/nvme.log 2>&1 || { cat /tmp/nvme.log; setup nvme-attach; }
for token in 1 0; do
    expect=-19 name=link-1-enodev
    [ "$token" = 1 ] || { expect=-22; name=link-0-einval; }
    ./xdev_ext_mech_ctl xdomain-probe --link "$token" --dir from --pool-fd-from-sw-provider > /tmp/probe.log 2>&1 || { cat /tmp/probe.log; fail "$name"; }
    cat /tmp/probe.log
    grep -Fxq "XDEV_EXT_XDOMAIN_CREATE errno=$expect" /tmp/probe.log || fail "$name"
    pass "$name"
done
./xdev_ext_mech_ctl detach --pin /sys/fs/bpf/xdomain-nvme || setup nvme-detach
./xdev_ext_mech_ctl detach --pin "$pin" || setup reference-detach
while read -r name expected; do
    rc=0
    echo "XDOMAIN_OBJECT_BEGIN name=$name expected=$expected"
    ./load "./$name.bpf.o" probe_ops > "/tmp/$name.log" 2>&1 || rc=$?
    cat "/tmp/$name.log"
    echo "XDOMAIN_OBJECT_END name=$name loader_exit=$rc"
    if [ "$expected" = ALLOW ]; then
        [ "$rc" = 0 ] || fail "$name"
    else
        [ "$rc" = 1 ] || setup "$name-loader-exit-$rc"
        if grep -Eiq 'not found in kernel BTF|failed to find|failed to open|invalid ELF|relocation.*failed|XDOMAIN_SETUP_FAIL' "/tmp/$name.log"; then setup "$name-prerequisite"; fi
        grep -Eiq 'not allowed|invalid (mem|bpf_context|access|indirect)|unknown func|cannot call|uninitialized|unbounded memory|read-only|readonly|rdonly_mem|write into map forbidden|R[0-9]+.*(invalid|offset|outside)|sleepable.*(not|unsupported|cannot)|not sleepable|helper call is not allowed' "/tmp/$name.log" || setup "$name-no-verifier-diagnostic"
    fi
    pass "$name"
done < matrix.txt
sleep 1
rmmod xdev_ext_peer_sw || setup provider-unload
rmmod xdev_ext_xdomain || fail module-unload
if lsmod | grep -q '^xdev_ext_xdomain '; then fail module-unload; fi
rmmod thunderbolt || setup thunderbolt-unload
dmesg > /tmp/xdomain-final-dmesg
if grep -Ei 'WARNING:|BUG:|KASAN:|lockdep:|lockdep (warning|failure)|possible circular locking|not ok|# SKIP' /tmp/xdomain-final-dmesg; then fail module-unload; fi
pass module-unload
