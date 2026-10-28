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
# Each full diagnostic loader releases its class slot before the next object.
# The same class cannot register two struct_ops instances simultaneously.
for role in reference observer; do
    object=xdomain_peer.bpf.o
    [ "$role" = reference ] || object=xdomain_check.bpf.o
    echo "XDOMAIN_OBJECT_BEGIN name=$role-attach expected=ALLOW"
    ./load "./$object" xdomain_peer_ops > "/tmp/$role.log" 2>&1 || { cat "/tmp/$role.log"; fail "$role-attach"; }
    cat "/tmp/$role.log"
    echo "XDOMAIN_OBJECT_END name=$role-attach loader_exit=0"
    pass "$role-attach"
done
# Keep just the reference registered for the following CREATE probes.
pin=/sys/fs/bpf/xdomain-reference
./xdev_ext_mech_ctl attach --obj ./xdomain_peer.bpf.o --map xdomain_peer_ops --pin "$pin" > /tmp/reference-probe.log 2>&1 || { cat /tmp/reference-probe.log; setup reference-probe-attach; }
cat /tmp/reference-probe.log
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
        helper= helper_id=
        case "$name" in
            helper-timer-init-deny) helper=bpf_timer_init; helper_id=169 ;;
            helper-timer-start-deny) helper=bpf_timer_start; helper_id=171 ;;
            helper-tail-call-deny) helper=bpf_tail_call; helper_id=12 ;;
            helper-probe-read-kernel-deny|helper-existing-class-control-deny)
                helper=bpf_probe_read_kernel; helper_id=113 ;;
            helper-probe-read-user-deny) helper=bpf_probe_read_user; helper_id=112 ;;
            helper-ringbuf-output-deny) helper=bpf_ringbuf_output; helper_id=130 ;;
        esac
        if [ -n "$helper" ]; then
            # Require this helper and UAPI ID in their own complete verifier log.
            awk -v wanted="program of this type cannot use helper $helper#$helper_id" '
            /-- BEGIN PROG LOAD LOG --$/ { if (inside) bad=1; inside=1; matched=0; next }
            $0 == "-- END PROG LOAD LOG --" {
                if (!inside) bad=1;
                if (inside && matched) found=1;
                inside=0; matched=0; next
            }
            inside && $0 == wanted { matched=1 }
            END { exit !(found && !inside && !bad) }
            ' "/tmp/$name.log" || setup "$name-wrong-helper-diagnostic"
        elif [ "$name" = xdomain-complete-sleepable-deny ] &&
           grep -Fxq 'attach to unsupported member complete of struct xdev_ext_xdomain_mech_ops' "/tmp/$name.log" &&
           grep -Fq -- '-- BEGIN PROG LOAD LOG --' "/tmp/$name.log" &&
           grep -Fq -- '-- END PROG LOAD LOG --' "/tmp/$name.log"; then
            : # Exact verifier member rejection for this one sleepable probe.
        else
        grep -Eiq 'not allowed|invalid (mem|bpf_context|access|indirect)|unknown func|cannot call|uninitialized|unbounded memory|read-only|readonly|rdonly_mem|write into map forbidden|R[0-9]+.*(invalid|offset|outside)|sleepable.*(not|unsupported|cannot)|not sleepable|helper call is not allowed' "/tmp/$name.log" || setup "$name-no-verifier-diagnostic"
        fi
    fi
    pass "$name"
done < matrix.txt
sleep 1
rmmod xdev_ext_peer_sw || setup provider-unload
rmmod xdev_ext_xdomain || fail module-unload
if lsmod | grep -q '^xdev_ext_xdomain '; then fail module-unload; fi
rmmod thunderbolt || setup thunderbolt-unload
dmesg > /tmp/xdomain-final-dmesg
# Preserve raw dmesg; only the exact healthy KASAN startup line is benign.
if sed 's/\r$//' /tmp/xdomain-final-dmesg |
   grep -Ev '^(\[[[:blank:]]*[[:digit:]]+\.[[:digit:]]+\][[:blank:]]+)?kasan: KernelAddressSanitizer initialized$' |
   grep -Ei 'WARNING:|BUG:|KASAN:|lockdep:|lockdep (warning|failure)|possible circular locking|not ok|# SKIP'; then
    fail module-unload
fi
pass module-unload
