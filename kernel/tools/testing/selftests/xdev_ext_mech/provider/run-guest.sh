#!/bin/sh
# Execute inside a freshly booted KVM guest of the target production kernel.
# Tests CPU memcpy simulation, not physical DMA throughput or hardware support.
set -eu
fixture_dir=${1:-/opt/provider-tests}
ce_module=${2:-/opt/xdev_ext_ce_sim.ko}
provider_module="$fixture_dir/xdev_ext_dma_provider_sim.ko"
case_name=${3:-normal}
case "$case_name" in normal|short|ambiguous) :;; *) echo 'FAIL unknown guest campaign';exit 1;; esac
quarantined=0
cleanup()
{
 [ "$quarantined" = 0 ] || return 0
 rmmod xdev_ext_dma_provider_sim 2>/dev/null || :
 rmmod xdev_ext_ce_sim 2>/dev/null || :
}
trap cleanup EXIT INT TERM
[ "$(id -u)" = 0 ] || { echo 'FAIL guest requires root'; exit 1; }
[ -r /sys/kernel/btf/vmlinux ] || { echo 'FAIL target kernel BTF absent'; exit 1; }
# Core must already expose the fourth struct_ops type before provider insertion.
grep -aq 'xdev_ext_dma_mech_ops' /sys/kernel/btf/vmlinux || {
 echo 'FAIL booted core lacks independent DMA struct_ops type'; exit 1;
}
[ ! -d /sys/module/xdev_ext_dma_provider_sim ] || {
 echo 'FAIL provider was loaded before this dynamic registration test'; exit 1;
}
echo "CORE_READY kernel=$(uname -r) provider=absent"
insmod "$ce_module"
# Load a wholly separate provider only after core is running.
insmod "$provider_module"
if [ "$case_name" != normal ]; then
 # Run this in a dedicated final guest. The core intentionally retains unknown
 # ownership and module pins; preserve it for evidence, then power off the VM.
 quarantined=1
 "$fixture_dir/dma_provider_runtime" "$fixture_dir/dma_provider_pair.bpf.o" "$case_name" 1 1
 echo "PASS quarantine case=$case_name retained=1 forced_unload=0 dedicated_guest_shutdown_required=1"
 trap - EXIT INT TERM
 exit 0
fi
for mode in normal delay stale duplicate stop; do
 echo "PROVIDER_CASE mode=$mode groups=257 depth=8"
 "$fixture_dir/dma_provider_runtime" "$fixture_dir/dma_provider_pair.bpf.o" "$mode" 257 8
done
"$fixture_dir/dma_provider_runtime" "$fixture_dir/dma_provider_pair.bpf.o" reject 1 1
rmmod xdev_ext_dma_provider_sim
[ ! -d /sys/module/xdev_ext_dma_provider_sim ]
echo 'PASS provider unloaded after mappings, frames and owners released'
# Same core and same pair object: unregister/register is not a new class/pair.
insmod "$provider_module"
"$fixture_dir/dma_provider_runtime" "$fixture_dir/dma_provider_pair.bpf.o" normal 257 8
rmmod xdev_ext_dma_provider_sim
echo 'PASS same provider contract reloaded without rebuilding core or pair'
rmmod xdev_ext_ce_sim
trap - EXIT INT TERM
