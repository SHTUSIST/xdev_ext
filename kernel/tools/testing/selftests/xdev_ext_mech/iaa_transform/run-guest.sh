#!/bin/sh
# Software IAA transforms use real CryptoAPI. DMA provider is explicit CPU simulation.
set -eu
fixture_dir=${1:-/opt/iaa-tests}
provider_module=${2:-/opt/provider-tests/xdev_ext_dma_provider_sim.ko}
cleanup() { rmmod xdev_ext_dma_provider_sim 2>/dev/null || :; }
trap cleanup EXIT INT TERM
[ "$(id -u)" = 0 ] || { echo 'FAIL IAA guest requires root';exit 1; }
[ -r /sys/kernel/btf/vmlinux ] || { echo 'FAIL IAA guest lacks BTF';exit 1; }
grep -aq 'xdev_ext_iaa_mech_ops' /sys/kernel/btf/vmlinux || { echo 'FAIL IAA struct_ops absent';exit 1; }
[ ! -d /sys/module/xdev_ext_dma_provider_sim ] || { echo 'FAIL provider already loaded';exit 1; }
insmod "$provider_module"
for mode in normal delay stale duplicate stop; do
 echo "IAA_CASE case=$mode groups=257 depth=8 software=deflate-generic"
 "$fixture_dir/iaa_runtime" "$fixture_dir/iaa_pair.bpf.o" "$mode"
done
rmmod xdev_ext_dma_provider_sim
[ ! -d /sys/module/xdev_ext_dma_provider_sim ]
echo 'PASS IAA software campaign unloaded provider after complete ownership return'
trap - EXIT INT TERM
