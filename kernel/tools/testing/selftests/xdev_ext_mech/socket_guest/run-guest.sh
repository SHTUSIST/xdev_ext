#!/bin/sh
# Place after main-harness NVMe BPF attach and provider/IAA unload, before
# main-harness CE insertion. Sources must come from the exact Git checkout.
set -eu
fixture_dir=${1:-/opt/xdev_ext/socket_guest}
ce_module=${2:-/opt/xdev_ext/xdev_ext_ce_sim.ko}
socket_object=${3:-/opt/xdev_ext/socket_sink.bpf.o}
source_slba=${4:?source SLBA from main-harness image_layout is required}
[ "$(id -u)" = 0 ] || { echo 'FAIL socket guest requires root';exit 1; }
[ ! -d /sys/module/xdev_ext_ce_sim ] || { echo 'FAIL socket CE fixture must start unloaded';exit 1; }
cleanup() { rmmod xdev_ext_ce_sim; }
trap cleanup EXIT INT TERM
insmod "$ce_module" fail_mode=none delay_us=2000
"$fixture_dir/socket_runtime" "$fixture_dir/ce_observe.bpf.o" "$socket_object" /dev/ng0n1 /dev/nvme0n1 "$source_slba"
rmmod xdev_ext_ce_sim
[ ! -d /sys/module/xdev_ext_ce_sim ]
trap - EXIT INT TERM
echo 'PASS socket_guest CE_module_unloaded=1 same_core=1'
