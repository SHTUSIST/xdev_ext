#!/bin/sh
# Run only in a fresh dedicated correctness guest, after root's existing loader
# has loaded the existing CE and DMA sim modules. Never loads/unloads a module.
set -eu
if [ "$#" -ne 3 ]; then
 echo "usage: $0 FIXTURE_DIR SCENARIO NEW_EVIDENCE_DIR" >&2
 exit 2
fi
fixture_dir=$1
scenario=$2
evidence_dir=$3
case "$scenario" in
 independent-normal|independent-ambiguous|dup-blocked|legacy-blocked) :;;
 *) echo "SETUP unknown scenario=$scenario" >&2; exit 2;;
esac
setup()
{
 echo "SETUP $*" >&2
 exit 77
}
[ "$(id -u)" = 0 ] || setup 'dedicated guest requires root'
[ -r /sys/kernel/btf/vmlinux ] || setup 'target kernel BTF absent'
grep -aq 'xdev_ext_dma_mech_ops' /sys/kernel/btf/vmlinux || setup 'DMA struct_ops type absent'
[ -x "$fixture_dir/dma_scope_runtime" ] || setup 'scope runtime absent'
[ -r "$fixture_dir/dma_provider_pair.bpf.o" ] || setup 'existing pair object absent'
[ -c /dev/xdev_ext_dma_provider_sim ] || setup 'existing DMA provider not loaded'
[ -c /dev/xdev_ext_ce_sim ] || setup 'existing CE provider not loaded'
[ ! -e "$evidence_dir" ] || setup 'evidence directory already exists'
# A retained earlier run cannot qualify as a fresh scenario. Root chooses the
# actual scoped or legacy provider build; this script does not change registry.
for module in xdev_ext_dma_provider_sim xdev_ext_ce_sim; do
 [ -r "/sys/module/$module/refcnt" ] || setup "missing $module refcount"
 [ "$(cat "/sys/module/$module/refcnt")" = 0 ] || setup "nonfresh module $module"
done
[ -r /sys/module/xdev_ext_ce_sim/parameters/fail_mode ] || setup 'CE fault control absent'
[ "$(cat /sys/module/xdev_ext_ce_sim/parameters/fail_mode)" = none ] || setup 'CE fault mode must be none'
[ -r /sys/module/xdev_ext_ce_sim/parameters/delay_us ] || setup 'CE delay control absent'
[ "$(cat /sys/module/xdev_ext_ce_sim/parameters/delay_us)" = 0 ] || setup 'CE delay must be zero'
echo "DMA_SCOPE_GUEST kernel=$(uname -r) scenario=$scenario existing_modules=1"
set +e
"$fixture_dir/dma_scope_runtime" "$fixture_dir/dma_provider_pair.bpf.o" "$scenario" "$evidence_dir"
result=$?
set -e
echo "DMA_SCOPE_GUEST_RUNTIME_EXIT=$result"
for module in xdev_ext_dma_provider_sim xdev_ext_ce_sim; do
 if [ -r "/sys/module/$module/refcnt" ]; then
  echo "DMA_SCOPE_FINAL_REFS module=$module refs=$(cat "/sys/module/$module/refcnt")"
 fi
done
echo 'DMA_SCOPE dedicated_guest_shutdown_required=1 forced_unload=0'
exit "$result"
