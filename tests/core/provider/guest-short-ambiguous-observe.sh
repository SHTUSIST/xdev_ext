#!/bin/sh
# Run ONLY inside a fresh dedicated software-correctness guest.
# Args: instrumented dma_provider_runtime, existing pair BPF object.
# This intentionally preserves the second runtime's failure exit status.
set -u
runtime=${1:?instrumented runtime required}
object=${2:?existing BPF object required}
trace_root=/sys/kernel/tracing
if [ ! -e "$trace_root/kprobe_events" ]; then
 trace_root=/sys/kernel/debug/tracing
fi
snapshot() {
 for module in xdev_ext_dma_provider_sim xdev_ext_ce_sim; do
  for file in /sys/module/"$module"/refcnt /sys/module/"$module"/parameters/*; do
   if [ -r "$file" ]; then
    printf 'DMA_COMPOSITION_SYSFS %s=' "$file"
    cat "$file"
   fi
  done
 done
}
trace_instance=
probe_defined=0
cleanup() {
 if [ -n "$trace_instance" ]; then
  printf '0\n' > "$trace_instance/events/xdev_dma_comp/submit_ret/enable"
 fi
 if [ "$probe_defined" = 1 ]; then
  printf '%s\n' '-:xdev_dma_comp/submit_ret' >> "$trace_root/kprobe_events"
 fi
 if [ -n "$trace_instance" ]; then rmdir "$trace_instance"; fi
}
trap cleanup EXIT HUP INT TERM
if [ -w "$trace_root/kprobe_events" ] && [ -d "$trace_root/instances" ]; then
 if [ -e "$trace_root/events/xdev_dma_comp/submit_ret" ] ||
    [ -e "$trace_root/instances/xdev-dma-composition" ]; then
  printf '%s\n' 'DMA_COMPOSITION_TRACE=refused-existing-probe-state'
  exit 2
 fi
 # Single quotes preserve the kernel fetcharg; no shell expansion of retval.
 if printf '%s\n' 'r:xdev_dma_comp/submit_ret xdev_ext_dma_submit ret=$retval:s32' >> "$trace_root/kprobe_events"; then
  probe_defined=1
  trace_instance="$trace_root/instances/xdev-dma-composition"
  mkdir "$trace_instance" || exit 2
  printf '2048\n' > "$trace_instance/buffer_size_kb"
  printf 'ret < 0\n' > "$trace_instance/events/xdev_dma_comp/submit_ret/filter"
  printf '1\n' > "$trace_instance/events/xdev_dma_comp/submit_ret/enable"
  printf '%s\n' 'DMA_COMPOSITION_TRACE=kretprobe-enabled'
 else
  printf '%s\n' 'DMA_COMPOSITION_TRACE=unsupported-symbol-or-kretprobe; stats-only'
 fi
else
 printf '%s\n' 'DMA_COMPOSITION_TRACE=unavailable; stats-only'
fi
snapshot
"$runtime" "$object" short 1 1
first_status=$?
printf 'DMA_COMPOSITION_RUNTIME mode=short exit=%s\n' "$first_status"
snapshot
if [ -n "$trace_instance" ]; then
 printf 'after-short-before-ambiguous\n' > "$trace_instance/trace_marker"
fi
"$runtime" "$object" ambiguous 1 1
second_status=$?
printf 'DMA_COMPOSITION_RUNTIME mode=ambiguous exit=%s\n' "$second_status"
snapshot
if [ -n "$trace_instance" ]; then
 printf '0\n' > "$trace_instance/events/xdev_dma_comp/submit_ret/enable"
 printf '%s\n' 'DMA_COMPOSITION_TRACE_BEGIN'
 cat "$trace_instance/trace"
 printf '%s\n' 'DMA_COMPOSITION_TRACE_END'
fi
printf '%s\n' 'DMA_COMPOSITION_DMESG_BEGIN'
dmesg
printf '%s\n' 'DMA_COMPOSITION_DMESG_END'
if [ "$first_status" != 0 ]; then exit "$first_status"; fi
exit "$second_status"
