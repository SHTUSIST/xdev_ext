#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Reserve 2 MiB hugepages and mount a hugetlbfs for the DPDK baseline.
#
#   hugepages.sh [--pages N] [--mount DIR] [--dry-run]
#
# Defaults: 512 pages (1 GiB) and /dev/hugepages-tb.  dpdk_tb needs about
# 40 MiB of mbufs plus EAL overhead; 1 GiB is DPDK's usual starting point,
# not a tuned value.  --dry-run prints the commands and changes nothing.
# Run as root on the machine (or guest) that runs dpdk_tb; it never touches
# 1 GiB pages, NIC settings or other mounts.  Pass the mount to EAL with
# --huge-dir DIR.
set -euo pipefail

pages=512
mount_dir=/dev/hugepages-tb
dry=0
usage() { sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
	case "$1" in
	--pages) [ $# -ge 2 ] || { usage >&2; exit 2; }; pages=$2; shift 2 ;;
	--mount) [ $# -ge 2 ] || { usage >&2; exit 2; }; mount_dir=$2; shift 2 ;;
	--dry-run) dry=1; shift ;;
	-h|--help) usage; exit 0 ;;
	*) echo "hugepages.sh: unknown argument $1" >&2; exit 2 ;;
	esac
done
case "$pages" in
''|*[!0-9]*) echo "hugepages.sh: --pages must be a positive integer" >&2; exit 2 ;;
esac
[ "$pages" -gt 0 ] || { echo "hugepages.sh: --pages must be a positive integer" >&2; exit 2; }
case "$mount_dir" in
/*) ;;
*) echo "hugepages.sh: --mount must be absolute" >&2; exit 2 ;;
esac

sysfs=/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
cmds=(
	"echo $pages > $sysfs"
	"mkdir -p $mount_dir"
	"mount -t hugetlbfs -o pagesize=2M nodev $mount_dir"
)
if [ "$dry" = 1 ]; then
	printf '%s\n' "${cmds[@]}"
	exit 0
fi
[ "$(id -u)" = 0 ] || { echo "hugepages.sh: run as root (or use --dry-run)" >&2; exit 1; }
echo "$pages" > "$sysfs"
got=$(cat "$sysfs")
if [ "$got" -lt "$pages" ]; then
	echo "hugepages.sh: only $got of $pages 2 MiB pages could be reserved" >&2
	exit 1
fi
mkdir -p "$mount_dir"
if ! grep -q " $mount_dir hugetlbfs " /proc/mounts; then
	mount -t hugetlbfs -o pagesize=2M nodev "$mount_dir"
fi
echo "hugepages: $got x 2 MiB reserved, hugetlbfs at $mount_dir"
