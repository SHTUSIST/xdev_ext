#!/usr/bin/env bash
# Re-runnable Thunderbolt topology check on a host whose NHI is already bound
# to vfio-pci (e.g. lab-vfio, Intel TB4 NHI 0000:00:0d.2). It answers one
# question: does the guest see a peer or a self-loop on the NHI's USB4 ports?
#
# Read-only on the device: one strict-debug guest, no rebind cycles, no
# authorized/forcepower writes, no payload, ordinary guest poweroff. The host
# never binds or unbinds anything; it refuses to start when another QEMU runs,
# when the NHI's IOMMU group is held, or when a group member is not on vfio-pci.
#
# Usage:
#   lab_vfio_tb_check.sh --source <checkout> [--scratch DIR] [--out DIR]
#                        [--nhi BDF] [--build] [--poll SECONDS]
#   lab_vfio_tb_check.sh --summarize <tb-nhi-enum.txt>
#
# --source must be a clean checkout of a pushed commit (clone it from GitHub);
# --build builds the guest first (stops before QEMU); later runs reuse it.
# --poll N samples, read-only, the lane adapter and USB4 port registers and
# the NHI FW-ready/force-power config dwords once per second for N seconds
# after the topology report (kept as tb-nhi-poll.txt).
# Final line: TB_LOOP_CHECK result=<PEER|SELF_LOOP|NO_LINK|UNKNOWN> ...
# Exit 0 when the check completed (whatever the topology), 2 on usage error,
# 3 when a precondition refused the launch, 4 when the guest run failed.
set -u

summarize() {
	local f=$1 routers xdomains same links
	[ -r "$f" ] || { echo "TB_LOOP_CHECK result=UNKNOWN reason=no-report"; return 1; }
	routers=$(sed -n 's/.*XDEV_EXT_TB_NHI_ENUM summary .*routers=\([0-9]*\).*/\1/p' "$f" | tail -n 1)
	xdomains=$(sed -n 's/.*XDEV_EXT_TB_NHI_ENUM summary .* xdomains=\([0-9]*\).*/\1/p' "$f" | tail -n 1)
	same=$(sed -n 's/.*XDEV_EXT_TB_NHI_ENUM summary .*same_uuid_xdomains=\([0-9]*\).*/\1/p' "$f" | tail -n 1)
	links=$(sed -n 's/.*XDEV_EXT_TB_NHI_ENUM port=[^ ]* link=\([^ ]*\).*/\1/p' "$f" | sort | uniq -c | awk '{printf "%s%s:%s", (NR>1?",":""), $2, $1}')
	if [ -z "$routers" ] || [ -z "$xdomains" ] || [ -z "$same" ]; then
		echo "TB_LOOP_CHECK result=UNKNOWN reason=no-summary links=${links:-none}"
		return 1
	fi
	local result=NO_LINK
	if [ "$same" -gt 0 ]; then result=SELF_LOOP
	elif [ "$xdomains" -gt 0 ] || [ "$routers" -gt 1 ]; then result=PEER
	fi
	echo "TB_LOOP_CHECK result=$result routers=$routers xdomains=$xdomains same_uuid_xdomains=$same port_links=${links:-none}"
}

if [ "${1:-}" = --summarize ]; then
	[ $# -eq 2 ] || { echo "usage: $0 --summarize <tb-nhi-enum.txt>" >&2; exit 2; }
	summarize "$2"; exit $?
fi

SRC= SCRATCH=/workspaces/xdev-ext-tb-check/scratch OUT= NHI=0000:00:0d.2 BUILD=0 POLL=0
while [ $# -gt 0 ]; do
	case $1 in
	--source) SRC=${2:-}; shift 2 ;;
	--scratch) SCRATCH=${2:-}; shift 2 ;;
	--out) OUT=${2:-}; shift 2 ;;
	--nhi) NHI=${2:-}; shift 2 ;;
	--build) BUILD=1; shift ;;
	--poll) POLL=${2:-}; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[ -n "$SRC" ] && [ -d "$SRC" ] || { echo "--source <checkout> is required" >&2; exit 2; }
[[ $NHI =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]] || { echo "bad --nhi: $NHI" >&2; exit 2; }
[[ $POLL =~ ^[0-9]{1,3}$ ]] && (( 10#$POLL <= 300 )) || { echo "bad --poll: $POLL (0-300 seconds)" >&2; exit 2; }
HARNESS=$SRC/tests/integration/session/native/xdev_ext_mech_zc_kvm.sh
[ -r "$HARNESS" ] || { echo "harness not found: $HARNESS" >&2; exit 2; }
[ -n "$OUT" ] || OUT=$(dirname "$SCRATCH")/run-$(date -u +%Y%m%dT%H%M%SZ)
umask 077
mkdir -p "$OUT" "$(dirname "$SCRATCH")"
export XDEV_EXT_QEMU=${XDEV_EXT_QEMU:-/usr/bin/qemu-system-x86_64}
FLAGS=(--scratch "$SCRATCH" --source "$SRC" --debug-locking --tb-nhi "$NHI" --tb-nhi-enumerate --tb-nhi-cycles 0)
(( 10#$POLL )) && FLAGS+=(--tb-nhi-poll "$((10#$POLL))")

if [ "$BUILD" = 1 ] || [ ! -s "$SCRATCH/build/xdev-ext-artifacts.sha256" ]; then
	echo "building guest into $SCRATCH (stops before QEMU)"
	XDEV_EXT_QEMU=/nonexistent-build-only-stop bash "$HARNESS" "${FLAGS[@]}" >"$OUT/build.log" 2>&1
	[ -s "$SCRATCH/build/xdev-ext-artifacts.sha256" ] || { echo "build failed, see $OUT/build.log" >&2; exit 4; }
fi

GROUP=$(basename "$(readlink -f "/sys/bus/pci/devices/$NHI/iommu_group")")
state() {
	date -u +%FT%TZ
	for d in /sys/kernel/iommu_groups/"$GROUP"/devices/*; do
		d=$(basename "$d")
		echo "$d driver=$(basename "$(readlink "/sys/bus/pci/devices/$d/driver" 2>/dev/null)" 2>/dev/null) power=$(cat "/sys/bus/pci/devices/$d/power_state" 2>/dev/null)"
	done
}
state >"$OUT/state-before.txt"
fail=
pgrep -a qemu-system >"$OUT/qemu-before.txt" && fail="$fail qemu-running"
fuser "/dev/vfio/$GROUP" >"$OUT/vfio-users-before.txt" 2>&1 && fail="$fail vfio-group-held"
for d in /sys/kernel/iommu_groups/"$GROUP"/devices/*; do
	d=$(basename "$d")
	[ "$(basename "$(readlink "/sys/bus/pci/devices/$d/driver" 2>/dev/null)" 2>/dev/null)" = vfio-pci ] || fail="$fail $d-not-vfio"
done
if [ -n "$fail" ]; then echo "PRECHECK_FAIL$fail" | tee "$OUT/precheck.txt"; exit 3; fi
echo PRECHECK_PASS >"$OUT/precheck.txt"

bash "$HARNESS" "${FLAGS[@]}" --run-only >"$OUT/run.log" 2>&1
rc=$?
echo "$rc" >"$OUT/run.exit"
state >"$OUT/state-after.txt"
cp -a "$SCRATCH/evidence/tb-nhi-enum.txt" "$OUT/" 2>/dev/null
(( 10#$POLL )) && cp -a "$SCRATCH/evidence/tb-nhi-poll.txt" "$OUT/" 2>/dev/null
grep -E 'XDEV_EXT_(TB_NHI|MECH_LOCKDEP|ZC_KVM)' "$OUT/run.log" | tail -n 4
summarize "$OUT/tb-nhi-enum.txt" | tee "$OUT/summary.txt"
[ "$rc" -eq 0 ] || { echo "guest run failed (exit $rc), see $OUT/run.log" >&2; exit 4; }
exit 0
