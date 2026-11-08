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
#                        [--nhi BDF] [--build] [--selfloop-echo]
#   lab_vfio_tb_check.sh --summarize <tb-nhi-enum.txt>
#   lab_vfio_tb_check.sh --summarize-echo <tb-nhi-enum.txt> <tb-selfloop-echo.txt>
#
# --source must be a clean checkout of a pushed commit (clone it from GitHub);
# --build builds the guest first (stops before QEMU); later runs reuse it.
# --selfloop-echo: when the guest sees a cable joining the NHI's two ports
# (SELF_LOOP), it loads the XDOMAIN module with self_loop_test=1 and each end
# sends one 128-byte PING and one 4096-byte PONG through the cable; the
# receiving end compares every byte. This moves payload through the NHI rings
# (still no timing). Other topologies print TB_SELFLOOP_ECHO result=NOT_RUN.
# Final line: TB_LOOP_CHECK result=<PEER|SELF_LOOP|NO_LINK|UNKNOWN> ...
# Exit 0 when the check completed (whatever the topology), 2 on usage error,
# 3 when a precondition refused the launch, 4 when the guest run failed,
# 5 when a requested self-loop echo failed.
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

# Echo verdict for --selfloop-echo: runs only on a SELF_LOOP topology.
summarize_echo() {
	local enum=$1 echo_file=$2 topology line
	topology=$(summarize "$enum" | sed -n 's/^TB_LOOP_CHECK result=\([A-Z_]*\).*/\1/p')
	if [ "$topology" != SELF_LOOP ]; then
		echo "TB_SELFLOOP_ECHO result=NOT_RUN topology=${topology:-UNKNOWN}"
		return 0
	fi
	line=$(sed -n 's/^XDEV_EXT_TB_SELFLOOP_ECHO=//p' "$echo_file" 2>/dev/null | tail -n 1)
	case $line in
	PASS*) echo "TB_SELFLOOP_ECHO result=PASS topology=SELF_LOOP${line#PASS}"; return 0 ;;
	FAIL*) echo "TB_SELFLOOP_ECHO result=FAIL topology=SELF_LOOP${line#FAIL}" ;;
	NOT_RUN*) echo "TB_SELFLOOP_ECHO result=FAIL topology=SELF_LOOP reason=echo-not-run" ;;
	*) echo "TB_SELFLOOP_ECHO result=FAIL topology=SELF_LOOP reason=no-echo-report" ;;
	esac
	return 1
}

if [ "${1:-}" = --summarize-echo ]; then
	[ $# -eq 3 ] || { echo "usage: $0 --summarize-echo <tb-nhi-enum.txt> <tb-selfloop-echo.txt>" >&2; exit 2; }
	summarize_echo "$2" "$3"; exit $?
fi
if [ "${1:-}" = --summarize ]; then
	[ $# -eq 2 ] || { echo "usage: $0 --summarize <tb-nhi-enum.txt>" >&2; exit 2; }
	summarize "$2"; exit $?
fi

SRC= SCRATCH=/workspaces/xdev-ext-tb-check/scratch OUT= NHI=0000:00:0d.2 BUILD=0 ECHO=0
while [ $# -gt 0 ]; do
	case $1 in
	--source) SRC=${2:-}; shift 2 ;;
	--scratch) SCRATCH=${2:-}; shift 2 ;;
	--out) OUT=${2:-}; shift 2 ;;
	--nhi) NHI=${2:-}; shift 2 ;;
	--build) BUILD=1; shift ;;
	--selfloop-echo) ECHO=1; shift ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[ -n "$SRC" ] && [ -d "$SRC" ] || { echo "--source <checkout> is required" >&2; exit 2; }
[[ $NHI =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]] || { echo "bad --nhi: $NHI" >&2; exit 2; }
HARNESS=$SRC/tests/integration/session/native/xdev_ext_mech_zc_kvm.sh
[ -r "$HARNESS" ] || { echo "harness not found: $HARNESS" >&2; exit 2; }
[ -n "$OUT" ] || OUT=$(dirname "$SCRATCH")/run-$(date -u +%Y%m%dT%H%M%SZ)
umask 077
mkdir -p "$OUT" "$(dirname "$SCRATCH")"
export XDEV_EXT_QEMU=${XDEV_EXT_QEMU:-/usr/bin/qemu-system-x86_64}
FLAGS=(--scratch "$SCRATCH" --source "$SRC" --debug-locking --tb-nhi "$NHI" --tb-nhi-enumerate --tb-nhi-cycles 0)
[ "$ECHO" = 1 ] && FLAGS+=(--tb-nhi-selfloop-echo)

# An echo run needs a guest build that contains the XDOMAIN module.
if [ "$ECHO" = 1 ] && [ -s "$SCRATCH/build/xdev-ext-artifacts.sha256" ] &&
	! grep -q 'xdev_ext_xdomain.ko$' "$SCRATCH/build/xdev-ext-artifacts.sha256"; then
	BUILD=1
fi
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
cp -a "$SCRATCH/evidence/tb-selfloop-echo.txt" "$OUT/" 2>/dev/null
grep -E 'XDEV_EXT_(TB_NHI|MECH_LOCKDEP|ZC_KVM)' "$OUT/run.log" | tail -n 4
echo_rc=0
if [ "$ECHO" = 1 ]; then
	summarize_echo "$OUT/tb-nhi-enum.txt" "$OUT/tb-selfloop-echo.txt" | tee "$OUT/echo-summary.txt"
	echo_rc=${PIPESTATUS[0]}
fi
summarize "$OUT/tb-nhi-enum.txt" | tee "$OUT/summary.txt"
[ "$rc" -eq 0 ] || { echo "guest run failed (exit $rc), see $OUT/run.log" >&2; exit 4; }
[ "$echo_rc" -eq 0 ] || { echo "self-loop echo failed, see $OUT/tb-selfloop-echo.txt" >&2; exit 5; }
exit 0
