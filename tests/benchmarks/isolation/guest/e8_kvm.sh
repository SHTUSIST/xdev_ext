#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# E8 tenants in a private KVM guest: correctness only, never a performance run.
# The guest writes the payload over a region of one QEMU NVMe namespace, then
# for each N runs N uring_tenant processes restricted (taskset) to the same
# CPUs, each in its own disjoint window, releases them together with one GO
# per tenant, and prints every TENANT_READY/TENANT_RESULT line. The host checks
# them with tenants.py validate-guest. Any NVMe + io_uring kernel works; the
# xdev_ext session arm is not exercised here.
#   bash e8_kvm.sh --scratch DIR --source GIT_ROOT --view VIEW --kernel BZIMAGE \
#        [--counts 1,2,4,8] [--cpus 0,1] [--smp 4]
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' VIEW='' KERNEL='' COUNTS=1,2,4,8 CPUS=0,1 SMP=4
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-600}
REGION=$((64 << 20))
while (($#)); do
	case "$1" in
	--scratch) SCRATCH=$2; shift 2 ;;
	--source) SOURCE=$2; shift 2 ;;
	--view) VIEW=$2; shift 2 ;;
	--kernel) KERNEL=$2; shift 2 ;;
	--counts) COUNTS=$2; shift 2 ;;
	--cpus) CPUS=$2; shift 2 ;;
	--smp) SMP=$2; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$VIEW" && -f "$KERNEL" ]] || { echo 'missing option' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
	echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
TEST=$VIEW/tests/eval/isolation
mkdir -p "$EV" "$OUT"
exec > >(tee -a "$EV/runner.log") 2>&1
SOURCE=$(git -C "$SOURCE" rev-parse --show-toplevel)
[[ -z $(git -C "$SOURCE" status --porcelain --untracked-files=all) ]] || { echo 'FAIL source checkout is dirty' >&2; exit 1; }
HEAD_SHA=$(git -C "$SOURCE" rev-parse --verify 'HEAD^{commit}')
for f in uring_tenant.c tenants.py guest/e8_kvm.sh; do
	cmp -s "$SOURCE/tests/benchmarks/isolation/$f" "$TEST/$f" || { echo "FAIL view differs from source: $f" >&2; exit 1; }
done
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
nice -n 10 make -s -C "$TEST" BUILD="$OUT/build" CC="$CC" "$OUT/build/uring_tenant" >"$EV/tenant-build.log" 2>&1
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; QEMU NVMe; io_uring tenants; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source_commit=%s\nkernel=%s\ncounts=%s\ncpus=%s\nsmp=%s\nregion_bytes=%s\n' \
		"$HEAD_SHA" "$KERNEL" "$COUNTS" "$CPUS" "$SMP" "$REGION"
	"$CC" --version | head -1
	sha256sum "$KERNEL" "$OUT/build/uring_tenant"
} >"$EV/provenance.txt"

rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/e8}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed grep sleep usleep taskset mkfifo sync basename readlink; do
	ln -sf busybox "$ROOT/bin/$app"
done
cp "$OUT/build/uring_tenant" "$ROOT/opt/e8/"
ldd "$OUT/build/uring_tenant" | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' \
	| sort -u >"$EV/guest-libraries.txt"
while IFS= read -r lib; do mkdir -p "$ROOT$(dirname "$lib")"; cp -L "$lib" "$ROOT$lib"; done <"$EV/guest-libraries.txt"
cat >"$ROOT/init" <<GUEST
#!/bin/sh
export PATH=/bin
COUNTS="$(echo "$COUNTS" | tr , ' ')" CPUS=$CPUS REGION=$REGION
GUEST
cat >>"$ROOT/init" <<'GUEST'
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
echo
echo E8_GUEST_BEGIN
echo "E8_GUEST_FACT cpus=$CPUS"
dev=
for f in /sys/class/nvme/nvme*/serial; do
	c=${f%/serial}; c=${c##*/}
	[ "$(sed 's/[[:space:]]*$//' "$f")" = E8SRC00001 ] && dev=/dev/${c}n1
done
if [ -z "$dev" ] || ! /opt/e8/uring_tenant --write-pattern --device "$dev" --region-offset 0 \
		--bytes "$REGION" --seed 7; then
	echo "E8_GUEST_FAIL setup dev=$dev"
else
	for n in $COUNTS; do
		w=$((REGION / n / 4096 * 4096))
		t=0
		while [ $t -lt $n ]; do
			mkfifo /tmp/go.$n.$t
			(taskset -c "$CPUS" /opt/e8/uring_tenant --device "$dev" --region-offset 0 \
				--offset $((t * w)) --bytes $w --io-bytes 4096 --depth 4 --seconds 1 \
				--warmup 0.2 --seed 7 --verify <>/tmp/go.$n.$t >/tmp/out.$n.$t 2>/tmp/err.$n.$t
			 echo $? >/tmp/rc.$n.$t) &
			t=$((t + 1))
		done
		t=0
		while [ $t -lt $n ]; do
			i=0
			while ! grep -q TENANT_READY /tmp/out.$n.$t 2>/dev/null && [ $i -lt 600 ]; do
				usleep 50000; i=$((i + 1))
			done
			t=$((t + 1))
		done
		t=0
		while [ $t -lt $n ]; do echo GO >/tmp/go.$n.$t; t=$((t + 1)); done
		wait
		t=0
		while [ $t -lt $n ]; do
			sed "s/^/E8_GUEST n=$n t=$t /" /tmp/out.$n.$t
			sed "s/^/E8_GUEST_STDERR n=$n t=$t /" /tmp/err.$n.$t
			echo "E8_GUEST n=$n t=$t EXIT $(cat /tmp/rc.$n.$t)"
			t=$((t + 1))
		done
	done
fi
echo E8_GUEST_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"
truncate -s $((128 << 20)) "$OUT/source.raw"
args=(-machine q35,accel=kvm -cpu host -smp "$SMP" -m 2048 -nographic -no-reboot
	-kernel "$KERNEL" -initrd "$OUT/initramfs.cpio.gz" -append 'console=ttyS0 rdinit=/init panic=-1 loglevel=4'
	-nic none -drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=E8SRC00001)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.raw.log" 2>&1 || qemu_status=$?
tr -d '\r' <"$EV/guest.raw.log" >"$EV/guest.log"
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
status=0
python3 -I "$TEST/tenants.py" validate-guest --log "$EV/guest.log" --counts "$COUNTS" --cpus "$CPUS" \
	--result "$EV/result.json" >"$EV/host-validate.txt" || status=$?
grep -m1 '"verdict"' "$EV/result.json" || true
if (( status == 0 && qemu_status == 0 )); then echo PASS >"$EV/verdict.txt"; else echo FAIL >"$EV/verdict.txt"; fi
cat "$EV/verdict.txt"
[[ $(cat "$EV/verdict.txt") == PASS ]]
