#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Functional check of dpdk_tb in one QEMU/KVM guest; correctness only.
#
#   vm_check.sh --work DIR --bin BIN [--kernel VMLINUZ] [--sizes SPEC] [--iters N]
#
# BIN is a `build.py --gpu none` build (host-memory stand-in for the GPU).
# The guest boots the given kernel (default: this host's /boot/vmlinuz) with
# an initramfs holding busybox, iproute2, BIN, their shared libraries and
# libxdp's BPF objects.  Inside it two dpdk_tb processes (separate EAL file
# prefixes and cores) talk over a virtual link through net_af_xdp:
#   veth     a veth pair: XDP attaches in native (drv) mode
#   macvlan  two bridge-mode macvlans on a dummy device: no ndo_bpf, so XDP
#            attaches in generic (skb) mode, as on thunderbolt-net
# On each link the client runs --mode pingpong and --mode stream with
# --verify all, so every message is compared byte for byte after its copy.
# Records land in DIR/results; DIR/verdict.json says PASS only if all four
# client runs and their servers exited 0 with the expected message counts.
# VM timings are not performance data.  Needs root and /dev/kvm; touches
# nothing on the host besides DIR and one QEMU process.
set -euo pipefail

work= bin= kernel=/boot/vmlinuz-$(uname -r) sizes=64..4194304 iters=20
while [ $# -gt 0 ]; do
	case "$1" in
	--work) work=$2; shift 2 ;;
	--bin) bin=$2; shift 2 ;;
	--kernel) kernel=$2; shift 2 ;;
	--sizes) sizes=$2; shift 2 ;;
	--iters) iters=$2; shift 2 ;;
	*) echo "vm_check.sh: unknown argument $1" >&2; exit 2 ;;
	esac
done
[ -n "$work" ] && [ -n "$bin" ] || { sed -n '3,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
case "$work" in /*) ;; *) echo "--work must be absolute" >&2; exit 2 ;; esac
[ -x "$bin" ] && [ -r "$kernel" ] || { echo "missing $bin or $kernel" >&2; exit 2; }
mkdir -p -m 0700 "$work"
root=$work/initramfs
rm -rf "$root" "$work/results"
mkdir -p "$root"/{bin,sbin,lib,proc,sys,dev,tmp,run,lib/bpf,lib/modules} "$work/results"

copy_with_libs() {
	local f=$1 dest=$2
	cp -L "$f" "$root/$dest"
	ldd "$f" | awk '/=>/ {print $3} /^\t\/lib|^\t\/usr/ {print $1}' | while read -r lib; do
		[ -n "$lib" ] && [ -e "$lib" ] || continue
		mkdir -p "$root$(dirname "$lib")"
		cp -L "$lib" "$root$lib"
	done
}
cp /usr/bin/busybox "$root/bin/busybox"
for a in sh mount mkdir echo cat sleep poweroff insmod timeout grep sed wc seq true; do
	ln -sf busybox "$root/bin/$a"
done
copy_with_libs "$(command -v ip)" sbin/ip
copy_with_libs "$bin" bin/dpdk_tb
mkdir -p "$root/lib64"
# glibc dlopens libgcc_s for pthread_cancel (EAL cleanup); ldd does not list it
for g in /lib/x86_64-linux-gnu/libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/libgcc_s.so.1; do
	[ -e "$g" ] && { mkdir -p "$root$(dirname "$g")"; cp -L "$g" "$root$g"; }
done
cp -L /lib64/ld-linux-x86-64.so.2 "$root/lib64/" 2>/dev/null || true
for o in /usr/lib/x86_64-linux-gnu/bpf/xsk_def_xdp_prog*.o /usr/local/lib/bpf/xsk_def_xdp_prog*.o \
	 /usr/lib/x86_64-linux-gnu/bpf/xdp-dispatcher.o /usr/local/lib/bpf/xdp-dispatcher.o; do
	[ -e "$o" ] && cp "$o" "$root/lib/bpf/"
done
kver=$(basename "$kernel" | sed 's/^vmlinuz-//')
for m in veth dummy macvlan; do
	src=$(modinfo -k "$kver" -n "$m")
	case "$src" in
	*.zst) zstd -q -d -c "$src" > "$root/lib/modules/$m.ko" ;;
	*.ko) cp "$src" "$root/lib/modules/$m.ko" ;;
	*) echo "module $m not found for $kver" >&2; exit 4 ;;
	esac
done

cat > "$root/init" <<EOF
#!/bin/sh
export PATH=/bin:/sbin LIBXDP_OBJECT_PATH=/lib/bpf
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
mount -t bpf bpf /sys/fs/bpf
mkdir -p /var/run /run /tmp
mkdir -p /dev/hugepages; mount -t hugetlbfs -o pagesize=2M nodev /dev/hugepages
echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
echo "TB_VM hugepages=\$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages) kernel=\$(cat /proc/sys/kernel/osrelease)"
for m in veth dummy macvlan; do insmod /lib/modules/\$m.ko || echo "TB_VM insmod \$m failed"; done
ip link add tba type veth peer name tbb
# this iproute2 build has been seen naming the peer veth0; rename it then
[ -e /sys/class/net/tbb ] || ip link set veth0 name tbb
ip link add tbd type dummy
ip link add link tbd name tbm1 type macvlan mode bridge
ip link add link tbd name tbm2 type macvlan mode bridge
for i in tba tbb tbd tbm1 tbm2; do ip link set \$i up; done
ip -o link | sed 's/^/TB_VM link /'
eal() { echo "--no-pci --no-telemetry --huge-dir /dev/hugepages --file-prefix \$1 -l \$2 --vdev net_af_xdp0,iface=\$3,start_queue=0,queue_count=1"; }
run() { # link a b mode
	tag=\$1-\$4
	timeout 600 dpdk_tb \$(eal srv-\$tag 1 \$3) -- --role server --max-size 4194304 \
		> /tmp/\$tag.server.json 2> /tmp/\$tag.server.err &
	spid=\$!
	sleep 2
	timeout 600 dpdk_tb \$(eal cli-\$tag 2 \$2) -- --role client --mode \$4 --sizes $sizes \
		--iters $iters --warmup 2 --verify all --stream-min-bytes 0 --timeout-ms 5000 \
		> /tmp/\$tag.client.json 2> /tmp/\$tag.client.err
	crc=\$?
	wait \$spid; src=\$?
	echo "TB_VM_EXIT \$tag client=\$crc server=\$src"
	for f in client server; do
		sed "s/^/TB_VM_OUT \$tag \$f /" /tmp/\$tag.\$f.json
		sed "s/^/TB_VM_ERR \$tag \$f /" /tmp/\$tag.\$f.err
	done
}
run veth tba tbb pingpong
run veth tba tbb stream
run macvlan tbm1 tbm2 pingpong
run macvlan tbm1 tbm2 stream
echo TB_VM_DONE
poweroff -f
EOF
chmod +x "$root/init"
(cd "$root" && find . | cpio -o -H newc --quiet | gzip -1) > "$work/initramfs.gz"

log=$work/console.log
timeout 2700 qemu-system-x86_64 -accel kvm -cpu host -smp 4 -m 3072 -name claude194-dpdk-tb \
	-kernel "$kernel" -initrd "$work/initramfs.gz" -nic none -nographic -no-reboot \
	-append "console=ttyS0 panic=-1 quiet" -serial "file:$log" -monitor none \
	-display none > "$work/qemu.out" 2>&1 || true

python3 - "$log" "$work" "$sizes" "$iters" <<'PY'
import json, re, sys
from pathlib import Path
log, work, sizes, iters = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], int(sys.argv[4])
text = log.read_text(errors="replace")
if ".." in sizes:
    a, b = map(int, sizes.split(".."))
    expect = []
    while a <= b:
        expect.append(a); a *= 2
else:
    expect = [int(x) for x in sizes.split(",")]
verdict = {"done": "TB_VM_DONE" in text, "runs": {}, "kernel": None}
m = re.search(r"TB_VM hugepages=(\d+) kernel=(\S+)", text)
if m:
    verdict["hugepages"], verdict["kernel"] = int(m.group(1)), m.group(2)
ok = verdict["done"]
for tag in ("veth-pingpong", "veth-stream", "macvlan-pingpong", "macvlan-stream"):
    e = re.search(r"TB_VM_EXIT %s client=(\d+) server=(\d+)" % tag, text)
    recs = {"client": [], "server": []}
    for side in recs:
        for line in re.findall(r"TB_VM_OUT %s %s (.*)" % (tag, side), text):
            try:
                recs[side].append(json.loads(line))
            except ValueError:
                recs[side].append({"unparsed": line})
        (Path(work) / "results" / ("%s.%s.jsonl" % (tag, side))).write_text(
            "".join(json.dumps(r) + "\n" for r in recs[side]))
    mode = tag.split("-")[1]
    sizes_seen = [r.get("size") for r in recs["client"]]
    per_size = iters + 2
    run = {"client_exit": int(e.group(1)) if e else None,
           "server_exit": int(e.group(2)) if e else None,
           "sizes": sizes_seen,
           "xdp_attach_mode": recs["client"][0].get("xdp_attach_mode") if recs["client"] else None,
           "xsk_zerocopy": recs["client"][0].get("xsk_zerocopy") if recs["client"] else None,
           "client_verified": sum(r.get("verified_messages", 0) for r in recs["client"]),
           "server_messages": recs["server"][0].get("messages") if recs["server"] else None,
           "server_verified": recs["server"][0].get("verified_messages") if recs["server"] else None}
    want = per_size * len(expect)
    good = (run["client_exit"] == 0 and run["server_exit"] == 0 and sizes_seen == expect and
            run["server_messages"] == want and run["server_verified"] == want and
            run["client_verified"] == want)
    run["pass"] = good
    ok = ok and good
    verdict["runs"][tag] = run
verdict["verdict"] = "PASS" if ok else "FAIL"
(Path(work) / "verdict.json").write_text(json.dumps(verdict, indent=1) + "\n")
print(json.dumps(verdict, indent=1))
sys.exit(0 if ok else 1)
PY
