#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Actual GCC-built module lifecycle + BPF verifier, no physical DMA claim.
set -euo pipefail
umask 077
SCRATCH= SOURCE= BUILD= TOOLS=
CC=${CC:-gcc-14} CLANG=${CLANG:-/usr/bin/clang-21} BPFTOOL=${BPFTOOL:-bpftool}
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
while (($#)); do
    case "$1" in
    --scratch) SCRATCH=$2; shift 2;;
    --source) SOURCE=$2; shift 2;;
    --build) BUILD=$2; shift 2;;
    --tools) TOOLS=$2; shift 2;;
    *) echo "unknown option: $1" >&2; exit 2;;
    esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$BUILD" && -n "$TOOLS" ]]
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]]
SCRATCH=$(cd "$SCRATCH" && pwd -P)
SOURCE=$(git -C "$SOURCE" rev-parse --show-toplevel)
REL=kernel/tools/testing/selftests/xdev_ext_mech/xdomain/guest
SRC=$SOURCE/kernel
EV=$SCRATCH/xdomain-evidence OUT=$SCRATCH/xdomain-out ROOT=$SCRATCH/xdomain-initroot
mkdir -p "$EV" "$OUT"
# A failed retry must never retain the previous terminal verdict.
rm -f -- "$EV/result.json"
exec > >(tee "$EV/runner.log") 2>&1
trap 'rc=$?; if (( rc )); then echo "XDOMAIN_SETUP_FAIL runner_exit=$rc"; fi' EXIT
git -C "$SOURCE" diff --quiet
git -C "$SOURCE" diff --cached --quiet
[[ -z $(git -C "$SOURCE" ls-files --others --exclude-standard) ]]
SHA=$(git -C "$SOURCE" rev-parse HEAD)
[[ $(cat "$BUILD/xdev-ext-source.commit") == "$SHA" ]]
sha256sum -c "$BUILD/xdev-ext-xdomain-build.sha256" >"$EV/build-identity-check.log" 2>&1
for symbol in MODULES MODULE_UNLOAD MEMORY_HOTPLUG MEMORY_HOTREMOVE MIGRATION SPARSEMEM_VMEMMAP ZONE_DEVICE PCI_P2PDMA DEBUG_INFO_BTF DEBUG_INFO_BTF_MODULES DEBUG_KERNEL PROVE_LOCKING DEBUG_ATOMIC_SLEEP KASAN KASAN_GENERIC DETECT_HUNG_TASK KUNIT USB4_KUNIT_TEST; do
    grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config"
done
for symbol in USB4 XDEV_EXT_MECH_XDOMAIN; do grep -Fxq "CONFIG_$symbol=m" "$BUILD/.config"; done
release=$(cat "$BUILD/include/config/kernel.release")
MODROOT=$TOOLS/xdomain-modules/lib/modules/$release
[[ -s "$MODROOT/modules.dep" && -s "$BUILD/vmlinux" && -s "$BUILD/Module.symvers" && -s "$TOOLS/peer-guest/xdev_ext_peer_sw.ko" ]]
# Resolve actual module dependency graph with the matching release, without
# loading or changing any host module.
depmod -b "$TOOLS/xdomain-modules" "$release" >"$EV/depmod.log" 2>&1
modprobe --show-depends --dirname "$TOOLS/xdomain-modules" --set-version "$release" xdev_ext_xdomain >"$EV/module-dependencies.txt"
grep -q 'xdev_ext_xdomain.ko' "$EV/module-dependencies.txt"
grep -q 'thunderbolt.ko' "$EV/module-dependencies.txt"
for a in "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux" "$TOOLS/xdev_ext_mech_ctl"; do [[ -s "$a" ]]; done
printf 'source_commit=%s\nbuild_commit=%s\nrelease=%s\nscope=software-module-and-verifier\n' "$SHA" "$SHA" "$release" >"$EV/provenance.txt"
cp "$BUILD/.config" "$EV/kernel.config"
make -C "$SOURCE/$REL" OUT="$OUT/build" KERNEL_SRC="$SRC" VMLINUX_BTF="$BUILD/vmlinux" \
    CLANG="$CLANG" BPFTOOL="$BPFTOOL" HOSTCC="$CC" >"$EV/bpf-build.log" 2>&1
# All modules are staged from modules_install so weak deps and KUnit remain
# genuine. The guest's modprobe reads the same depmod graph as the host check.
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/xdomain,lib/modules}
cp -a "$MODROOT" "$ROOT/lib/modules/"
# Do not archive build/source symlinks pointing out of the initramfs.
rm -f "$ROOT/lib/modules/$release/build" "$ROOT/lib/modules/$release/source"
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo printf poweroff dmesg grep sed mkdir sync sleep lsmod modprobe insmod rmmod uname ls; do ln -s busybox "$ROOT/bin/$app"; done
cp "$OUT/build/"*.bpf.o "$OUT/build/load" "$OUT/build/matrix.txt" \
    "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/nvme_s0.bpf.o" "$TOOLS/peer-guest/xdev_ext_peer_sw.ko" "$SOURCE/$REL/run-guest.sh" "$ROOT/opt/xdomain/"
: >"$EV/libraries.txt"
collect_xdomain_libraries() {
    local binary=$1 destination=$2 elf dependencies
    # Only a successfully inspected ELF with no interpreter is static.
    elf=$(readelf -l -- "$binary") || return 1
    if ! grep -q 'INTERP' <<<"$elf"; then return 0; fi
    dependencies=$(ldd "$binary" 2>&1) || return 1
    if grep -q 'not found' <<<"$dependencies"; then
        printf '%s\n' "$dependencies" >&2
        return 1
    fi
    awk '/=> \/|^[[:space:]]*\// {for(i=1;i<=NF;i++) if($i ~ /^\//) print $i}' <<<"$dependencies" >>"$destination"
}
for binary in "$TOOLS/xdev_ext_mech_ctl" "$OUT/build/load" /bin/busybox; do
    collect_xdomain_libraries "$binary" "$EV/libraries.txt"
done
sort -u -o "$EV/libraries.txt" "$EV/libraries.txt"
while IFS= read -r library; do mkdir -p "$ROOT$(dirname "$library")"; cp -L "$library" "$ROOT$library"; done <"$EV/libraries.txt"
cat >"$ROOT/init" <<'GUEST'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t bpf bpf /sys/fs/bpf
# KUnit at module load can need a console-visible scheduling window.
echo
export XDEV_EXT_XDOMAIN_GUEST=1
sh /opt/xdomain/run-guest.sh /opt/xdomain
rc=$?
echo "XDEV_EXT_XDOMAIN_GUEST_EXIT=$rc"
echo XDOMAIN_DMESG_BEGIN
dmesg
echo XDOMAIN_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"
truncate -s 16M "$OUT/private-nvme.raw"
sha256sum "$BUILD/.config" "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux" "$BUILD/Module.symvers" \
    "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/peer-guest/xdev_ext_peer_sw.ko" "$OUT/build/"*.bpf.o "$OUT/build/load" >"$EV/artifacts.sha256"
find "$MODROOT" -type f -name '*.ko*' -print0 | sort -z | xargs -0 -r sha256sum >>"$EV/artifacts.sha256"
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
    -kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
    -append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr' -nic none
    -drive "file=$OUT/private-nvme.raw,if=none,id=private,format=raw"
    -device nvme,drive=private,serial=XDEVX7ONLY)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qrc=0
timeout "${TIMEOUT_SECONDS:-1500}" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qrc=$?
printf 'qemu_exit=%s\n' "$qrc" >>"$EV/provenance.txt"
# Preserve each complete object verifier diagnostic as its own evidence file.
python3 - "$EV" <<'PY'
import pathlib, re, sys
root=pathlib.Path(sys.argv[1]); log=(root/'guest.log').read_text(errors='replace')
for match in re.finditer(r'^XDOMAIN_OBJECT_BEGIN name=([a-z0-9-]+)[^\n]*\n(.*?)^XDOMAIN_OBJECT_END name=\1[^\n]*$',log,re.M|re.S):
    (root/(match[1]+'.verifier.log')).write_text(match[0]+'\n')
PY
[[ "$qrc" == 0 ]]
grep -Fxq 'XDEV_EXT_XDOMAIN_GUEST_EXIT=0' "$EV/guest.log"
python3 -I "$SOURCE/$REL/verdict.py" "$EV/guest.log" >"$EV/result.json"
echo XDEV_EXT_XDOMAIN_KVM=PASS
