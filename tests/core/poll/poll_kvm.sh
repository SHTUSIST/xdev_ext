#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused KVM correctness run of stage polling (XDEV_EXT_MECH_STAGE_F_POLL),
# never a performance benchmark: nothing is timed.  It reuses a kernel and
# tools built by xdev_ext_mech_zc_kvm.sh --ce-sim from the same checkout
# (bzImage, xdev_ext_mech_ctl, nvme_s0/nxp_mech BPF, the DMA selftest provider
# and dma_poll_runtime) and builds only guest/nvme_poll_e2e.  All writes stay in
# --scratch: private raw images, initramfs and evidence.  No host module is
# loaded and no host NIC, route or disk is touched; the guest's two virtio-net
# devices meet on a QEMU hub.
#   bash poll_kvm.sh --scratch DIR --source GIT_ROOT --build O_DIR --tools TOOLS_DIR
# --red boots an older kernel (O_DIR of a commit before stage polling) with the
# same guest programs and passes only if the first polled CREATE is refused:
# the guest test's RED baseline.  Only build revision and module-release
# equality are exempt in that mode; source and artifact evidence is required.
set -euo pipefail
umask 077
SCRATCH='' SOURCE='' BUILD='' TOOLS='' RED=0
QEMU=${QEMU:-/usr/local/bin/qemu-system-x86_64}
CC=${CC:-gcc-14}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-1200}
while (($#)); do
	case "$1" in
	--scratch) SCRATCH=$2; shift 2 ;;
	--source) SOURCE=$2; shift 2 ;;
	--build) BUILD=$2; shift 2 ;;
	--tools) TOOLS=$2; shift 2 ;;
	--red) RED=1; shift ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
[[ -n "$SCRATCH" && -n "$SOURCE" && -n "$BUILD" && -n "$TOOLS" ]] || { echo 'missing option' >&2; exit 2; }
[[ -d "$SCRATCH" && ! -L "$SCRATCH" && $(stat -c %a "$SCRATCH") == 700 && $(stat -c %u "$SCRATCH") == $(id -u) ]] || {
	echo 'FAIL scratch must be an existing private 0700 directory' >&2; exit 1; }
SCRATCH=$(cd "$SCRATCH" && pwd -P)
EV=$SCRATCH/evidence OUT=$SCRATCH/out ROOT=$SCRATCH/initroot
mkdir -p "$EV" "$OUT"
rm -f -- "$EV/result.json" "$EV/verdict.txt"
exec > >(tee -a "$EV/runner.log") 2>&1

# Source setup is separate from the unchanged guest workload below.
resolve_poll_source() {
	local resolved
	resolved=$(python3 -B - "$SOURCE" "$BUILD" "$RED" <<'PY_POLL_SOURCE'
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


def fail(message):
    raise ValueError(message)


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], capture_output=True)
    if result.returncode:
        fail(result.stderr.decode(errors='replace').strip() or 'source Git check failed')
    return result.stdout


def plain_path(value):
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    current = Path(path.anchor)
    # Check before normalizing '..': a symlink followed by '..' still traverses it.
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            fail('symlink source path: ' + str(current))
    return Path(os.path.abspath(path))


def directory(value):
    path = plain_path(value)
    if not path.is_dir():
        fail('missing source/build directory: ' + str(path))
    return path


def regular(repo, name):
    if not isinstance(name, str) or not name or '\\' in name:
        fail('invalid canonical source path: ' + repr(name))
    relative = Path(name)
    if relative.is_absolute() or any(part in ('', '.', '..', '.git') for part in name.split('/')):
        fail('invalid canonical source path: ' + name)
    path = plain_path(repo / name)
    if not path.is_file():
        fail('missing regular canonical source: ' + str(path))
    return path


try:
    selected = directory(sys.argv[1])
    build = directory(sys.argv[2])
    red = int(sys.argv[3])
    marker = selected / '.xdev-ext-source.json'
    if marker.exists() or marker.is_symlink():
        receipt = json.loads(regular(selected, marker.name).read_text())
        if (receipt.get('schema') != 2 or receipt.get('kind') != 'full-assembly'
                or receipt.get('component') != 'linux'):
            fail('source must be a schema-2 full Linux assembly')
        owner = receipt.get('canonical_root')
        if not isinstance(owner, str) or not Path(owner).is_absolute():
            fail('assembly canonical root must be absolute')
        repo = directory(owner)
        if receipt.get('output') != str(selected):
            fail('assembly output differs from selected source')
        native = selected
    else:
        if (selected / 'view.json').is_file():
            fail('logical source view is not a full assembly; select the canonical Git root or full assembly')
        repo = selected
        native = None
    top = directory(os.fsdecode(git(repo, 'rev-parse', '--show-toplevel')).strip())
    if top != repo:
        fail('canonical source directory is not its own Git checkout; select the canonical root or full assembly')
    if git(repo, 'status', '--porcelain', '--untracked-files=all').strip():
        fail('canonical source Git root contains dirty, staged or untracked files')
    head = git(repo, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
    tracked = {}
    for row in git(repo, 'ls-files', '--stage', '-z').split(b'\0'):
        if row:
            meta, name = row.split(b'\t', 1)
            mode, oid, stage = meta.split()
            if stage == b'0' and mode in (b'100644', b'100755'):
                tracked[os.fsdecode(name)] = mode

    def tracked_regular(name):
        path = regular(repo, name)
        if name not in tracked:
            fail('canonical source is not a tracked regular file: ' + name)
        return path

    # Prove all declared inputs before importing any source-selected tooling.
    for name in ('source-layout.json', 'tools/layout.py', 'tools/build/prepare_sources.py'):
        tracked_regular(name)
    manifest = json.loads((repo / 'source-layout.json').read_text())
    tracked_regular(manifest.get('dependency_lock', 'third_party/sources.lock.json'))
    for entry in manifest['files']:
        tracked_regular(entry['source'])
    sys.path.insert(0, str(repo / 'tools'))
    from layout import load_layout, safe_file
    layout = load_layout(repo)
    layout.validate_sources()

    link = build / 'source'
    if not link.is_symlink():
        fail('missing BUILD/source Kbuild symlink; rebuild against the prepared full assembly')
    target = Path(os.readlink(link))
    built_native = directory(target if target.is_absolute() else link.parent / target)
    if link.resolve(strict=True) != built_native:
        fail('BUILD/source target identity differs from the prepared assembly')
    if native is None:
        native = built_native
    if native != built_native:
        fail('BUILD/source differs from selected full assembly')
    native_marker = native / '.xdev-ext-source.json'
    assembly = json.loads(regular(native, native_marker.name).read_text())
    if (assembly.get('schema') != 2 or assembly.get('kind') != 'full-assembly'
            or assembly.get('component') != 'linux'
            or assembly.get('canonical_root') != str(repo)
            or assembly.get('output') != str(native)):
        fail('BUILD/source is not the selected owner\'s schema-2 full Linux assembly')
    checked = subprocess.run([sys.executable, '-B', str(repo / 'tools/build/prepare_sources.py'),
                              '--component', 'linux', '--output', str(native), '--check'],
                             capture_output=True, text=True)
    if checked.returncode:
        fail('prepared source check failed: ' + checked.stdout + checked.stderr)

    poll_native = 'tools/testing/selftests/xdev_ext_mech/poll/'
    spec_native = 'Documentation/userspace-api/xdev_ext-poll.rst'
    poll = safe_file(repo, layout.source('linux', poll_native + 'poll_kvm.sh').relative_to(repo).as_posix()).parent
    spec = safe_file(repo, layout.source('linux', spec_native).relative_to(repo).as_posix())
    provider = safe_file(repo, layout.source('linux',
        'tools/testing/selftests/xdev_ext_mech/provider/dma_poll_runtime.c').relative_to(repo).as_posix()).parent
    build_sha = (build / 'xdev-ext-source.commit').read_text().strip()
    if not re.fullmatch('[0-9a-f]{40}', build_sha):
        fail('missing or invalid build source commit; rebuild exact source')
    changed = 'red baseline kernel ' + build_sha + ', guest programs of ' + head
    if not red:
        git(repo, 'cat-file', '-e', build_sha + '^{commit}')
        git(repo, 'merge-base', '--is-ancestor', build_sha, head)
        names = [os.fsdecode(name) for name in git(repo, 'diff', '--name-only', '-z',
                 '--no-renames', build_sha, head).split(b'\0') if name]
        revisions = {}
        for revision in dict.fromkeys((build_sha, head)):
            files = {os.fsdecode(name) for name in git(repo, 'ls-tree', '-rz', '--name-only',
                                                     revision).split(b'\0') if name}
            if 'source-layout.json' in files:
                revisions[revision] = (files, load_layout(repo, revision))
            else:
                lock = json.loads(git(repo, 'show', revision + ':sources.lock.json'))
                if lock.get('schema') != 1 or lock['components']['linux']['path'] != 'kernel':
                    fail('historical revision has no supported source layout')
                revisions[revision] = (files, None)
        for name in names:
            classified = False
            for files, old_layout in revisions.values():
                if name not in files:
                    continue
                classified = True
                if old_layout is None:
                    logical = name
                else:
                    logical = old_layout.by_source.get(name)
                    if logical is None:
                        fail('changed input has no revision-specific mapping: ' + name)
                if not (logical.startswith('kernel/' + poll_native)
                        or logical == 'kernel/' + spec_native):
                    fail('source differs from prebuilt kernel/tools outside stage-POLL files: ' + name)
            if not classified:
                fail('changed input missing from both revisions: ' + name)
        changed = '\n'.join(names)
    values = dict(SOURCE_GIT_ROOT=str(repo), HEAD_SHA=head, NATIVE_SOURCE=str(native),
                  POLL_SOURCE=str(poll), POLL_SPEC=str(spec), PROVIDER_SOURCE=str(provider),
                  BUILD_SHA=build_sha, changed=changed, BUILD=str(build))
    for name, value in values.items():
        print(name + '=' + shlex.quote(value))
except (OSError, ValueError, KeyError, TypeError) as error:
    print('FAIL stage-POLL source setup: ' + str(error), file=sys.stderr)
    sys.exit(1)
PY_POLL_SOURCE
	) || return 1
	eval "$resolved"
}

verify_poll_artifacts() {
	local module_release
	TOOLS=$(cd "$TOOLS" && pwd -P) || return 1
	DMA=$TOOLS/dma-provider
	python3 -B - "$BUILD" "$TOOLS" <<'PY_POLL_ARTIFACTS' || return 1
import hashlib
from pathlib import Path
import re
import sys


try:
    build, tools = map(Path, sys.argv[1:])
    dma = tools / 'dma-provider'
    required = [build / '.config', build / 'arch/x86/boot/bzImage', build / 'vmlinux',
                tools / 'xdev_ext_mech_ctl', tools / 'nvme_s0.bpf.o', tools / 'nxp_mech.bpf.o',
                dma / 'xdev_ext_dma_provider_sim.ko', dma / 'dma_poll_runtime',
                dma / 'dma_provider_pair.bpf.o']
    receipt = build / 'xdev-ext-artifacts.sha256'
    if not receipt.is_file() or not receipt.stat().st_size:
        raise ValueError('missing build-produced artifact receipt; rebuild kernel/tools')
    entries = {}
    for row in receipt.read_text(errors='surrogateescape').split('\n'):
        if not row:
            continue
        match = re.fullmatch(r'(\\?)([0-9a-fA-F]{64}) ([ *])(.+)', row)
        if match is None:
            raise ValueError('malformed build artifact receipt; rebuild kernel/tools')
        escaped, digest, mode, name = match.groups()
        if escaped:
            decoded = []
            index = 0
            while index < len(name):
                char = name[index]
                if char == '\\':
                    index += 1
                    if index == len(name) or name[index] not in ('\\', 'n', 'r'):
                        raise ValueError('malformed escaped artifact receipt path')
                    char = {'\\': '\\', 'n': '\n', 'r': '\r'}[name[index]]
                decoded.append(char)
                index += 1
            name = ''.join(decoded)
        entries.setdefault(name, []).append(digest.lower())
    for path in required:
        if not path.is_file() or not path.stat().st_size:
            raise ValueError('missing nonempty prebuilt artifact: ' + str(path))
        matches = entries.get(str(path), [])
        if len(matches) != 1:
            raise ValueError('missing or ambiguous exact artifact receipt member: ' + str(path)
                             + '; rebuild kernel/tools')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != matches[0]:
            raise ValueError('prebuilt artifact hash mismatch: ' + str(path))
except (OSError, ValueError) as error:
    print('FAIL stage-POLL artifact setup: ' + str(error), file=sys.stderr)
    sys.exit(1)
PY_POLL_ARTIFACTS
	sha256sum -c "$BUILD/xdev-ext-artifacts.sha256" >"$EV/reused-artifact-check.log" 2>&1 || {
		echo 'FAIL complete build artifact receipt verification; rebuild kernel/tools' >&2; return 1; }
	for symbol in MODULES MODULE_UNLOAD XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY XDEV_EXT_MECH_DMA BLK_DEV_NVME \
		BLK_DEV_INITRD DEVTMPFS IO_URING BPF_SYSCALL DEBUG_INFO_BTF XDP_SOCKETS VIRTIO_NET NET_RX_BUSY_POLL \
		PCI_MSI SERIAL_8250_CONSOLE DEBUG_FS; do
		grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || {
			echo "FAIL kernel requires CONFIG_$symbol=y" >&2; return 1; }
	done
	release=$(cat "$BUILD/include/config/kernel.release") || return 1
	[[ -n "$release" ]] || { echo 'FAIL missing kernel release' >&2; return 1; }
	[[ -x "$TOOLS/xdev_ext_mech_ctl" && -x "$DMA/dma_poll_runtime" ]] || {
		echo 'FAIL controller and polling runtime must be executable; rebuild tools' >&2; return 1; }
	module_release=$(modinfo -F vermagic "$DMA/xdev_ext_dma_provider_sim.ko") || {
		echo 'FAIL cannot read provider module vermagic' >&2; return 1; }
	[[ ${module_release%% *} == "$release" ]] || (( RED )) || {
		echo 'FAIL provider module vermagic differs from kernel release' >&2; return 1; }
	cmp "$PROVIDER_SOURCE/dma_poll_runtime.c" "$DMA/dma_poll_runtime.c" || {
		echo 'FAIL polling runtime source copy differs from current provider' >&2; return 1; }
	cmp "$PROVIDER_SOURCE/xdev_ext_dma_provider_sim.c" "$DMA/xdev_ext_dma_provider_sim.c" || {
		echo 'FAIL provider module source copy differs from current provider' >&2; return 1; }
}

resolve_poll_source || exit 1
verify_poll_artifacts || exit 1
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" ]]
{
	printf 'date_utc=%s\nhost=%s\nclaim=KVM correctness only; QEMU NVMe and virtio-net; DMA provider is CPU memcpy; no timing\n' \
		"$(date -u +%FT%TZ)" "$(hostname)"
	printf 'source=%s\nsource_commit=%s\nbuild=%s\nbuild_commit=%s\ntools=%s\nkernel_release=%s\n' \
		"$SOURCE" "$HEAD_SHA" "$BUILD" "$BUILD_SHA" "$TOOLS" "$release"
	printf 'changed_since_build=%s\n' "$(tr '\n' ' ' <<<"$changed")"
	grep -E '^CONFIG_(KASAN|PROVE_LOCKING|DEBUG_ATOMIC_SLEEP|NET_RX_BUSY_POLL|PREEMPT[A-Z_]*)=' "$BUILD/.config" || true
} >"$EV/provenance.txt"

# Build only the guest test program, from the exact checkout.
mkdir -p "$OUT/build"
cp "$POLL_SOURCE/guest/"{Makefile,nvme_poll_e2e.c} "$OUT/build/"
nice -n 10 make -C "$OUT/build" KERNEL_SRC="$NATIVE_SOURCE" CC="$CC" nvme_poll_e2e >"$EV/test-build.log" 2>&1

# Minimal initramfs: busybox, the guest programs and their libraries.
rm -rf -- "$ROOT"
mkdir -p "$ROOT"/{bin,dev,proc,sys,tmp,opt/poll}
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount cat echo poweroff dmesg sed cut basename dirname mknod insmod rmmod sync awk grep \
	seq sleep kill cmp dd blockdev ip ls tr wc head tail readlink; do
	ln -sf busybox "$ROOT/bin/$app"
done
cp "$OUT/build/nvme_poll_e2e" "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/nvme_s0.bpf.o" "$TOOLS/nxp_mech.bpf.o" \
	"$DMA/xdev_ext_dma_provider_sim.ko" "$DMA/dma_poll_runtime" "$DMA/dma_provider_pair.bpf.o" \
	"$POLL_SOURCE/guest/run-guest.sh" "$ROOT/opt/poll/"
: >"$EV/guest-libraries.txt"
for program in "$OUT/build/nvme_poll_e2e" "$TOOLS/xdev_ext_mech_ctl" "$DMA/dma_poll_runtime"; do
	ldd "$program" | awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' >>"$EV/guest-libraries.txt"
done
sort -u -o "$EV/guest-libraries.txt" "$EV/guest-libraries.txt"
while IFS= read -r lib; do
	mkdir -p "$ROOT$(dirname "$lib")"; cp -L "$lib" "$ROOT$lib"
done <"$EV/guest-libraries.txt"
cat >"$ROOT/init" <<'GUEST'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t bpf bpf /sys/fs/bpf
# Firmware leaves escape sequences on the console line; start a clean one.
echo
echo XDEV_EXT_POLL_GUEST_BEGIN
XDEV_EXT_POLL_GUEST=1 sh /opt/poll/run-guest.sh /opt/poll
code=$?
echo "XDEV_EXT_POLL_GUEST_EXIT=$code"
echo XDEV_EXT_POLL_DMESG_BEGIN
dmesg
echo XDEV_EXT_POLL_DMESG_END
sync
poweroff -f
GUEST
chmod 755 "$ROOT/init" "$ROOT/opt/poll/run-guest.sh"
(cd "$ROOT" && find . | cpio -o -H newc --quiet | gzip -1) >"$OUT/initramfs.cpio.gz"
sha256sum "$BUILD/arch/x86/boot/bzImage" "$OUT/build/nvme_poll_e2e" "$TOOLS/xdev_ext_mech_ctl" \
	"$TOOLS/nvme_s0.bpf.o" "$TOOLS/nxp_mech.bpf.o" "$DMA/xdev_ext_dma_provider_sim.ko" \
	"$DMA/dma_poll_runtime" "$DMA/dma_provider_pair.bpf.o" >"$EV/artifacts.sha256"

# Private disks and a private two-port hub; the kernel gets two poll queues.
python3 -I "$POLL_SOURCE/poll_validate.py" make-images "$OUT"
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$OUT/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr ipv6.disable=1 nvme.poll_queues=2'
	-nic none -netdev hubport,id=wire0,hubid=0 -netdev hubport,id=wire1,hubid=0
	-device virtio-net-pci,netdev=wire0,mac=02:00:00:00:00:01,iommu_platform=on,disable-legacy=on,rx_queue_size=1024
	-device virtio-net-pci,netdev=wire1,mac=02:00:00:00:00:02,iommu_platform=on,disable-legacy=on,rx_queue_size=1024
	-drive "file=$OUT/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=XDEVPSRC01
	-drive "file=$OUT/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
	-device nvme,drive=dst,serial=XDEVPDST01
	-drive "file=$OUT/spare.raw,if=none,id=spare,format=raw,cache=none,aio=threads"
	-device nvme,drive=spare,serial=XDEVPSPR01)
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"; printf '\n' >>"$EV/qemu.command"
qemu_status=0
timeout "$TIMEOUT_SECONDS" "$QEMU" "${args[@]}" </dev/null >"$EV/guest.log" 2>&1 || qemu_status=$?
printf 'qemu_exit=%s\n' "$qemu_status" >>"$EV/provenance.txt"
if (( RED )); then
	# Expected: the kernel without stage polling refuses the bit at CREATE.
	if (( qemu_status == 0 )) && tr -d '\r' <"$EV/guest.log" |
		grep -Eq '^not ok [0-9]+ - polled-copy: CREATE with POLL on NVMe READ and WRITE$' &&
		! grep -q 'XDEV_EXT_POLL_NVME=PASS' "$EV/guest.log"; then
		echo 'XDEV_EXT_POLL_KVM=RED_CONFIRMED first_failure=polled-copy-CREATE' | tee "$EV/verdict.txt"
		exit 0
	fi
	echo "XDEV_EXT_POLL_KVM=RED_UNEXPECTED qemu_exit=$qemu_status" | tee "$EV/verdict.txt"
	exit 1
fi
validator_status=0
python3 -I "$POLL_SOURCE/poll_validate.py" validate --dir "$OUT" --log "$EV/guest.log" \
	--result "$EV/result.json" || validator_status=$?
if (( qemu_status == 0 && validator_status == 0 )); then
	echo 'XDEV_EXT_POLL_KVM=PASS' | tee "$EV/verdict.txt"
else
	echo "XDEV_EXT_POLL_KVM=FAIL qemu_exit=$qemu_status validator_exit=$validator_status" | tee "$EV/verdict.txt"
	exit 1
fi
