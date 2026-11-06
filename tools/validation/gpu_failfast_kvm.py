#!/usr/bin/env python3
"""codex_115: source-only author handoff; root executes on 6787p.

No-device diagnostic: actual shell helper spans and whole unload source mode.
No GPU, RM, D-state, reset, DMA or performance acceptance is produced.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import time


GUEST = r'''#!/bin/sh
export PATH=/proof-bin:/bin
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
mount -t tmpfs tmpfs /tmp || exit 1
finish() {
    code=$?
    trap - EXIT
    echo "PROOF_FINISH status=$code"
    echo PROOF_DMESG_BEGIN
    dmesg
    echo PROOF_DMESG_END
    sync
    echo PROOF_POWEROFF
    poweroff -f
}
trap finish EXIT
set -u
fail() { echo "PROOF_ASSERT_FAIL $*"; exit 1; }
expect() { [ "$1" = "$2" ] || fail "$3 expected=$2 actual=$1"; }
. /proof/helpers.sh
failed=0 unsupported=0 case_limit_s=2 gpu_problem=
export XDEV_EXT_GPU_CLEANUP_LIMIT_S=1 XDEV_EXT_GPU_UNLOAD_LIMIT_S=1

# Controls produce no fake GPU module/capability/case success evidence.
bounded 1 /tmp/true.log /bin/busybox true
expect "$?" 0 bounded-success
bounded 1 /tmp/false.log /bin/busybox false
expect "$?" 1 bounded-command-failure
timed_out control 1
expect "$?" 1 non-timeout-status
expect "$gpu_problem" '' no-problem
expect "$(cleanup_limit_s)" 2 normal-cleanup-limit
skipped control
expect "$?" 1 no-premature-skip
echo PROOF_HELPER_CONTROLS=PASS

make_modules() {
    rm -rf /tmp/proof-module
    mkdir -p /tmp/proof-module/nvidia_uvm/holders /tmp/proof-module/nvidia/holders
    echo 0 >/tmp/proof-module/nvidia_uvm/refcnt
    echo 0 >/tmp/proof-module/nvidia/refcnt
    : >/tmp/unload-attempts
}

echo PROOF_INJECT_BEGIN
# This command immediately execs sleep. bounded's direct PID is the sleeper;
# it has no worker child that could outlive the actual helper's SIGKILL.
bounded "$case_limit_s" /tmp/block.log /proof-bin/block
rc=$?
expect "$rc" 124 blocking-case-status
timed_out ce-chain-d "$rc"
expect "$?" 0 timeout-recognized
expect "$gpu_problem" timeout timeout-state
case_result ce-chain-d FAIL rc="$rc" reason=timeout allocation=diagnostic-only
for name in ce-chain-a peer-nvme dmabuf-peer; do
    skipped "$name"
    expect "$?" 0 skipped-after-problem
done
expect "$failed" 4 four-failed-cases
limit_s=$(cleanup_limit_s)
expect "$limit_s" 1 shortened-cleanup
bounded "$limit_s" /tmp/cleanup-block.log /proof-bin/block
rc=$?
expect "$rc" 124 blocking-cleanup-status
timed_out detach-ce-plan "$rc" "$limit_s"
expect "$?" 0 cleanup-timeout-recognized
echo "PROOF_CLEANUP_LIMIT=$limit_s"

# Whole actual source's unload mode, with only its module fixture root changed.
# These commands are userspace observations, not real NVIDIA module unloads.
make_modules
echo success >/tmp/unload-mode
sh /proof/unload-projection.sh unload
expect "$?" 0 unload-after-problem
attempts=$(cat /tmp/unload-attempts | tr '\n' ',')
expect "$attempts" nvidia_uvm,nvidia, unload-order
cat /tmp/unload-attempts | sed 's/^/PROOF_UNLOAD_ATTEMPT module=/'
echo PROOF_INJECT_END

make_modules
echo error >/tmp/unload-mode
echo PROOF_UNLOAD_ERROR_BEGIN
sh /proof/unload-projection.sh unload
expect "$?" 1 unload-error-control
attempts=$(cat /tmp/unload-attempts | tr '\n' ',')
expect "$attempts" nvidia_uvm,nvidia, unload-error-order
echo PROOF_UNLOAD_ERROR_END

make_modules
echo timeout >/tmp/unload-mode
echo PROOF_UNLOAD_TIMEOUT_BEGIN
sh /proof/unload-projection.sh unload
expect "$?" 1 unload-timeout-control
attempts=$(cat /tmp/unload-attempts | tr '\n' ',')
expect "$attempts" nvidia_uvm,nvidia, unload-timeout-order
echo PROOF_UNLOAD_TIMEOUT_END
echo PROOF_GUEST=PASS
exit 0
'''

RMMOD = r'''#!/bin/sh
echo "$1" >>/tmp/unload-attempts
mode=$(cat /tmp/unload-mode)
if [ "$1" = nvidia ]; then
    case "$mode" in
        error) echo diagnostic-userspace-refusal; exit 17 ;;
        timeout) exec /bin/busybox sleep 30 ;;
        success) ;;
        *) exit 99 ;;
    esac
fi
/bin/busybox rm -rf "/tmp/proof-module/$1"
'''

WATCHDOG_GUEST = r'''#!/bin/sh
export PATH=/bin
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
echo PROOF_WATCHDOG_ARMED
echo PROOF_WATCHDOG_DMESG_BEGIN
dmesg
echo PROOF_WATCHDOG_DMESG_END
# Test-only userspace non-poweroff control; never accesses a device.
exec /bin/busybox sleep 300
'''


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(0o700 if executable else 0o600)


def metadata(info):
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
                mode=oct(stat.S_IMODE(info.st_mode)), size=info.st_size,
                mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)


def secure_directory(path):
    require(path.is_absolute() and '..' not in path.parts, 'absolute non-traversing path required')
    receipts = []
    for current in list(reversed(path.parents)) + [path]:
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                'directory/symlink violation: ' + str(current))
        require(info.st_uid == 0 and not (info.st_mode & 0o022),
                'directory must be root-owned and not group/world writable: ' + str(current))
        receipts.append(dict(path=str(current), **metadata(info)))
    require(path.resolve(strict=True) == path, 'resolved directory differs from literal path')
    return receipts


def create_output(path):
    approved = Path('/root/xdev_ext/build-cache')
    approved_receipt = secure_directory(approved)
    require(path.is_absolute() and '..' not in path.parts and path != approved,
            'invalid output path')
    require(approved in path.parents, 'output must be strictly below approved build-cache')
    parent_receipt = secure_directory(path.parent)
    # Refuse tmpfs/overlay or a filesystem whose block device cannot be tied to NVMe.
    device = approved.stat().st_dev
    block = Path('/sys/dev/block') / f'{os.major(device)}:{os.minor(device)}'
    resolved_block = block.resolve(strict=True)
    require(any(part.startswith('nvme') for part in resolved_block.parts),
            'approved root is not backed by an observable NVMe block device')
    require(path.parent.stat().st_dev == device, 'output parent crosses approved filesystem')
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_identity = os.fstat(fd)
        require((parent_identity.st_dev, parent_identity.st_ino) ==
                (path.parent.stat().st_dev, path.parent.stat().st_ino), 'parent identity changed')
        os.mkdir(path.name, mode=0o700, dir_fd=fd)  # exclusive; EEXIST stops, including symlinks
        created = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISDIR(created.st_mode) and created.st_uid == 0 and
                stat.S_IMODE(created.st_mode) == 0o700, 'new output directory ownership/mode mismatch')
        require(path.resolve(strict=True) == path and
                (path.stat().st_dev, path.stat().st_ino) == (created.st_dev, created.st_ino),
                'output directory identity changed')
    finally:
        os.close(fd)
    return dict(approved_root=approved_receipt, ancestors=parent_receipt,
                output=dict(path=str(path), **metadata(created)), nvme_sysfs=str(resolved_block),
                mountinfo=Path('/proc/self/mountinfo').read_text())


def input_bytes(path):
    secure_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
                not (before.st_mode & 0o022), 'input ownership/type/mode violation: ' + str(path))
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read()
        after = os.fstat(fd)
        named = path.lstat()
        require(metadata(before) == metadata(after) == metadata(named),
                'input changed while reading: ' + str(path))
    finally:
        os.close(fd)
    return data, dict(path=str(path), **metadata(before), sha256=sha(data),
                      policy='root-owned, non-group/world-writable, no symlinks; content/metadata rechecked; no immutable flag claimed')


def verify_inputs(inputs):
    for name, expected in inputs.items():
        unused, current = input_bytes(Path(expected['path']))
        require(current == expected, 'input changed since initial receipt: ' + name)


def process_identity(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
    except FileNotFoundError:
        return None
    fields = raw.rsplit(')', 1)[1].split()
    return dict(pid=pid, state=fields[0], ppid=int(fields[1]), pgid=int(fields[2]),
                session=int(fields[3]), starttime=int(fields[19]))


def owned_process(command, out, name, deadline_s):
    """Direct owned child, finite supervision; never assumes SIGKILL forces exit."""
    record = dict(argv=command, deadline_s=deadline_s, events=[], state='STARTING')
    receipt = out / (name + '-process.json')
    def save():
        write(receipt, json.dumps(record, indent=2) + '\n')
    save()
    with (out / (name + '.log')).open('xb') as log:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        record['pid'] = child.pid
        identity = process_identity(child.pid)
        record['identity'] = identity
        save()
        if identity is None:
            # A fast ordinary exit may be reaped immediately; never signal a missing identity.
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                record['state'] = 'FAILED_UNREAPED'
                save()
                raise RuntimeError('STOP: FAILED_UNREAPED pid=' + str(child.pid))
        else:
            if identity['pgid'] != child.pid or identity['session'] != child.pid:
                record['state'] = 'FAILED_IDENTITY_STOP'
                save()
                raise RuntimeError('STOP: owned child session identity mismatch pid=' + str(child.pid))
        try:
            child.wait(timeout=deadline_s)
            record['deadline_fired'] = False
        except subprocess.TimeoutExpired:
            record['deadline_fired'] = True
            record['events'].append(dict(action='deadline', monotonic=time.monotonic()))
            save()
            for sig, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
                current = process_identity(child.pid)
                if child.poll() is not None:
                    break
                if current is None or identity is None or any(
                        current[key] != identity[key] for key in ('pid', 'starttime', 'pgid', 'session')):
                    record['state'] = 'FAILED_IDENTITY_STOP'
                    record['observed_identity'] = current
                    save()
                    raise RuntimeError('STOP: child PID/starttime/session identity changed')
                try:
                    os.killpg(child.pid, sig)
                    delivered = True
                except ProcessLookupError:
                    delivered = False  # exited between identity check and signal
                record['events'].append(dict(action=signal.Signals(sig).name, delivered=delivered,
                                             identity=current, monotonic=time.monotonic()))
                save()
                try:
                    child.wait(timeout=grace)
                    break
                except subprocess.TimeoutExpired:
                    continue
            if child.poll() is None:
                record['state'] = 'FAILED_UNREAPED'
                record['observed_identity'] = process_identity(child.pid)
                save()
                raise RuntimeError('STOP: FAILED_UNREAPED pid=' + str(child.pid))
        record['returncode'] = child.returncode
        record['post_reap_identity'] = process_identity(child.pid)
        require(record['post_reap_identity'] is None or identity is None or
                record['post_reap_identity']['starttime'] != identity['starttime'],
                'STOP: original process remains after wait')
        record['state'] = 'REAPED'
        save()
    return record


def debug_gate(out, name, enabled):
    output = out / (name + '-debug.json')
    result = owned_process([sys.executable, '-I', str(out / 'source/xdev_ext_mech_zc_debug.py'),
                           'console', str(out / (name + '.log')), str(output), str(int(enabled))],
                           out, name + '-debug-scanner', 10)
    require(not result['deadline_fired'] and result['returncode'] == 0,
            'actual debug scanner failed: ' + name)
    counts = json.loads(output.read_text())
    require(counts == dict(enabled=enabled, lockdep=0, atomic_sleep=0, kasan=0,
                           hung=0, rcu_stall=0, diagnostic=0),
            'original diagnostic counts must all be zero: ' + name)
    return counts


def span(source, start, end):
    require(source.count(start) == 1 and source.count(end) == 1,
            'source boundary is absent or ambiguous')
    first = source.index(start)
    last = source.index(end, first)
    value = source[first:last]
    return value, dict(start_literal=start, end_literal=end,
                      first_line=source.count('\n', 0, first) + 1,
                      last_line=source.count('\n', 0, last), sha256=sha(value.encode()))


def archive(root, output):
    """Small newc initramfs, no build tool or external cpio dependency."""
    with gzip.open(output, 'wb', compresslevel=1) as stream:
        def entry(name, mode, content, ino, rdevmajor=0, rdevminor=0):
            encoded = name.encode() + b'\0'
            fields = (ino, mode, 0, 0, 1, 0, len(content), 0, 0,
                      rdevmajor, rdevminor, len(encoded), 0)
            header = b'070701' + ''.join(f'{item:08x}' for item in fields).encode()
            stream.write(header + encoded)
            stream.write(b'\0' * (-(110 + len(encoded)) % 4))
            stream.write(content)
            stream.write(b'\0' * (-len(content) % 4))
        for ino, path in enumerate(sorted(root.rglob('*')), 1):
            mode = path.lstat().st_mode
            content = os.readlink(path).encode() if path.is_symlink() else \
                path.read_bytes() if path.is_file() else b''
            entry(str(path.relative_to(root)), mode, content, ino)
        # The kernel opens /dev/console before /init can mount devtmpfs.
        entry('dev/console', stat.S_IFCHR | 0o600, b'', 1000001, 5, 1)
        entry('dev/null', stat.S_IFCHR | 0o666, b'', 1000002, 1, 3)
        entry('TRAILER!!!', 0, b'', 0)


def region(text, begin, end):
    lines = text.splitlines()
    require(lines.count(begin) == 1 and lines.count(end) == 1,
            'missing/repeated guest region ' + begin)
    first, last = lines.index(begin), lines.index(end)
    require(first < last, 'reversed guest region')
    return '\n'.join(lines[first + 1:last]) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='exact candidate repository root')
    parser.add_argument('--kernel', type=Path, required=True, help='existing built bzImage on 6787p')
    parser.add_argument('--kernel-config', type=Path, required=True, help='config for that exact existing bzImage')
    parser.add_argument('--busybox', type=Path, required=True, help='existing STATIC busybox')
    parser.add_argument('--debug-locking', action='store_true', help='require existing strict-debug kernel config')
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new directory on project NVMe')
    args = parser.parse_args()
    os.umask(0o077)
    require(os.geteuid() == 0, 'root execution required for root-owned proof inputs')
    output_receipt = create_output(args.output)
    out = args.output
    write(out / 'output-preflight.json', json.dumps(output_receipt, indent=2) + '\n')
    require(Path('/dev/kvm').exists(), '/dev/kvm missing')
    native = args.source / 'tests/integration/session/native'
    input_paths = dict(kernel=args.kernel, kernel_config=args.kernel_config,
                       busybox=args.busybox, qemu=args.qemu,
                       guest=native / 'xdev_ext_gpu_guest.sh',
                       validator=native / 'xdev_ext_gpu_validate.py',
                       debug_scanner=native / 'xdev_ext_mech_zc_debug.py',
                       author_runner=Path(__file__).absolute())
    blobs, inputs = {}, {}
    for name, path in input_paths.items():
        blobs[name], inputs[name] = input_bytes(path)
    write(out / 'input-receipt.json', json.dumps(inputs, indent=2) + '\n')
    raw, validator = blobs['guest'], blobs['validator']
    source = raw.decode()
    write(out / 'source/xdev_ext_gpu_guest.sh', raw)
    write(out / 'source/xdev_ext_gpu_validate.py', validator)
    write(out / 'source/xdev_ext_mech_zc_debug.py', blobs['debug_scanner'])
    write(out / 'source/run-proof.py', blobs['author_runner'])
    write(out / 'inputs/bzImage', blobs['kernel'])
    write(out / 'inputs/kernel.config', blobs['kernel_config'])
    write(out / 'inputs/busybox', blobs['busybox'], True)
    for path in (out / 'source').iterdir():
        path.chmod(0o400)
    (out / 'inputs/bzImage').chmod(0o400)
    (out / 'inputs/kernel.config').chmod(0o400)
    (out / 'inputs/busybox').chmod(0o500)
    snapshots = {}
    for path in list((out / 'source').iterdir()) + list((out / 'inputs').iterdir()):
        unused, snapshots[str(path.relative_to(out))] = input_bytes(path)
    write(out / 'snapshot-receipt.json', json.dumps(snapshots, indent=2) + '\n')
    tracked_inputs = dict(inputs, **{'snapshot:' + name: value for name, value in snapshots.items()})
    # x86-64 little-endian ELF without PT_INTERP is the admitted static input.
    elf = blobs['busybox']
    require(elf[:6] == b'\x7fELF\x02\x01' and len(elf) >= 64 and
            struct.unpack_from('<H', elf, 18)[0] == 62, 'busybox is not x86-64 ELF')
    phoff = struct.unpack_from('<Q', elf, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', elf, 54)
    require(phsize >= 56 and phnum > 0 and phoff + phsize * phnum <= len(elf),
            'invalid busybox ELF program headers')
    require(all(struct.unpack_from('<I', elf, phoff + phsize * index)[0] != 3
                for index in range(phnum)), 'busybox has dynamic ELF interpreter')
    bb = str(out / 'inputs/busybox')
    bb_list = owned_process([bb, '--list'], out, 'busybox-applets', 10)
    require(not bb_list['deadline_fired'] and bb_list['returncode'] == 0, 'busybox applet preflight failed')
    required_applets = {'sh', 'mount', 'sleep', 'cat', 'sed', 'rm', 'ls', 'tr', 'mkdir',
                        'sync', 'poweroff', 'dmesg', 'grep', 'true', 'false'}
    require(required_applets <= set((out / 'busybox-applets.log').read_text().splitlines()),
            'busybox required applet missing')
    bb_sleep = owned_process([bb, 'sleep', '0.1'], out, 'busybox-fractional-sleep', 10)
    require(not bb_sleep['deadline_fired'] and bb_sleep['returncode'] == 0, 'busybox fractional sleep failed')
    debug_config = owned_process([sys.executable, '-I', str(out / 'source/xdev_ext_mech_zc_debug.py'),
                   'config', str(out / 'inputs/kernel.config'), '/dev/null',
                   str(int(args.debug_locking))], out, 'debug-config', 10)
    require(not debug_config['deadline_fired'] and debug_config['returncode'] == 0,
            'actual debug config preflight failed')
    bounded, b_receipt = span(source, '# bounded LIMIT_S', '\nif [ "${1:-}" = unload ]; then')
    helpers, h_receipt = span(source, 'case_result() {', '\n# module_step STEP STATUS LOG:')
    require(source.count('/sys/module') == 4, 'unexpected unload module path count')
    projection = source.replace('/sys/module', '/tmp/proof-module')
    receipt = dict(scope='shell watchdog and userspace unload-attempt only; no GPU/RM/DMA/reset proof',
                   claimed_candidate='e1959a76e5fa196c3dafd468760f2f8288ae8fec; root verifies provenance',
                   source_path=str(native.resolve()), source_sha256=sha(raw),
                   validator_sha256=sha(validator), extraction=[b_receipt, h_receipt],
                   projection=dict(before='/sys/module', after='/tmp/proof-module', occurrences=4,
                                   sha256=sha(projection.encode())),
                   kernel=inputs['kernel'], busybox=inputs['busybox'],
                   debug_scanner=inputs['debug_scanner'],
                   host_uname=list(os.uname()))
    write(out / 'projection-receipt.json', json.dumps(receipt, indent=2) + '\n')
    write(out / 'bounded-exact.sh', bounded)
    write(out / 'case-helpers-exact.sh', helpers)
    write(out / 'unload-projection.sh', projection)
    root = out / 'initramfs-root'
    for name in ('bin', 'sbin', 'usr/bin', 'proc', 'sys', 'dev', 'tmp', 'proof', 'proof-bin'):
        (root / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    write(root / 'bin/busybox', blobs['busybox'], True)
    for applet in ('sh', 'mount', 'sleep', 'cat', 'sed', 'rm', 'ls', 'tr', 'mkdir',
                   'sync', 'poweroff', 'dmesg', 'grep'):
        (root / 'bin' / applet).symlink_to('busybox')
    write(root / 'proof/helpers.sh', bounded + '\n' + helpers)
    write(root / 'proof/unload-projection.sh', projection)
    write(root / 'proof-bin/rmmod', RMMOD, True)
    write(root / 'proof-bin/block', '#!/bin/sh\nexec /bin/busybox sleep 30\n', True)
    write(root / 'init', GUEST, True)
    archive(root, out / 'helper-initramfs.cpio.gz')
    command = [str(args.qemu),
               '-no-user-config', '-nodefaults', '-machine', 'q35,accel=kvm', '-cpu', 'host',
               '-m', '256', '-smp', '1', '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-kernel', str(out / 'inputs/bzImage'),
               '-initrd', str(out / 'helper-initramfs.cpio.gz'),
               '-append', 'console=ttyS0 rdinit=/init panic=-1']
    write(out / 'qemu-command.json', json.dumps(command, indent=2) + '\n')
    verify_inputs(tracked_inputs)
    helper_process = owned_process(command, out, 'helper-console', 90)
    verify_inputs(tracked_inputs)
    require(not helper_process['deadline_fired'] and helper_process['returncode'] == 0,
            'helper QEMU failed or host deadline fired; STOP before another VM')
    text = (out / 'helper-console.log').read_text(errors='replace').replace('\r', '')
    lines = text.splitlines()
    for marker in ('PROOF_HELPER_CONTROLS=PASS', 'PROOF_GUEST=PASS',
                   'PROOF_FINISH status=0', 'PROOF_POWEROFF'):
        require(lines.count(marker) == 1, 'missing/repeated ' + marker)
    require('PROOF_ASSERT_FAIL' not in text, 'guest assertion failed')
    region(text, 'PROOF_DMESG_BEGIN', 'PROOF_DMESG_END')
    injected = region(text, 'PROOF_INJECT_BEGIN', 'PROOF_INJECT_END')
    wanted = ['XDEV_EXT_GPU_PROBLEM case=ce-chain-d reason=timeout limit_s=2',
              'XDEV_EXT_GPU_PROBLEM case=detach-ce-plan reason=timeout limit_s=1',
              'PROOF_CLEANUP_LIMIT=1', 'XDEV_EXT_GPU_UNLOAD=PASS',
              'PROOF_UNLOAD_ATTEMPT module=nvidia_uvm', 'PROOF_UNLOAD_ATTEMPT module=nvidia']
    for marker in wanted:
        require(injected.splitlines().count(marker) == 1, 'missing/repeated ' + marker)
    for name in ('ce-chain-a', 'peer-nvme', 'dmabuf-peer'):
        require(injected.splitlines().count('XDEV_EXT_GPU_CASE name=' + name +
                ' result=FAIL reason=skipped-after-timeout') == 1, 'missing skip ' + name)
    for mode, reason in (('ERROR', 'reason=error'), ('TIMEOUT', 'reason=timeout limit_s=1')):
        control = region(text, 'PROOF_UNLOAD_' + mode + '_BEGIN', 'PROOF_UNLOAD_' + mode + '_END')
        unload_lines = [line for line in control.splitlines() if line.startswith('XDEV_EXT_GPU_UNLOAD=')]
        expected_line = 'XDEV_EXT_GPU_UNLOAD=FAIL module=nvidia ' + reason + \
            ' refcnt=0 holders= error=' + ('diagnostic-userspace-refusal ' if mode == 'ERROR' else '')
        require(unload_lines == [expected_line], 'exact unload negative control mismatch: ' + mode)
    require('XDEV_EXT_GPU_CAPS ' not in text and 'XDEV_EXT_GPU_MODULES=PASS' not in text,
            'unexpected fabricated hardware evidence')
    helper_diagnostics = debug_gate(out, 'helper-console', args.debug_locking)
    write(out / 'injected.log', injected)
    stripped = '\n'.join(line for line in injected.splitlines()
                         if not line.startswith('XDEV_EXT_GPU_PROBLEM ')) + '\n'
    write(out / 'without-problem-markers.log', stripped)
    results = {}
    for name in ('injected', 'without-problem-markers'):
        validator_command = [sys.executable, '-I', str(out / 'source/xdev_ext_gpu_validate.py'),
                             str(out / (name + '.log')), str(out / (name + '.json')),
                             '--release', 'diagnostic-no-device', '--device', 'absent']
        result = owned_process(validator_command, out, name + '-validator', 10)
        require(not result['deadline_fired'] and result['returncode'] == 1,
                'actual validator must reject diagnostic log ' + name)
        results[name] = json.loads((out / (name + '.json')).read_text())
        require(results[name]['verdict'] == 'FAIL', 'diagnostic accepted by validator')
    expected = ['guest problem: case ce-chain-d reason=timeout',
                'guest problem: case detach-ce-plan reason=timeout']
    for problem in expected:
        require(results['injected']['problems'].count(problem) == 1, 'problem not recognized')
        require(problem not in results['without-problem-markers']['problems'],
                'marker-stripped differential did not change validator diagnosis')

    # Only the verified, reaped first QEMU may be followed by this final boot.
    # No more VMs launch after the deliberate external-watchdog treatment.
    write(root / 'init', WATCHDOG_GUEST, True)
    archive(root, out / 'watchdog-initramfs.cpio.gz')
    watchdog_command = list(command)
    watchdog_command[watchdog_command.index('-initrd') + 1] = str(out / 'watchdog-initramfs.cpio.gz')
    write(out / 'watchdog-qemu-command.json', json.dumps(watchdog_command, indent=2) + '\n')
    verify_inputs(tracked_inputs)
    watchdog_process = owned_process(watchdog_command, out, 'watchdog-console', 10)
    verify_inputs(tracked_inputs)
    require(watchdog_process['deadline_fired'] and watchdog_process['state'] == 'REAPED',
            'watchdog control did not hit deadline and reap')
    require(any(event['action'] in ('SIGTERM', 'SIGKILL') and event.get('delivered')
                for event in watchdog_process['events']), 'watchdog sent no termination signal')
    watchdog_text = (out / 'watchdog-console.log').read_text(errors='replace').replace('\r', '')
    require(watchdog_text.splitlines().count('PROOF_WATCHDOG_ARMED') == 1,
            'watchdog control never reached userspace blocking phase')
    require('PROOF_POWEROFF' not in watchdog_text and 'Power down' not in watchdog_text,
            'watchdog guest unexpectedly powered off')
    region(watchdog_text, 'PROOF_WATCHDOG_DMESG_BEGIN', 'PROOF_WATCHDOG_DMESG_END')
    watchdog_diagnostics = debug_gate(out, 'watchdog-console', args.debug_locking)
    verify_inputs(tracked_inputs)
    write(out / 'input-recheck-final.json', json.dumps(tracked_inputs, indent=2) + '\n')
    write(out / 'proof-result.json', json.dumps(dict(verdict='PASS',
          scope=receipt['scope'], helper_qemu=helper_process, watchdog_qemu=watchdog_process,
          original_helper_diagnostics=helper_diagnostics, original_watchdog_diagnostics=watchdog_diagnostics,
          validator_injected='FAIL with both exact guest problems',
          validator_without_markers='FAIL without guest problem diagnoses; no fake hardware'), indent=2) + '\n')
    print('codex_115 PROOF=PASS scope=shell-watchdog-userspace-unload-attempt-only evidence=' + str(out))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print('codex_115 PROOF=FAIL ' + str(error), file=sys.stderr)
        sys.exit(1)
