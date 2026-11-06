#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host test of the NVMe LBA window handle code (prototype for ASK.69).

host_window_test.py [SOURCE_ROOT]. Pastes the production window handle code
and nvme_xdev_ext_member_bind verbatim into host_window_fixture.c, runs it
under gcc and UBSan, then requires every listed mutant of the production
code to make the fixture fail. A missing anchor or a mutant that does not
compile is SETUP (exit 2), never a kill. No devices, no DMA.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE.parents[3]
NATIVE = ROOT / 'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c'


def function(text, name):
    """One C definition with its whole body, braces counted outside comments/strings."""
    found = list(re.finditer(r'^\w[^;{}]*\b' + re.escape(name) + r'\([^;{}]*\)\s*\{', text, re.M))
    if len(found) != 1:
        raise SystemExit('SETUP %s: %d definitions' % (name, len(found)))
    start = found[0].start()
    scan = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"', lambda m: ' ' * len(m[0]),
                  text[start:], flags=re.S)
    depth = 0
    for i in range(scan.index('{'), len(scan)):
        depth += scan[i] == '{'
        depth -= scan[i] == '}'
        if not depth:
            return text[start:start + i + 1]
    raise SystemExit('SETUP %s: unbalanced' % name)


def production():
    text = NATIVE.read_text()
    begin = text.find('struct nvme_xdev_ext_window_handle {')
    if begin < 0 or text.count('struct nvme_xdev_ext_window_handle {') != 1:
        raise SystemExit('SETUP window handle block not found exactly once')
    admit = function(text, 'nvme_xdev_ext_window_admit')
    end = text.index(admit) + len(admit)
    return text[begin:end] + '\n\n' + function(text, 'nvme_xdev_ext_member_bind') + '\n'


MUTANTS = [
    ('bind-skips-window-admit', 'ret = nvme_xdev_ext_window_admit(st, write);', 'ret = 0;'),
    ('bind-uses-handle-as-namespace', 'nvme_xdev_ext_class_ns(nvme_xdev_ext_window_target(st->file))',
     'nvme_xdev_ext_class_ns(st->file)'),
    ('admit-ignores-handles', '\tif (st->file->f_op != &nvme_xdev_ext_window_fops)\n\t\treturn 0;\n\tw = st->file->private_data;',
     '\tif (st->file)\n\t\treturn 0;\n\tw = st->file->private_data;'),
    ('admit-wrong-direction', 'xdev_ext_stor_grant_admit(&w->grant, write, st->arg0, st->arg1)',
     'xdev_ext_stor_grant_admit(&w->grant, true, st->arg0, st->arg1)'),
    ('issue-no-overlap-check', '\t\tif (o->head == w->head &&\n\t\t    xdev_ext_stor_grant_conflict(&o->grant, &w->grant)) {',
     '\t\tif (0 && o->head == w->head &&\n\t\t    xdev_ext_stor_grant_conflict(&o->grant, &w->grant)) {'),
    ('issue-overlap-ignores-namespace', '\t\tif (o->head == w->head &&', '\t\tif ((o->head || w->head) &&'),
    ('issue-no-fd-mode-check', '\tif (!(file->f_mode & FMODE_WRITE) ||\n\t    (rd && !(file->f_mode & FMODE_READ)))\n\t\treturn -EBADF;',
     '\tif (0 && (!(file->f_mode & FMODE_WRITE) ||\n\t    (rd && !(file->f_mode & FMODE_READ))))\n\t\treturn -EBADF;'),
    ('issue-read-handle-from-read-only-fd', '\tif (!(file->f_mode & FMODE_WRITE) ||',
     '\tif (((access & XDEV_EXT_STOR_GRANT_WRITE) && !(file->f_mode & FMODE_WRITE)) ||'),
    ('issue-no-read-fd-check', '\t    (rd && !(file->f_mode & FMODE_READ)))', '\t    (0 && rd && !(file->f_mode & FMODE_READ)))'),
    ('issue-no-native-policy', '\tif (!nvme_xdev_ext_mech_cmd_allowed(ns, file, true) ||\n\t    (rd && !nvme_xdev_ext_mech_cmd_allowed(ns, file, false)))',
     '\tif (0 && (!nvme_xdev_ext_mech_cmd_allowed(ns, file, true) ||\n\t    (rd && !nvme_xdev_ext_mech_cmd_allowed(ns, file, false))))'),
    ('issue-read-handle-skips-write-policy', '\tif (!nvme_xdev_ext_mech_cmd_allowed(ns, file, true) ||',
     '\tif (((access & XDEV_EXT_STOR_GRANT_WRITE) && !nvme_xdev_ext_mech_cmd_allowed(ns, file, true)) ||'),
    ('issue-no-read-policy', '\t    (rd && !nvme_xdev_ext_mech_cmd_allowed(ns, file, false)))',
     '\t    (0 && rd && !nvme_xdev_ext_mech_cmd_allowed(ns, file, false)))'),
    ('issue-no-rsvd-check', '\tif (u.rsvd)\n\t\treturn -EINVAL;', '\tif (0 && u.rsvd)\n\t\treturn -EINVAL;'),
    ('issue-ignores-namespace-state', '\tif (!ret && (!id.namespace_ready || id.namespace_removing))',
     '\tif (0 && !ret && (!id.namespace_ready || id.namespace_removing))'),
    ('issue-ignores-removing', '(!id.namespace_ready || id.namespace_removing)', '(!id.namespace_ready || 0)'),
    ('issue-busy-leaks-reserved-fd', '\t\t\tmutex_unlock(&nvme_xdev_ext_windows_lock);\n\t\t\tput_unused_fd(fd);\n',
     '\t\t\tmutex_unlock(&nvme_xdev_ext_windows_lock);\n'),
    ('issue-always-read-write', '\t\t\t!(u.flags & XDEV_EXT_STOR_GRANT_WRITE) ? O_RDONLY :',
     '\t\t\t0 ? O_RDONLY :'),
    ('release-stays-listed', '\tlist_del_init(&w->node);\n\tmutex_unlock', '\tmutex_unlock'),
    ('release-keeps-holder-pin', '\tfput(w->target);\n\tkfree(w);\n\treturn 0;', '\tkfree(w);\n\treturn 0;'),
    ('issue-lists-before-check', '\tlist_add(&w->node, &nvme_xdev_ext_windows);\n\tmutex_unlock(&nvme_xdev_ext_windows_lock);\n\tfd_install',
     '\tmutex_unlock(&nvme_xdev_ext_windows_lock);\n\tfd_install'),
]


IOCTL = re.compile(r"^#define\s+(\w+)\s+_IO(?:R|W|WR)?\(\s*'N'\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*[,)]", re.M)
# 'N' ranges of the upstream registry,
# Documentation/userspace-api/ioctl/ioctl-number.rst: scanner, nvme, ntsync.
UPSTREAM_N = ((0x00, 0x1f), (0x40, 0x7f), (0x80, 0x8f))


def uapi_number_check():
    """The window ioctl has its own ('N', nr): no product ioctl and no
    upstream-registered range shares it, so the size field is never the only
    thing telling two commands apart."""
    numbers = {}
    for header in sorted((ROOT / 'src').glob('*/include/uapi/linux/*.h')):
        for name, nr in IOCTL.findall(header.read_text()):
            numbers.setdefault(int(nr, 0), []).append(name)
    window = [nr for nr, names in numbers.items() if 'NVME_IOCTL_XDEV_EXT_WINDOW' in names]
    if len(window) != 1:
        raise SystemExit('SETUP NVME_IOCTL_XDEV_EXT_WINDOW defined %d times' % len(window))
    nr = window[0]
    shared = [name for name in numbers[nr] if name != 'NVME_IOCTL_XDEV_EXT_WINDOW']
    if shared:
        return "FAIL uapi: NVME_IOCTL_XDEV_EXT_WINDOW shares 'N' 0x%02x with %s" % (nr, ', '.join(shared))
    if any(low <= nr <= high for low, high in UPSTREAM_N):
        return "FAIL uapi: 'N' 0x%02x lies in an upstream-registered range" % nr
    return "PASS uapi: 'N' 0x%02x used once among %d 'N' ioctls" % (nr, sum(map(len, numbers.values())))


def build_and_run(directory, code, profile):
    fixture = (HERE / 'host_window_fixture.c').read_text()
    if fixture.count('/* PRODUCTION */') != 1:
        raise SystemExit('SETUP fixture marker')
    probe = directory / ('probe-%s.c' % profile)
    probe.write_text(fixture.replace('/* PRODUCTION */', code))
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
             '-Wno-unused-parameter']
    if profile == 'ubsan':
        flags += ['-fsanitize=undefined', '-fno-sanitize-recover=all']
    binary = directory / ('probe-' + profile)
    build = subprocess.run(['gcc', *flags, '-I' + str(ROOT / 'src/storage/include/linux'),
                            '-I' + str(ROOT / 'src/storage/include/uapi/linux'), str(probe),
                            '-o', str(binary)], capture_output=True, text=True)
    if build.returncode:
        return None, build.stderr
    run = subprocess.run([str(binary)], capture_output=True, text=True)
    return run, run.stdout + run.stderr


def main():
    verdict = uapi_number_check()
    print(verdict)
    if not verdict.startswith('PASS'):
        return 1
    code = production()
    rc = 0
    with tempfile.TemporaryDirectory(prefix='window-handle-host-') as tmp:
        directory = Path(tmp)
        for profile in ('gcc', 'ubsan'):
            run, out = build_and_run(directory, code, profile)
            if run is None:
                print('SETUP compile %s\n%s' % (profile, out))
                return 2
            print(profile, out.strip())
            if run.returncode:
                return 1
        detected = 0
        for name, old, new in MUTANTS:
            if code.count(old) != 1:
                print('SETUP mutant anchor %s count %d' % (name, code.count(old)))
                rc = 2
                continue
            run, out = build_and_run(directory, code.replace(old, new, 1), 'gcc')
            if run is None:
                print('SETUP mutant %s does not compile\n%s' % (name, out[-1500:]))
                rc = 2
                continue
            fails = [line for line in out.splitlines() if line.startswith('FAIL ') or 'Assertion' in line]
            if run.returncode and fails:
                detected += 1
                print('DETECTED', name, '-', fails[0])
            else:
                print('SURVIVED', name, 'exit', run.returncode)
                rc = rc or 1
        print('%s host window handle mutants detected=%d of %d' %
              ('PASS' if detected == len(MUTANTS) and not rc else 'FAIL', detected, len(MUTANTS)))
    return rc


if __name__ == '__main__':
    sys.exit(main())
