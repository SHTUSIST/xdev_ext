#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host oracle for the dma-buf device-DMA guest test (dmabuf_device_dma.c).

It regenerates the source image, rebuilds the whole expected destination image
from the frozen plan, and checks the guest's TAP stream, its accounting and
attachment observations, the kernel console, and (with --viommu) that the
emulated IOMMU translated every NVMe function in its own group with no fault.
The plan is duplicated here on purpose, not imported from the guest program.
Correctness only: no timing is read or reported.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parents[2] / 'integration/session/native'
sys.path.insert(0, str(NATIVE))
from xdev_ext_mech_zc_debug import check_console  # noqa: E402
from xdev_ext_mech_zc_viommu import validate_viommu_console  # noqa: E402

LBA = 512
IMAGE = 32 << 20
GUARD = 0x6b
EXPORT = 65536
PAGE = 4096
PAGES = EXPORT // PAGE
GROUP = 8192
PLANS = (
    'PLAN case=batch-read src_slba=2048 pages=16 order=reverse',
    'PLAN case=batch-write dst_slba=2048 pages=16 pattern=xor5a',
    'PLAN case=chain frame=4096 seg=4096 group=8192 depth=4 groups=96 src_slba=4096 dst_slba=4096 copies=ALL',
    'PLAN case=exporter-close frame=4096 seg=4096 group=8192 depth=4 groups=1024 src_slba=8192 dst_slba=8192 copies=ALL',
    'PLAN case=kill frame=4096 seg=4096 group=8192 depth=4 groups=512 src_slba=32768 dst_slba=32768 copies=PART',
    'PLAN case=victim frame=4096 seg=4096 group=8192 depth=4 groups=1536 src_slba=40960 dst_slba=40960 copies=ALL',
)
FINAL = ('XDEV_EXT_DMABUF_DMA=PASS cases=batch-read,batch-write,chain,exporter-close,kill,victim '
         'exporter=system-heap requesters=2 timing=none')
BATCH_READ_SLBA = 2048
BATCH_WRITE_SLBA = 2048
ALL_CASES = ((4096, 96), (8192, 1024), (40960, 1536))
KILL_SLBA, KILL_GROUPS = 32768, 512


def make_source():
    out = bytearray()
    for sector in range(IMAGE // LBA):
        out += hashlib.sha256(b'xdev-dmabuf-dma' + sector.to_bytes(8, 'little')).digest() * 16
    return bytes(out)


def write_pattern():
    return bytes((((offset * 131) + 7) & 0xff) ^ 0x5a for offset in range(EXPORT))


def fnv64(data):
    value = 0xcbf29ce484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    return value


def check_tap(lines):
    if lines.count('TAP version 13') != 1:
        raise ValueError('TAP: exactly one "TAP version 13" header required')
    plans = [line for line in lines if re.fullmatch(r'1\.\.[0-9]+', line)]
    if len(plans) != 1:
        raise ValueError('TAP: exactly one plan line required')
    numbers = []
    for line in lines:
        if re.match(r'not ok [0-9]+', line):
            raise ValueError('TAP: failed check: ' + line)
        match = re.match(r'ok ([0-9]+) - ', line)
        if match:
            if re.search(r'#\s*(SKIP|TODO)', line, re.I):
                raise ValueError('TAP: skipped or todo check: ' + line)
            numbers.append(int(match.group(1)))
    count = int(plans[0][3:])
    if numbers != list(range(1, count + 1)):
        raise ValueError('TAP: checks %d do not match plan 1..%d' % (len(numbers), count))
    return count


def observations(lines):
    seen = {}
    for line in lines:
        if not line.startswith('OBSERVE '):
            continue
        fields = dict(item.split('=', 1) for item in line.split()[1:] if '=' in item)
        seen.setdefault(fields.get('case', ''), []).append(fields)
    return seen


def one(seen, case, key):
    values = [entry[key] for entry in seen.get(case, ()) if key in entry]
    if len(values) != 1:
        raise ValueError('expected one %s observation for case %s, got %d' % (key, case, len(values)))
    return values[0]


def validate(source, dest, log, viommu=False):
    if len(source) != IMAGE or len(dest) != IMAGE:
        raise ValueError('image size differs from the frozen 32 MiB plan')
    expected_source = make_source()
    if source != expected_source:
        raise ValueError('source image changed or differs from the generated pattern')
    text = log.replace('\r', '')
    lines = [line.strip() for line in text.splitlines()]
    if 'XDEV_EXT_DMABUF_GUEST_EXIT=0' not in lines:
        raise ValueError('guest exit status 0 not reported')
    checks = check_tap(lines)
    if FINAL not in lines:
        raise ValueError('final PASS line missing')
    plans = tuple(line for line in lines if line.startswith('PLAN '))
    if plans != PLANS:
        raise ValueError('guest plan mismatch: %r' % (plans,))
    seen = observations(lines)

    read_view = b''.join(source[(BATCH_READ_SLBA + (PAGES - 1 - i) * (PAGE // LBA)) * LBA:][:PAGE]
                         for i in range(PAGES))
    if one(seen, 'batch-read', 'fnv64') != '%016x' % fnv64(read_view):
        raise ValueError('batch-read CPU view of the dma-buf differs from the source pages')

    nvme = sorted(set(re.findall(r'nvme nvme[0-9]+: pci function (0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])', text)))
    if len(nvme) != 2:
        raise ValueError('expected two NVMe PCI functions in the guest log, found %d' % len(nvme))
    for case in ('batch', 'chain', 'exporter-close', 'victim'):
        base = int(one(seen, case, 'vmpin_baseline'))
        registered = int(one(seen, case, 'vmpin_registered'))
        closed = int(one(seen, case, 'vmpin_closed'))
        if registered - base != EXPORT or closed != base:
            raise ValueError('VmPin accounting for %s: baseline=%d registered=%d closed=%d'
                             % (case, base, registered, closed))
        attached = sorted(one(seen, case, 'attached').split(','))
        if attached != nvme:
            raise ValueError('dma-buf attached devices for %s are %s, expected both NVMe requesters %s'
                             % (case, attached, nvme))
        if one(seen, case, 'bufinfo_after_close') != 'absent':
            raise ValueError('dma-buf still listed in bufinfo after final close: ' + case)
    caps = [entry for entry in seen.get('chain', ()) if 'stage' in entry]
    if sorted(entry['stage'] for entry in caps) != ['0', '1']:
        raise ValueError('stage caps: need one observation per chain stage')
    for entry in caps:
        if (entry.get('family'), entry.get('reachability'), entry.get('requester_mapping'),
                entry.get('backing'), entry.get('refused')) != ('2', '7', '1', '0x22', '0x0'):
            raise ValueError('stage caps differ from STORAGE/HOST_DMA_MAPPED/ESTABLISHED/HOST_SYSTEM: %r' % entry)
    if one(seen, 'exporter-close', 'exporter_fd_closed_inflight') != '1' or \
            int(one(seen, 'exporter-close', 'done_at_close')) >= int(one(seen, 'exporter-close', 'groups')):
        raise ValueError('exporter fd was not closed while the session still had batches outstanding')
    if (one(seen, 'kill', 'quota_while_owner_alive'), one(seen, 'kill', 'quota_after_owner_exit')) != ('ENOMEM', 'ok'):
        raise ValueError('kill: MEMLOCK quota not held by the live owner or not returned after its exit')
    if one(seen, 'kill', 'bufinfo_after_owner_exit') != 'absent':
        raise ValueError('kill: dma-buf still listed in bufinfo after the owner exited')
    if one(seen, 'victim', 'running_at_kill') != '1' or \
            int(one(seen, 'victim', 'done_at_kill')) >= int(one(seen, 'victim', 'groups')):
        raise ValueError('victim session had already finished when the other importer was killed')

    expected = bytearray([GUARD]) * IMAGE
    offset = BATCH_WRITE_SLBA * LBA
    expected[offset:offset + EXPORT] = write_pattern()
    for slba, groups in ALL_CASES:
        start = slba * LBA
        expected[start:start + groups * GROUP] = source[start:start + groups * GROUP]
    copied = 0
    guard = bytes([GUARD]) * GROUP
    for group in range(KILL_GROUPS):
        start = KILL_SLBA * LBA + group * GROUP
        actual = dest[start:start + GROUP]
        if actual == source[start:start + GROUP]:
            expected[start:start + GROUP] = actual
            copied += 1
        elif actual != guard:
            raise ValueError('kill group %d is neither its source group nor untouched guard' % group)
    if copied != int(one(seen, 'kill', 'copied_groups')):
        raise ValueError('kill copied groups %d differ from the guest report' % copied)
    if bytes(expected) != dest:
        first = next(i for i in range(IMAGE) if expected[i] != dest[i])
        raise ValueError('destination image differs from the expected image at byte %d' % first)

    check_console(text)
    result = dict(checks=checks, requesters=nvme, kill_copied_groups=copied, viommu=None)
    if viommu:
        report = validate_viommu_console(text)
        groups = [report['groups'][bdf] for bdf in nvme]
        if len(set(groups)) != len(groups):
            raise ValueError('NVMe requesters share one IOMMU group: %r' % groups)
        result['viommu'] = report
    elif 'DMAR: IOMMU enabled' in text:
        raise ValueError('vIOMMU off run reports DMAR enabled')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    make = sub.add_parser('make-source')
    make.add_argument('output', type=Path)
    check = sub.add_parser('validate')
    for name in ('--source', '--dest', '--log', '--result'):
        check.add_argument(name, type=Path, required=True)
    check.add_argument('--viommu', action='store_true')
    args = parser.parse_args(argv)
    if args.action == 'make-source':
        args.output.write_bytes(make_source())
        return 0
    try:
        result = validate(args.source.read_bytes(), args.dest.read_bytes(),
                          args.log.read_text(errors='replace'), viommu=args.viommu)
    except ValueError as error:
        args.result.write_text(json.dumps(dict(status='FAIL', reason=str(error))) + '\n')
        print('XDEV_EXT_DMABUF_DMA_HOST=FAIL ' + str(error))
        return 1
    result['status'] = 'PASS'
    args.result.write_text(json.dumps(result, sort_keys=True) + '\n')
    print('XDEV_EXT_DMABUF_DMA_HOST=PASS checks=%d requesters=%s kill_copied=%d viommu=%s'
          % (result['checks'], ','.join(result['requesters']), result['kill_copied_groups'],
             'on' if args.viommu else 'off'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
