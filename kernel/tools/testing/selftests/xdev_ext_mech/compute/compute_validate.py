#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Disk images and the host-side verdict of the BPF compute KVM run.

make-images DIR
    private source and destination NVMe images
validate --dir DIR --log LOG --layout LAYOUT --result JSON [--red]
    every guest marker, no failed case, a clean kernel console, and a
    whole-destination comparison with an independent oracle: Python CRC32C
    and XOR, not the kernel's or the program's code
The plan is duplicated, not shared, with guest/run-guest.sh: a guest that
drifts from it fails here. --red accepts only the expected first failure on
a kernel without the compute member.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

LBA = 512
SOURCE_BYTES = 2 << 20
DEST_BYTES = 4 << 20
GUARD = 0x6B
GROUPS = 16
GROUP_BYTES = 8192
SOURCE_SLBA = 2048
NLB = GROUPS * GROUP_BYTES // LBA
XOR = 0x5A
# destination slba -> what the stage wrote there (None: nothing).
REGIONS = {
    1024: 'seal',          # old-layout object, fixed CRC32C_SEAL
    2048: 'xor-seal',      # compute mode 0
    3072: 'xor-seal',      # compute mode 3 (probe, then as 0)
    4096: None,            # wrong recorded length: every batch failed
    5120: None,            # the program's -EBADMSG
    6144: None,            # no compute program: CREATE refused
    7168: None,            # declared change before NVMe: CREATE refused
}
CASES = ('attach-compute', 'compute-xor-seal', 'delta-before-nvme', 'compute-probe',
         'bad-set-len', 'program-error', 'attach-old-layout', 'old-layout-seal',
         'no-compute-program', 'verifier-run_compute', 'verifier-run', 'verifier-run_state')
MARKERS = ('XDEV_EXT_MECH_VERIFIER_COMPUTES=PASS cases=7',
           'XDEV_EXT_MECH_VERIFIER_NEGATIVES=PASS cases=7',
           'XDEV_EXT_MECH_VERIFIER_STATES=PASS cases=2',
           'XDEV_EXT_COMPUTE_GUEST=PASS',
           'XDEV_EXT_COMPUTE_GUEST_EXIT=0')


def _crc_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    return table


CRC_TABLE = _crc_table()


def crc32c(data):
    """Standard CRC-32C (Castagnoli), reflected, init and final XOR all ones."""
    crc = 0xFFFFFFFF
    for b in data:
        crc = CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def frames(group, seg_len):
    """The frames of one batch: seg_len bytes each, the last one shorter."""
    return [group[i:i + seg_len] for i in range(0, len(group), seg_len)]


def seal(frame):
    body = bytes(frame[:-4])
    return body + crc32c(body).to_bytes(4, 'little')


def xor_seal(frame):
    body = bytes(b ^ XOR for b in frame[:-4])
    return body + crc32c(body).to_bytes(4, 'little')


def transform(source, kind, seg_len):
    out = bytearray()
    for g in range(0, len(source), GROUP_BYTES):
        for frame in frames(source[g:g + GROUP_BYTES], seg_len):
            out += seal(frame) if kind == 'seal' else xor_seal(frame)
    return bytes(out)


def pattern(name, size):
    return hashlib.shake_256(b'XDEV_EXT BPF compute ' + name.encode()).digest(size)


def make_images(directory):
    directory = Path(directory)
    (directory / 'source.raw').write_bytes(pattern('source', SOURCE_BYTES))
    (directory / 'destination.raw').write_bytes(bytes([GUARD]) * DEST_BYTES)


def expected_destination(source, seg_len):
    window = source[SOURCE_SLBA * LBA:(SOURCE_SLBA + NLB) * LBA]
    expected = bytearray([GUARD]) * DEST_BYTES
    for slba, kind in REGIONS.items():
        if kind:
            expected[slba * LBA:(slba + NLB) * LBA] = transform(window, kind, seg_len)
    return expected


def check_images(directory, seg_len):
    directory = Path(directory)
    source = (directory / 'source.raw').read_bytes()
    destination = (directory / 'destination.raw').read_bytes()
    if source != pattern('source', SOURCE_BYTES):
        return 'source image changed'
    if len(destination) != DEST_BYTES:
        return 'destination size changed'
    expected = expected_destination(source, seg_len)
    if destination != expected:
        first = next(i for i in range(DEST_BYTES) if destination[i] != expected[i])
        region = max((s for s in REGIONS if s * LBA <= first), default=None)
        return f'destination differs from the oracle at byte {first} (region slba {region})'
    return None


def parse_layout(text):
    values = dict(w.split('=', 1) for w in text.split())
    return {k: int(v) for k, v in values.items()}


def check_log(text, red=False):
    """Problems in the guest console, as a list of strings."""
    errors = []
    lines = text.replace('\r', '').splitlines()
    passed = {m.group(1) for m in (re.match(r'^XDEV_EXT_COMPUTE_CASE=PASS name=(\S+)', l)
                                   for l in lines) if m}
    failed = [l for l in lines if l.startswith('XDEV_EXT_COMPUTE_CASE=FAIL')]
    if red:
        if failed[:1] != ['XDEV_EXT_COMPUTE_CASE=FAIL name=attach-compute reason=attach-failed']:
            errors.append('red: first failure is not the compute attach: %r' % failed[:1])
        elif not any('compute' in l and ('not found' in l or 'kernel' in l) for l in lines):
            errors.append('red: libbpf did not refuse the compute member')
        if passed:
            errors.append('red: cases passed on a kernel without compute: %s' % sorted(passed))
        return errors
    errors += ['failed case: ' + l for l in failed]
    errors += ['missing case: ' + c for c in CASES if c not in passed]
    errors += ['missing marker: ' + m for m in MARKERS if m not in lines]
    errors += ['TAP failure: ' + l for l in lines if re.match(r'^not ok\b', l)]
    return errors


def check_console(text):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'xdev_ext_integration'))
    from xdev_ext_mech_zc_debug import debug_reports
    counts = debug_reports(text)
    return [] if not any(counts.values()) else ['kernel diagnostic: ' + json.dumps(counts, sort_keys=True)]


def validate(directory, log, layout, result, red=False):
    text = Path(log).read_text(errors='replace')
    geometry = parse_layout(Path(layout).read_text())
    errors = check_log(text, red)
    errors += check_console(text)
    if not red:
        image = check_images(directory, geometry['seg_len'])
        if image:
            errors.append(image)
    verdict = {'pass': not errors, 'red': red, 'errors': errors, 'layout': geometry,
               'regions': {str(k): v for k, v in REGIONS.items()}, 'groups': GROUPS,
               'group_bytes': GROUP_BYTES, 'oracle': 'python crc32c + xor'}
    Path(result).write_text(json.dumps(verdict, indent=1, sort_keys=True) + '\n')
    for e in errors:
        print('FAIL ' + e)
    return 0 if not errors else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    images = sub.add_parser('make-images')
    images.add_argument('dir')
    check = sub.add_parser('validate')
    check.add_argument('--dir', required=True)
    check.add_argument('--log', required=True)
    check.add_argument('--layout', required=True)
    check.add_argument('--result', required=True)
    check.add_argument('--red', action='store_true')
    args = parser.parse_args()
    if args.action == 'make-images':
        make_images(args.dir)
        return 0
    return validate(args.dir, args.log, args.layout, args.result, args.red)


if __name__ == '__main__':
    sys.exit(main())
