#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Disk images and the host-side verdict of the stage-polling KVM run.

make-images DIR       private source, destination and spare NVMe images
validate --dir DIR --log LOG --result JSON
                      every guest marker, no failed TAP line, and an
                      independent whole-destination check against the source
The plan below is duplicated, not shared, with guest/nvme_poll_e2e.c and
guest/run-guest.sh: a guest that drifts from it fails here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

LBA = 512
SOURCE_BYTES = 32 << 20
DEST_BYTES = 32 << 20
SPARE_BYTES = 16 << 20
GUARD = 0x6B
# (destination slba, source slba, bytes) written with source data.
COPIES = ((4096, 2048, 256 * 4096), (8192, 2048, 256 * 4096), (32768, 32768, 16 * 8192))
STOP_WINDOW = (16384, 8192)        # destination slba, nlb: contents not specified
MARKERS = (
    'XDEV_EXT_POLL_NVME=PASS',
    'XDEV_EXT_NVME_POLL=PASS cases=polled-copy,plain-copy,polled-stop timing=none',
    'XDEV_EXT_NVME_POLL_RESET=PASS cases=lost-queues,refuse timing=none',
    'XDEV_EXT_POLL_NVME_RESET=PASS',
    'XDEV_EXT_POLL_DMA=PASS cases=poll,plain,stop,refuse-provider,refuse-class backend=CPU-memcpy',
    'XDEV_EXT_POLL_NIC_REFUSE=PASS reason=no-napi-deferral create=-EOPNOTSUPP',
    'XDEV_EXT_POLL_NIC_REFUSE=PASS reason=copy-transmit create=-EOPNOTSUPP',
    'XDEV_EXT_POLL_NIC=PASS chain=nvme-read,afxdp-tx-zc,afxdp-rx,nvme-write data=identical',
    'XDEV_EXT_POLL_DMESG=PASS no_completion_polled_timeout=1 no_deferred_drain=1 no_warning=1',
    'XDEV_EXT_POLL_GUEST=PASS',
    'XDEV_EXT_POLL_GUEST_EXIT=0',
)
DMA_CASES = ('poll', 'plain', 'stop', 'refuse-provider', 'refuse-class')


def pattern(name, size):
    return hashlib.shake_256(b'XDEV_EXT stage polling ' + name.encode()).digest(size)


def make_images(directory):
    directory = Path(directory)
    (directory / 'source.raw').write_bytes(pattern('source', SOURCE_BYTES))
    (directory / 'destination.raw').write_bytes(bytes(DEST_BYTES))
    (directory / 'spare.raw').write_bytes(pattern('spare', SPARE_BYTES))


def expected_destination(source):
    expected = bytearray([GUARD]) * DEST_BYTES
    for dst, src, size in COPIES:
        expected[dst * LBA:dst * LBA + size] = source[src * LBA:src * LBA + size]
    return expected


def check_images(directory):
    directory = Path(directory)
    source = (directory / 'source.raw').read_bytes()
    destination = (directory / 'destination.raw').read_bytes()
    if source != pattern('source', SOURCE_BYTES):
        return 'source image changed'
    if len(destination) != DEST_BYTES:
        return 'destination size changed'
    expected = expected_destination(source)
    start, nlb = STOP_WINDOW
    expected[start * LBA:(start + nlb) * LBA] = destination[start * LBA:(start + nlb) * LBA]
    if destination != expected:
        first = next(i for i in range(DEST_BYTES) if destination[i] != expected[i])
        return f'destination differs from both copies plus guards at byte {first}'
    return None


def check_log(text):
    errors = []
    for marker in MARKERS:
        if not re.search('^' + re.escape(marker) + r'\s*$', text, re.M):
            errors.append('missing marker: ' + marker)
    for case in DMA_CASES:
        if not re.search(r'^PASS poll case=' + re.escape(case) + r' ', text, re.M):
            errors.append('missing DMA case: ' + case)
    if len(re.findall(r'^XDEV_EXT_POLL_IO_POLL controller=nvme\d+ io_poll=1\s*$', text, re.M)) != 3:
        errors.append('not every controller started with poll queues')
    if not re.search(r'^XDEV_EXT_POLL_DMESG_RESET=PASS no_completion_polled_timeout=1 no_deferred_drain=1 '
                     r'upstream_group_cpus_warnings=\d+ other_warnings=0\s*$', text, re.M):
        errors.append('missing marker: XDEV_EXT_POLL_DMESG_RESET=PASS')
    if re.search(r'^not ok\b', text, re.M):
        errors.append('a guest TAP check failed')
    if re.search(r'^FAIL\b', text, re.M):
        errors.append('a guest step failed')
    return errors


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    images = sub.add_parser('make-images')
    images.add_argument('dir')
    validate = sub.add_parser('validate')
    validate.add_argument('--dir', required=True)
    validate.add_argument('--log', required=True)
    validate.add_argument('--result', required=True)
    args = parser.parse_args()
    if args.command == 'make-images':
        make_images(args.dir)
        return 0
    text = Path(args.log).read_text(errors='replace').replace('\r', '')
    errors = check_log(text)
    image_error = check_images(args.dir)
    if image_error:
        errors.append(image_error)
    result = {'verdict': 'FAIL' if errors else 'PASS', 'errors': errors,
              'claim': 'KVM correctness only; QEMU NVMe and virtio-net; DMA provider is CPU memcpy; no timing'}
    Path(args.result).write_text(json.dumps(result, indent=2) + '\n')
    print('XDEV_EXT_POLL_VALIDATE=' + result['verdict'] + (' ' + '; '.join(errors) if errors else ''))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
