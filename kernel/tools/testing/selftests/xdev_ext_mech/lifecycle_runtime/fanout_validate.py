#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fail-closed verdict for the existing --lifecycle KVM campaign.

Guest counters alone do not establish native execution. Require the captured
native trace and both independent sink readbacks, plus whole-image guards.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from fanout_trace import validate_trace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'xdev_ext_integration'))
from xdev_ext_mech_zc_validate import image_layout


def check_counts(text, groups, depth):
    records = re.findall(r'^XDEV_EXT_MECH_FANOUT_COUNTS=(.*)$', text, re.M)
    if len(records) != 1:
        raise ValueError('expected exactly one fanout counter record')
    record = json.loads(records[0])
    expected = dict(groups=groups, frames_per_group=6, window_groups=min(groups, depth),
                    window_frames=6 * min(groups, depth),
                    submitted=[groups, groups, groups, 0],
                    completed=[groups, groups, groups, 0], recycled=6 * groups,
                    published=0, inflight=0, sequestered=0, batches_done=groups,
                    batches_abort=0, rejects=0, protocol_err=0, timeouts=0,
                    last_err=0, state=1)
    if record.get('pass') is not True or type(record.get('session')) is not int or record['session'] <= 0:
        raise ValueError('fanout counter verdict/session invalid')
    for key, value in expected.items():
        observed = record.get(key)
        if type(observed) is not type(value) or observed != value:
            raise ValueError(f'fanout {key}: expected {value}, observed {observed}')
    session = record['session']
    ready = rf'^XDEV_EXT_MECH_READY mode=source session={session} frames=6 seg_len=1432 xsk=zc$'
    if not re.search(ready, text, re.M):
        raise ValueError('sender did not establish strict AF_XDP zero-copy')
    accounting = re.findall(rf'^XDEV_EXT_MECH_NIC_ACCOUNTING session={session} (.*)$', text, re.M)
    if len(accounting) != 1:
        raise ValueError('missing or duplicate sender NIC accounting')
    fields = dict(word.split('=', 1) for word in accounting[0].split())
    if fields.get('path') != 'zc' or fields.get('nic_copy_ops') != '0' or fields.get('nic_copy_bytes') != '0':
        raise ValueError('sender NIC copy fallback or wrong path')
    if int(fields.get('nic_zc_ops', '0')) != 6 * groups or int(fields.get('nic_zc_bytes', '0')) != groups * 8192:
        raise ValueError('sender NIC descriptor accounting incomplete')
    return record


def check_images(directory, groups):
    images = {name: (directory / name).read_bytes() for name in
              ('source-before.raw', 'source.raw', 'destination-before.raw',
               'destination.raw', 'expected.raw')}
    sizes = {len(data) for data in images.values()}
    if len(sizes) != 1 or not next(iter(sizes)):
        raise ValueError('image size changed or empty image')
    if images['source-before.raw'] != images['source.raw']:
        raise ValueError('source image changed')
    if images['destination.raw'] != images['expected.raw']:
        raise ValueError('whole destination differs from expected sinks/guards')
    layout = image_layout(groups)
    src = layout['source_slba'] * 512
    dst = layout['rx_slba'] * 512
    size = groups * 8192
    if dst + 4 * size > len(images['destination.raw']):
        raise ValueError('sink range outside image')
    payload = images['source-before.raw'][src:src + size]
    if len(payload) != size or not any(payload):
        raise ValueError('source payload empty or truncated')
    sinks = []
    for label, offset in (('nvme_write', dst), ('afxdp_peer_nvme_write', dst + size)):
        data = images['destination.raw'][offset:offset + size]
        if data != payload:
            raise ValueError(label + ' differs from source bytes')
        sinks.append(dict(sink=label, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    before, after = images['destination-before.raw'], images['destination.raw']
    if before[:dst] != after[:dst] or before[dst + 4 * size:] != after[dst + 4 * size:]:
        raise ValueError('destination guard changed')
    return dict(sinks=sinks, source_unchanged=True, whole_destination_matches=True,
                hashes={name: hashlib.sha256(data).hexdigest() for name, data in images.items()})


def validate(directory, log, groups, depth, qemu_exit):
    result = dict(schema='xdev_ext.fanout_guest.v1', status='FAIL',
                  scope='KVM guest; QEMU NVMe and virtio-net; correctness only',
                  physical_dma_verified=False, groups=groups, depth=depth, errors=[])
    try:
        if not 1 <= groups <= 1024 or not 1 <= depth <= 64:
            raise ValueError('invalid groups/depth')
        if qemu_exit != 0:
            raise ValueError(f'QEMU exit={qemu_exit}')
        text = log.replace('\r', '')
        for marker in ('XDEV_EXT_MECH_FANOUT=PASS', 'XDEV_EXT_MECH_LIFECYCLE_GUEST=PASS',
                       'XDEV_EXT_ZC_GUEST_EXIT=0'):
            if len(re.findall('^' + re.escape(marker) + '$', text, re.M)) != 1:
                raise ValueError('missing/duplicate marker: ' + marker)
        if re.search(r'^not ok\b|^FAIL\b|BUG:|WARNING:|Kernel panic|Oops:', text, re.M):
            raise ValueError('guest failure or kernel diagnostic')
        result['counters'] = check_counts(text, groups, depth)
        result['trace'] = validate_trace(text, result['counters']['session'], groups, 6)
        result['data'] = check_images(Path(directory), groups)
        result['status'] = 'PASS'
    except (ValueError, OSError, KeyError, TypeError) as error:
        result['errors'].append(str(error))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir', type=Path, required=True)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--groups', type=int, required=True)
    parser.add_argument('--depth', type=int, required=True)
    parser.add_argument('--qemu-exit', type=int, required=True)
    args = parser.parse_args()
    try:
        text = args.log.read_text(errors='replace')
    except OSError as error:
        text = ''
    result = validate(args.dir, text, args.groups, args.depth, args.qemu_exit)
    args.result.write_text(json.dumps(result, indent=2) + '\n')
    print('XDEV_EXT_FANOUT_VALIDATE=' + result['status'])
    return result['status'] != 'PASS'


if __name__ == '__main__':
    sys.exit(main())
