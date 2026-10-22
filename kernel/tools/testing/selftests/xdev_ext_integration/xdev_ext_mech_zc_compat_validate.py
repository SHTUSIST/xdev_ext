#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Validate separate socket-chain and unchanged-application guest evidence."""
import importlib.util
from pathlib import Path
import re
import sys

NAMES = frozenset(('compat-udp.log', 'compat-dio-off.log', 'compat-dio-on.log',
    'mech-socket-base.log', 'mech-socket-lifecycle.log',
    'mech-ce-socket-base.log', 'mech-ce-socket-lifecycle.log',
    'mech-socket-threads.log', 'mech-socket-processes.log',
    'mech-ce-socket-threads.log', 'mech-ce-socket-processes.log'))


def extract_logs(console):
    logs = {}
    current = None
    lines = []
    for line in console.splitlines():
        if line.startswith('XDEV_EXT_PRELOAD_LOG_BEGIN '):
            name = line.removeprefix('XDEV_EXT_PRELOAD_LOG_BEGIN name=')
            if current is not None or name not in NAMES or name in logs:
                raise ValueError('nested, duplicate, or unknown preload log')
            current, lines = name, []
        elif line.startswith('XDEV_EXT_PRELOAD_LOG_END '):
            if current is None or line != 'XDEV_EXT_PRELOAD_LOG_END name='+current:
                raise ValueError('preload log end mismatch')
            logs[current] = '\n'.join(lines)+'\n'
            current = None
        elif current is not None:
            lines.append(line)
    if current is not None or set(logs) != NAMES:
        raise ValueError('incomplete preload evidence')
    return logs


def validate_socket(console):
    rows = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in console.splitlines()
            if line.startswith('PASS socket_guest groups=')]
    want = dict(groups='257', depth='8', slots='8', controller_START='1',
        actual_nvme_source='1', unique_groups='257', datagrams='257',
        peer_bytes=str(257*8192), full_compare='1', source_whole_disk_unchanged='1',
        pool_guards='1', ce_guards='1', ce_slot_data='1',
        stage_counts='257,257,257,257', ce_accepted='514', ce_completed='514',
        pending='0', original_socket_fd_closed='1', STOP='0', owner_refs_released='1',
        CE_CPU_simulation='1', socket_native_copy='1', local_completion_not_remote_ACK='1')
    if len(rows) != 1 or rows[0] != want:
        raise ValueError('missing/duplicate/corrupt socket-chain evidence')
    if console.splitlines().count('PASS socket_guest CE_module_unloaded=1 same_core=1') != 1:
        raise ValueError('socket-chain module lifetime evidence missing')


def validate_peer(console):
    rows = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in console.splitlines()
            if line.startswith('XDEV_EXT_PEER_NATIVE=PASS ')]
    want = dict(XDEV_EXT_PEER_NATIVE='PASS', reads='259', writes='257', groups='257', batches='5', max_desc='64',
        native_depth='1', source_whole_disk_unchanged='1', destination_whole_disk='1',
        allocation_guards='1', maps='2', pins='2', live_maps='0', live_pins='0',
        memory='host-RAM-standin')
    if len(rows) != 1 or rows[0] != want:
        raise ValueError('missing/duplicate/corrupt native peer evidence')
    for marker in ('# software provider cleanly unloaded after exact reference drain',
            'XDEV_EXT_PEER_SOFTWARE_GUEST=PASS native=NVMe-SGL memory=host-RAM-standin gpu=none'):
        if console.splitlines().count(marker) != 1:
            raise ValueError('peer provider lifetime evidence missing')


def validate(source, console_path, output):
    console = console_path.read_text()
    validate_socket(console)
    if console.splitlines().count('XDEV_EXT_COMPAT_GUEST=PASS ce_module_unloaded=1') != 1:
        raise ValueError('compatibility module lifetime evidence missing')
    logs = extract_logs(console)
    output.mkdir(exist_ok=True)
    for name, text in logs.items():
        (output/name).write_text(text)
    path = source/'tools/testing/selftests/xdev_ext_preload/xdev_ext_preload_mech_validate.py'
    spec = importlib.util.spec_from_file_location('preload_validate', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.validate(output, ce=True)


if __name__ == '__main__':
    validate(*(Path(arg) for arg in sys.argv[1:]))
