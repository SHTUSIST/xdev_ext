# SPDX-License-Identifier: GPL-2.0
"""Rank-local admission input. Process-local native pointers are never input."""
import json
import os
from pathlib import Path

_NUMBERS = {'version', 'rank', 'world_size', 'device_index', 'mode', 'link_token',
            'allocation_bytes', 'group_bytes', 'depth', 'nr_batches',
            'first_sequence', 'timeout_ns', 'communicator_id', 'epoch',
            'max_payload_bytes'}
_PATHS = {'nvidia_node', 'bpf_object', 'user_bpf_object', 'ptx_path'}
_ALLOWED = _NUMBERS | _PATHS | {'control_ptx_path', 'trace_capacity'}
_AGREEMENT = ('version', 'world_size', 'mode', 'allocation_bytes', 'group_bytes',
              'depth', 'nr_batches', 'first_sequence', 'timeout_ns',
              'communicator_id', 'epoch', 'max_payload_bytes')


def validate_options(options, *, rank, device_index, environ=None):
    if not isinstance(options, dict) or set(options) - _ALLOWED:
        raise ValueError('unknown admission options; native pointers are not input')
    if (_NUMBERS | _PATHS) - set(options):
        raise ValueError('rank-local admission options are incomplete')
    data = dict(options)
    for key in _NUMBERS | ({'trace_capacity'} & set(data)):
        value = data[key]
        if type(value) is not int or value < 0 or value > (1 << 64) - 1:
            raise ValueError(f'invalid unsigned admission option: {key}')
    if (data['version'] != 1 or data['world_size'] != 2 or
            data['rank'] != rank or rank not in (0, 1) or
            data['device_index'] != device_index or data['mode'] not in (1, 2)):
        raise ValueError('rank/device/world/mode does not match actual TP group')
    if any(data[key] == 0 for key in ('link_token', 'allocation_bytes', 'depth',
            'nr_batches', 'first_sequence', 'timeout_ns', 'communicator_id', 'epoch')):
        raise ValueError('zero namespace/geometry/deadline option')
    frames_per_group = (data['group_bytes'] + 4095) // 4096
    if (data['group_bytes'] < 64 or data['group_bytes'] > 32*4096 or
            data['group_bytes'] % 64 or data['allocation_bytes'] % 65536 or
            data['allocation_bytes'] > (1 << 64)-1-65536 or
            data['allocation_bytes'] < frames_per_group * 4096 * data['depth'] or
            data['depth'] > 256 or data['device_index'] > (1 << 31)-1 or
            data['nr_batches'] > (1 << 64)-1-data['first_sequence'] or
            data['timeout_ns'] < 1000000 or data['timeout_ns']//1000000 > (1 << 31)-1 or
            data['max_payload_bytes'] > min(data['group_bytes']-64, (1 << 32)-1) or
            data.get('trace_capacity', 0) > (1 << 32)-1 or
            (data['mode'] == 1 and data['depth'] != 1)):
        raise ValueError('unsupported admission geometry/depth/payload capacity')
    for key in _PATHS | ({'control_ptx_path'} & set(data)):
        if not isinstance(data[key], str) or not data[key] or '\x00' in data[key]:
            raise ValueError(f'invalid admission path: {key}')
    for key in ('bpf_object', 'user_bpf_object', 'ptx_path'):
        if not Path(data[key]).is_file():
            raise ValueError(f'admission source file missing: {key}')
    if data['mode'] == 2:
        env = os.environ if environ is None else environ
        path = data.get('control_ptx_path')
        actual = env.get('XDEV_EXT_CUDA_PTX')
        if not path or not actual or not Path(path).is_file() or Path(path).resolve() != Path(actual).resolve():
            raise ValueError('d2 control_ptx_path must match actual XDEV_EXT_CUDA_PTX')
    return data


def load_options(path, *, rank, group, device_index, environ=None):
    try:
        filename = path.format(rank=rank, group=group)
    except (KeyError, ValueError) as error:
        raise ValueError('XDEV_TP_CONFIG supports {rank} and {group} only') from error
    with open(filename, encoding='utf-8') as source:
        data = json.load(source)
    return validate_options(data, rank=rank, device_index=device_index, environ=environ)


def agreement_key(options):
    return {key: options[key] for key in _AGREEMENT}
