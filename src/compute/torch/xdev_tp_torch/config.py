# SPDX-License-Identifier: GPL-2.0
"""Rank-local admission input. Process-local native pointers are never input."""
import json
import os
from pathlib import Path

_NUMBERS = {'version', 'rank', 'world_size', 'device_index', 'mode', 'link_token',
            'allocation_bytes', 'group_bytes', 'depth', 'nr_batches',
            'first_sequence', 'timeout_ns', 'communicator_id', 'epoch',
            'max_payload_bytes'}
_PATHS = {'nvidia_node', 'ptx_path'}
_OBJECT_PATHS = {'bpf_object', 'user_bpf_object'}
_PIN_COUNTS = {'tx_program_pins': 3, 'rx_program_pins': 2}
_ALLOWED = (_NUMBERS | _PATHS | _OBJECT_PATHS | set(_PIN_COUNTS) |
            {'control_ptx_path', 'trace_capacity', 'early_cts', 'template_capacity', 'frames', 'ce_bpf_object', 'receive_groups'})
# Native work templates; mirrors XDEV_TP_TEMPLATE_CAPACITY and _MAX in xdev_tp.h.
TEMPLATE_CAPACITY_DEFAULT = 256
TEMPLATE_CAPACITY_MAX = 1 << 20
_AGREEMENT = ('version', 'world_size', 'mode', 'allocation_bytes', 'group_bytes',
              'depth', 'nr_batches', 'first_sequence', 'timeout_ns',
              'communicator_id', 'epoch', 'max_payload_bytes')


def validate_options(options, *, rank, device_index, environ=None):
    if not isinstance(options, dict) or set(options) - _ALLOWED:
        raise ValueError('unknown admission options; native pointers are not input')
    if (_NUMBERS | _PATHS) - set(options):
        raise ValueError('rank-local admission options are incomplete')
    data = dict(options)
    for key, count in _PIN_COUNTS.items():
        pins = data.get(key, [None] * count)
        if not isinstance(pins, list) or len(pins) != count:
            raise ValueError(f'invalid stage pin array: {key}')
        for pin in pins:
            if pin is not None and (not isinstance(pin, str) or not pin or
                    '\x00' in pin or not Path(pin).is_absolute()):
                raise ValueError(f'invalid PRIVATE link pin: {key}')
        if key in data:
            data[key] = list(pins)
    tx = data.get('tx_program_pins', [None] * 3)
    rx = data.get('rx_program_pins', [None] * 2)
    # Host frames plus the GPU copy engine (GPU without GPUDirect RDMA): d1
    # only, no USER stages and no PEER stage pins; the CE program is required.
    # Absent means peer; legacy inputs are returned unchanged.
    frames = data.get('frames', 'peer')
    if frames not in ('peer', 'host'):
        raise ValueError('frames must be peer or host')
    host = frames == 'host'
    if not host and ({'ce_bpf_object', 'receive_groups'} & set(data)):
        raise ValueError('ce_bpf_object/receive_groups apply to host frames only')
    if host:
        if 'tx_program_pins' in data or 'rx_program_pins' in data:
            raise ValueError('host frames take no PEER stage pins')
        groups = data.setdefault('receive_groups', 1)
        if type(groups) is not int or groups < 1 or groups > 256:
            raise ValueError('receive_groups must be 1..256')
        ce = data.get('ce_bpf_object')
        if not isinstance(ce, str) or not ce or '\x00' in ce or not Path(ce).is_file():
            raise ValueError('host frames need an existing ce_bpf_object')
    needed_objects = set()
    if host or tx[1] is None or rx[0] is None:
        needed_objects.add('bpf_object')
    if not host and (tx[0] is None or tx[2] is None or rx[1] is None):
        needed_objects.add('user_bpf_object')
    for key in _OBJECT_PATHS:
        value = data.get(key)
        if value is None and key not in needed_objects:
            data[key] = None
        elif not isinstance(value, str) or not value or '\x00' in value:
            raise ValueError(f'invalid admission path: {key}')
    # Optional EARLY receiver CTS request (configuration d1/d2 ingredient).
    # It selects the native endpoint flag; it is not evidence that EARLY ran.
    if 'early_cts' in data and (type(data['early_cts']) is not int or
                                data['early_cts'] not in (0, 1)):
        raise ValueError('early_cts must be 0 or 1')
    # Optional native template pool size (TODO.54). Each captured collective
    # keeps one template while its CUDA graph lives; zero selects the native default.
    if 'template_capacity' in data and (type(data['template_capacity']) is not int or
            not 0 <= data['template_capacity'] <= TEMPLATE_CAPACITY_MAX):
        raise ValueError(f'template_capacity must be an int in 0..{TEMPLATE_CAPACITY_MAX}')
    if data.get('template_capacity') == 0:
        data['template_capacity'] = TEMPLATE_CAPACITY_DEFAULT
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
    if host and data['mode'] != 1:
        raise ValueError('host frames run d1 collectives only')
    for key in _PATHS | ({'control_ptx_path'} & set(data)):
        if not isinstance(data[key], str) or not data[key] or '\x00' in data[key]:
            raise ValueError(f'invalid admission path: {key}')
    for key in needed_objects | {'ptx_path'}:
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
    key = {name: options[name] for name in _AGREEMENT}
    key['early_cts'] = options.get('early_cts', 0)
    # Both ranks capture the same graphs, so both need the same template pool.
    key['template_capacity'] = (options.get('template_capacity', TEMPLATE_CAPACITY_DEFAULT)
                                or TEMPLATE_CAPACITY_DEFAULT)
    if options.get('frames', 'peer') == 'host':
        key['frames'] = 'host'
        key['receive_groups'] = options.get('receive_groups', 1)
    return key
