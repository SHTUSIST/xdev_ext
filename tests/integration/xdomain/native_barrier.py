# SPDX-License-Identifier: GPL-2.0
"""Qualify actual native-event ledgers; no hardware or filesystem side effects."""

import re
from check_protocol import keys, integer, _identity

ABI = 'xdev-native-v1-nvme-xsk-batch'
RECEIPT = set('version identity boot_id kernel_build_id source_commit clock clock_domain nhi_bdf link_token local_inc remote_inc create_begin_ns create_end_ns capture_begin_ns capture_end_ns captured_monotonic_ns trace_dropped formats raw_path'.split())
EXPECTED = set('identity boot_id kernel_build_id source_commit clock_domain nhi_bdf link_token local_inc remote_inc session_id stage batch_key direction group_bytes max_age_ms'.split())
FIELDS = set('abi phase origin session_id batch_id batch_key frame_id generation stage ticket class_id accepted status cookie address bytes aux sequence ts_ns origin_tgid process_start_ticks native_user_data frame_ordinal frame_offset frame_length'.split())
U32_FIELDS = set('frame_id stage class_id bytes origin_tgid frame_ordinal frame_offset frame_length'.split())


def _text(x):
    if type(x) is not str or not x or '\0' in x or len(x.encode()) > 4096:
        raise ValueError('invalid native text')


def qualify_native_barrier(raw_trace, receipt, expected, *, now_ns, action=None):
    """Return ready only for a full, fresh, identity-bound pending native group.

    acceptance_seq is a raw ledger row coordinate (one based), never a kernel
    counter. With action, readiness is retrospective across continued capture.
    """
    keys(receipt, RECEIPT)
    keys(expected, EXPECTED)
    _identity(receipt['identity'])
    _identity(expected['identity'])
    integer(now_ns)
    if type(raw_trace) is not str:
        raise ValueError('raw trace text required')
    if len(raw_trace.encode()) > 16 * 1024 * 1024:
        raise ValueError('raw trace capacity')
    for k in ('boot_id', 'kernel_build_id', 'source_commit', 'clock_domain', 'nhi_bdf'):
        _text(receipt[k]); _text(expected[k])
    _text(receipt['raw_path']); _text(receipt['clock'])
    if integer(receipt['version']) != 1:
        raise ValueError('native receipt version')
    for k in ('link_token', 'local_inc', 'remote_inc', 'create_begin_ns', 'create_end_ns', 'capture_begin_ns', 'capture_end_ns', 'captured_monotonic_ns', 'trace_dropped'):
        integer(receipt[k])
    for k in ('link_token', 'local_inc', 'remote_inc', 'session_id', 'stage', 'batch_key', 'direction', 'group_bytes'):
        integer(expected[k])
    integer(expected['max_age_ms'], minimum=1, maximum=120000)
    if type(receipt['formats']) is not dict:
        raise ValueError('native event formats object required')

    def incomplete(reason):
        return {'status': 'incomplete', 'reason': reason, 'barrier': None}

    for k in ('identity', 'boot_id', 'kernel_build_id', 'source_commit', 'clock_domain', 'nhi_bdf', 'link_token', 'local_inc', 'remote_inc'):
        if receipt[k] != expected[k]:
            return incomplete('native receipt identity mismatch: ' + k)
    if receipt['clock'] != 'CLOCK_MONOTONIC' or receipt['trace_dropped']:
        return incomplete('unknown clock or lost native trace')
    if not (receipt['capture_begin_ns'] <= receipt['create_begin_ns'] <= receipt['create_end_ns'] <= receipt['capture_end_ns'] <= receipt['captured_monotonic_ns'] <= now_ns):
        return incomplete('native capture does not cover CREATE or is future')
    if now_ns - receipt['captured_monotonic_ns'] > expected['max_age_ms'] * 1000000:
        return incomplete('stale native trace')
    formats = receipt['formats']
    fmt = formats.get('native_event', formats.get('xdev_ext:native_event'))
    if type(fmt) is not str or any(k not in fmt for k in FIELDS - {'abi', 'phase', 'origin'}):
        return incomplete('missing actual native-event format')
    rows = []
    if raw_trace and not raw_trace.endswith('\n'):
        return incomplete('truncated native trace')
    for ordinal, line in enumerate(raw_trace.splitlines(), 1):
        if len(line.encode()) > 16384:
            raise ValueError('native trace line capacity')
        if ('lost' in line.lower() and 'events' in line.lower()) or 'buffer overrun' in line.lower():
            return incomplete('native trace loss')
        if not line.strip() or line.startswith('#'):
            continue
        if 'native_event:' not in line:
            continue
        body = line.split('native_event:', 1)[1].strip()
        row = {}
        for part in body.split():
            if '=' not in part:
                return incomplete('malformed native row')
            k, v = part.split('=', 1)
            if k in row:
                return incomplete('duplicate native field')
            row[k] = v
        if set(row) != FIELDS or row['abi'] != ABI:
            return incomplete('native ABI fields mismatch')
        for k in FIELDS - {'abi', 'phase', 'origin'}:
            if re.fullmatch(r'-?[0-9]{1,20}', row[k]) is None:
                return incomplete('invalid native scalar')
            value = int(row[k])
            try:
                integer(value, maximum=(1 << 31) - 1 if k in ('status', 'accepted') else ((1 << 32) - 1 if k in U32_FIELDS else (1 << 64) - 1), minimum=-(1 << 31) if k in ('status', 'accepted') else 0)
            except ValueError:
                return incomplete('native scalar overflow')
            row[k] = value
        row['_ordinal'] = ordinal
        rows.append(row)
    scoped = [r for r in rows if all(r[k] == expected[k] for k in ('session_id', 'stage', 'batch_key')) and r['phase'] in ('native_submit', 'native_complete')]
    submits = [r for r in scoped if r['phase'] == 'native_submit']
    if not submits:
        return incomplete('no scoped native acceptance')
    signatures = {(r['batch_id'], r['ticket'], r['cookie']) for r in submits}
    if len(signatures) != 1:
        return incomplete('ambiguous native groups')
    group = submits[0]
    for r in submits:
        if (r['origin'] != 'K' or r['class_id'] != 11 or r['accepted'] != 1 or r['status'] != 0 or r['address'] != 0 or r['bytes'] != expected['group_bytes'] or r['aux'] != expected['direction'] or r['sequence'] != 0):
            return incomplete('native acceptance facts mismatch')
        if not receipt['create_begin_ns'] <= r['ts_ns'] <= receipt['capture_end_ns']:
            return incomplete('native acceptance outside capture')
    submits.sort(key=lambda r: r['frame_ordinal'])
    offset = 0
    frames = set()
    for n, r in enumerate(submits):
        frame = (r['frame_id'], r['generation'])
        if r['frame_ordinal'] != n or r['frame_offset'] != offset or not r['frame_length'] or frame in frames:
            return incomplete('partial or duplicate native frame coverage')
        frames.add(frame)
        offset += r['frame_length']
    if offset != expected['group_bytes']:
        return incomplete('native frame coverage incomplete')
    accepted = max(r['ts_ns'] for r in submits)
    completes = [r for r in scoped if r['phase'] == 'native_complete' and r['batch_id'] == group['batch_id']]
    if any(r['ticket'] != group['ticket'] for r in completes):
        return incomplete('contradictory completion ticket')
    seen = set()
    for r in completes:
        frame = (r['frame_id'], r['generation'])
        matching = next((s for s in submits if (s['frame_id'], s['generation']) == frame), None)
        if matching is None or frame in seen or r['origin'] != 'K' or r['class_id'] != 11 or r['sequence'] != 0 or r['accepted'] != 1:
            return incomplete('contradictory or duplicate native completion')
        if any(r[k] != matching[k] for k in ('frame_ordinal', 'frame_offset', 'frame_length', 'cookie', 'address', 'bytes', 'aux')) or r['ts_ns'] < accepted or r['ts_ns'] > receipt['capture_end_ns']:
            return incomplete('completion frame or time mismatch')
        seen.add(frame)
    completion = min((r['ts_ns'] for r in completes), default=None)
    barrier = dict(native_accepted=True, inflight=1, session_id=group['session_id'], batch_id=group['batch_id'], group=group['cookie'], acceptance_seq=min(r['_ordinal'] for r in submits), local_inc=receipt['local_inc'], remote_inc=receipt['remote_inc'], identity=receipt['identity'], batch_key=group['batch_key'], stage=group['stage'], ticket=group['ticket'], boot_id=receipt['boot_id'], clock_domain=receipt['clock_domain'], accepted_monotonic_ns=accepted, observed_monotonic_ns=receipt['captured_monotonic_ns'], raw_path=receipt['raw_path'])
    if action is None:
        if completion is not None:
            return incomplete('native work already completed')
    else:
        if type(action) is not dict:
            raise ValueError('action receipt object')
        # The action echoes the provisional barrier; its observation time/path
        # precede this continued capture, while immutable binding must agree.
        old = action.get('barrier')
        if type(old) is not dict or set(old) != set(barrier):
            return incomplete('action barrier missing')
        if any(old[k] != v for k, v in barrier.items() if k not in ('observed_monotonic_ns', 'raw_path')):
            return incomplete('action barrier binding mismatch')
        start, finish = action.get('started_monotonic_ns'), action.get('finished_monotonic_ns')
        integer(start); integer(finish)
        if not accepted <= old['observed_monotonic_ns'] <= start <= finish <= receipt['capture_end_ns'] or start == finish:
            return incomplete('action outside continued capture')
        if start - old['observed_monotonic_ns'] > expected['max_age_ms'] * 1000000:
            return incomplete('action used stale pending sample')
        if completion is not None and completion <= start:
            return incomplete('native completion preceded action')
        if action.get('kind') == 'stop':
            stop = action.get('evidence', {}).get('stop_response', {})
            if completion is None or len(seen) != len(frames) or action.get('error') != 0 or stop.get('payload', {}).get('stop_error') != 0 or stop.get('payload', {}).get('stop_proved') is not True:
                return incomplete('STOP requires explicit success and later full native completion')
        if action.get('identity') != barrier['identity'] or any(action.get('target', {}).get(k) != receipt[k] for k in ('boot_id', 'clock_domain', 'nhi_bdf', 'link_token', 'local_inc', 'remote_inc')):
            return incomplete('action target identity mismatch')
    return {'status': 'ready', 'reason': 'continued action evidence qualified' if action else 'provisional pending native group', 'barrier': barrier}
