#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Conservative physical-byte joins over verified native observations.

The zero counters describe only the certified READ -> native AF_XDP TX payload
boundary. They do not count arbitrary CPU accesses or attest to remote receipt.
Unknown mappings, partial captures and ambiguous lifetimes raise ValueError.
"""
from bisect import bisect_left, bisect_right
from collections import defaultdict


SCOPE = 'verified_nvme_read_to_native_afxdp_tx_boundary'
U64 = 1 << 64


def _require(condition, message):
    if not condition:
        raise ValueError('native backing unavailable: ' + message)


def _positive_range(start, size):
    _require(type(start) is int and type(size) is int and
             0 <= start < U64 and 0 < size < U64 and start + size <= U64,
             'invalid/overflowed physical or logical range')


class _Ranges(list):
    def __init__(self, rows):
        super().__init__(rows)
        self.offsets = [row['aux'] for row in rows]


def _ranges(rows, total, ordinal=False):
    """Validate a complete logical mapping, retaining its physical ordering."""
    _positive_range(0, total)
    ordered = sorted(rows, key=lambda row: row['aux'])
    cursor = 0
    for i, row in enumerate(ordered):
        _require(row.get('probe_accepted') == 1 and row['status'] == 0,
                 'uncertified mapping span')
        _positive_range(row['address'], row['bytes'])
        _positive_range(row['aux'], row['bytes'])
        if ordinal:
            _require(row['sequence'] == i, 'mapping ordinal missing/duplicate/reordered')
            _positive_range(row['native_user_data'], row['bytes'])
        _require(row['aux'] == cursor, 'mapping has byte holes/overlap/duplicates')
        cursor += row['bytes']
    _require(cursor == total, 'mapping does not cover whole sealed byte count')
    return _Ranges(ordered)


def _slice(rows, start, size, field='address'):
    _positive_range(start, size)
    end, cursor, result = start + size, start, []
    index = max(0, bisect_right(rows.offsets, start) - 1)
    for i in range(index, len(rows)):
        row = rows[i]
        if row['aux'] >= end:
            break
        left, right = max(start, row['aux']), min(end, row['aux'] + row['bytes'])
        if left >= right:
            continue
        _require(left == cursor, 'payload physical coverage gap')
        address, length = row[field] + left - row['aux'], right - left
        if result and result[-1][0] + result[-1][1] == address:
            result[-1][1] += length
        else:
            result.append([address, length])
        cursor = right
    _require(cursor == end, 'payload exceeds observed mapping')
    return result


def derive(plan, events, runtime, journal):
    """Consume only freshly decoded events and verified immutable sideband."""
    _require(plan.get('recipe', {}).get('chain') == 'nvme-nic', 'unsupported chain')
    _require(runtime is not None, 'actual runtime owner bindings required')
    origin = 'K' if plan['arm'].startswith('K') else 'U'
    observations = defaultdict(lambda: defaultdict(list))
    operations, endpoints = defaultdict(lambda: defaultdict(list)), {}
    descriptors, consumed_descriptors = defaultdict(list), set()
    for event in events:
        phase = event['event']
        if event.get('observation_only'):
            observations[(event['class_id'], event['cookie'])][phase].append(event)
            if phase == 'dma_tx':
                descriptors[(event['cookie'], event['address'])].append(event)
        elif phase == 'record_admit':
            for frame in event.get('endpoint_frames', []):
                endpoints[(frame['session_id'], frame['record_id'], frame['generation'],
                           frame['endpoint_frame_id'])] = frame
        elif phase in ('native_submit', 'native_complete'):
            key = tuple(event[f] for f in ('session_id', 'record_id', 'generation', 'frame_id'))
            operations[key][(event['class_id'], phase)].append(event)
    journals = defaultdict(list)
    for row in journal:
        if row.get('kind') == 'nvme':
            owner = (row['_origin_tgid'], row['_process_start_ticks'])
            binding = runtime['owners'].get(owner)
            _require(binding is not None and row['session_id'] == binding['native_session_id'],
                     'U payload anchor lacks verified protocol owner/session')
            key = (binding['logical_id'], row['record_id'], row['generation'], row['frame_ordinal'])
            journals[key].append(row)
    for rows in descriptors.values():
        rows.sort(key=lambda row: row['ts_ns'])
    descriptor_times = {key: [row['ts_ns'] for row in rows] for key, rows in descriptors.items()}
    observation_times = {key: {phase: [row['ts_ns'] for row in rows]
                              for phase, rows in group.items()}
                         for key, group in observations.items()}
    mapping_cache, commands, frame_commands = {}, defaultdict(list), {}
    source_checked = set()
    for key, group in operations.items():
        submits, completes = group[(3, 'native_submit')], group[(3, 'native_complete')]
        if len(submits) == len(completes) == 1:
            submit, complete = submits[0], completes[0]
            reqptr = submit['cookie'] if origin == 'K' else submit['sequence']
            identity = (reqptr,) + key[:3] + tuple(submit[field] for field in
                ('cookie', 'sequence', 'stage', 'ticket', 'origin_tgid', 'process_start_ticks'))
            commands[identity].append((submit['ts_ns'], complete['ts_ns']))
            frame_commands[key] = identity
    lifetimes, command_windows = defaultdict(list), {}
    for identity, intervals in commands.items():
        # K emits one probe per frame, each with its own ktime. The hardware
        # mapping must follow every frame submit and precede every completion.
        start, end = max(a for a, b in intervals), min(b for a, b in intervals)
        _require(start <= end, 'inconsistent per-frame native command lifetime')
        command_windows[identity] = (start, end)
        lifetimes[identity[0]].append((min(a for a, b in intervals), max(b for a, b in intervals)))
    for intervals in lifetimes.values():
        ordered = sorted(intervals)
        _require(all(left[1] < right[0] for left, right in zip(ordered, ordered[1:])),
                 'request pointer reused across overlapping/ambiguous native lifetimes')

    def mapping(class_id, cookie, start, end, owner=None):
        observation_key = (class_id, cookie)
        key = observation_key + ((start, end) if class_id == 3 else ())
        if key not in mapping_cache:
            group = observations[observation_key]
            if class_id == 3:
                selected = {}
                for phase in ('dma_span', 'dma_seal', 'dma_unmap'):
                    times = observation_times.get(observation_key, {}).get(phase, [])
                    left, right = bisect_left(times, start), bisect_right(times, end)
                    selected[phase] = group[phase][left:right]
                group = selected
            seals = group['dma_seal']
            _require(len(seals) == 1, 'missing/duplicate/reused DMA seal')
            seal = seals[0]
            _require(seal.get('probe_accepted') == 1 and seal['status'] == 0,
                     'DMA whole-map certification failed/unknown')
            _require(seal['aux'] > 0 and len(group['dma_span']) == seal['aux'],
                     'DMA seal span count differs from actual observations')
            _require(seal['address'] == seal['sequence'] == seal['native_user_data'] == 0,
                     'invalid whole-map seal fields')
            _require(all(row['ts_ns'] <= seal['ts_ns'] for row in group['dma_span']),
                     'DMA spans after sealed map')
            _require(len(group['dma_unmap']) <= 1, 'ambiguous duplicate unmap/request reuse')
            unmap = group['dma_unmap'][0] if group['dma_unmap'] else None
            if unmap:
                _require(unmap['ts_ns'] >= seal['ts_ns'] and
                         unmap.get('probe_accepted') == 1 and unmap['status'] == 0 and
                         unmap['bytes'] == (0 if class_id == 2 else seal['bytes']) and
                         unmap['address'] == unmap['aux'] == unmap['sequence'] ==
                         unmap['native_user_data'] == 0, 'invalid/stale map unmap')
            rows = _ranges(group['dma_span'], seal['bytes'], ordinal=True)
            first = min(row['ts_ns'] for row in rows)
            if class_id == 2:
                binds = group['pool_bind']
                _require(len(binds) == 1, 'missing/duplicate/stale pool identity')
                identity = binds[0]
                _require(identity.get('probe_accepted') == 1 and identity['status'] == 0 and
                         identity['ts_ns'] <= first, 'pool bind after mapping')
                _positive_range(0, identity['bytes'])
                _require(0 < identity['aux'] <= seal['bytes'] and
                         identity['aux'] % identity['bytes'] == 0,
                         'pool registration exceeds mapping or has partial chunk')
                region = _ranges(group['region_span'], seal['bytes'])
                _require(region[-1]['aux'] < identity['aux'] <=
                         region[-1]['aux'] + region[-1]['bytes'],
                         'mapped pool contains unregistered whole pages')
                _require(all(identity['ts_ns'] <= row['ts_ns'] <= seal['ts_ns'] and
                             (row['origin_tgid'], row['process_start_ticks']) ==
                             (identity['origin_tgid'], identity['process_start_ticks']) for row in region),
                         'region has stale pool/owner identity')
                _require(_slice(region, 0, seal['bytes']) == _slice(rows, 0, seal['bytes']),
                         'mapped NIC bytes differ from actual UMEM pages')
            else:
                identity = seal
                _require(seal['origin'] == origin and
                         all(row['origin'] == origin for row in rows), 'NVMe map origin mismatch')
            mapping_cache[key] = rows, identity, seal, unmap, first
        rows, identity, seal, unmap, first = mapping_cache[key]
        _require(start <= first <= seal['ts_ns'] <= end, 'DMA map outside native mapping lifetime')
        if class_id == 2:
            _require(unmap is None or unmap['ts_ns'] > end, 'NIC map unmapped before native completion')
            _require((identity['origin_tgid'], identity['process_start_ticks']) == owner,
                     'native descriptor uses foreign pool owner')
        return rows, identity

    frames = []
    for record in plan['records']:
        offset = 0
        for frame_id in record['frame_ids']:
            key = tuple(record[f] for f in ('session_id', 'record_id', 'generation')) + (frame_id,)
            group = operations[key]
            pairs = []
            for class_id in (3, 2):
                submits, completes = group[(class_id, 'native_submit')], group[(class_id, 'native_complete')]
                _require(len(submits) == len(completes) == 1, 'incomplete/ambiguous native frame operation')
                submit, complete = submits[0], completes[0]
                _require(submit['accepted'] is True and complete['accepted'] is True and
                         submit['status'] == complete['status'] == 0 and
                         submit['ts_ns'] <= complete['ts_ns'], 'unsuccessful native operation')
                _require(all(submit[f] == complete[f] for f in
                             ('cookie', 'sequence', 'ticket', 'class_id', 'frame_length', 'frame_offset')),
                         'native operation changed identity')
                pairs.append((submit, complete))
            (nvme, nvme_done), (nic, nic_done) = pairs
            _require(nvme['aux'] & 0xff == 2 and nvme_done['ts_ns'] <= nic['ts_ns'],
                     'not a completed NVMe READ before native TX')
            _require(nvme['native_frame_id'] == nic['native_frame_id'],
                     'native views refer to different actual frame slots')
            length = nvme['frame_length']
            _require(length > 0 and nvme['bytes'] == plan['record_bytes'] and
                     nvme['frame_offset'] == offset and nic['frame_offset'] == offset and
                     nic['frame_length'] == length, 'incomplete/noncontiguous record payload')
            reqptr = nvme['cookie'] if origin == 'K' else nvme['sequence']
            _require(reqptr != 0, 'actual request pointer missing')
            command_start, command_end = command_windows[frame_commands[key]]
            nvme_rows, seal = mapping(3, reqptr, command_start, command_end)
            _require(seal['bytes'] == nvme['bytes'], 'NVMe whole command mapping size mismatch')
            if origin == 'U' and frame_commands[key] not in source_checked:
                source = [row for row in observations[(3, nvme['cookie'])]['native_span']
                          if (row['origin_tgid'], row['process_start_ticks']) ==
                             (nvme['origin_tgid'], nvme['process_start_ticks'])]
                _require(all(row['origin'] == 'U' and row['sequence'] == reqptr and
                             row['native_user_data'] == nvme['cookie'] and
                             (row['origin_tgid'], row['process_start_ticks']) ==
                             (nvme['origin_tgid'], nvme['process_start_ticks']) and
                             row['ts_ns'] <= command_start for row in source),
                         'U request source spans have different owner/request/time')
                source_rows = _ranges(source, nvme['bytes'])
                _require(_slice(source_rows, 0, nvme['bytes']) == _slice(nvme_rows, 0, nvme['bytes']),
                         'U request source bytes differ from final DMA mapping')
                source_checked.add(frame_commands[key])
            owner = (nvme['origin_tgid'], nvme['process_start_ticks'])
            _require(owner == (nic['origin_tgid'], nic['process_start_ticks']), 'cross-owner native work')
            # A pool map is established before actual driver descriptor consume.
            nic_rows, pool = mapping(2, nic['cookie'], 0, nic_done['ts_ns'], owner)
            _require(observations[(2, nic['cookie'])]['dma_seal'][0]['ts_ns'] <= nic['ts_ns'],
                     'NIC consumed descriptor before sealed mapping')
            desc_key = (nic['cookie'], nic['address'])
            times = descriptor_times.get(desc_key, [])
            left = bisect_left(times, nic['ts_ns'])
            right = bisect_right(times, nic_done['ts_ns'])
            _require(right - left == 1, 'actual native DMA descriptor missing/duplicate')
            observation_id = desc_key + (left,)
            _require(observation_id not in consumed_descriptors,
                     'one hardware DMA descriptor reused for multiple native operations')
            consumed_descriptors.add(observation_id)
            desc = descriptors[desc_key][left]
            _require(desc.get('probe_accepted') == 1 and desc['status'] == 0 and
                     desc['bytes'] == nic['bytes'] and desc['aux'] == desc['sequence'] == 0,
                     'native DMA descriptor unsupported/mismatched')
            _positive_range(desc['native_user_data'], desc['bytes'])
            _require(_slice(nic_rows, nic['address'], nic['bytes'], 'native_user_data') ==
                     [[desc['native_user_data'], desc['bytes']]],
                     'actual native descriptor DMA differs from sealed map')
            chunk = pool['bytes']
            frame_start = nic['address'] // chunk * chunk
            _require(nic['bytes'] >= length and nic['address'] >= 0 and
                     nic['address'] + nic['bytes'] <= min(frame_start + chunk, pool['aux']),
                     'descriptor payload/header exceeds actual pool frame')
            payload = nic['address'] + nic['bytes'] - length
            if origin == 'K':
                admit = endpoints.get(key)
                _require(admit is not None and admit['status'] == 0 and admit['accepted'] is True and
                         admit['ts_ns'] <= nvme['ts_ns'] and admit['frame_length'] == length and
                         admit['frame_offset'] == offset and
                         admit['native_frame_id'] == nvme['native_frame_id'],
                         'actual K payload admission anchor missing/foreign native slot')
                anchor = admit['address']
            else:
                entries = journals[key]
                _require(len(entries) == 1 and entries[0]['cookie'] == nvme['cookie'] and
                         entries[0]['bytes'] == length and entries[0]['ts_ns'] <= nvme['ts_ns'],
                         'actual U immutable payload anchor missing/ambiguous')
                anchor = entries[0]['address']
            _require(anchor == payload and frame_start <= payload and payload + length <= frame_start + chunk,
                     'actual payload anchors differ/header overlaps payload')
            nvme_physical = _slice(nvme_rows, offset, length)
            nic_physical = _slice(nic_rows, payload, length)
            _require(nvme_physical == nic_physical, 'ordered physical payload bytes differ between native views')
            backing_id = 'physical:' + ','.join('%d+%d' % tuple(span) for span in nvme_physical)
            payload_offset = payload - frame_start
            frames.append(dict(session_id=key[0], record_id=key[1], generation=key[2], frame_id=frame_id,
                backing_id=backing_id, valid_bytes=chunk, record_offset_bytes=offset,
                payload_offset_bytes=payload_offset, payload_bytes=length,
                physical_ranges=nvme_physical,
                native_views=[dict(kind=kind, backing_id=backing_id, offset_bytes=payload_offset,
                                   length_bytes=length) for kind in ('nvme', 'afxdp')]))
            offset += length
        _require(offset == plan['record_bytes'], 'record payload is incomplete')
    _require(bool(frames), 'no native frames')
    return dict(schema_version=1, source='native_provider', run_id=plan['run_id'],
                exact_sha=plan['exact_sha'], afxdp_mode='zc', nvme_bounces=0,
                payload_copy_bytes=0, payload_copy_scope=SCOPE, frames=frames)
