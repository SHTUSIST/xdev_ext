#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Private tracefs capture and deterministic decoding of native-event ABI.

No user completion or manifest assertion substitutes for a native probe. Raw
trace/journal bytes remain the source of normalized events. Missing record
endpoints stay absent. See README.md for the supported capture prerequisites.
"""
from decimal import Decimal
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid

EVENT = 'xdev_ext:native_event'
PHASES = {'record_admit', 'native_submit', 'native_complete', 'record_terminal'}
OBSERVATIONS = {'class_validate', 'downstream_complete', 'frame_recycle',
                'native_span', 'region_span', 'pool_bind', 'session_bind'}
FIELDS = ('session_id', 'batch_id', 'batch_key', 'frame_id', 'generation',
          'stage', 'ticket', 'class_id', 'accepted', 'status', 'cookie',
          'address', 'bytes', 'aux', 'sequence', 'origin_tgid', 'process_start_ticks', 'native_user_data', 'frame_ordinal', 'frame_offset', 'frame_length')
LINE = re.compile(r'\[(\d+)\].*?\s(\d+\.\d+):\s+(?:xdev_ext:)?native_event:\s+(.*)$')


def _integer(value):
    text = str(value)
    return int(text, 16 if text.lower().startswith(('0x', '-0x')) else 10)


def trace_loss(cpu_stats):
    """All per-CPU ftrace ring errors, including overwritten committed events."""
    if not cpu_stats:
        raise ValueError('trace per-CPU loss statistics unavailable')
    total = 0
    for cpu, text in cpu_stats.items():
        values = dict(re.findall(r'^([\w ]+):\s*(\d+)\s*$', text, re.M))
        for field in ('overrun', 'dropped events', 'commit overrun'):
            if field not in values:
                raise ValueError('missing %s loss counter for %s' % (field, cpu))
            total += int(values[field])
    return total


def decode_trace(manifest, raw_text, metadata):
    """Reconstruct native requests from actual events and immutable sideband.

    ``generation`` is logical record generation. ``frame_generation`` preserves
    the kernel's stage-local lifecycle token, which must match within a native
    operation but can legitimately advance between stages. K's explicit
    generation_mapping=batch_key uses the actual immutable batch key. No user
    completion supplies a native completion timestamp.
    """
    trace = manifest.get('trace', {})
    if metadata.get('clock') != 'CLOCK_MONOTONIC' or manifest.get('clock') != 'CLOCK_MONOTONIC':
        raise ValueError('clock must be CLOCK_MONOTONIC')
    if metadata.get('clock_domain') != manifest.get('clock_domain'):
        raise ValueError('clock domain mismatch')
    if metadata.get('trace_dropped') != 0:
        raise ValueError('trace loss or unknown loss invalidates correlation')
    maximum = _integer(trace.get('max_pending', 65536))
    if not 1 <= maximum <= 1048576:
        raise ValueError('invalid bounded correlation capacity')
    records = {(r['session_id'], r['record_id'], r['generation']): set(r['frame_ids'])
               for r in manifest.get('records', [])}
    if not records or len(records) != len(manifest['records']):
        raise ValueError('missing/ambiguous declared record set')
    layout = _layout(manifest)
    stage_map = trace.get('stage_map', {})
    stages = {s['id'] for s in manifest.get('stages', [])}
    runtime = _runtime_binding(manifest, raw_text, metadata)
    journal = _journal_rows(manifest, metadata)
    nvme, tx = {}, {}
    for binding in journal:
        if binding['kind'] == 'nvme':
            key = _integer(binding['cookie'])
            entries = nvme.setdefault(key, [])
            if not key or any(r['frame_id'] == binding['frame_id'] for r in entries):
                raise ValueError('ambiguous or reused U command cookie/frame in journal')
            if entries and any(binding.get(f) != entries[0].get(f) for f in
                               ('session_id', 'record_id', 'generation', 'lba', 'command_bytes', 'stage')):
                raise ValueError('U command cookie changes immutable record/span')
            entries.append(binding)
        elif binding['kind'] == 'tx':
            tx.setdefault(_integer(binding['address']), []).append(binding)
    for entries in tx.values():
        entries.sort(key=lambda row: _integer(row['ts_ns']))
    pending, completed, output, live_cookie = {}, set(), [], {}
    bindings, driver_requests, next_submit, next_complete = {}, {}, {}, {}
    seen = set()
    record_events = {}
    expected_origin = 'K' if manifest['arm'].startswith('K') else 'U'

    def observation(item, *, reason=None):
        row = dict(run_id=manifest['run_id'], event=item['phase'],
                   stage='observation', record_id=-1, clock='CLOCK_MONOTONIC',
                   clock_domain=metadata['clock_domain'], observation_only=True,
                   probe_accepted=item['accepted'], native_stage=item['stage'],
                   **{key: value for key, value in item.items() if key not in ('phase', 'accepted', 'stage')},
                   accepted=False)
        if reason:
            row['scope_excluded'] = reason
        output.append(row)

    def normalize(item, binding=None):
        phase = item['phase']
        source = binding or item
        is_record = phase.startswith('record_')
        if binding is not None and expected_origin == 'U':
            record_id, generation = _integer(source['record_id']), _integer(source['generation'])
        else:
            if trace.get('record_mapping') != 'batch_key_div_burst':
                raise ValueError('unsupported/missing record mapper')
            burst = _integer(trace.get('burst', 0))
            if burst <= 0:
                raise ValueError('invalid record mapping burst')
            logical_key = _integer(source['batch_key']) - _integer(trace.get('batch_key_origin', 0))
            if logical_key < 0:
                raise ValueError('native batch key precedes predeclared origin')
            record_id = logical_key // burst
            generation = (logical_key if trace.get('generation_mapping') == 'batch_key_relative' else _integer(source['batch_key']) if trace.get('generation_mapping') == 'batch_key'
                          else _integer(source['generation']))
        actual_session = _integer(source['session_id'])
        owner = (_integer(source.get('origin_tgid', source.get('_origin_tgid', 0))),
                 _integer(source.get('process_start_ticks', source.get('_process_start_ticks', 0))))
        logical_session = actual_session
        if runtime is not None:
            if expected_origin == 'K':
                match = runtime['sessions'].get(actual_session)
                if match is None or match['owner'] != owner:
                    raise ValueError('native work lacks matching actual CREATE owner/session binding')
                logical_session = match['logical_id']
            else:
                match = runtime['owners'].get(owner)
                if match is None:
                    raise ValueError('U work lacks immutable owning-process binding')
                logical_session = match['logical_id']
                if actual_session != match['native_session_id']:
                    raise ValueError('U immutable protocol session differs from predeclared binding')
        key = (logical_session, record_id, generation)
        if key not in records:
            raise ValueError('native event outside declared record identity set')
        native_frame = _integer(source['frame_id'])
        frame = -1 if is_record else _integer(source['frame_ordinal'] if layout else source['frame_id'])
        if layout:
            ordinal = _integer(source['frame_ordinal'])
            expected_span = layout.get(ordinal)
            if expected_span is None or (_integer(source['frame_offset']), _integer(source['frame_length'])) != expected_span:
                raise ValueError('actual frame ordinal/payload span differs from predeclared layout')
        stage = 'record' if is_record else stage_map.get(str(source['stage']))
        if not is_record and (frame not in records[key] or stage not in stages):
            raise ValueError('native frame/stage identity not mapped')
        # Kernel/local TX terminal is not a remote receive/ACK endpoint.
        if phase == 'record_terminal' and manifest.get('endpoint') not in ('local_tx_complete', 'local_native_complete'):
            return
        row = dict(run_id=manifest['run_id'], session_id=key[0], record_id=key[1],
                   frame_id=frame, generation=key[2], stage=stage, event=phase,
                   ts_ns=item['ts_ns'], clock='CLOCK_MONOTONIC',
                   clock_domain=metadata['clock_domain'], accepted=bool(item['accepted']),
                   status=item['status'], origin=expected_origin, cpu=item['cpu'],
                   frame_generation=_integer(source['generation']), native_frame_id=native_frame,
                   frame_offset=_integer(source.get('frame_offset', 0)), frame_length=_integer(source.get('frame_length', 0)),
                   native_user_data=item['native_user_data'],
                   **{name: item[name] for name in ('batch_id', 'batch_key', 'ticket',
                       'class_id', 'cookie', 'address', 'bytes', 'aux', 'sequence')})
        if runtime is not None:
            row.update(native_session_id=actual_session, origin_tgid=owner[0], process_start_ticks=owner[1])
        if binding is not None:
            row['ticket'] = _integer(source.get('ticket', item['ticket']))
            row['batch_key'] = _integer(source.get('batch_key', item['batch_key']))
            row['batch_id'] = _integer(source.get('batch_id', item['batch_id']))
            if expected_origin == 'U':
                row['binding_cookie'] = _integer(source['cookie'])
        if is_record:
            # Hooks emit each participating frame; collapse only after all raw
            # rows were read. Admit is first acceptance, terminal last endpoint.
            record_events.setdefault((key, phase), []).append(row)
            return
        unique = (key, frame, stage, phase, row['ticket'], row['cookie'], row['sequence'])
        if unique in seen:
            raise ValueError('duplicate native identity event')
        seen.add(unique)
        request = (key, frame, stage, row['ticket'], row['cookie'], row['sequence'])
        if row['accepted']:
            if not row['cookie']:
                raise ValueError('zero native request cookie')
            scope = (expected_origin, row['class_id'], row['cookie'], row['sequence'])
            owner = (key, stage, row['ticket'])
            if phase == 'native_submit':
                if request in pending or request in completed or (scope in live_cookie and live_cookie[scope] != owner):
                    raise ValueError('ambiguous/reused native submit cookie')
                if len(pending) >= maximum:
                    raise ValueError('bounded native correlation table overflow')
                pending[request] = row
                live_cookie[scope] = owner
            else:
                start = pending.pop(request, None)
                if start is None or row['ts_ns'] < start['ts_ns']:
                    raise ValueError('native completion without prior accepted submit')
                for field in ('address', 'bytes', 'class_id', 'frame_generation', 'native_frame_id', 'frame_offset', 'frame_length'):
                    if row[field] != start[field]:
                        raise ValueError('native completion changed immutable request span/generation')
                completed.add(request)
                if not any(p[4] == row['cookie'] and p[5] == row['sequence'] for p in pending):
                    live_cookie.pop(scope, None)
        output.append(row)

    for line in raw_text.splitlines():
        if 'native_event:' not in line:
            continue
        match = LINE.search(line)
        if not match:
            raise ValueError('malformed native event line')
        cpu, stamp, payload = match.groups()
        pairs = re.findall(r'(\w+)=([^\s]+)', payload)
        item = dict(pairs)
        if len(item) != len(pairs):
            raise ValueError('duplicate native event field')
        if item.get('phase') == 'trace_invalid':
            raise ValueError('native journal trace_invalid (overflow/underflow/cancel)')
        if item.get('phase') not in PHASES | OBSERVATIONS | {'descriptor_bind'} or item.get('origin') not in ('K', 'U'):
            raise ValueError('unsupported native phase/origin')
        try:
            item.update({name: _integer(item[name]) for name in FIELDS})
        except (KeyError, ValueError) as error:
            raise ValueError('native event lacks typed identity: %s' % error) from error
        if item['origin'] != expected_origin:
            continue
        item.update(cpu=int(cpu), ts_ns=(_integer(item['ts_ns']) if 'ts_ns' in item
                                        else int(Decimal(stamp) * 1000000000)))
        if item['ts_ns'] < 0 or item['accepted'] not in (0, 1):
            raise ValueError('invalid native timestamp/accepted flag')
        phase = item['phase']
        if phase in OBSERVATIONS:
            # Resource/validation observations are not accepted native work.
            # Preserve the actual probe flag independently; they cannot satisfy
            # a submit/completion or silently become a record endpoint.
            observation(item)
            continue
        if runtime is not None:
            raw_owner = (item['origin_tgid'], item['process_start_ticks'])
            if expected_origin == 'K' and item['session_id'] in runtime['excluded_sessions']:
                if runtime['excluded_sessions'][item['session_id']] != raw_owner:
                    raise ValueError('paired receiver raw owner/session mismatch')
                observation(item, reason='paired_receiver')
                continue
            if expected_origin == 'U':
                if item['class_id'] == 2:
                    raw_owner = runtime['pools'].get(item['cookie'], raw_owner)
                if raw_owner in runtime['excluded_owners']:
                    observation(item, reason='paired_receiver')
                    continue
                if raw_owner not in runtime['owners']:
                    raise ValueError('native U work from unbound owning process')
                if item['class_id'] == 3 and item['native_user_data'] != item['cookie']:
                    raise ValueError('actual native userdata/cookie mismatch')
        if phase == 'descriptor_bind':
            if item['origin'] != 'K' or item['class_id'] != 2:
                raise ValueError('unsupported descriptor binding')
            key = (item['cookie'], item['address'])
            if len(bindings) >= maximum or key in bindings:
                raise ValueError('bounded/ambiguous descriptor binding')
            bindings[key] = item
            continue
        if item['class_id'] == 2 and not phase.startswith('record_'):
            # Native kernel FIFO assigns a sequence at accepted driver consume.
            # Verify the emitted per-pool order too, rather than sorting text
            # timestamps into an invented completion order.
            pool, sequence = item['cookie'], item['sequence']
            key = (pool, sequence)
            if phase == 'native_submit':
                if sequence != next_submit.get(pool, 1):
                    raise ValueError('native TX descriptor sequence gap/reorder')
                next_submit[pool] = sequence + 1
                if expected_origin == 'K':
                    binding = bindings.pop((pool, item['address']), None)
                    if binding is None:
                        raise ValueError('K native descriptor immutable prequeue binding missing')
                else:
                    candidates = tx.get(item['address'], [])
                    if not candidates:
                        raise ValueError('U native descriptor immutable TX journal missing')
                    binding = candidates.pop(0)
                length = _integer(binding.get('descriptor_bytes', binding['bytes']))
                if item['bytes'] != length or _integer(binding.get('ts_ns', 0)) > item['ts_ns']:
                    raise ValueError('native descriptor differs from immutable TX span/time')
                if len(driver_requests) >= maximum:
                    raise ValueError('bounded native TX request journal overflow')
                driver_requests[key] = binding
            else:
                if sequence != next_complete.get(pool, 1):
                    raise ValueError('native TX FIFO completion sequence gap/reorder')
                next_complete[pool] = sequence + 1
                binding = driver_requests.pop(key, None)
                if binding is None:
                    raise ValueError('native TX FIFO completion underflow')
            normalize(item, binding)
        elif expected_origin == 'U':
            candidates = nvme.get(item['cookie'])
            if not candidates:
                raise ValueError('U immutable submit-side NVMe cookie journal unavailable')
            for binding in candidates:
                if runtime is not None and (binding.get('_origin_tgid'), binding.get('_process_start_ticks')) != (item['origin_tgid'], item['process_start_ticks']):
                    raise ValueError('U cookie belongs to a different submitting process')
                if (item['address'] != _integer(binding['lba']) or
                        item['bytes'] != _integer(binding.get('command_bytes', binding['bytes']))):
                    raise ValueError('U native LBA/byte count differs from immutable mapping')
                normalize(item, binding)
        else:
            normalize(item)
    # Application record observations are authentic sideband endpoints; they
    # remain separate from driver/native completions above.
    for binding in journal:
        if binding['kind'] not in ('record_admit', 'record_terminal'):
            continue
        item = {name: 0 for name in FIELDS}
        item.update(phase=binding['kind'], accepted=1, cpu=-1,
                    ts_ns=_integer(binding['ts_ns']), cookie=_integer(binding['cookie']))
        normalize(item, binding)
    for (key, phase), candidates in record_events.items():
        select = min if phase == 'record_admit' else max
        row = dict(select(candidates, key=lambda value: value['ts_ns']))
        row['frame_generations'] = sorted({value['frame_generation'] for value in candidates})
        output.append(row)
    if not output:
        raise ValueError('no resolved native events captured')
    if pending or driver_requests or bindings:
        raise ValueError('native FIFO/request/binding completion debt remains at end of capture')
    # Stable order is defined by actual monotonic timestamps, never used to
    # reconstruct the kernel's FIFO (validated before this presentation sort).
    return sorted(output, key=lambda row: row['ts_ns'])


def derive_mapped_manifest(manifest, raw_text, metadata):
    """Append verified runtime identities without deriving expected work counts.

    This artifact preserves every original expectation, including records,
    logical frame layout, shape, warmup and seed. Runtime frame observations
    only describe actual accepted inputs/submits and never shrink that plan.
    """
    runtime = _runtime_binding(manifest, raw_text, metadata)
    if runtime is None:
        raise ValueError('runtime mapping requires predeclared logical sessions')
    events = decode_trace(manifest, raw_text, metadata)
    frames = []
    fields = ('session_id', 'record_id', 'generation', 'frame_id', 'native_session_id',
              'native_frame_id', 'frame_generation', 'frame_offset', 'frame_length',
              'stage', 'origin_tgid', 'process_start_ticks')
    for event in events:
        if event.get('event') == 'native_submit' and event.get('accepted') is True:
            frame = {key: event[key] for key in fields}
            if frame not in frames:
                frames.append(frame)
    result = copy.deepcopy(manifest)
    result['runtime_mapping_version'] = 1
    result['runtime_bindings'] = sorted(runtime['entries'], key=lambda row: row['logical_session_id'])
    result['runtime_frames'] = sorted(frames, key=lambda row: (row['session_id'], row['record_id'], row['frame_id'], row['stage']))
    return result


def _layout(manifest):
    rows = manifest.get('trace', {}).get('layout')
    if rows is None:
        return None
    if not isinstance(rows, list) or not rows:
        raise ValueError('predeclared logical frame layout missing')
    result, offset = {}, 0
    for ordinal, row in enumerate(rows):
        if (row.get('frame_id') != ordinal or row.get('offset_bytes') != offset or
                type(row.get('length_bytes')) is not int or row['length_bytes'] <= 0):
            raise ValueError('logical frame layout must be contiguous positive ordered segments')
        result[ordinal] = (offset, row['length_bytes'])
        offset += row['length_bytes']
    if offset != manifest.get('record_bytes'):
        raise ValueError('logical frame layout does not cover complete expected record bytes')
    expected = set(result)
    if any(set(row['frame_ids']) != expected for row in manifest.get('records', [])):
        raise ValueError('expected record frame IDs differ from predeclared layout')
    return result


def _raw_journal(metadata):
    descriptor = metadata.get('journal_artifact')
    if not isinstance(descriptor, dict) or not descriptor.get('path') or not descriptor.get('sha256'):
        raise ValueError('immutable raw journal artifact unavailable')
    if artifact(descriptor['path']) != descriptor:
        raise ValueError('raw journal artifact hash mismatch')
    return [json.loads(line) for line in Path(descriptor['path']).read_text().splitlines() if line.strip()]


def _runtime_binding(manifest, raw_text, metadata):
    plans = manifest.get('trace', {}).get('sessions')
    if plans is None:
        return None
    if not isinstance(plans, list) or not plans:
        raise ValueError('predeclared logical sessions missing')
    roles = {row['role']: row for row in plans}
    if len(roles) != len(plans) or len({r['logical_id'] for r in plans}) != len(plans):
        raise ValueError('ambiguous predeclared logical session roles/IDs')
    raw_binds, pools = {}, {}
    for line in raw_text.splitlines():
        match = LINE.search(line)
        if not match:
            continue
        values = dict(re.findall(r'(\w+)=([^\s]+)', match.group(3)))
        if values.get('phase') not in ('session_bind', 'pool_bind'):
            continue
        owner = (_integer(values.get('origin_tgid', 0)), _integer(values.get('process_start_ticks', 0)))
        if not owner[0] or not owner[1]:
            raise ValueError('actual native session/pool owner identity unavailable')
        if values['phase'] == 'session_bind':
            key = _integer(values['session_id'])
            if key in raw_binds:
                raise ValueError('duplicate actual CREATE binding')
            raw_binds[key] = owner
        else:
            pools[_integer(values['cookie'])] = owner
    sessions, owners, seen_roles = {}, {}, set()
    excluded_sessions, excluded_owners, entries = {}, set(), []
    rows = _raw_journal(metadata)
    for row in rows:
        role = row.get('role')
        if row.get('kind') == 'metadata':
            if manifest['arm'].startswith('K'):
                continue
            role = role or ('receiver' if row.get('rx') else 'sender')
        elif row.get('kind') != 'session_bind':
            continue
        if role not in roles:
            raise ValueError('runtime sideband role was not predeclared')
        plan = roles[role]
        owner = (_integer(row.get('pid', 0)), _integer(row.get('process_start_ticks', 0)))
        if not all(owner) or row.get('user_hz') != os.sysconf('SC_CLK_TCK'):
            raise ValueError('sideband process identity/USER_HZ unavailable')
        if role in seen_roles:
            raise ValueError('duplicate runtime sideband for logical role')
        if manifest['arm'].startswith('K'):
            actual = _integer(row['native_session_id'])
            if raw_binds.get(actual) != owner or row.get('session_id') != actual:
                raise ValueError('actual CREATE sideband/native session owner mismatch')
            if row.get('logical_session_id') != plan.get('protocol_session_id', plan['logical_id']):
                raise ValueError('actual protocol session differs from predeclared plan')
            origin = manifest['trace'].get('batch_key_origin')
            if row.get('first_batch_key') != origin:
                raise ValueError('actual first_batch_key differs from predeclared origin')
            recipe = manifest.get('recipe')
            if recipe:
                burst = manifest['trace']['burst']
                warmup = recipe.get('warmup_records', 4) * burst
                groups = recipe['records'] * burst + warmup
                if (row.get('groups') != groups or row.get('warmup') != warmup or row.get('burst') != burst):
                    raise ValueError('actual CREATE group/warmup/burst differs from plan')
        else:
            if owner not in pools.values():
                raise ValueError('U sideband process lacks actual native pool binding')
            actual = _integer(plan.get('protocol_session_id', plan['logical_id']))
            if 'session_id' in row and _integer(row['session_id']) != actual:
                raise ValueError('U actual protocol session differs from predeclared plan')
        measured = plan.get('measured', role == 'sender')
        entry = dict(logical_session_id=plan['logical_id'], native_session_id=actual,
                     origin_tgid=owner[0], process_start_ticks=owner[1], role=role, measured=measured)
        entries.append(entry)
        if measured:
            sessions[actual] = dict(logical_id=plan['logical_id'], owner=owner, role=role)
            owners[owner] = dict(logical_id=plan['logical_id'], native_session_id=actual, role=role)
        else:
            excluded_sessions[actual] = owner
            excluded_owners.add(owner)
        seen_roles.add(role)
    if set(roles) != seen_roles:
        raise ValueError('actual runtime binding missing for predeclared logical role')
    return dict(sessions=sessions, owners=owners, pools=pools,
                entries=entries, excluded_sessions=excluded_sessions, excluded_owners=excluded_owners)


def _journal_rows(manifest, metadata):
    if manifest['arm'].startswith('K'):
        return []
    rows, header = [], None
    for row in _raw_journal(metadata):
        if row.get('kind') == 'metadata':
            header = row
            if row.get('abi') != 'xdev-native-v1' or row.get('clock') != 'CLOCK_MONOTONIC':
                raise ValueError('U journal ABI/clock mismatch')
            if row.get('lost') is not False or row.get('fixed_io') is not False:
                raise ValueError('U journal lost/unsupported fixed IO capture')
            continue
        if header is None:
            raise ValueError('U journal metadata header missing')
        if header.get('rx') is True:
            continue  # Uninstrumented receiver executes its independent oracle.
        if header.get('rx') is not False:
            raise ValueError('U journal direction unknown')
        row = dict(row, _origin_tgid=header.get('pid', 0), _process_start_ticks=header.get('process_start_ticks', 0))
        rows.append(row)
    return rows


def collect(manifest, command, output_dir, *, tracefs_root=Path('/sys/kernel/tracing'),
            correctness_only=False):
    """Capture a real command only after trace interfaces pass admission."""
    # The capture implementation follows below; admission has precedence over
    # touching output or starting a child.
    trace = manifest.get('trace', {})
    reasons = []
    if not isinstance(command, list) or not command or any(not isinstance(v, str) or not v or '\0' in v for v in command):
        reasons.append('native workload command must be a nonempty argv list')
    if (manifest.get('clock') != 'CLOCK_MONOTONIC' or
            trace.get('clock', manifest.get('clock')) != 'CLOCK_MONOTONIC'):
        reasons.append('clock must be CLOCK_MONOTONIC matched to tracefs mono')
    root = Path(tracefs_root)
    if not (root / 'instances').is_dir():
        reasons.append('native tracefs instances unavailable')
    if not (root / 'events/xdev_ext/native_event/format').is_file():
        reasons.append('native provider submit/complete trace probe unavailable')
    if reasons:
        return dict(status='unavailable', performance_eligible=False, reasons=reasons,
                    returncode=None, artifacts={})
    return _capture(manifest, command, Path(output_dir), root, correctness_only)


def artifact(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1048576), b''):
            digest.update(chunk)
    return dict(path=str(path), sha256=digest.hexdigest())


def validate_format(text):
    """Require the compiled event ABI declaring both XSK consumption paths."""
    if 'abi=xdev-native-v1-nvme-xsk-batch' not in text:
        raise ValueError('native event lacks matched NVMe/XSK single+batch ABI coverage')
    for name in (*FIELDS, 'phase', 'origin'):
        if not re.search(r'field:[^;\n]*\b' + name + r'(?:\[[^]]*\])?;', text):
            raise ValueError('native event format missing field ' + name)


def retain_readback(spec, output):
    """Read actual receiver destination after command; retain full bytes/hash.

    A runner verdict never substitutes for reading the destination. This first
    implementation supports file/block receiver oracles, never CE/window mocks.
    Memory use is bounded at 1 MiB regardless of the transferred byte count.
    """
    oracle = spec.get('oracle', {})
    if oracle.get('kind') != 'file':
        raise ValueError('actual file/block receiver readback unavailable')
    reference = Path(oracle['reference'])
    size = reference.stat().st_size
    if size <= 0:
        raise ValueError('empty expected-byte oracle')
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    expected = output / 'expected.bin'
    readback = output / 'readback.bin'
    offset, consumed = _integer(oracle.get('offset', 0)), 0
    if offset < 0:
        raise ValueError('negative readback offset')
    fd = os.open(oracle['path'], os.O_RDONLY | os.O_CLOEXEC)
    try:
        with reference.open('rb') as source, expected.open('xb') as saved, readback.open('xb') as target:
            while consumed < size:
                want = min(1048576, size - consumed)
                actual = os.pread(fd, want, offset + consumed)
                wanted = source.read(want)
                target.write(actual)
                saved.write(wanted)
                if len(actual) != want or actual != wanted:
                    raise ValueError('actual whole-byte postoracle readback mismatch at chunk %d' % consumed)
                consumed += want
    finally:
        os.close(fd)
    return dict(readback=artifact(readback), expected=artifact(expected), bytes=consumed,
                source=str(Path(oracle['path']).resolve()), offset=offset)


class PrivateTrace:
    """A bounded private tracefs instance; never changes global tracing state."""
    def __init__(self, root, events=(EVENT,), buffer_kb=256):
        self.root, self.events = Path(root), tuple(events)
        self.path = self.root / 'instances' / ('xdev-native-' + uuid.uuid4().hex)
        self.buffer_kb = _integer(buffer_kb)
        if not 4 <= self.buffer_kb <= 16384:
            raise ValueError('trace buffer must be bounded 4..16384 KiB per CPU')

    def __enter__(self):
        self.path.mkdir(mode=0o700)
        try:
            self.write('tracing_on', '0')
            self.write('current_tracer', 'nop')
            self.write('trace_clock', 'mono')
            self.write('buffer_size_kb', str(self.buffer_kb))
            self.write('options/overwrite', '0')
            self.write('options/record-tgid', '1')
            self.write('trace', '')
            # A new instance starts with all CPUs enabled; preserve/read it
            # rather than narrowing to process affinity and losing IRQ/workers.
            for event in self.events:
                group, name = event.split(':', 1)
                self.write('events/%s/%s/enable' % (group, name), '1')
            if '[mono]' not in (self.path / 'trace_clock').read_text():
                raise ValueError('private trace instance did not select mono clock')
            self.stats()  # Refuse execution without all CPU loss counters.
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def write(self, relative, value):
        (self.path / relative).write_text(value)

    def mark(self, text):
        self.write('trace_marker', text + '\n')

    def start(self):
        self.write('tracing_on', '1')

    def stop(self):
        self.write('tracing_on', '0')

    def stats(self):
        values = {p.parent.name: p.read_text() for p in sorted((self.path / 'per_cpu').glob('cpu*/stats'))}
        trace_loss(values)
        return values

    def configuration(self):
        paths = ('trace_clock', 'buffer_size_kb', 'buffer_total_size_kb',
                 'tracing_cpumask', 'trace_options', 'set_event', 'timestamp_mode')
        return {name: (self.path / name).read_text() for name in paths if (self.path / name).exists()}

    def __exit__(self, *ignored):
        if self.path.exists():
            self.stop()
            for event in self.events:
                group, name = event.split(':', 1)
                self.write('events/%s/%s/enable' % (group, name), '0')
            self.path.rmdir()


def _module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def _native_preflight(manifest, root):
    """Resolve actual kernel interfaces, driver, devices and running config."""
    trace = manifest.get('trace', {})
    fmt = (root / 'events/xdev_ext/native_event/format').read_text()
    validate_format(fmt)
    if not any(' - tracefs ' in line and Path(line.split()[4]).resolve() == root.resolve()
               for line in Path('/proc/self/mountinfo').read_text().splitlines()):
        raise ValueError('native trace root is not an actual tracefs mount')
    if trace.get('record_mapping') != 'batch_key_div_burst' or _integer(trace.get('burst', 0)) != 1:
        raise ValueError('native immutable record mapping unavailable (supported burst=1)')
    if manifest['arm'].startswith('K') and trace.get('generation_mapping') not in ('batch_key', 'batch_key_relative'):
        raise ValueError('native K logical generation requires explicit batch_key mapping')
    if 'ts_ns' not in fmt:
        raise ValueError('native monotonic nanosecond timestamp field unavailable')
    if not trace.get('sessions'):
        raise ValueError('predeclared logical session/role runtime binding required')
    if {row.get('role') for row in trace['sessions']} != {'sender', 'receiver'}:
        raise ValueError('predeclared sender and paired receiver roles required')
    if {row['role'] for row in trace['sessions'] if row.get('measured', row['role'] == 'sender')} != {'sender'}:
        raise ValueError('native matched path currently measures sender role only')
    if _layout(manifest) is None:
        raise ValueError('predeclared contiguous logical frame layout required')
    if not manifest.get('records') or not trace.get('stage_map'):
        raise ValueError('native record/frame/stage mapping required before execution')
    if trace.get('clock_domain', manifest.get('clock_domain')) != manifest.get('clock_domain'):
        raise ValueError('trace clock domain differs from local monotonic domain')
    if not isinstance(manifest.get('clock_domain'), str) or not manifest['clock_domain']:
        raise ValueError('local monotonic clock-domain binding required')
    recipe = manifest.get('recipe', {})
    if recipe.get('chain') != 'nvme-nic':
        raise ValueError('native matched coverage currently supports nvme-nic only')
    rig = json.loads(Path(recipe['rig']).read_text())
    source = subprocess.run(['git', '-C', str(Path(__file__).resolve().parents[3]),
                             'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
    if source != manifest.get('exact_sha'):
        raise ValueError('collector source HEAD differs from declared exact_sha')
    gate = _module(Path(__file__).resolve().parent.parent / 'chains/hardware_gate.py', 'native_trace_hardware_gate')
    arm = 'session' if manifest['arm'].startswith('K') else 'userspace-shared'
    try:
        evidence = gate.admit(rig, [('nvme', 'from', 'src'), ('afxdp', 'to', 'tx'),
                                  ('afxdp', 'from', 'rx'), ('nvme', 'to', 'dst')], [arm])
    except gate.Refusal as error:
        raise ValueError('physical native hardware gate: ' + str(error)) from error
    nics = [row for row in evidence['devices'] if 'ifname' in row]
    if not nics or any(row.get('driver') != 'ice' for row in nics):
        raise ValueError('native unsupported NIC driver: audited ice TX FIFO and teardown coverage required')
    symbols = Path('/proc/kallsyms').read_text()
    resolved = {}
    for symbol in ('nvme_uring_cmd_io', 'nvme_uring_cmd_end_io'):
        found = re.findall(r'^\S+\s+\S\s+(' + symbol + r'(?:\.\S+)?)\s*(?:\[[^]]+\])?$', symbols, re.M)
        if not found:
            raise ValueError('native matched symbol unavailable: ' + symbol)
        resolved[symbol] = found
    for nic in nics:
        if nic['driver'] == 'ice':
            for symbol in ('ice_xmit_zc', 'ice_clean_xdp_irq_zc', 'ice_xsk_clean_xdp_ring'):
                matches = re.findall(r'^\S+\s+\S\s+(' + symbol + r'(?:\.\S+)?)\s*(?:\[[^]]+\])?$', symbols, re.M)
                if not matches:
                    raise ValueError('native driver completion/teardown coverage unavailable: ' + symbol)
                resolved[symbol] = matches
    configuration = gate.kernel_config(Path('/'))
    config_path = Path(configuration['config'])
    config_hash = artifact(config_path)['sha256']
    if manifest.get('config_hash') != config_hash:
        raise ValueError('running kernel config hash differs from declared config_hash')
    modules = {}
    for driver in {n['driver'] for n in nics}:
        directory = Path('/sys/module') / driver
        modules[driver] = {p.name: p.read_text() for p in (directory / 'srcversion', directory / 'version') if p.exists()}
        note = directory / 'notes/.note.gnu.build-id'
        if note.is_file():
            modules[driver]['build_id'] = artifact(note)
    return dict(formats={EVENT: fmt}, hardware=evidence, resolved_symbols=resolved,
                driver_modules=modules, kernel_release=os.uname().release,
                kernel_notes=artifact('/sys/kernel/notes'), config_hash=config_hash,
                collector_sha=source, timestamp_resolution_ns=(1 if 'ts_ns' in fmt else 1000),
                physical=True, environment='physical', evidence_kind='physical')


def _cpu_snapshot():
    before = time.monotonic_ns()
    text = Path('/proc/stat').read_text()
    after = time.monotonic_ns()
    cpus = re.findall(r'^(cpu\d+)\s', text, re.M)
    if not cpus:
        raise ValueError('all-CPU /proc/stat counters unavailable')
    return text, dict(before_ns=before, after_ns=after, cpus=cpus)



def execute_command(command, stdout, stderr, environment, timeout):
    """Run one owned process group; a timeout cannot leave device workers alive."""
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= 86400:
        raise ValueError('bounded command timeout must be 0..86400 seconds')
    child = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=environment,
                             start_new_session=True)
    timed_out = False
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        # The direct child may exit before its subprocesses. The session's
        # remaining process group is still ours, so terminate those members too.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return dict(returncode=child.returncode, timed_out=timed_out)


def _capture(manifest, command, output, root, correctness_only):
    artifacts, reasons = {}, []
    try:
        observed = _native_preflight(manifest, root)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        return dict(status='unavailable', performance_eligible=False, returncode=None,
                    reasons=['native preflight: ' + str(error)], artifacts={})
    # Fresh output protects an old campaign, journal, or proof from being reused
    # after a successful child which produced none of its own evidence.
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(output.iterdir()):
        return dict(status='unavailable', performance_eligible=False, returncode=None,
                    reasons=['native collector output directory must be empty'], artifacts={})
    output.chmod(0o700)
    journal_dir = output / 'journal'
    journal_dir.mkdir(mode=0o700)
    metadata = {k: manifest.get(k) for k in ('run_id', 'exact_sha', 'arm', 'clock',
                'clock_domain', 'endpoint', 'complete_boundary', 'submit_boundary',
                'cpu_budget', 'numa', 'iommu', 'group_bytes', 'segments_per_group',
                'inflight_bytes', 'native_batch', 'processing')}
    metadata.update(observed, schema_version=1, command=list(command),
                    cpu_interval_scope='whole_command', cpu_tick_hz=os.sysconf('SC_CLK_TCK'),
                    trace_dropped=None, correctness_only=bool(correctness_only))
    metadata['probes'] = {phase: dict(layer='native_provider', source=EVENT + ':' + phase)
                          for phase in ('native_submit', 'native_complete')}
    status, returncode = 'unavailable', None
    def save(kind, name, data):
        target = output / name
        target.write_text(data)
        artifacts[kind] = artifact(target)
    try:
        with PrivateTrace(root, buffer_kb=manifest['trace'].get('buffer_kb', 256)) as instance:
            metadata['instance'] = str(instance.path)
            metadata['instance_configuration'] = instance.configuration()
            metadata['cpu_stats_before'] = instance.stats()
            token = 'XDEV_NATIVE_BEGIN ' + str(manifest['run_id']) + ' ' + instance.path.name
            metadata['begin_marker'] = token
            instance.start()
            instance.mark(token)
            cpu_before, metadata['cpu_sample_before'] = _cpu_snapshot()
            save('system_cpu_before', 'system-cpu-before.stat', cpu_before)
            started_ns = time.monotonic_ns()
            environment = dict(os.environ, XDEV_EXT_NATIVE_JOURNAL_DIR=str(journal_dir.resolve()))
            with (output / 'workload.stdout').open('xb') as stdout, (output / 'workload.stderr').open('xb') as stderr:
                child = execute_command(command, stdout, stderr, environment,
                                        manifest['trace'].get('timeout_seconds', 3600))
                returncode = child['returncode']
                if child['timed_out']:
                    reasons.append('actual workload timeout; owned process group terminated')
            metadata['command_begin_ns'] = started_ns
            metadata['command_end_ns'] = time.monotonic_ns()
            cpu_after, metadata['cpu_sample_after'] = _cpu_snapshot()
            save('system_cpu_after', 'system-cpu-after.stat', cpu_after)
            metadata['end_marker'] = 'XDEV_NATIVE_END ' + instance.path.name
            instance.mark(metadata['end_marker'])
            instance.stop()
            metadata['cpu_stats_after'] = instance.stats()
            metadata['trace_dropped'] = trace_loss(metadata['cpu_stats_after'])
            # Fixed kernel ring capacity bounds the retained raw capture. Stop
            # tracing before reading, so the workload never depends on a reader.
            raw = (instance.path / 'trace').read_text()
            save('raw_trace', 'raw-trace.txt', raw)
        for kind, name in (('workload_stdout', 'workload.stdout'), ('workload_stderr', 'workload.stderr')):
            artifacts[kind] = artifact(output / name)
        if returncode != 0:
            raise ValueError('actual workload failed with returncode %s' % returncode)
        if metadata['begin_marker'] not in raw or metadata['end_marker'] not in raw:
            raise ValueError('trace run/instance boundary markers missing')
        if metadata['cpu_sample_before']['cpus'] != metadata['cpu_sample_after']['cpus']:
            raise ValueError('all-CPU set changed during command')
        # Journal raw bytes are retained separately and hash bound in metadata.
        journals = sorted(journal_dir.glob('*.jsonl'))
        if not manifest['arm'].startswith('K') or manifest['trace'].get('sessions') is not None:
            if not journals:
                raise ValueError('actual U immutable command journal missing')
            target = output / 'journal.jsonl'
            with target.open('xb') as stream:
                for path in journals:
                    stream.write(path.read_bytes())
            artifacts['journal'] = artifact(target)
            metadata['journal_artifact'] = artifacts['journal']
        rows = decode_trace(manifest, raw, metadata)
        save('events', 'events.jsonl', ''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows))
        if manifest['trace'].get('sessions') is not None:
            mapped = derive_mapped_manifest(manifest, raw, metadata)
            save('mapped_manifest', 'mapped-manifest.json', json.dumps(mapped, indent=2, sort_keys=True) + '\n')
        campaigns = list(output.glob('chains/**/campaign.json'))
        if len(campaigns) != 1:
            raise ValueError('one actual chains campaign.json postoracle required')
        artifacts['oracle'] = artifact(campaigns[0])
        campaign = json.loads(campaigns[0].read_text())
        if campaign.get('schema') != 'xdev-chain-campaign-v1' or len(campaign.get('rows', [])) != 1:
            raise ValueError('actual single-arm chains campaign schema mismatch')
        row = campaign['rows'][0]
        result = row.get('result', {})
        if result.get('status') != 'pass' or any(result.get(side, {}).get('exit') != 0 for side in ('sender', 'receiver')):
            raise ValueError('actual sender/receiver whole-byte oracle failed/not run')
        receiver_specs = []
        for path in campaigns[0].parent.glob('*/*.spec.json'):
            spec = json.loads(path.read_text())
            if spec.get('oracle', {}).get('kind') == 'file':
                receiver_specs.append((path, spec))
        if len(receiver_specs) != 1:
            raise ValueError('one actual receiver readback spec required')
        metadata['postoracle_readback'] = retain_readback(receiver_specs[0][1], output / 'postoracle')
        artifacts['oracle_spec'] = artifact(receiver_specs[0][0])
        artifacts['oracle_readback'] = metadata['postoracle_readback']['readback']
        artifacts['oracle_expected'] = metadata['postoracle_readback']['expected']
        # Native backing proof has no generic fallback: absence is reported, not
        # generated from manifest flags or a zero-valued counter declaration.
        proof = output / 'native-backing.json'
        if proof.is_file():
            artifacts['zero_copy'] = artifact(proof)
        else:
            reasons.append('actual native backing/no-bounce proof unavailable')
        reasons.append('steady-state all-CPU interval unavailable (whole command snapshots retained)')
        status = 'ok'
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        reasons.append(str(error))
        status = 'failed' if returncode is not None else 'unavailable'
    finally:
        metadata.update(returncode=returncode, capture_status=status, reasons=reasons)
        save('trace_metadata', 'trace-metadata.json', json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    return dict(status=status, returncode=returncode, reasons=reasons,
                performance_eligible=False, artifacts=artifacts)
