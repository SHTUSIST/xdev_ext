#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Validate native fanout events; no user CQE substitutes for device completion.

This narrow decoder covers the lifecycle guest's 8192-byte, MTU-1500 NXP
fanout. It reuses the existing native collector's ABI and loss parsing. The
peer receiver has a separate session; driver TX records have no session and
are joined through the sender's immutable descriptor_bind pool/address.
"""
import importlib.util
from pathlib import Path
import re

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'tests/eval/native_trace/collector.py').is_file())
spec = importlib.util.spec_from_file_location(
    'fanout_native_collector', ROOT / 'tests/eval/native_trace/collector.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
ABI = 'xdev-native-v1-nvme-xsk-batch'
GROUP_BYTES = 8192
SEG_BYTES = 1432
PACKET_HEADER = 82
FRAME_BYTES = 4096
PAYLOAD_OFFSET = 360
# Fixed by the lifecycle guest image contract, not inferred from the trace.
SOURCE_SLBA = 2048
SINK_SLBA = 4096


def block(text, begin, end):
    if text.splitlines().count(begin) != 1 or text.splitlines().count(end) != 1:
        raise ValueError('missing/duplicate trace block: ' + begin)
    a, b = text.index(begin) + len(begin), text.index(end)
    if a >= b:
        raise ValueError('reversed trace block')
    return text[a:b]


def parse_trace(text):
    """Strictly type the existing ABI and require every retained CPU loss count."""
    if text.splitlines().count('XDEV_EXT_FANOUT_TRACE_CLOCK=mono') != 1:
        raise ValueError('trace monotonic clock provenance missing/duplicated')
    raw = block(text, 'XDEV_EXT_FANOUT_TRACE_BEGIN', 'XDEV_EXT_FANOUT_TRACE_END')
    stats = {}
    for cpu, data in re.findall(
            r'^XDEV_EXT_FANOUT_TRACE_CPU_BEGIN (cpu\d+)\n(.*?)'
            r'^XDEV_EXT_FANOUT_TRACE_CPU_END \1\s*$', text, re.M | re.S):
        if cpu in stats:
            raise ValueError('duplicate CPU statistics')
        stats[cpu] = data
    if (len(re.findall(r'^XDEV_EXT_FANOUT_TRACE_CPU_BEGIN ', text, re.M)) != len(stats) or
            len(re.findall(r'^XDEV_EXT_FANOUT_TRACE_CPU_END ', text, re.M)) != len(stats)):
        raise ValueError('malformed/missing CPU statistics block')
    if collector.trace_loss(stats):
        raise ValueError('trace loss invalidates completion accounting')
    events = []
    for line in raw.splitlines():
        if 'native_event:' not in line:
            continue
        match = collector.LINE.search(line)
        if not match:
            raise ValueError('malformed native trace line')
        cpu, _, payload = match.groups()
        pairs = re.findall(r'(\w+)=([^\s]+)', payload)
        event = dict(pairs)
        if len(event) != len(pairs) or event.get('abi') != ABI:
            raise ValueError('duplicate fields or unexpected trace ABI')
        if 'cpu' + str(int(cpu)) not in stats:
            raise ValueError('event CPU has no loss statistics')
        try:
            event.update({name: collector._integer(event[name])
                          for name in (*collector.FIELDS, 'ts_ns')})
        except (KeyError, ValueError) as error:
            raise ValueError('untyped native identity: ' + str(error)) from error
        if event['phase'] == 'trace_invalid':
            raise ValueError('native trace journal invalid')
        if event['ts_ns'] < 0:
            raise ValueError('invalid native timestamp')
        events.append(event)
    if not events:
        raise ValueError('no native events')
    # ts_ns is ktime_get_ns() in every producer; display timestamps truncate it.
    return sorted(events, key=lambda e: e['ts_ns'])


def validate_trace(text, session_id, groups, frames_per_group=6):
    """Return verified counts, or ValueError on incomplete/ambiguous evidence."""
    if session_id <= 0 or groups <= 0 or frames_per_group != 6:
        raise ValueError('expected positive sender session/groups and six-frame geometry')
    events = parse_trace(text.replace('\r', ''))
    source = [e for e in events if e['session_id'] == session_id]
    bindings = [e for e in source if e['phase'] == 'descriptor_bind']
    pools = {e['cookie'] for e in bindings}
    if len(pools) != 1 or 0 in pools:
        raise ValueError('fanout requires one identified sender XSK pool')
    relevant = [e for e in events if e['session_id'] == session_id or
                (e['class_id'] == 2 and e['cookie'] in pools and
                 e['phase'] in ('native_submit', 'native_complete'))]
    if any(e['origin'] != 'K' or e['accepted'] != 1 or e['status'] != 0
           for e in relevant):
        raise ValueError('native operation failed, was refused, or used a non-kernel path')

    # Match each real driver descriptor consume/completion to an immutable
    # core binding. Address reuse is legal only after its prior completion.
    pending_bind, pending_tx, tx_done, live_address = {}, {}, {}, {}
    next_submit = next_complete = 1
    for e in relevant:
        phase = e['phase']
        if phase == 'descriptor_bind':
            key = (e['cookie'], e['address'])
            if key in pending_bind or key in live_address:
                raise ValueError('descriptor address rebound before native completion')
            pending_bind[key] = e
        elif e['class_id'] == 2 and phase in ('native_submit', 'native_complete'):
            key = (e['cookie'], e['sequence'])
            if e['session_id'] != 0 or not e['sequence']:
                raise ValueError('unexpected native driver descriptor identity')
            if phase == 'native_submit':
                if e['sequence'] != next_submit:
                    raise ValueError('TX submit sequence gap/duplicate')
                next_submit += 1
                b = pending_bind.pop((e['cookie'], e['address']), None)
                if b is None or b['bytes'] != e['bytes'] or b['ts_ns'] > e['ts_ns']:
                    raise ValueError('TX submit lacks matching prior descriptor binding')
                pending_tx[key] = (e, b)
                live_address[(e['cookie'], e['address'])] = key
            else:
                if e['sequence'] != next_complete:
                    raise ValueError('TX completion sequence gap/duplicate')
                next_complete += 1
                pair = pending_tx.pop(key, None)
                if pair is None:
                    raise ValueError('TX completion lacks native submit')
                submit, b = pair
                address = (submit['cookie'], submit['address'])
                if live_address.pop(address, None) != key:
                    raise ValueError('TX completion lost its live descriptor address')
                if (e['address'], e['bytes']) != (submit['address'], submit['bytes']):
                    raise ValueError('TX completion span changed')
                frame = (b['batch_key'], b['frame_ordinal'])
                if frame in tx_done:
                    raise ValueError('duplicate TX completion for logical frame')
                tx_done[frame] = (b, submit, e)
    if pending_bind or pending_tx or live_address:
        raise ValueError('missing native TX submit/completion')

    rows = {}
    checked_phases = {'record_admit', 'native_submit', 'native_complete',
                      'descriptor_bind', 'downstream_complete', 'frame_recycle',
                      'record_terminal'}
    for e in source:
        if e['phase'] not in checked_phases:
            continue
        # Core TX has descriptor_bind and downstream_complete, whereas its
        # native callbacks are the session-less driver records above.
        key = (e['batch_key'], e['frame_ordinal'], e['phase'], e['stage'])
        if key in rows:
            raise ValueError('duplicate core frame event')
        rows[key] = e
    admissions = [e for e in source if e['phase'] == 'record_admit']
    group_keys = {e['batch_key'] for e in admissions}
    expected_frames = groups * frames_per_group
    if group_keys != set(range(1, groups + 1)) or len(admissions) != expected_frames:
        raise ValueError('producer admission count differs from requested groups')
    if len(tx_done) != expected_frames:
        raise ValueError('TX descriptor count differs from requested frames')

    def get(group, ordinal, phase, stage):
        e = rows.get((group, ordinal, phase, stage))
        if e is None:
            raise ValueError(f'missing {phase} stage={stage} group={group} frame={ordinal}')
        return e

    previous_use = {}
    native_commands = [set(), set()]
    # Per frame: admit + 2 NVMe submit/complete pairs + TX bind + 3 landed
    # + recycle + terminal = 11. Keep exact cardinality to reject extras.
    expected_rows = expected_frames * 11
    if len(rows) != expected_rows:
        raise ValueError('unexpected/missing core event cardinality')
    for group in sorted(group_keys):
        frames = []
        for ordinal in range(frames_per_group):
            admit = get(group, ordinal, 'record_admit', 0)
            length = min(SEG_BYTES, GROUP_BYTES - ordinal * SEG_BYTES)
            identity = (admit['frame_id'], admit['generation'], admit['frame_offset'],
                        admit['frame_length'], admit['batch_id'])
            if (admit['frame_offset'] != ordinal * SEG_BYTES or admit['frame_length'] != length or
                    admit['frame_id'] < 0 or admit['address'] !=
                    admit['frame_id'] * FRAME_BYTES + PAYLOAD_OFFSET):
                raise ValueError('producer payload geometry differs from lifecycle request')
            if admit['frame_id'] in frames:
                raise ValueError('two spans alias the same producer frame')
            frames.append(admit['frame_id'])
            required = []
            nvme_done = []
            for stage, opcode in ((0, 2), (1, 1)):
                submit = get(group, ordinal, 'native_submit', stage)
                done = get(group, ordinal, 'native_complete', stage)
                landed = get(group, ordinal, 'downstream_complete', stage)
                required += [submit, done, landed]
                for field in ('ticket', 'cookie', 'address', 'bytes', 'aux'):
                    if submit[field] != done[field]:
                        raise ValueError('NVMe native request changed at completion')
                expected_lba = (SOURCE_SLBA if stage == 0 else SINK_SLBA) + (group - 1) * 16
                if (submit['class_id'] != 3 or not submit['cookie'] or not submit['ticket'] or
                        submit['aux'] != (opcode | (15 << 8)) or submit['bytes'] != GROUP_BYTES or
                        submit['address'] != expected_lba):
                    raise ValueError('wrong native NVMe direction/command span')
                if landed['ticket'] != submit['ticket']:
                    raise ValueError('NVMe landed event has a different native ticket')
                if not admit['ts_ns'] <= submit['ts_ns'] <= done['ts_ns'] <= landed['ts_ns']:
                    raise ValueError('NVMe admission/submit/completion ordering invalid')
                native_commands[stage].add((group, submit['cookie'], submit['ticket']))
                nvme_done.append(done)
            bind, tx_submit, tx_complete = tx_done[(group, ordinal)]
            tx_landed = get(group, ordinal, 'downstream_complete', 2)
            recycle = get(group, ordinal, 'frame_recycle', 2)
            terminal = get(group, ordinal, 'record_terminal', 2)
            required += [bind, tx_landed, recycle, terminal]
            if (bind['stage'] != 2 or bind['class_id'] != 2 or bind['bytes'] != length + PACKET_HEADER or
                    not bind['ticket'] or tx_landed['ticket'] != bind['ticket']):
                raise ValueError('AF_XDP descriptor differs from expected payload span')
            if bind['address'] + PACKET_HEADER != admit['address']:
                raise ValueError('AF_XDP descriptor does not address the producer frame payload')
            if not (nvme_done[0]['ts_ns'] <= bind['ts_ns'] <= tx_submit['ts_ns'] <=
                    tx_complete['ts_ns'] <= tx_landed['ts_ns'] <= recycle['ts_ns'] <= terminal['ts_ns']):
                raise ValueError('TX completion/recycle ordering invalid')
            if nvme_done[1]['ts_ns'] > recycle['ts_ns']:
                raise ValueError('frame recycled before NVMe consumer completed')
            if nvme_done[0]['ts_ns'] > get(group, ordinal, 'native_submit', 1)['ts_ns']:
                raise ValueError('NVMe consumer submitted before producer completion')
            for e in required:
                current = (e['frame_id'], e['generation'], e['frame_offset'],
                           e['frame_length'], e['batch_id'])
                if current != identity:
                    raise ValueError('consumers/recycle do not share producer frame identity')
            old = previous_use.get(admit['frame_id'])
            if old and (admit['generation'] <= old[0] or admit['ts_ns'] < old[1]):
                raise ValueError('frame reused before recycle or without advancing generation')
            previous_use[admit['frame_id']] = (admit['generation'], recycle['ts_ns'])
    if [len(s) for s in native_commands] != [groups, groups]:
        raise ValueError('NVMe command count differs from requested groups')
    return {'status': 'PASS', 'scope': 'native-events-from-QEMU-guest-if-executed',
            'groups': groups, 'shared_frame_publications': expected_frames,
            'nvme_read_commands': groups, 'nvme_write_commands': groups,
            'afxdp_native_submitted': len(tx_done), 'afxdp_native_completed': len(tx_done),
            'frame_recycles': expected_frames, 'trace_loss': 0,
            'reuse_observed': expected_frames > len(previous_use),
            'transient_refs_and_READY': 'not exposed by this trace ABI; host core test only',
            'physical_dma_proven': False}
