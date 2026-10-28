# SPDX-License-Identifier: GPL-2.0
"""Account actual native traces and independent GPU correctness observations.

This module computes arithmetic; synthetic inputs certify no device execution.
No timestamp from another rank or clock domain enters a local denominator.
"""


def _integer(value, name, minimum=0):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError('invalid ' + name)
    return value


def _key(record):
    return (_integer(record['communicator'], 'communicator', 1),
            _integer(record['epoch'], 'epoch', 1),
            _integer(record['sequence'], 'sequence', 1),
            _integer(record['rank'], 'rank'), record['direction'])


def validated_payload_totals(records):
    """Count each full namespace/direction key once, only delivered+GPU-valid.

    Identical repeated observations are deduplicated. Conflicting records for
    one key invalidate accounting instead of selecting whichever came first.
    """
    seen, totals = {}, {}
    for r in records:
        key = _key(r)
        if key[3] not in (0, 1) or key[4] not in ('tx', 'rx'):
            raise ValueError('invalid rank or direction')
        size = _integer(r['payload_bytes'], 'payload_bytes')
        if type(r['valid']) is not bool or type(r['delivered']) is not bool:
            raise ValueError('valid/delivered must be observations')
        observation = (size, r['valid'], r['delivered'])
        if key in seen:
            if seen[key] != observation:
                raise ValueError('conflicting payload observations')
            continue
        seen[key] = observation
        if r['valid'] and r['delivered']:
            totals[key[4]] = totals.get(key[4], 0) + size
    return totals


def local_durations(intervals):
    """Require result and custody completion on one rank's one clock."""
    durations = []
    for i in intervals:
        rank = _integer(i['rank'], 'rank')
        clock = _integer(i['clock'], 'clock', 1)
        if rank not in (0, 1) or i.get('end_rank', rank) != rank or i.get('end_clock', clock) != clock:
            raise ValueError('cross-rank/clock interval')
        start = _integer(i['start'], 'start')
        end = _integer(i['end'], 'end')
        if end < start or i.get('completed') is not True or i.get('custody_released') is not True:
            raise ValueError('incomplete or reversed interval')
        if i['kind'] not in ('allreduce', 'rtt', 'gather', 'all_gather', 'batch', 'echo_reply'):
            raise ValueError('unknown interval kind')
        durations.append(dict(kind=i['kind'], rank=rank, clock=clock, duration_ns=end-start))
    return durations


def analyze(events, validations, metadata, intervals=()):
    """Analyze a single rank, communicator, epoch and clock's complete trace."""
    if _integer(metadata['trace_dropped'], 'trace_dropped'):
        raise ValueError('lost trace invalidates occupancy')
    rank, clock = metadata['rank'], metadata['clock']
    namespace = dict(communicator=metadata['communicator'], epoch=metadata['epoch'])
    requested = _integer(metadata['requested_depth'], 'requested_depth', 1)
    if rank not in (0, 1) or clock not in (1, 2):
        raise ValueError('invalid local clock/rank')
    durations = local_durations(intervals)
    if any(d['rank'] != rank or d['clock'] != clock for d in durations):
        raise ValueError('interval outside local trace domain')
    active, delivered, results, released = set(), set(), set(), set()
    messages, timeline = {}, []
    previous, area, high = None, 0, 0
    for e in events:
        if e['rank'] != rank or e['clock'] != clock:
            raise ValueError('mixed clock/rank trace')
        t = _integer(e['timestamp'], 'timestamp')
        seq = _integer(e['sequence'], 'sequence', 1)
        key = (seq, e.get('direction', 'rx'))
        payload = _integer(e['payload_bytes'], 'payload_bytes')
        wire = _integer(e['wire_bytes'], 'wire_bytes')
        if wire < payload:
            raise ValueError('wire smaller than payload')
        if previous is not None:
            if t < previous:
                raise ValueError('unordered trace')
            area += (t-previous)*len(active)
        previous = t
        if e.get('error', 0) or e['kind'] == 6:
            raise ValueError('failed/retained lifetime')
        if e['kind'] == 1:
            if key in messages:
                raise ValueError('duplicate slot acquisition')
            active.add(key)
            messages[key] = (payload, wire)
        else:
            if key not in active or messages[key] != (payload, wire):
                raise ValueError('event outside lifetime or changed bytes')
            if e['kind'] == 3:
                if key in delivered:
                    raise ValueError('duplicate delivery')
                delivered.add(key)
            elif e['kind'] == 4:
                if key not in delivered or key in results:
                    raise ValueError('result before delivery or duplicate result')
                results.add(key)
            elif e['kind'] == 5:
                if key not in results:
                    raise ValueError('release before actual result')
                active.remove(key)
                released.add(key)
            elif e['kind'] != 2:
                raise ValueError('unknown trace event')
        if _integer(e['logical_inflight'], 'logical_inflight') != len(active):
            raise ValueError('native depth disagrees with complete lifetime')
        if len(active) > requested:
            raise ValueError('depth exceeds admitted bound')
        high = max(high, len(active))
        timeline.append(dict(timestamp=t, inflight=len(active)))
    if active or delivered != set(messages) or released != set(messages):
        raise ValueError('incomplete lifetime')
    observed = []
    for v in validations:
        if any(v.get(k, value) != value for k, value in namespace.items()) or v['rank'] != rank:
            raise ValueError('validation outside local namespace')
        key = (v['sequence'], v.get('direction', 'rx'))
        if key not in delivered or v['payload_bytes'] != messages[key][0] or v['valid'] is not True:
            raise ValueError('payload not independently GPU validated')
        observed.append(dict(v, **namespace, delivered=True, direction=key[1]))
    if {(v['sequence'],v['direction']) for v in observed} != delivered:
        raise ValueError('missing per-message GPU validation')
    totals = validated_payload_totals(observed)
    duration = timeline[-1]['timestamp']-timeline[0]['timestamp'] if timeline else 0
    if messages and duration <= 0:
        raise ValueError('nonpositive throughput interval')
    wire_totals, header_totals = {}, {}
    header = _integer(metadata.get('wire_header_bytes',0), 'wire_header_bytes')
    for (seq, direction), (payload, wire) in messages.items():
        if wire < payload+header:
            raise ValueError('wire omits actual header')
        wire_totals[direction] = wire_totals.get(direction, 0)+wire
        header_totals[direction] = header_totals.get(direction, 0)+header
    return dict(payload_bytes_by_direction=totals, wire_bytes_by_direction=wire_totals,
                nonpayload_bytes_by_direction={d:wire_totals[d]-totals.get(d,0) for d in wire_totals},
                header_bytes_by_direction=header_totals,
                padding_bytes_by_direction={d:wire_totals[d]-totals.get(d,0)-header_totals[d] for d in wire_totals},
                logical_inflight_high_water=high, requested_depth=requested,
                timeline=timeline, occupied_time_ns=area, duration_ns=duration,
                mean_logical_inflight=area/duration if duration else 0,
                payload_bytes_per_second_by_direction={d:n*1e9/duration for d,n in totals.items()},
                durations_ns=durations)


def observe_lifetimes(events):
    """Observe partial custody without converting failure into a release.

    Unlike strict analyze(), this diagnostic observer permits live/failed
    resources at trace end. It never produces a throughput admission verdict.
    Named source-native request events may omit unchanged acquire fields.
    """
    names = {1:'acquire',2:'produced',3:'delivered',4:'result',5:'release',
             6:'failed_retained',7:'tx_done'}
    ledger, live, timeline, validated, completed_lifetimes = {}, set(), [], set(), []
    previous, area, high, failed_bytes, released_bytes = None,0,0,0,0
    domain = None
    for event in events:
        e = dict(event)
        seq = _integer(e.get('sequence',e.get('seq')), 'sequence', 1)
        t = _integer(e.get('timestamp',e.get('t')), 'timestamp')
        clock = e.get('clock',domain[1] if domain else 1)
        rank = e.get('rank',domain[0] if domain else 0)
        if domain is None:
            domain=(rank,clock)
        if (rank,clock)!=domain or (previous is not None and t<previous):
            raise ValueError('mixed domain or unordered trace')
        if previous is not None:
            area+=(t-previous)*len(live)
        previous=t
        kind=names.get(e['kind'],e['kind'])
        if kind=='acquire':
            if seq in ledger:
                raise ValueError('duplicate acquisition')
            payload=_integer(e.get('payload_bytes',e.get('payload',0)),'payload')
            wire=_integer(e.get('wire_bytes',e.get('wire',payload)),'wire')
            if wire<payload:
                raise ValueError('wire smaller than payload')
            ledger[seq]=dict(payload=payload,wire=wire,failed=False,start=t)
            live.add(seq)
        else:
            if seq not in ledger:
                raise ValueError('event without acquisition')
            r=ledger[seq]
            if seq not in live and kind!='gpu_validated':
                raise ValueError('event after release')
            if e.get('payload_bytes',e.get('payload',r['payload']))!=r['payload']:
                raise ValueError('changed payload')
            if kind=='release':
                live.remove(seq)
                released_bytes+=r['payload']
                completed_lifetimes.append(dict(seq=seq,start=r['start'],end=t))
            elif kind=='failed_retained':
                if not r['failed']:
                    failed_bytes+=r['payload']
                    r['failed']=True
            elif kind=='gpu_validated':
                validated.add(seq)
            elif kind not in ('produced','delivered','result','tx_done'):
                raise ValueError('unknown lifetime event')
        if 'logical_inflight' in e and e['logical_inflight']!=len(live):
            raise ValueError('native occupancy counter disagrees')
        high=max(high,len(live))
        timeline.append(dict(timestamp=t,inflight=len(live)))
    return dict(logical_inflight_high_water=high,logical_inflight=len(live),
                timeline=timeline,occupied_time_ns=area,
                failed_payload_bytes=failed_bytes,released_payload_bytes=released_bytes,
                unique_validated_payload_bytes=sum(ledger[s]['payload'] for s in validated),
                completed_lifetimes=completed_lifetimes)
