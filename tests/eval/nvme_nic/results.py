#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Strict validation of nnb_producer records and paired summaries (no thresholds)."""
import json

HDR = 40
TIMING = ('local_release_ns', 'receipt_ns', 'durable_ns', 'cpu_user_us', 'cpu_sys_us')
# Per-unit latency distribution (nearest-rank percentiles of the trial's units).
LATENCY = ('lat_min_ns', 'lat_p50_ns', 'lat_p90_ns', 'lat_p99_ns', 'lat_p999_ns', 'lat_max_ns')
COUNTERS = ('read_ops', 'read_bytes', 'write_ops', 'write_bytes', 'send_calls', 'send_bytes',
            'datagrams', 'recv_calls', 'cqes', 'notifs', 'zc_copied', 'splice_calls', 'batches')
COMMON = ('record', 'arm', 'direction', 'size', 'qd', 'effective_qd', 'session_depth',
          'xsk_zerocopy', 'pair', 'position', 'trial', 'units', 'groups', 'group_bytes', 'seg',
          'dgrams_per_group', 'payload_bytes', 'bursts', 'wire_session', 'first_gen', 'inflight_bytes',
          'window_passes', 'lat_samples') + COUNTERS
FWD = ('peer_datagrams', 'peer_bytes', 'peer_foreign', 'peer_buffers', 'peer_compare')
REV = ('readback_compare',)


class Invalid(ValueError):
    pass


def geometry(mtu, size, window_bytes):
    """Independent Python statement of nnb_geom_init (nnb_wire.h)."""
    if mtu <= 68 or size < 4096 or size > 4 << 20 or size & (size - 1) or window_bytes <= 0 or window_bytes % (4 << 20):
        raise Invalid('geometry: size must be a power of two in 4KiB..4MiB, window a multiple of 4MiB')
    seg = min(mtu - 68, 4096 - 360) & ~7
    group = 4 << 20
    while group > size or group > 32 * seg:
        group >>= 1
    if group < 4096:
        raise Invalid('geometry: MTU too small for a 4KiB group')
    dgrams = (group - 1) // seg + 1
    return dict(seg=seg, group=group, dgrams=dgrams, groups_per_unit=size // group,
                window_units=window_bytes // size, window_groups=window_bytes // group)


def inflight_bytes(arm, direction, size, qd, geo, session_depth):
    """Independent statement of the payload bytes an arm keeps in flight at most.

    posix forward and uring: qd units; posix reverse: one unit (synchronous);
    splice: one datagram per thread; session: its live batches (at most 64) of
    one group each, which can be fewer bytes than qd units.
    """
    if arm == 'session':
        return session_depth * geo['group']
    if arm == 'splice':
        return qd * geo['seg']
    if arm == 'posix' and direction == 'rev':
        return size
    return qd * size


def generator_byte(seed, off):
    """Independent payload oracle: splitmix64 of the 8-byte word index."""
    m = (1 << 64) - 1
    x = (seed + ((off >> 3) + 1) * 0x9e3779b97f4a7c15) & m
    x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & m
    x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & m
    x ^= x >> 31
    return (x >> (8 * (off & 7))) & 0xff


def generator(seed, off, n):
    return bytes(generator_byte(seed, off + i) for i in range(n))


def _int(record, key, minimum=0):
    value = record.get(key)
    if type(value) is not int or value < minimum:
        raise Invalid(f'{record.get("record")}/{record.get("arm")}: invalid {key}')
    return value


def check_trial(r, expect, measured):
    """One trial/warmup/integrity record against the requested configuration."""
    kind = r.get('record')
    direction = expect['direction']
    wanted = set(COMMON) | set(FWD if direction == 'fwd' else REV)
    timed = measured and kind != 'integrity'
    if timed:
        wanted |= {'local_release_ns', 'receipt_ns', 'cpu_user_us', 'cpu_sys_us'} if direction == 'fwd' \
            else {'durable_ns', 'cpu_user_us', 'cpu_sys_us'}
        if r.get('arm') != 'session':
            wanted |= set(LATENCY)
    if set(r) != wanted:
        extra = sorted(set(r) - wanted)
        missing = sorted(wanted - set(r))
        raise Invalid(f'{kind}/{r.get("arm")}: schema (extra {extra}, missing {missing})')
    for key in ('size', 'qd', 'group_bytes', 'seg', 'dgrams_per_group', 'units', 'groups', 'trial'):
        _int(r, key, 1)
    for key in COUNTERS + ('payload_bytes', 'bursts', 'wire_session', 'first_gen', 'effective_qd', 'session_depth',
                           'inflight_bytes', 'window_passes', 'lat_samples'):
        _int(r, key)
    g = expect['geometry']
    if (r['direction'], r['size'], r['qd']) != (direction, expect['size'], expect['qd']):
        raise Invalid('record is for another configuration')
    if (r['group_bytes'], r['seg'], r['dgrams_per_group']) != (g['group'], g['seg'], g['dgrams']):
        raise Invalid(f'{r["arm"]}: geometry differs from the independent statement')
    units = g['window_units'] if kind == 'integrity' else expect['units']
    if r['units'] != units or r['groups'] != units * g['groups_per_unit'] or r['payload_bytes'] != units * r['size']:
        raise Invalid(f'{kind}/{r["arm"]}: unit/group/payload accounting')
    if r['window_passes'] != -(-units // g['window_units']):
        raise Invalid(f'{kind}/{r["arm"]}: window passes')
    if r['inflight_bytes'] != inflight_bytes(r['arm'], direction, r['size'], r['qd'], g, r['session_depth']):
        raise Invalid(f'{kind}/{r["arm"]}: bytes in flight')
    # One completion-time sample per unit, except the session (no per-unit completions).
    if r['lat_samples'] != (0 if r['arm'] == 'session' else units):
        raise Invalid(f'{kind}/{r["arm"]}: latency samples')
    datagrams = r['groups'] * g['dgrams']
    wire = r['payload_bytes'] + datagrams * HDR
    if r['datagrams'] != datagrams:
        raise Invalid(f'{kind}/{r["arm"]}: datagram count')
    if direction == 'fwd':
        if r['read_bytes'] != r['payload_bytes'] or r['send_bytes'] != wire:
            raise Invalid(f'{kind}/{r["arm"]}: read/send bytes')
        if (r['peer_datagrams'], r['peer_bytes']) != (datagrams, wire):
            raise Invalid(f'{kind}/{r["arm"]}: peer receipt totals')
        if not 1 <= _int(r, 'peer_buffers') <= datagrams:
            raise Invalid(f'{kind}/{r["arm"]}: peer receive buffers')
        if r['peer_compare'] != (1 if kind == 'integrity' else 0):
            raise Invalid(f'{kind}/{r["arm"]}: full byte compare')
    else:
        if r['write_bytes'] != r['payload_bytes']:
            raise Invalid(f'{kind}/{r["arm"]}: write bytes')
        if r['readback_compare'] != (1 if kind == 'integrity' else 0):
            raise Invalid(f'{kind}/{r["arm"]}: readback compare')
        if r['bursts'] != -(-units // r['qd']):
            raise Invalid(f'{kind}/{r["arm"]}: bursts')
    if r['arm'] == 'uring' and direction == 'fwd':
        if not 0 <= r['zc_copied'] <= r['notifs'] <= r['send_calls']:
            raise Invalid('uring: notification accounting')
    if r['arm'] == 'session':
        if r['batches'] != r['groups'] or r['xsk_zerocopy'] != 1 or not 1 <= r['session_depth'] <= 64:
            raise Invalid('session: batches/zero-copy/depth')
    elif r['session_depth'] or r['xsk_zerocopy'] != -1 or r['batches']:
        raise Invalid(f'{r["arm"]}: session-only fields')
    if timed:
        for key in wanted & set(TIMING + LATENCY):
            _int(r, key, 0 if key.startswith('cpu') else 1)
        if r['arm'] != 'session' and [r[k] for k in LATENCY] != sorted(r[k] for k in LATENCY):
            raise Invalid(f'{kind}/{r["arm"]}: latency percentiles out of order')
    return r


def validate(lines, expect, measured):
    """All records of one producer run; returns (trials, integrity)."""
    records = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except ValueError as error:
            raise Invalid('producer output is not JSON lines') from error
    arms = expect['arms']
    setups = [r for r in records if r.get('record') == 'setup']
    if [r.get('arm') for r in setups] != arms or any(r.get('status') != 'ok' for r in setups):
        raise Invalid('setup records')
    for r in setups:
        if r.get('inflight_bytes') != inflight_bytes(r['arm'], expect['direction'], expect['size'], expect['qd'],
                                                     expect['geometry'], r.get('session_depth')):
            raise Invalid(f'setup/{r["arm"]}: bytes in flight')
    teardown = [r for r in records if r.get('record') == 'teardown']
    if any(r.get('stop_ret') != 0 for r in teardown) or ('session' in arms) != bool(teardown):
        raise Invalid('session STOP')
    body = [r for r in records if r.get('record') in ('warmup', 'trial', 'integrity')]
    if len(body) + len(setups) + len(teardown) != len(records):
        raise Invalid('unexpected record kind')
    for r in body:
        check_trial(r, expect, measured)
    warm = [r for r in body if r['record'] == 'warmup']
    trials = [r for r in body if r['record'] == 'trial']
    integrity = [r for r in body if r['record'] == 'integrity']
    if len(warm) != expect['warmup'] * len(arms) or sorted(r['arm'] for r in integrity) != sorted(arms):
        raise Invalid('warmup/integrity coverage')
    if len(trials) != expect['pairs'] * len(arms):
        raise Invalid('trial count')
    for p in range(expect['pairs']):
        pair = [r for r in trials if r['pair'] == p]
        if sorted(r['arm'] for r in pair) != sorted(arms) or sorted(r['position'] for r in pair) != list(range(len(arms))):
            raise Invalid(f'pair {p}: every arm exactly once')
    # Generations of one arm never repeat inside its session.
    for arm in arms:
        mine = sorted((r for r in body if r['arm'] == arm), key=lambda r: r['trial'])
        nxt = 1
        for r in mine:
            if r['first_gen'] != nxt:
                raise Invalid(f'{arm}: generations not contiguous')
            nxt += r['groups']
    return trials, integrity


def summarize(trials, direction, reference='posix'):
    """Raw samples, throughput and paired ratios; slower and no-benefit results stay."""
    key = 'local_release_ns' if direction == 'fwd' else 'durable_ns'
    arms = sorted({r['arm'] for r in trials})
    out = dict(metric=key, arms={})
    for arm in arms:
        mine = sorted((r for r in trials if r['arm'] == arm), key=lambda r: r['pair'])
        out['arms'][arm] = dict(
            samples_ns=[r[key] for r in mine],
            gbytes_per_s=[r['payload_bytes'] / r[key] for r in mine],
            receipt_ns=[r['receipt_ns'] for r in mine] if direction == 'fwd' else None,
            cpu_us=[r['cpu_user_us'] + r['cpu_sys_us'] for r in mine],
            zc_copied_fraction=[(r['zc_copied'] / r['notifs']) if r['notifs'] else None for r in mine],
            unit_latency_ns=None if arm == 'session' else {
                name: [r['lat_%s_ns' % name] for r in mine] for name in ('min', 'p50', 'p90', 'p99', 'p999', 'max')},
            window_passes=mine[0]['window_passes'] if mine else None,
            inflight_bytes=mine[0]['inflight_bytes'] if mine else None,
            effective_qd=mine[0]['effective_qd'] if mine else None,
            session_depth=mine[0]['session_depth'] if mine else None)
    if reference in arms:
        base = {r['pair']: r[key] for r in trials if r['arm'] == reference}
        out['paired_ratio_vs_' + reference] = {
            arm: [r[key] / base[r['pair']] for r in sorted((t for t in trials if t['arm'] == arm), key=lambda t: t['pair'])]
            for arm in arms if arm != reference}
    return out
