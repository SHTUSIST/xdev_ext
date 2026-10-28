#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Campaign-end checks of a reliable-random cable run (E17), outside timing.

The cable (xdev_ext_mech_zc_wire.py --fault reliable-random) counts every
valid NXP v3 frame it saw independently of the kernel. The kernel reports its
own protocol counters (XDEV_EXT_ZC_{RX,TX}_TRANSPORT_COUNTERS, transport stats
version 2). The two must agree:

* every DATA attempt the sender made crossed the cable once, so
  (groups + retransmits) * frames_per_group == DATA dropped + forwarded
  (one frame may still be held for reordering when the cable stops);
* the receiver can suppress at most the DATA frames it did not hold, and never
  passes a group downstream twice (stage vectors equal done groups);
* a successful sender retained no frame without an ACK at finalization.

A run whose loss exhausted the retry budget may end UNKNOWN; that outcome is
accepted only with loss > 0 and the same exactly-once receiver checks.
Software-cable timing is not a network result; nothing here measures goodput.
"""
from xdev_ext_mech_zc_validate import _fields, _integer, _require, _vector

UNKNOWN_U64 = (1 << 64) - 1
COUNTERS = ('retransmits', 'dup_suppressed', 'held_acks', 'held_unacked')


def _counters(text, role):
    fields = _fields(text, 'XDEV_EXT_ZC_' + role + '_TRANSPORT_COUNTERS')
    values = {key: _integer(fields, key) for key in COUNTERS}
    _require(all(0 <= values[key] < UNKNOWN_U64 for key in COUNTERS[:3]) and
             0 <= values['held_unacked'] < 0xffffffff, role + ' transport counters unknown')
    return values


def validate_wire_random(wire, *, loss, reorder, seed, slow_receiver_us):
    _require(wire.get('mode') == 'reliable-random' and wire.get('errors') == [], 'cable mode/errors')
    _require((wire.get('loss'), wire.get('reorder'), wire.get('seed'), wire.get('slow_receiver_us')) ==
             (loss, reorder, seed, slow_receiver_us), 'cable parameters differ from campaign')
    keys = ('matched', 'dropped', 'dropped_data', 'dropped_control', 'reordered', 'delayed',
            'forwarded_data', 'forwarded_control', 'duplicated')
    _require(all(isinstance(wire.get(key), int) and wire[key] >= 0 for key in keys), 'cable counts')
    _require(wire['duplicated'] == 0, 'random cable duplicated a frame')
    _require(wire['dropped'] == wire['dropped_data'] + wire['dropped_control'], 'cable drop split')
    held = wire['matched'] - wire['dropped'] - wire['forwarded_data'] - wire['forwarded_control']
    _require(0 <= held <= (2 if reorder else 0), 'cable lost track of frames')
    _require(loss or not wire['dropped'], 'loss without --loss')
    _require(reorder or not wire['reordered'], 'reorder without --reorder')
    _require(wire['delayed'] == (wire['forwarded_data'] if slow_receiver_us else 0),
             'slow receiver delay not applied to every forwarded DATA frame')
    return held


def validate_reliable_random(text, wire, *, groups, loss, reorder, seed, slow_receiver_us):
    _require(0 < groups <= 1024 and 0 <= loss < 1 and 0 <= reorder <= 1 and slow_receiver_us >= 0,
             'bad random campaign')
    held_frames = validate_wire_random(wire, loss=loss, reorder=reorder, seed=seed,
                                       slow_receiver_us=slow_receiver_us)
    line = _fields(text, 'XDEV_EXT_ZC_WIRE_RANDOM')
    for key in ('matched', 'dropped_data', 'dropped_control', 'reordered', 'delayed',
                'forwarded_data', 'forwarded_control'):
        _require(_integer(line, key) == wire[key], 'cable console/json mismatch ' + key)
    rx, tx = _fields(text, 'XDEV_EXT_ZC_RX_STATS'), _fields(text, 'XDEV_EXT_ZC_TX_STATS')
    rx_result, tx_result = _fields(text, 'XDEV_EXT_ZC_RX_RESULT'), _fields(text, 'XDEV_EXT_ZC_TX_RESULT')
    rxc, txc = _counters(text, 'RX'), _counters(text, 'TX')
    done = _integer(rx, 'batches_done')
    held = _integer(rx, 'held')
    _require(0 < done <= groups and held % done == 0, 'receiver group accounting')
    per_group = held // done
    _require(0 < per_group <= 32, 'frames per group')
    # Exactly once downstream, whatever the cable did.
    for key in ('submitted', 'completed'):
        _require(_vector(rx, key)[1] == done, 'receiver stage ' + key + ' not exactly once')
    _require(_integer(rx, 'sequestered') == 0 and _integer(rx, 'protocol_err') == 0, 'receiver custody')
    data_seen = wire['dropped_data'] + wire['forwarded_data']
    # The sender's network stage is its last stage with accepted submits;
    # each accepted submit is one first DATA attempt of one group.
    submitted = _vector(tx, 'submitted')
    first = next((value for value in reversed(submitted) if value), 0)
    sent = (first + txc['retransmits']) * per_group
    _require(0 <= sent - data_seen <= held_frames, 'sender retransmit counter disagrees with cable')
    _require(rxc['dup_suppressed'] + held <= wire['forwarded_data'],
             'receiver suppressed more DATA than the cable delivered')
    _require(txc['held_acks'] <= wire['forwarded_control'], 'sender accepted HELD the cable never carried')
    success = tx_result.get('outcome') == 'success'
    if success:
        _require(_integer(tx_result, 'exit') == 0 and rx_result.get('outcome') == 'success' and
                 _integer(rx_result, 'exit') == 0, 'random campaign failed')
        _require(done == groups and _integer(tx, 'batches_done') == groups, 'incomplete transfer')
        _require(txc['held_unacked'] == 0 and rxc['held_unacked'] == 0, 'frames retained without ACK')
        _require(wire['forwarded_control'] >= groups, 'a group completed without a delivered ACK')
        _require(not wire['dropped'] or txc['retransmits'] > 0, 'loss recovered without retransmission')
        _require(not (rxc['retransmits'] or txc['dup_suppressed']), 'role counters crossed')
    else:
        _require(loss > 0 and tx_result.get('outcome') == 'unknown' and _integer(tx_result, 'exit') != 0,
                 'unexpected random campaign outcome')
        _require(tx.get('last_err') in ('-EREMOTEIO', '-121') and _integer(tx, 'batches_abort') > 0,
                 'UNKNOWN without exhausted remote budget')
    return dict(groups_done=done, retransmits=txc['retransmits'], dup_suppressed=rxc['dup_suppressed'],
                held_acks=txc['held_acks'], dropped=wire['dropped'], success=success)
