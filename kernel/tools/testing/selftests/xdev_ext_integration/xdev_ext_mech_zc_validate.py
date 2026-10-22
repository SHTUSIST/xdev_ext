#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Campaign-end correctness checks, outside the timed data path."""
import re

from xdev_ext_mech_zc_debug import check_console


def _fields(text, marker):
    lines = [line for line in text.splitlines() if line.startswith(marker + ' ')]
    if len(lines) != 1:
        raise ValueError('expected exactly one ' + marker)
    pairs = re.findall(r'([a-z_]+)=([^\s]+)', lines[0])
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError('duplicate field in ' + marker)
    return dict(pairs)


def _integer(fields, key):
    try:
        return int(fields[key], 0)
    except (KeyError, ValueError) as exc:
        raise ValueError('missing/invalid ' + key) from exc


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _vector(fields, key):
    try:
        result = [int(value) for value in fields[key].split(',')]
    except (KeyError, ValueError) as exc:
        raise ValueError('invalid ' + key) from exc
    _require(len(result) == 4 and all(value >= 0 for value in result), 'bad stage vector')
    return result


def _final_role(text, role, stats, *, success):
    """A snapshot precedes STOP; its zeroes do not prove late-error-safe STOP."""
    prefix = 'XDEV_EXT_ZC_' + role + '_'
    transport = _fields(text, prefix + 'TRANSPORT')
    final = _fields(text, prefix + 'FINALIZE')
    session = _integer(stats, 'session')
    _require(session > 0 and _integer(transport, 'session') == session and
             _integer(final, 'session') == session, role + ' final session mismatch')
    counters = [_integer(transport, key) for key in
                ('native_controls', 'pending_acks', 'uncertain_controls')]
    _require(all(0 <= value < 0xffffffff for value in counters),
             role + ' missing/invalid final ownership')
    _require(-4095 <= _integer(final, 'stop_ret') <= 0, role + ' invalid STOP return')
    if success:
        _require(counters == [0, 0, 0], role + ' final ACK not drained')
        _require(_integer(final, 'stop_ret') == 0, role + ' STOP failed')
        _require(stats.get('state') == 'ACTIVE', role + ' pre-STOP snapshot not ACTIVE')
    markers = [prefix + kind + ' ' for kind in ('STATS', 'TRANSPORT', 'FINALIZE', 'RESULT')]
    positions = [next((i for i, line in enumerate(text.splitlines())
                       if line.startswith(marker)), -1) for marker in markers]
    _require(all(index >= 0 for index in positions) and positions == sorted(positions),
             role + ' finalization order')
    return transport, final


def validate_provider_console(text, *, case):
    """Dedicated guest must terminate with retained ambiguous native owners."""
    _require(case in ('short', 'ambiguous'), 'bad dedicated provider case')
    check_console(text)
    _require(not re.search(r'BUG:|WARNING:|Kernel panic|Oops:', text), 'kernel diagnostic')
    exits = [line for line in text.splitlines() if line.startswith('XDEV_EXT_ZC_GUEST_EXIT=')]
    _require(exits == ['XDEV_EXT_ZC_GUEST_EXIT=0'], 'provider guest failed')
    result = _fields(text, 'PASS provider')
    quarantine = _fields(text, 'PASS quarantine')
    verdict = _fields(text, 'XDEV_EXT_ZC_PROVIDER_CASE=PASS')
    _require(all(fields.get('case') == case for fields in (result, quarantine, verdict)),
             'wrong dedicated provider fault')
    for key, expected in (('groups', 1), ('depth', 1), ('success', 0), ('accepted', 1),
                          ('completed', 1), ('sequestered', 2), ('owner_refs_retained', 1),
                          ('stop_ret', -16), ('region_unbinds', 0), ('host_unbinds', 0),
                          ('ce_refs_retained', 1)):
        _require(_integer(result, key) == expected, 'provider quarantine ' + key)
    _require(result.get('source_and_guards') == 'unchanged', 'provider data/guards changed')
    for key, expected in (('retained', 1), ('forced_unload', 0),
                          ('dedicated_guest_shutdown_required', 1)):
        _require(_integer(quarantine, key) == expected, 'provider ownership ' + key)
    _require(verdict.get('backend') == 'CPU-memcpy-standin', 'provider scope mismatch')


def validate_iaa_console(text):
    """Require all independent software transforms and their byte/owner checks."""
    names = re.findall(r'^PASS IAA case=([^\s]+) ', text, re.M)
    _require(len(names) == 5 and set(names) == {'normal', 'delay', 'stale', 'duplicate', 'stop'},
             'missing/duplicate IAA software case')
    summary = _fields(text, 'XDEV_EXT_IAA_SOFTWARE=PASS')
    for key, expected in (('cases', 5), ('groups', 257), ('depth', 8)):
        _require(_integer(summary, key) == expected, 'IAA summary ' + key)
    _require(summary.get('backend') == 'deflate-generic' and
             summary.get('dma_backend') == 'CPU-memcpy-standin', 'IAA evidence scope')
    for case in names:
        fields = _fields(text, 'PASS IAA case=' + case)
        for key, expected in (('groups', 257), ('depth', 8), ('owners_released', 1),
                              ('pending', 0), ('dma_cpu_simulation', 1)):
            _require(_integer(fields, key) == expected, 'IAA ' + case + ' ' + key)
        _require(fields.get('software') == 'deflate-generic', 'IAA software backend')
        if case == 'stop':
            for key, expected in (('pending_drained', 1), ('full_source_and_guards', 1),
                                  ('region_unbinds', 2), ('host_unbinds', 2)):
                _require(_integer(fields, key) == expected, 'IAA STOP ' + key)
            _require(fields.get('stopped_stage') == 'DMA', 'IAA STOP scope')
            accepted = _integer(fields, 'native_accepted')
            _require(0 < accepted <= 8 and _integer(fields, 'native_completed') == accepted,
                     'IAA STOP native completion balance')
            continue
        for key, expected in (('actual_lengths', 257), ('restored_bytes', 257 * 4096),
                              ('full_source', 1), ('all_window_guards', 1),
                              ('all_pool_guards', 1), ('mutation_rejects', 4),
                              ('native_accepted', 514), ('native_completed', 514)):
            _require(_integer(fields, key) == expected, 'IAA ' + case + ' ' + key)
        _require(_vector(fields, 'stage_counts') == [257] * 4, 'IAA stage counts')
        _require(0 < _integer(fields, 'compressed_min') < 4096 <
                 _integer(fields, 'compressed_max') <= 8192,
                 'IAA variable output did not exercise shrink and expansion')
    _require(text.splitlines().count('PASS IAA software campaign unloaded provider after complete ownership return') == 1,
             'IAA provider unload missing/duplicated')


def validate_console(text, *, groups, ce_sim=False, ce_delay_us=0,
                     fault='none', rx_ce=False, reliable=False, depth=None, ce_slots=None):
    _require(groups > 0 and fault in ('none', 'drop-middle', 'duplicate-middle',
             'reliable-drop-data', 'reliable-drop-ack', 'reliable-duplicate-ack',
             'reliable-replay-group', 'reliable-reorder-group',
             'reliable-budget-unknown'), 'bad campaign')
    _require(not fault.startswith('reliable-') or reliable, 'reliable mode required')
    depth = min(groups, 64) if depth is None else depth
    ce_slots = depth if ce_slots is None else ce_slots
    _require(0 < groups <= 1024 and 0 < depth <= 64 and depth <= ce_slots <= 1024, 'bad window depth')
    _require(not rx_ce or ce_sim, 'rx-ce requires ce-sim')
    check_console(text)
    _require(not re.search(r'BUG:|WARNING:|Kernel panic|Oops:', text), 'kernel diagnostic')
    raw_lines = text.splitlines()
    lines = set(raw_lines)
    exits = [line for line in raw_lines if line.startswith('XDEV_EXT_ZC_GUEST_EXIT=')]
    _require(exits == ['XDEV_EXT_ZC_GUEST_EXIT=0'], 'missing/ambiguous successful guest exit')
    delays = [line for line in raw_lines if line.startswith('XDEV_EXT_ZC_CE_DELAY_US=')]
    _require(delays == ['XDEV_EXT_ZC_CE_DELAY_US=' + str(ce_delay_us)], 'wrong CE delay record')
    trace = _fields(text, 'XDEV_EXT_ZC_TRACE_CONTROL=PASS')
    fallback = _fields(text, 'XDEV_EXT_ZC_COPY_FALLBACK=PASS')
    _require(_integer(trace, 'calls') > 0, 'no native zero-copy trace')
    _require(_integer(fallback, 'calls') == 0, 'copy fallback observed')
    stats = _fields(text, 'XDEV_EXT_ZC_RX_STATS')
    result = _fields(text, 'XDEV_EXT_ZC_RX_RESULT')
    done = _integer(stats, 'batches_done')
    for key in ('inflight', 'sequestered', 'published', 'native_publish', 'protocol_err'):
        _require(_integer(stats, key) == 0, 'receiver ' + key)
    held, recycled = _integer(stats, 'held'), _integer(stats, 'recycled')
    _require(recycled >= held, 'receiver retained frames')
    unknown = fault == 'reliable-budget-unknown'
    if fault != 'drop-middle' and not unknown:
        _require(held == groups * 6, 'wrong receiver frame count')
        if not reliable:
            _require(recycled == held + (fault == 'duplicate-middle'), 'wrong frame recycle count')
    elapsed, timeout = _integer(result, 'elapsed_ms'), _integer(result, 'timeout_ms')
    _require(timeout > 0 and 0 <= elapsed <= timeout, 'unbounded receiver termination')
    if fault == 'drop-middle':
        _require(not re.search(r'(?:NIC_(?:CE_)?NVME_E2E|RECOVERY)=PASS', text),
                 'drop incorrectly claims successful transfer/recovery')
        _require(result.get('outcome') == 'fail-stop' and _integer(result, 'exit') != 0,
                 'drop falsely succeeded')
        _require(done == 1 and done < groups, 'drop must commit only generation 1')
        _require(_integer(stats, 'timeouts') == 1 and _integer(stats, 'batches_abort') == 1,
                 'wrong incomplete-group accounting')
        _require(stats.get('last_err') in ('-ETIMEDOUT', str(-110)), 'wrong fail-stop cause')
        _require('XDEV_EXT_ZC_FAIL_STOP=PASS' in lines and 'XDEV_EXT_ZC_CHAIN=PASS' not in lines,
                 'missing fail-stop verdict')
    elif unknown:
        _require(result.get('outcome') == 'incomplete-remote-unknown' and
                 _integer(result, 'exit') != 0, 'UNKNOWN receiver incorrectly succeeded')
        _require(1 <= done <= min(groups, depth + 1), 'UNKNOWN admitted prefix outside window')
        _require(stats.get('last_err') in ('0', '-ETIMEDOUT', '-110'), 'unexpected receiver failure')
        _require('XDEV_EXT_ZC_UNKNOWN=PASS' in lines and 'XDEV_EXT_ZC_CHAIN=PASS' not in lines,
                 'missing UNKNOWN verdict')
        _require(not re.search(r'XDEV_EXT_MECH_(?:NIC_(?:CE_)?NVME_E2E|NVME_NIC_E2E)=PASS', text),
                 'UNKNOWN falsely reports network success')
    else:
        _require(result.get('outcome') == 'success' and _integer(result, 'exit') == 0,
                 'receiver failed')
        _require(done == groups, 'incomplete receiver')
        for key in ('batches_abort', 'timeouts', 'rejects'):
            _require(_integer(stats, key) == 0, 'receiver ' + key)
        _require(stats.get('last_err') == '0', 'receiver last_err')
        _require('XDEV_EXT_ZC_CHAIN=PASS' in lines and 'XDEV_EXT_ZC_FAIL_STOP=PASS' not in lines,
                 'missing normal verdict')
    expected = [0, done, done, done] if rx_ce else [0, done, 0, 0]
    for key in ('submitted', 'completed'):
        vector = _vector(stats, key)
        _require(vector == ([done] + expected[1:] if key == 'completed' else expected),
                 'receiver stage ' + key)
    if reliable:
        tx = _fields(text, 'XDEV_EXT_ZC_TX_STATS')
        tx_result = _fields(text, 'XDEV_EXT_ZC_TX_RESULT')
        _require(_integer(tx, 'session') != _integer(stats, 'session'), 'role session collision')
        if unknown:
            outcome = _fields(text, 'XDEV_EXT_ZC_TX_REMOTE_OUTCOME')
            _require(outcome.get('outcome') == 'UNKNOWN' and
                     outcome.get('cause') == 'remote-ack-unconfirmed' and
                     outcome.get('durable') == 'unclaimed', 'missing remote UNKNOWN cause')
            _require(tx.get('last_err') in ('-EREMOTEIO', '-121') and
                     _integer(tx, 'batches_abort') > 0 and
                     tx_result.get('outcome') == 'unknown' and _integer(tx_result, 'exit') != 0,
                     'sender falsely succeeded after exhausted ACK budget')
            _require(not re.search(r'XDEV_EXT_MECH_(?:CE_SIM|NVME_NIC_E2E)=PASS chain=b', text),
                     'UNKNOWN falsely reports source PASS')
            for role, role_stats in (('RX', stats), ('TX', tx)):
                transport, final = _final_role(text, role, role_stats, success=False)
                retained = any(_integer(transport, key) for key in
                    ('native_controls', 'pending_acks', 'uncertain_controls')) or \
                    _integer(role_stats, 'sequestered') > 0
                expected_stop = -16 if retained else -121 if role == 'TX' else \
                    -110 if role_stats.get('last_err') in ('-ETIMEDOUT', '-110') else 0
                _require(_integer(final, 'stop_ret') == expected_stop,
                         role + ' UNKNOWN STOP lost failure or ownership')
        else:
            _require(tx_result.get('outcome') == 'success' and _integer(tx_result, 'exit') == 0,
                     'sender failed')
            for key in ('batches_abort', 'inflight', 'sequestered', 'native_publish',
                        'protocol_err', 'rejects', 'timeouts'):
                _require(_integer(tx, key) == 0, 'sender ' + key)
            _require(_integer(tx, 'batches_done') == groups and tx.get('last_err') == '0',
                     'sender incomplete')
            _final_role(text, 'RX', stats, success=True)
            _final_role(text, 'TX', tx, success=True)
        native_groups = _vector(tx, 'submitted')[0] if unknown else groups
        if unknown:
            _require(done <= native_groups <= min(groups, done + depth),
                     'UNKNOWN native admission outside bounded batch window')
        tx_expected = [native_groups] * (4 if ce_sim else 2) + ([0, 0] if not ce_sim else [])
        for key in ('submitted', 'completed'):
            vector = _vector(tx, key)
            # The terminal network stage may abort one group without an ACK;
            # accepted NVMe/CE commands still execute exactly once per group.
            native_stages = 3 if ce_sim else 1
            if unknown:
                _require(all(value <= native_groups for value in vector[:native_stages]) and
                         vector[:native_stages] == sorted(vector[:native_stages], reverse=True),
                         'UNKNOWN sender native stage ' + key)
            else:
                _require(vector == tx_expected, 'sender native stage ' + key)
    fault_stats = _fields(text, 'XDEV_EXT_ZC_FAULT_COUNTS')
    _require(fault_stats.get('mode') == fault, 'wrong injection mode')
    matched = _integer(fault_stats, 'matched')
    dropped, duplicated = (_integer(fault_stats, key) for key in ('dropped', 'duplicated'))
    if unknown:
        _require(dropped >= 2 and duplicated == 0 and matched == dropped,
                 'UNKNOWN needs persistent ACK loss across retries')
    else:
        _require((dropped, duplicated) == ((1, 0) if fault in ('drop-middle', 'reliable-drop-data', 'reliable-drop-ack') else
                                     (0, 1) if fault in ('duplicate-middle', 'reliable-duplicate-ack') else
                                     (0, 6) if fault == 'reliable-replay-group' else (0, 0)),
             'wrong fault event count')
        _require(matched == (fault != 'none'), 'wrong injection match count')
    if fault == 'reliable-reorder-group':
        _require(_integer(fault_stats, 'reordered') == 6, 'whole group not reordered')
    for key, value in (('session', 270019), ('generation', 2), ('index', 2), ('count', 6)):
        _require(_integer(fault_stats, key) == value, 'wrong injection target ' + key)
    if ce_sim:
        validate_iaa_console(text)
        ce = _fields(text, 'XDEV_EXT_ZC_CE_SIM_STATS')
        _require(_integer(ce, 'delay_us') == ce_delay_us, 'wrong simulator delay')
        expected_ce = (4 * groups + sum(_vector(tx, 'submitted')[1:3]) if unknown
                       else 6 * groups) + (2 * done if rx_ce else 0)
        _require(_integer(ce, 'accepted') == _integer(ce, 'completed') == expected_ce,
                 'CE count mismatch')
        _require(_integer(ce, 'pending') == 0, 'CE not drained')
        peak = _integer(ce, 'peak_pending')
        first = _integer(ce, 'submit_before_first_complete')
        _require(1 <= peak <= expected_ce and 1 <= first <= expected_ce,
                 'impossible CE overlap accounting')
        if ce_delay_us and min(groups, depth) >= 2:
            _require(peak >= 2 and first >= 2, 'no asynchronous overlap')
    return dict(receiver_batches_done=done)


def image_layout(groups):
    """Separate full campaign spans by at least one 8 KiB guard group.

    In-flight depth does not bound the total native NVMe write range.
    Keep the historical short-campaign LBAs, growing CE placement and the
    private images when a longer RX campaign reaches the old CE window.
    """
    _require(0 < groups <= 1024, 'bad campaign length')
    source_slba, rx_slba = 2048, 4096
    ce_slba = max(8192, rx_slba + (groups + 1) * 16)
    image_bytes = max(16 * 1024 * 1024, ce_slba * 512 + (groups + 1) * 8192)
    return dict(source_slba=source_slba, rx_slba=rx_slba,
                ce_slba=ce_slba, image_bytes=image_bytes)


def validate_images(source_before, source_after, destination_before, destination_after,
                    *, groups, receiver_batches_done, ce_sim=False, fault='none', rx_ce=False, reliable=False, depth=None, ce_slots=None):
    _require(groups > 0 and fault in ('none', 'drop-middle', 'duplicate-middle',
             'reliable-drop-data', 'reliable-drop-ack', 'reliable-duplicate-ack',
             'reliable-replay-group', 'reliable-reorder-group',
             'reliable-budget-unknown'), 'bad campaign')
    _require(not fault.startswith('reliable-') or reliable, 'reliable mode required')
    depth = min(groups, 64) if depth is None else depth
    ce_slots = depth if ce_slots is None else ce_slots
    _require(0 < groups <= 1024 and 0 < depth <= 64 and depth <= ce_slots <= 1024, 'bad window depth')
    _require(source_before == source_after, 'source image changed')
    _require(len(destination_before) == len(destination_after), 'destination size changed')
    done = receiver_batches_done
    _require(0 <= done < groups if fault == 'drop-middle' else
             1 <= done <= min(groups, depth + 1) if fault == 'reliable-budget-unknown'
             else done == groups,
             'wrong complete prefix')
    layout = image_layout(groups)
    size = 8192
    source_offset = layout['source_slba'] * 512
    destination_offset = layout['rx_slba'] * 512
    _require(len(source_before) >= source_offset + groups * size, 'short source')
    _require(len(destination_before) >= destination_offset + groups * size, 'short destination')
    expected = bytearray(destination_before)
    expected[destination_offset:destination_offset + done * size] = source_before[source_offset:source_offset + done * size]
    if ce_sim:
        offset = layout['ce_slba'] * 512
        _require(len(expected) >= offset + groups * size, 'short CE destination')
        expected[offset:offset + groups * size] = source_before[source_offset:source_offset + groups * size]
    _require(destination_after == expected, 'whole destination differs (partial/extra write)')
