# SPDX-License-Identifier: GPL-2.0
"""Independent HFT1 fixtures; no producer, validator, digest or device calls."""
import copy
import struct

POLICY = 'benchmark-policy-v1'
PROFILE = dict(schema=1, record_bytes=64, payload_bytes=512, burst_packets=2,
               depth=2, bursts=2, actors=1, seed=9, session_base=0x1020304050607080)
IDENTITY = dict(token='independent-fixture-run', session_base=PROFILE['session_base'])


def expected_header(session, generation, size):
    return struct.pack('!IBBBBQIHHIIII', 0x48465431, 1, 40, 2, 0,
                       session, generation, 0, 1, size, 0, size, 0)


def expected_payload(p, group):
    out = bytearray()
    for record in range(p['payload_bytes'] // p['record_bytes']):
        out.extend(struct.pack('!IHHIHH', 0x4846544d, 0, p['record_bytes'],
                               group, record, 0))
        out.extend((p['seed'] + 17 * group + 11 * record + 7 * j) & 255
                   for j in range(16, p['record_bytes']))
    return bytes(out)


def packet(p, generation):
    return expected_header(p['session_base'], generation, p['payload_bytes']) + expected_payload(p, generation - 1)


def campaign(payload=512):
    p = dict(PROFILE, payload_bytes=payload)
    trials, captures, guards = [], [], []
    for index, backend in enumerate(('posix', 'uring-fixed-zc', 'session')):
        profile = dict(p, session_base=p['session_base'] + index)
        trial = dict(trial_id='trial-' + str(index), profile=profile,
                     backend=backend, stop_ret=0 if backend == 'session' else None,
                     frame_slots=[0x1000, 0x2000])
        trials.append(trial)
        for generation in range(1, p['burst_packets'] * p['bursts'] + 1):
            captures.append(dict(trial_id=trial['trial_id'], datagram=packet(profile, generation), truncated=False))
            frame = (generation - 1) % p['depth']
            guards.append(dict(trial_id=trial['trial_id'], generation=generation,
                frame_pos=frame, slot_addr=trial['frame_slots'][frame], terminal_phase='post-send',
                raw_prefix=b'\xa5' * 430, raw_tail=b'\x5a' * (4096 - 512 - payload),
                committed=True, before_reuse=True, notification_complete=True))
    manifest = dict(schema=1, measurement_policy=POLICY, workload_complete=True,
                    local_release_complete=True, trials=trials)
    source = b''.join(expected_payload(p, g) for g in range(p['burst_packets'] * p['bursts']))
    return manifest, captures, guards, source


def changed(data, index):
    out = bytearray(data)
    out[index] ^= 1
    return bytes(out)


def clone(value):
    return copy.deepcopy(value)
