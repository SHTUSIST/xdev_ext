#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Validate the console of xdev_ext_eval_session_guest.sh (host side).

The guest prints, per case of CASES,
  XDEV_EXT_EVAL_SESSION=<arm>:<case> PASS|FAIL bytes=<n> sha256=<hex>
where the hash covers the bytes the guest's independent oracle read back
(tests/eval/session_guest/eval_session_oracle.c), in the canonical order
described at canonical().  This validator recomputes every expected byte
count and hash from the case parameters with its own transcription of the
arms' payload generators, and requires exactly one PASS marker per case,
the backend and scratch-restore lines, and a final
  XDEV_EXT_EVAL_SESSION_DONE=<n_pass>/<n_total>
after every marker.  A correctness check in a KVM guest with the CPU-memcpy
CE stand-in; nothing here is performance data.

  python3 xdev_ext_eval_session_validate.py GUEST_LOG
"""
import hashlib
from pathlib import Path
import re
import sys

M64 = (1 << 64) - 1
XG_WORD_MUL = 0x9e3779b97f4a7c15
RECORDS, WARMUP, DEPTH = 4, 1, 4		# chains: records, warmup records, depth
SEG_LEN_1500 = 1432			# NXP segment at MTU 1500, 4 KiB AF_XDP chunks
NXP_MAX_FRAMES = 32
IAA_MAX = 131072

# One tuple per guest case, in the guest script's order.
CASES = (
    ('nvme_gpu', 'load', 8192, 4, 11),
    ('nvme_gpu', 'load', 65536, 4, 12),
    ('nvme_gpu', 'save', 8192, 4, 13),
    ('nvme_gpu', 'save', 65536, 4, 14),
    ('gpu_nic', 4096, 4, 21),
    ('gpu_nic', 16384, 4, 22),
    ('chains', 'pair', 'nvme-nic', 'nic-nvme', 'closed', 4096, 31),
    ('chains', 'pair', 'nvme-nic', 'nic-nvme', 'sustained', 4096, 32),
    ('chains', 'pair', 'nvme-gpu-nic', 'nic-gpu-nvme', 'closed', 4096, 33),
    ('chains', 'pair', 'nvme-gpu-nic', 'nic-gpu-nvme', 'sustained', 4096, 34),
    ('chains', 'pair', 'nvme-gpu-nic', 'nic-gpu-nvme', 'closed', 65536, 35),
    ('chains', 'pair', 'nvme-gpu-nic', 'nic-gpu-nvme', 'sustained', 65536, 36),
    ('chains', 'iaa', 'closed', 4096, 41),
    ('chains', 'iaa', 'sustained', 4096, 42),
    ('chains', 'iaa', 'closed', 65536, 43),
    ('chains', 'iaa', 'sustained', 65536, 44),
)

MARKER = re.compile(r'^XDEV_EXT_EVAL_SESSION=(\S+?):(\S+) (PASS|FAIL) bytes=(\d+) sha256=([0-9a-f]{64})$')
DONE = re.compile(r'^XDEV_EXT_EVAL_SESSION_DONE=(\d+)/(\d+)$')
BACKEND = 'XDEV_EXT_EVAL_SESSION_BACKEND=CPU-memcpy-standin gpu=none performance_claim=none'
SCRATCH = re.compile(r'^XDEV_EXT_EVAL_SESSION_SCRATCH=restored source_sha256=[0-9a-f]{64} '
                     r'destination_sha256=[0-9a-f]{64}$')


def case_id(c):
    if c[0] == 'nvme_gpu':
        return 'nvme_gpu:%s-s%d-q%d-seed%d' % c[1:]
    if c[0] == 'gpu_nic':
        return 'gpu_nic:egress-ingest-s%d-d%d-seed%d' % c[1:]
    if c[1] == 'pair':
        return 'chains:%s+%s-%s-r%d-seed%d' % c[2:]
    return 'chains:nvme-iaa-gpu-%s-r%d-seed%d' % c[2:]


def guest_call(c):
    """The line of the guest script that runs case @c."""
    if c[0] == 'nvme_gpu':
        return 'nvme_gpu_case %s %d %d %d' % c[1:]
    if c[0] == 'gpu_nic':
        return 'gpu_nic_case %d %d %d' % c[1:]
    if c[1] == 'pair':
        return 'chain_pair_case %s %s %s %d %d' % c[2:]
    return 'chain_iaa_case %s %d %d' % c[2:]


# --- payload of tests/eval/nvme_gpu/nvme_gpu_core.h (also gpu_nic) ----------

def xg_mix64(x):
    """splitmix64 finaliser."""
    x = (x + 0x9e3779b97f4a7c15) & M64
    x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & M64
    x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & M64
    return x ^ (x >> 31)


def xg_payload(seed, length, offset=0):
    """Window bytes [offset, offset + length): word w holds (w ^ mix(seed)) * MUL."""
    key = xg_mix64(seed & 0xffffffff)
    return b''.join((((w ^ key) * XG_WORD_MUL) & M64).to_bytes(8, 'little')
                    for w in range(offset // 8, (offset + length) // 8))


# --- payload of tests/eval/chains/chain_oracle.h --------------------------------

def chain_mix(x):
    x ^= x >> 33
    x = (x * 0xff51afd7ed558ccd) & M64
    x ^= x >> 33
    x = (x * 0xc4ceb9fe1a85ec53) & M64
    return x ^ (x >> 33)


def chain_group(seed, g, length, text=False):
    """Bytes [0, length) of group g: bytes 0..7 are g, little endian."""
    base = seed ^ ((g * 0x9e3779b97f4a7c15) & M64)
    out = bytearray()
    if text:
        for run in range((length + 63) // 64):
            out += bytes([0x61 + (chain_mix(base ^ run) & 15)]) * 64
    else:
        for word in range((length + 7) // 8):
            out += chain_mix(base ^ ((word * 0xc2b2ae3d27d4eb4f) & M64)).to_bytes(8, 'little')
    out[0:8] = (g & M64).to_bytes(8, 'little')
    return bytes(out[:length])


def chain_shape(record, iaa):
    """(group_bytes, groups per record) as tests/eval/chains/run.py record_shape()."""
    if iaa:
        group = min(record, IAA_MAX)
    else:
        limit = NXP_MAX_FRAMES * SEG_LEN_1500
        group = 1 << (min(record, limit).bit_length() - 1)
    return group, record // group


def canonical(c):
    """The bytes a passing case's oracle hashes.

    nvme_gpu  window/size == qd blocks; load: the device slots, save: the file
              window's groups, each reordered by the block it holds, which
              makes blocks 0..qd-1 of the payload.
    gpu_nic   messages == depth groups of one group each: the ingest side's
              device slots reordered by block, blocks 0..depth-1.
    chains    paired NIC chains: the receiver's whole NVMe destination window,
              groups 0..total-1; nvme-iaa-gpu: the newest group's slot, the one
              group no later batch can overwrite (the free batch list is LIFO).
    """
    if c[0] == 'nvme_gpu':
        _, _, size, qd, seed = c
        return xg_payload(seed, size * qd)
    if c[0] == 'gpu_nic':
        _, size, depth, seed = c
        return xg_payload(seed, size * depth)
    if c[1] == 'pair':
        record, seed = c[5], c[6]
        group, burst = chain_shape(record, False)
        total = (RECORDS + WARMUP) * burst
        return b''.join(chain_group(seed, g, group) for g in range(total))
    record, seed = c[3], c[4]
    group, burst = chain_shape(record, True)
    total = burst  # IAA: one record, zero warmup; every produced byte is retained.
    return chain_group(seed, total - 1, group, text=True)


def expected(c):
    data = canonical(c)
    return len(data), hashlib.sha256(data).hexdigest()


def arm_shapes(c):
    """role -> (batches per session, stages, RX-first, sessions)."""
    if c[0] == 'nvme_gpu':
        return {'main': (c[3], 2, False, 2)}
    if c[0] == 'gpu_nic':
        return {'tx': (c[2], 2, False, 1), 'rx': (c[2], 2, True, 1)}
    if c[1] == 'pair':
        _, burst = chain_shape(c[5], False)
        n = (RECORDS + WARMUP) * burst
        stages = 2 if c[2] == 'nvme-nic' else 4
        return {'tx': (n, stages, False, 1), 'rx': (n, stages, True, 1)}
    _, burst = chain_shape(c[3], True)
    return {'main': (burst, 3, False, 1)}


def check_arm(records, shape):
    batches, stages, rx, sessions = shape
    if len(records) != sessions * 2 + 1:
        raise ValueError('missing or extra statistics/STOP/FD records')
    for i in range(sessions):
        stats, stop = records[2 * i:2 * i + 2]
        if not stats.startswith('XDEV_EXT_MECH_STATS ') or stop != 'EVAL_STOP=PASS result=0':
            raise ValueError('session statistics or successful STOP missing')
        pairs = stats.split()[1:]
        fields = dict(pair.split('=', 1) for pair in pairs)
        if len(fields) != len(pairs):
            raise ValueError('duplicate statistics field')
        if fields.get('state') != 'ACTIVE' or fields.get('last_err') != '0':
            raise ValueError('session was not healthy and ACTIVE')
        for field in ('batches_abort', 'rejects', 'sequestered', 'timeouts', 'inflight', 'protocol_err'):
            if fields.get(field) != '0':
                raise ValueError('session error/ownership count: ' + field)
        if fields.get('batches_done') != str(batches):
            raise ValueError('wrong batch count')
        submitted = [int(x) for x in fields.get('submitted', '').split(',')]
        completed = [int(x) for x in fields.get('completed', '').split(',')]
        if len(submitted) != 4 or len(completed) != 4:
            raise ValueError('missing stage counts')
        for stage in range(4):
            if stage >= stages:
                ok = submitted[stage] == completed[stage] == 0
            elif stage == 0 and rx:
                ok = submitted[stage] == 0 and completed[stage] == batches
            else:
                ok = submitted[stage] == completed[stage] and completed[stage] >= batches
            if not ok:
                raise ValueError('stage did not complete all admitted work')
    fd = re.fullmatch(r'EVAL_FD_CHECK=PASS before=(\d+) after=(\d+)', records[-1])
    if not fd or fd[1] != fd[2]:
        raise ValueError('descriptor cleanup mismatch')


def validate(text):
    lines = text.splitlines()
    want = {case_id(c): c for c in CASES}
    seen = {}
    checks = set()
    arms = {}
    scratch_at = None
    done_at = None
    for index, line in enumerate(lines):
        if line.startswith('XDEV_EXT_EVAL_ARM='):
            prefix, record = line.split(' ', 1)
            name, role = prefix.split('=', 1)[1].rsplit('/', 1)
            if name not in want or role not in arm_shapes(want[name]) or name in checks or name in seen or done_at is not None:
                raise ValueError('unknown, late or misplaced arm record')
            arms.setdefault((name, role), []).append(record)
        elif line.startswith('XDEV_EXT_EVAL_SESSION_CHECKS='):
            m = re.fullmatch(r'XDEV_EXT_EVAL_SESSION_CHECKS=(\S+) guards=pass ce_refs=0', line)
            if not m or m[1] not in want or m[1] in checks or m[1] in seen or done_at is not None:
                raise ValueError('missing or invalid guard/CE ownership check')
            name = m[1]
            for role, shape in arm_shapes(want[name]).items():
                check_arm(arms.get((name, role), []), shape)
            checks.add(name)
        elif line.startswith('XDEV_EXT_EVAL_SESSION_SCRATCH='):
            if not SCRATCH.fullmatch(line) or scratch_at is not None or len(seen) != len(want) or done_at is not None:
                raise ValueError('missing marker or misplaced scratch restore before DONE')
            scratch_at = index
        elif line.startswith('XDEV_EXT_EVAL_SESSION='):
            m = MARKER.fullmatch(line)
            if not m:
                raise ValueError('malformed marker: %r' % line)
            name = m.group(1) + ':' + m.group(2)
            if name not in want:
                raise ValueError('unknown case %s' % name)
            if name in seen:
                raise ValueError('duplicate marker for %s' % name)
            if done_at is not None:
                raise ValueError('marker %s after DONE' % name)
            if name not in checks:
                raise ValueError('missing guard and arm checks for ' + name)
            seen[name] = (m.group(3), int(m.group(4)), m.group(5))
        elif line.startswith('XDEV_EXT_EVAL_SESSION_DONE='):
            m = DONE.fullmatch(line)
            if not m or done_at is not None:
                raise ValueError('malformed or repeated DONE line: %r' % line)
            done_at = index
            done = (int(m.group(1)), int(m.group(2)))
    if lines.count(BACKEND) != 1:
        raise ValueError('XDEV_EXT_EVAL_SESSION_BACKEND line missing or repeated')
    if sum(1 for line in lines if SCRATCH.fullmatch(line)) != 1:
        raise ValueError('XDEV_EXT_EVAL_SESSION_SCRATCH restore line missing or repeated')
    for name, c in want.items():
        if name not in seen:
            raise ValueError('missing marker for %s' % name)
        verdict, nbytes, digest = seen[name]
        if verdict != 'PASS':
            raise ValueError('%s reported FAIL' % name)
        size, sha = expected(c)
        if nbytes != size:
            raise ValueError('%s: bytes=%d, expected %d' % (name, nbytes, size))
        if digest != sha:
            raise ValueError('%s: sha256 %s, expected %s' % (name, digest, sha))
    if done_at is None:
        raise ValueError('no DONE line')
    if done != (len(CASES), len(CASES)):
        raise ValueError('DONE=%d/%d, expected %d/%d' % (*done, len(CASES), len(CASES)))
    return dict(passed=len(seen), total=len(CASES), performance_claim='none',
                cases=sorted(seen))


def main(argv):
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    try:
        result = validate(Path(argv[0]).read_text(errors='replace'))
    except (OSError, ValueError) as error:
        print('XDEV_EXT_EVAL_SESSION_VALIDATE=FAIL %s' % error, file=sys.stderr)
        return 1
    print('XDEV_EXT_EVAL_SESSION_VALIDATE=PASS cases=%d performance_claim=none' % result['total'])
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
