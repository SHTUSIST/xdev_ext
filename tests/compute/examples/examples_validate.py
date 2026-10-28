#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Results disk and host-side verdict of the BPF compute examples KVM run.

make-images DIR
    a private, empty results disk (results.raw)
validate --dir DIR --log LOG --result JSON
    every guest marker, no failed case, a clean kernel console, the verifier
    statistics of every example program, and for every case of PLAN its two
    record streams from the results disk (one tar archive): the fixed
    transform's run and the BPF example's run of identical inputs. Both runs
    must agree with each other and with an independent oracle written here
    (Python CRC32C, XXH64 and the parse header rule), batch by batch and byte
    by byte, and no chunk byte outside an output may change.
The plan is duplicated, not shared, with guest/run-guest.sh and with
guest/compute_examples_guest.c (the record layout): a guest that drifts from
it fails here.
"""
import argparse
import io
import json
from pathlib import Path
import re
import struct
import sys
import tarfile

RESULTS_BYTES = 64 << 20
FRAME_SIZE = 4096
MAX_FRAMES = 32
EBADMSG = 74

STREAM = struct.Struct('<QII2I2QQiI32s')     # struct stream_hdr
RECORD = struct.Struct('<IIIIIIIIiiI32I32I')  # struct rec_hdr
END = struct.Struct('<IIII')                 # struct end_rec
STREAM_MAGIC = 0x4d525453584558
REC_MAGIC = 0x52584558
END_MAGIC = 0x45584558

SPAN_EDGES = (301, 383, 384, 385, 511, 512, 513, 1023, 1024, 1025, 1431, 1432, 1433,
              2047, 2048, 2049, 3000, 3728, 3732, 3735, 3736, 4087, 4088, 4091, 4092, 4095,
              4096)
FRAMES = (('frames', 1432, 8192, 360, 3), ('frames', 300, 8192, 360, 3),
          ('frames', 7, 200, 0, 3), ('frames', 16, 512, 0, 3), ('frames', 4064, 8192, 0, 3))
XXH_SEED = 0x9E3779B185EBCA87

OBJECTS = ('crc32c_append_bytewise.bpf.o', 'crc32c_append_slice8.bpf.o',
           'crc32c_check_bytewise.bpf.o', 'crc32c_check_slice8.bpf.o',
           'parse_check.bpf.o', 'xxh64_append.bpf.o')


def case(fixed, bpf, input_kind, negatives, layouts, compare='identical'):
    return dict(fixed=fixed, bpf=bpf, input=input_kind, negatives=negatives,
                layouts=layouts, compare=compare)


# name -> (fixed stages, BPF stages, semantics of each run, inputs, layouts)
PLAN = {
    'crc32c_check_bytewise': case(['crc32c-check'], ['crc32c-check'], 'sealed', True,
                                  (('spans', 4096, 0), ('spans', 3736, 360)) + FRAMES),
    'crc32c_check_slice8': case(['crc32c-check'], ['crc32c-check'], 'sealed', True,
                                (('spans', 4096, 0), ('spans', 3736, 360)) + FRAMES),
    'crc32c_strip_slice8': case(['crc32c-strip'], ['crc32c-strip'], 'sealed', True,
                                (('spans', 4096, 0), ('spans', 3736, 360)) + FRAMES),
    'crc32c_append_bytewise': case(['crc32c-append'], ['crc32c-append'], 'random', False,
                                   (('spans', 4092, 0), ('spans', 3732, 360)) + FRAMES),
    'crc32c_append_slice8': case(['crc32c-append'], ['crc32c-append'], 'random', False,
                                 (('spans', 4092, 0), ('spans', 3732, 360)) + FRAMES),
    'xxh64_append_seed0': case(['xxh64-append:0'], ['xxh64-append:0'], 'random', False,
                               (('spans', 4088, 0), ('spans', 3728, 360)) + FRAMES),
    'xxh64_append_seed': case([f'xxh64-append:{XXH_SEED}'], [f'xxh64-append:{XXH_SEED}'],
                              'random', False,
                              (('spans', 4088, 0), ('spans', 3728, 360)) + FRAMES),
    'parse_check_h16': case(['parse-strip:16'], ['parse-check:16'], 'parse:16', True,
                            (('spans', 4096, 0),) + FRAMES, compare='strip:16'),
    'parse_check_h4': case(['parse-strip:4'], ['parse-check:4'], 'parse:4', True,
                           (('spans', 4096, 0),) + FRAMES, compare='strip:4'),
    'parse_compose_h16': case(['parse-strip:16'], ['parse-check:16', 'parse-strip:16'],
                              'parse:16', True, (('spans', 4096, 0),) + FRAMES),
}
# The stage words each run must carry: fixed transform id or BPF (10) with D.
STAGES = {
    'crc32c-check': (4, 0), 'crc32c-strip': (2, 0), 'crc32c-append': (1, 0),
    'parse-strip:16': (5, 16), 'parse-strip:4': (5, 4), 'xxh64-append:0': (6, 0),
    f'xxh64-append:{XXH_SEED}': (6, XXH_SEED),
}
BPF_DELTA = {'crc32c-check': 0, 'crc32c-strip': -4, 'crc32c-append': 4, 'parse-check:16': 0,
             'parse-check:4': 0, 'xxh64-append:0': 8, f'xxh64-append:{XXH_SEED}': 8,
             'parse-strip:16': -16}


# --- independent oracles ----------------------------------------------------

def _crc_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    return table


CRC_TABLE = _crc_table()


def crc32c(data):
    """Standard CRC-32C (Castagnoli), reflected, init and final XOR all ones."""
    crc = 0xFFFFFFFF
    for b in data:
        crc = CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


M64 = (1 << 64) - 1
P1, P2, P3 = 0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9
P4, P5 = 0x85EBCA77C2B2AE63, 0x27D4EB2F165667C5


def _rotl(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


def _round(acc, lane):
    return (_rotl((acc + lane * P2) & M64, 31) * P1) & M64


def xxh64(data, seed=0):
    """XXH64 from its published specification."""
    n, i = len(data), 0
    if n >= 32:
        v = [(seed + P1 + P2) & M64, (seed + P2) & M64, seed & M64, (seed - P1) & M64]
        while n - i >= 32:
            for k in range(4):
                v[k] = _round(v[k], int.from_bytes(data[i + 8 * k:i + 8 * k + 8], 'little'))
            i += 32
        h = (_rotl(v[0], 1) + _rotl(v[1], 7) + _rotl(v[2], 12) + _rotl(v[3], 18)) & M64
        for k in range(4):
            h = ((h ^ _round(0, v[k])) * P1 + P4) & M64
    else:
        h = (seed + P5) & M64
    h = (h + n) & M64
    while n - i >= 8:
        h ^= _round(0, int.from_bytes(data[i:i + 8], 'little'))
        h = (_rotl(h, 27) * P1 + P4) & M64
        i += 8
    if n - i >= 4:
        h ^= (int.from_bytes(data[i:i + 4], 'little') * P1) & M64
        h = (_rotl(h, 23) * P2 + P3) & M64
        i += 4
    while i < n:
        h ^= (data[i] * P5) & M64
        h = (_rotl(h, 11) * P1) & M64
        i += 1
    h ^= h >> 33
    h = (h * P2) & M64
    h ^= h >> 29
    h = (h * P3) & M64
    return h ^ (h >> 32)


def apply(semantic, frame):
    """The transform of one frame: its output bytes, or None to fail the batch."""
    name, _, arg = semantic.partition(':')
    if name in ('crc32c-check', 'crc32c-strip'):
        if len(frame) < 4 or int.from_bytes(frame[-4:], 'little') != crc32c(frame[:-4]):
            return None
        return frame if name == 'crc32c-check' else frame[:-4]
    if name == 'crc32c-append':
        return frame + crc32c(frame).to_bytes(4, 'little')
    if name == 'xxh64-append':
        return frame + xxh64(frame, int(arg)).to_bytes(8, 'big')
    if name in ('parse-check', 'parse-strip'):
        hdr = int(arg)
        if len(frame) < hdr or int.from_bytes(frame[:4], 'little') != len(frame) - hdr:
            return None
        return frame if name == 'parse-check' else frame[hdr:]
    raise ValueError('unknown semantic ' + semantic)


# Transforms that write no payload byte, not even on the way to a refusal.
WRITE_FREE = ('crc32c-check', 'crc32c-strip', 'parse-check')


def write_free(semantics):
    """True when no stage of the run may write a payload byte."""
    return all(s.partition(':')[0] in WRITE_FREE for s in semantics)


def expect_batch(semantics, frames):
    """Every stage over every frame, stage by stage: outputs, or None (aborted)."""
    for semantic in semantics:
        out = [apply(semantic, f) for f in frames]
        if any(o is None for o in out):
            return None
        frames = out
    return frames


# --- record streams -----------------------------------------------------------

def parse_stream(data):
    """(header dict, [record dict], end dict) of one guest record stream."""
    if len(data) < STREAM.size:
        raise ValueError('short stream')
    magic, version, nr_stages, x0, x1, a0, a1, seed, delta, negatives, inp = \
        STREAM.unpack_from(data, 0)
    if magic != STREAM_MAGIC or version != 2 or not 1 <= nr_stages <= 2:
        raise ValueError('bad stream header')
    head = dict(stages=[(x0, a0), (x1, a1)][:nr_stages], seed=seed, delta=delta,
                negatives=negatives, input=inp.rstrip(b'\0').decode())
    off, records = STREAM.size, []
    while True:
        if len(data) - off >= END.size and \
                struct.unpack_from('<I', data, off)[0] == END_MAGIC:
            _, count, done, aborted = END.unpack_from(data, off)
            if off + END.size != len(data):
                raise ValueError('bytes after the end record')
            end = dict(records=count, done=done, aborted=aborted)
            break
        if len(data) - off < RECORD.size:
            raise ValueError('truncated record')
        f = RECORD.unpack_from(data, off)
        off += RECORD.size
        if f[0] != REC_MAGIC or not 1 <= f[5] <= MAX_FRAMES:
            raise ValueError('bad record header')
        n = f[5]
        in_len, out_len = f[11:11 + n], f[43:43 + n]
        rec = dict(spans=f[1], hdr_room=f[2], seg_len=f[3], group_bytes=f[4], nframes=n,
                   corrupted=f[6], outcome=f[7], err_before=f[8], last_err=f[9], stray=f[10],
                   in_len=list(in_len), out_len=list(out_len))
        need = sum(in_len) + sum(out_len)
        if len(data) - off < need:
            raise ValueError('truncated record payload')
        rec['inputs'], rec['outputs'] = [], []
        for n_in in in_len:
            rec['inputs'].append(bytes(data[off:off + n_in]))
            off += n_in
        for n_out in out_len:
            rec['outputs'].append(bytes(data[off:off + n_out]))
            off += n_out
        records.append(rec)
    return head, records, end


def layout_records(layout, negatives):
    """The (spans, hdr_room, seg, group, in_len) sequence one layout must produce."""
    passes = 2 if negatives else 1
    if layout[0] == 'spans':
        _, seg, hdr = layout
        lens = [n for n in list(range(1, 301)) + list(SPAN_EDGES) if n <= seg]
        return [(1, hdr, seg, seg, [n]) for n in lens for _ in range(passes)]
    _, seg, group, hdr, batches = layout
    n = (group + seg - 1) // seg
    lens = [seg] * (n - 1) + [group - (n - 1) * seg]
    return [(0, hdr, seg, group, lens)] * (batches * passes)


def check_stream(name, mode, semantics, plan, head, records, end):
    """Problems of one run against the plan and the oracle, as strings."""
    errors = []
    want_stages = [STAGES[s] if mode == 'fixed' else (10, BPF_DELTA[s] & ((1 << 64) - 1))
                   for s in semantics]
    if mode == 'bpf' and name == 'parse_compose_h16':
        want_stages = [(10, 0), STAGES['parse-strip:16']]
    if head['stages'] != want_stages:
        errors.append(f'{name}.{mode}: stages {head["stages"]} != {want_stages}')
    if head['input'] != plan['input'] or bool(head['negatives']) != plan['negatives']:
        errors.append(f'{name}.{mode}: inputs {head["input"]} negatives {head["negatives"]}')
    shape = [r for layout in plan['layouts'] for r in layout_records(layout, plan['negatives'])]
    got = [(r['spans'], r['hdr_room'], r['seg_len'], r['group_bytes'], r['in_len'])
           for r in records]
    if got != shape:
        errors.append(f'{name}.{mode}: {len(got)} records, plan {len(shape)}, or a different shape')
    done = sum(1 for r in records if not r['outcome'])
    if end != dict(records=len(records), done=done, aborted=len(records) - done):
        errors.append(f'{name}.{mode}: end record {end}')
    for i, r in enumerate(records):
        where = f'{name}.{mode} record {i} (seg {r["seg_len"]} len {r["in_len"][:3]})'
        want = expect_batch(semantics, r['inputs'])
        if r['stray']:
            errors.append(f'{where}: {r["stray"]} chunk bytes changed outside the output')
        # The kernel keeps a session's first error only: a code read after a
        # batch is that batch's own only in a session that held none before.
        if r['err_before']:
            errors.append(f'{where}: the session held error {r["err_before"]} before the '
                          'batch, so its own error code is not observed')
        if r['corrupted'] and want is not None:
            errors.append(f'{where}: a corrupted input the oracle accepts')
        if want is None:
            # A refused batch may keep partial writes of a writing transform
            # (a failed batch is never retried); a write-free run changes nothing.
            if r['outcome'] != 1 or (write_free(semantics) and r['outputs'] != r['inputs']):
                errors.append(f'{where}: the oracle refuses this batch; outcome {r["outcome"]}, '
                              f'frames {"unchanged" if r["outputs"] == r["inputs"] else "changed"}')
            if r['last_err'] != -EBADMSG:
                errors.append(f'{where}: last_err {r["last_err"]} after a refused batch')
        elif r['outcome'] != 0 or r['outputs'] != want:
            errors.append(f'{where}: outcome {r["outcome"]}, output differs from the oracle')
        elif r['last_err']:
            errors.append(f'{where}: last_err {r["last_err"]} after a completed batch')
        if len(errors) > 20:
            errors.append(f'{name}.{mode}: more problems not listed')
            break
    return errors


def compare_runs(name, plan, fixed, bpf):
    """The fixed and the BPF run of one case: same inputs, same verdicts, same bytes."""
    errors = []
    if len(fixed) != len(bpf):
        return [f'{name}: {len(fixed)} fixed records, {len(bpf)} BPF records']
    hdr = int(plan['compare'].split(':')[1]) if plan['compare'] != 'identical' else 0
    for i, (f, b) in enumerate(zip(fixed, bpf)):
        if f['inputs'] != b['inputs'] or f['in_len'] != b['in_len']:
            errors.append(f'{name} record {i}: the two runs saw different inputs')
        elif f['outcome'] != b['outcome'] or f['last_err'] != b['last_err']:
            errors.append(f'{name} record {i}: fixed outcome {f["outcome"]}/{f["last_err"]}, '
                          f'BPF {b["outcome"]}/{b["last_err"]}')
        elif f['outcome']:
            # Refused in both runs: bytes compare only where neither run writes.
            if write_free(plan['fixed']) and write_free(plan['bpf']) and \
                    f['outputs'] != b['outputs']:
                errors.append(f'{name} record {i}: refused batch, frames differ')
        elif not hdr:
            if f['outputs'] != b['outputs']:
                errors.append(f'{name} record {i}: output bytes differ')
        elif f['outputs'] != [o[hdr:] for o in b['outputs']]:
            errors.append(f'{name} record {i}: BPF check + strip differs from the fixed strip')
        if len(errors) > 20:
            break
    return errors


# --- guest log ----------------------------------------------------------------

def check_log(text):
    errors = []
    lines = text.replace('\r', '').splitlines()
    passed = {m.group(1) for m in (re.match(r'^XDEV_EXT_EXAMPLES_CASE=PASS name=(\S+)', l)
                                   for l in lines) if m}
    errors += ['failed case: ' + l for l in lines if l.startswith('XDEV_EXT_EXAMPLES_CASE=FAIL')]
    errors += ['missing case: ' + c for c in ('verifier',) + tuple(PLAN) if c not in passed]
    for marker in ('XDEV_EXT_EXAMPLES_GUEST=PASS', 'XDEV_EXT_EXAMPLES_GUEST_EXIT=0',
                   'XDEV_EXT_EXAMPLE_VERIFIER_DONE objects=6 failed=0'):
        if marker not in lines:
            errors.append('missing marker: ' + marker)
    errors += ['run failed: ' + l for l in lines
               if l.startswith('XDEV_EXT_EXAMPLE_RUN') and 'result=PASS' not in l]
    return errors


def parse_verifier(text):
    """{object: {program: processed_insns}} from the guest tool's verify output."""
    out, errors = {}, []
    for line in text.splitlines():
        m = re.match(r'^XDEV_EXT_EXAMPLE_VERIFIER object=(\S+) program=(\S+) '
                     r'processed_insns=(\d+) verified_insns=(\d+) xlated_insns=(\d+) stats="(.*)"$',
                     line)
        if not m:
            continue
        obj, prog, processed, verified = m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
        if not processed or processed != verified:
            errors.append(f'{obj} {prog}: processed {processed} verified {verified}')
        out.setdefault(obj, {})[prog] = dict(processed_insns=processed, verified_insns=verified,
                                             xlated_insns=int(m.group(5)), stats=m.group(6))
    if sorted(out) != sorted(OBJECTS):
        errors.append(f'verifier objects {sorted(out)}')
    for obj, progs in out.items():
        if len(progs) != 3:
            errors.append(f'{obj}: {len(progs)} programs, want build, complete and compute')
    return out, errors


def check_console(text):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'xdev_ext_integration'))
    from xdev_ext_mech_zc_debug import debug_reports
    counts = debug_reports(text)
    return [] if not any(counts.values()) else ['kernel diagnostic: ' + json.dumps(counts, sort_keys=True)]


def read_results(path):
    """{member name: bytes} of the tar archive at the start of the results disk."""
    data = Path(path).read_bytes()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
        return {m.name.lstrip('./'): tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}


def validate(directory, log, result):
    text = Path(log).read_text(errors='replace')
    errors = check_log(text) + check_console(text)
    summary, verifier = {}, {}
    try:
        files = read_results(Path(directory) / 'results.raw')
    except (OSError, tarfile.TarError) as err:
        files = {}
        errors.append(f'results disk: {err}')
    if files:
        verifier, verr = parse_verifier(files.get('verifier.txt', b'').decode(errors='replace'))
        errors += verr
    for name, plan in PLAN.items():
        runs = {}
        for mode in ('fixed', 'bpf'):
            member = f'{name}.{mode}.bin'
            if member not in files:
                errors.append('missing stream ' + member)
                continue
            try:
                head, records, end = parse_stream(files[member])
            except ValueError as err:
                errors.append(f'{member}: {err}')
                continue
            errors += check_stream(name, mode, plan[mode], plan, head, records, end)
            runs[mode] = records
        if len(runs) == 2:
            errors += compare_runs(name, plan, runs['fixed'], runs['bpf'])
            recs = runs['bpf']
            summary[name] = dict(records=len(recs),
                                 done=sum(1 for r in recs if not r['outcome']),
                                 aborted=sum(1 for r in recs if r['outcome']),
                                 frames=sum(r['nframes'] for r in recs),
                                 input_bytes=sum(sum(r['in_len']) for r in recs),
                                 min_len=min(min(r['in_len']) for r in recs),
                                 max_len=max(max(r['in_len']) for r in recs))
    verdict = {'pass': not errors, 'errors': errors, 'cases': summary, 'verifier': verifier,
               'oracle': 'python crc32c, xxh64 and parse rule; fixed vs BPF byte compare',
               'claim': 'correctness only; no timing'}
    Path(result).write_text(json.dumps(verdict, indent=1, sort_keys=True) + '\n')
    for e in errors:
        print('FAIL ' + e)
    return 0 if not errors else 1


def make_images(directory):
    with open(Path(directory) / 'results.raw', 'wb') as fh:
        fh.truncate(RESULTS_BYTES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    images = sub.add_parser('make-images')
    images.add_argument('dir')
    check = sub.add_parser('validate')
    check.add_argument('--dir', required=True)
    check.add_argument('--log', required=True)
    check.add_argument('--result', required=True)
    args = parser.parse_args()
    if args.action == 'make-images':
        make_images(args.dir)
        return 0
    return validate(args.dir, args.log, args.result)


if __name__ == '__main__':
    sys.exit(main())
