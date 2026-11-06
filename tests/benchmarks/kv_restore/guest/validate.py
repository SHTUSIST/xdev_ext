#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host side of the K-KV local-verify KVM correctness run.

make-plan  writes the KV manifest, the worker GO scripts and the private
           QEMU NVMe source image: two KV objects in the pattern of
           kv_layout.py at their LBAs and a decoy pattern everywhere else in
           the window, so a wrong LBA or a wrong frame cannot pass.
validate   reads the guest console and requires, for every planned GO, the
           exact outcome: accepted restores verified by the worker AND a
           digest equal to the one computed here from the pattern; refused
           requests refused with the planned errno before any START; exact
           cumulative batch counts; clean KV_BYE; no kernel diagnostic.

Correctness only (QEMU NVMe, system-heap dma-buf, no XDOMAIN): it measures
nothing and proves nothing about Thunderbolt, GPU memory or performance.
"""
import argparse
import errno
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kl = _load('kv_layout', HERE.parent / 'kv_layout.py')
kp = _load('kv_protocol', HERE.parent / 'kv_protocol.py')

KIB, MIB = 1 << 10, 1 << 20
DISK_BYTES = 64 * MIB
SERIAL = 'KVSRC00001'
DECOY_SEED = 0xDEC0DEC0DEC0DEC0
MANIFEST = {
    'schema': 1, 'kind': 'kv-layout', 'lba_bytes': 512,
    'window': {'slba': 2048, 'nlb': 48 * MIB // 512},
    'objects': [
        {'name': 'qwen3-14b-ctx', 'model': 'qwen3-14b', 'tokens': 32, 'seed': 0x14,
         'slba': 2048 + 8 * MIB // 512, 'nlb': 32 * 163840 // 512},
        {'name': 'qwen3-8b-ctx', 'model': 'qwen3-8b-bf16', 'tokens': 64, 'seed': 0x8,
         'slba': 2048 + 24 * MIB // 512, 'nlb': 64 * 147456 // 512},
    ],
}
# Two worker invocations (geometries); each GO is (run, object, tokens, ordinal, dst0, error).
RUNS = [
    {'name': 'A', 'geometry': dict(group_bytes=256 * KIB, frame_bytes=128 * KIB, depth=4,
                                   window=4, early=False), 'pool_frames': 128,
     'go': [('a1', 'qwen3-14b-ctx', 32, 1, 0, 0),
            ('a2', 'qwen3-8b-ctx', 64, 2, 5, 0),
            ('a3', 'qwen3-14b-ctx', 16, 3, 70, 0),
            ('a4', 'qwen3-8b-ctx', 8, 3, 0, -errno.EALREADY),
            ('a5', 'qwen3-8b-ctx', 64, 4, 100, -errno.ENOSPC)]},
    {'name': 'B', 'geometry': dict(group_bytes=256 * KIB, frame_bytes=256 * KIB, depth=8,
                                   window=8, early=False), 'pool_frames': 64,
     'go': [('b1', 'qwen3-8b-ctx', 64, 1, 3, 0),
            ('b2', 'qwen3-14b-ctx', 32, 7, 40, 0)]},
]


class OracleError(ValueError):
    pass


def manifest():
    return kl.parse_manifest(MANIFEST)


def fnv1a(data, h=0xCBF29CE484222325):
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & ((1 << 64) - 1)
    return h


def worker_args(run):
    m, g = manifest(), run['geometry']
    return ['--window-slba', m.window_slba, '--window-nlb', m.window_nlb, '--lba-bytes',
            m.lba_bytes, '--group-bytes', g['group_bytes'], '--frame-bytes', g['frame_bytes'],
            '--depth', g['depth'], '--window', g['window'],
            '--pool-bytes', run['pool_frames'] * g['frame_bytes']] + (['--early'] if g['early'] else [])


def expectations():
    """Per run: KV_READY facts and the outcome of every GO, computed here."""
    m, out = manifest(), []
    for run in RUNS:
        g = kl.Geometry(**run['geometry'])
        done, results = 0, []
        for name, obj_name, tokens, ordinal, dst0, error in run['go']:
            obj = m.object(obj_name)
            size = kl.kv_bytes(obj.model, tokens)
            item = dict(run=name, object=obj_name, ordinal=ordinal, dst0=dst0, bytes=size,
                        seed=obj.seed, slba=obj.slba, error=error)
            if not error:
                plan = kl.plan_restore(m, obj_name, tokens, g, ordinal, dst0, run['pool_frames'])
                done += plan.groups
                item.update(groups=plan.groups, first_seq=plan.first_seq, cumulative=done,
                            digest=fnv1a(kl.pattern_bytes(obj.seed, 0, size)))
            results.append(item)
        out.append(dict(name=run['name'], pool_frames=run['pool_frames'], results=results,
                        restores=len(results)))
    return out


def make_plan(output):
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    m = manifest()
    disk = bytearray(DISK_BYTES)
    # Decoy pattern over the whole window, then the objects at their LBAs.
    start, end = m.window_slba * 512, (m.window_slba + m.window_nlb) * 512
    disk[start:end] = kl.pattern_bytes(DECOY_SEED, start, end - start)
    for o in m.objects:
        disk[o.slba * 512:o.slba * 512 + o.bytes] = kl.pattern_bytes(o.seed, 0, o.bytes)
    (out / 'source.raw').write_bytes(disk)
    for run in RUNS:
        lines = [kp.go_line(name, ordinal, m.object(obj).slba, kl.kv_bytes(m.object(obj).model, tok),
                            dst0, m.object(obj).seed, True)
                 for name, obj, tok, ordinal, dst0, _ in run['go']]
        (out / f'go-{run["name"]}.txt').write_text(''.join(lines) + 'QUIT\n')
        (out / f'args-{run["name"]}.txt').write_text(' '.join(str(a) for a in worker_args(run)) + '\n')
    plan = dict(schema=1, serial=SERIAL, disk_bytes=DISK_BYTES, manifest=MANIFEST,
                runs=[dict(name=r['name'], args=[str(a) for a in worker_args(r)]) for r in RUNS],
                expectations=expectations())
    (out / 'plan.json').write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
    return plan


def _sections(text):
    """Worker stdout lines per run name, and the guest's own markers."""
    runs, current, facts = {}, None, {}
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r'^KV_GUEST_RUN_BEGIN (\w+)$', line)
        if m:
            current = m.group(1)
            if current in runs:
                raise OracleError(f'run {current} started twice')
            runs[current] = dict(lines=[], exit=None)
            continue
        m = re.match(r'^KV_GUEST_RUN_EXIT (\w+) (\d+)$', line)
        if m:
            if m.group(1) != current:
                raise OracleError('run exit without its begin')
            runs[current]['exit'] = int(m.group(2))
            current = None
            continue
        m = re.match(r'^KV_GUEST_FACT (\w+)=(\S+)$', line)
        if m:
            facts[m.group(1)] = m.group(2)
            continue
        if current and line.startswith('KV_'):
            runs[current]['lines'].append(kp.parse_line(line))
    return runs, facts


def validate(text, expected):
    runs, facts = _sections(text)
    if facts.get('lba_bytes') != '512':
        raise OracleError(f'guest namespace LBA size {facts.get("lba_bytes")!r}, expected 512')
    if set(runs) != {e['name'] for e in expected}:
        raise OracleError(f'guest runs {sorted(runs)}, expected {[e["name"] for e in expected]}')
    report = []
    for e in expected:
        r = runs[e['name']]
        if r['exit'] != 0:
            raise OracleError(f'run {e["name"]}: worker exit {r["exit"]}')
        kinds = [k for k, _ in r['lines']]
        want = ['KV_READY'] + ['KV_RESULT'] * len(e['results']) + ['KV_BYE']
        if kinds != want:
            raise OracleError(f'run {e["name"]}: lines {kinds}, expected {want}')
        ready, bye = r['lines'][0][1], r['lines'][-1][1]
        if ready.get('role') != 'local-verify' or ready.get('dry_run') is not False or \
                not ready.get('session_id') or ready.get('pool_frames') != e['pool_frames']:
            raise OracleError(f'run {e["name"]}: bad KV_READY {ready}')
        for (_, got), want_r in zip(r['lines'][1:-1], e['results']):
            kp.check_result(got, want_r['run'])
            tag = f'{e["name"]}/{want_r["run"]}'
            if want_r['error']:
                if got['ok'] or got['error'] != want_r['error'] or got.get('started') is not False:
                    raise OracleError(f'{tag}: expected refusal {want_r["error"]} before START, got {got}')
                continue
            if not got['ok'] or got.get('verified') is not True or got.get('started') is not True:
                raise OracleError(f'{tag}: restore not verified: {got}')
            if got['bytes'] != want_r['bytes'] or got['plan']['groups'] != want_r['groups'] or \
                    got['plan']['first_seq'] != want_r['first_seq']:
                raise OracleError(f'{tag}: plan/bytes differ from the host plan')
            if int(got['digest'], 16) != want_r['digest']:
                raise OracleError(f'{tag}: digest {got["digest"]} != host pattern digest '
                                  f'0x{want_r["digest"]:016x}')
            st = got['stats']
            if (st['done'], st['abort'], st['sequestered'], st['inflight'], st['last_err']) != \
                    (want_r['cumulative'], 0, 0, 0, 0) or \
                    st['submitted'][0] != want_r['cumulative'] or \
                    st['completed'][0] != want_r['cumulative']:
                raise OracleError(f'{tag}: session counts {st}, expected {want_r["cumulative"]} '
                                  'done/submitted/completed and nothing aborted or retained')
            report.append(dict(run=tag, bytes=got['bytes'], groups=want_r['groups'],
                               digest=got['digest']))
        if bye != dict(error=0, retained=False, restores=e['restores']):
            raise OracleError(f'run {e["name"]}: KV_BYE {bye}')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('make-plan')
    p.add_argument('--output', required=True)
    v = sub.add_parser('validate')
    v.add_argument('--plan', required=True)
    v.add_argument('--log', required=True)
    v.add_argument('--result', required=True)
    args = parser.parse_args()
    if args.action == 'make-plan':
        make_plan(args.output)
        return 0
    plan = json.loads(Path(args.plan).read_text())
    if plan['expectations'] != json.loads(json.dumps(expectations())):
        print('FAIL plan file does not match this oracle')
        return 1
    try:
        report = validate(Path(args.log).read_text(errors='replace'), plan['expectations'])
        verdict, detail = 'PASS', report
    except (OracleError, kp.ProtocolError, KeyError, TypeError, ValueError) as error:
        verdict, detail = 'FAIL', str(error)
    Path(args.result).write_text(json.dumps(dict(verdict=verdict, detail=detail), indent=2) + '\n')
    print(f'KV_LOCAL_VERIFY_ORACLE={verdict}' + ('' if verdict == 'PASS' else f' {detail}'))
    return 0 if verdict == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
