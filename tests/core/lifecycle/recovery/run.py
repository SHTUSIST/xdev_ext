#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run actual core recovery and UMEM/lifecycle bodies with OS/class boundaries.

Required behavior: covered, settled UNKNOWN batches release only their own
frame claims, making those same registered frames reusable. No proof, an
old/wrong proof, live callbacks, stale tokens or failed unbind permit reuse.
The native class evidence service and final session destructor are boundaries;
the session recovery decision, list worker, claims and UMEM release are real.
This is host correctness, not a device/DMA test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
for parent in HERE.parents:
    if (parent / 'source-layout.json').is_file():
        ROOT = parent
        break
else:
    raise SystemExit('SETUP canonical source root missing')
sys.path.insert(0, str(ROOT / 'tools'))
from layout import materialize_view

CASES = ('producer', 'consumer', 'no-proof', 'same-epoch', 'wrong-requester',
         'unsettled', 'inflight', 'references', 'native-control', 'unbind-fails',
         'release-fails', 'stale-generation', 'foreign-frame', 'foreign-consumer',
         'stale-consumer', 'multi-frame-invalid', 'active-transform', 'reserved-output')


def entity(text, pattern):
    match = re.search(pattern, text, re.M)
    if not match:
        raise RuntimeError('missing source definition: ' + pattern)
    opening = text.index('{', match.start())
    end, level = opening + 1, 1
    while level and end < len(text):
        level += (text[end] == '{') - (text[end] == '}')
        end += 1
    if level:
        raise RuntimeError('unbalanced source definition')
    return text[match.start():end]


def function(text, name):
    return entity(text, r'^\w[^;{}]*\b' + re.escape(name) + r'\([^;{}]*\)\s*\{')


def structure(text, name):
    return entity(text, r'^struct ' + re.escape(name) + r' \{') + ';'


def enum_for(text, token):
    enums = re.findall(r'enum\b[^{};]*\{[^{}]*\};', text)
    found = [e for e in enums if re.search(r'\b' + re.escape(token) + r'\b', e)]
    if len(found) != 1:
        raise RuntimeError('expected one enum for ' + token)
    return found[0]


def generate(root, view, out):
    inputs = ['src/core/io_uring/xdev_ext_mech.c', 'src/core/io_uring/xdev_ext_mech_core.h',
              'src/core/io_uring/xdev_ext_mech_lifecycle.h', 'src/core/io_uring/xdev_ext_umem.c',
              'src/core/io_uring/xdev_ext_peer.c', 'src/core/include/linux/xdev_ext_peer.h']
    input_hashes = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in inputs}
    core = (root / 'src/core/io_uring/xdev_ext_mech.c').read_text()
    rules = (root / 'src/core/io_uring/xdev_ext_mech_core.h').read_text()
    uapi = (root / 'src/core/include/uapi/linux/xdev_ext_mech.h').read_text()
    step = (root / 'src/core/io_uring/xdev_ext_mech_step.h').read_text()
    names = ['xdev_ext_mech_pool_frame_state', 'xdev_ext_mech_unbind_checked', 'xdev_ext_mech_recovery_fate',
             'xdev_ext_mech_repark', 'xdev_ext_mech_recover', 'xdev_ext_mech_recovery_fn']
    names += re.findall(r'^static (?:int|bool|void)\s+(xdev_ext_mech_recover_\w+)\(', core, re.M)
    bodies = [function(core, name) for name in dict.fromkeys(names)]
    prototypes = '\n'.join(b[:b.index('{')].rstrip() + ';' for b in bodies)
    defines = '\n'.join(re.findall(r'^#define XDEV_EXT_MECH_EVIDENCE_.*$', rules, re.M))
    selected = [enum_for(uapi, 'XDEV_EXT_MECH_SESSION_ZOMBIE'),
                enum_for(rules, 'XDEV_EXT_MECH_B_SEQUESTERED'),
                enum_for(rules, 'XDEV_EXT_MECH_REFS_RELEASE'), defines,
                structure(rules, 'xdev_ext_mech_qrecovery'),
                structure(rules, 'xdev_ext_mech_sess'),
                structure(rules, 'xdev_ext_mech_quarantine')]
    rule_bodies = [function(rules, n) for n in ('xdev_ext_mech_sess_recovery',
                   'xdev_ext_mech_quarantine_add', 'xdev_ext_mech_quarantine_sub')]
    peer = (root / 'src/core/io_uring/xdev_ext_peer.c').read_text()
    peer_api = (root / 'src/core/include/linux/xdev_ext_peer.h').read_text()
    selected += [enum_for(peer_api, 'XDEV_EXT_PEER_EVIDENCE_COVERED')]
    # Actual evidence query and strict proven > submit comparison, with the
    # requester's mutex and counter represented by the existing OS primitives.
    peer_bodies = [function(peer, n) for n in ('xdev_ext_peer_requester_covers',
                   'xdev_ext_peer_requester_evidence')]
    custody = view / 'kernel/tools/testing/selftests/xdev_ext_umem/xdev_ext_umem_custody_test.c'
    header = '#include <assert.h>\n#define main umem_baseline_main\n#include "' + str(custody) + '"\n#undef main\n'
    shim = (HERE / 'boundary.c').read_text()
    unit = header + '\n' + '\n'.join(selected) + '\n' + shim
    unit = unit.replace('/* ACTUAL_PEER */', '\n'.join(rule_bodies + peer_bodies))
    unit = unit.replace('/* ACTUAL_CORE */', prototypes + '\n' + '\n'.join(bodies))
    unit += '\n' + (HERE / 'cases.c').read_text()
    (out / 'unit.c').write_text(unit)
    return input_hashes



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.source_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    view = materialize_view(root, root / 'build/recovery-view').root
    facade = out / 'facade'
    facade.mkdir(exist_ok=True)
    for name in ('io_uring.h', 'rsrc.h'):
        (facade / name).write_text('/* Existing UMEM shim excludes these OS declarations. */\n')
    try:
        inputs = generate(root, view, out)
    except Exception as error:
        print('SETUP ' + str(error))
        return 2
    includes = view / 'kernel/tools/testing/selftests/xdev_ext_umem'
    results = []
    for profile, flags in [('ubsan', ['-fsanitize=undefined', '-fno-sanitize-recover=all']),
                           ('asan', ['-fsanitize=address', '-fno-omit-frame-pointer'])]:
        binary = out / ('cases-' + profile)
        command = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                   '-Werror', '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-sign-compare', '-pthread', *flags,
                   '-I' + str(facade), '-I' + str(includes / 'fake_include'), '-I' + str(includes),
                   str(out / 'unit.c'), '-o', str(binary)]
        build = subprocess.run(command, capture_output=True, text=True)
        (out / (profile + '-build.log')).write_text(build.stdout + build.stderr)
        if build.returncode:
            print('SETUP compile ' + profile + '\n' + build.stderr[-10000:])
            return 2
        for case in CASES:
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
            run = subprocess.run([str(binary), case], env=env, capture_output=True, text=True, timeout=20)
            (out / (profile + '-' + case + '.log')).write_text(run.stdout + run.stderr + '\nexit=%d\n' % run.returncode)
            passed = run.returncode == 0 and 'RECOVERY_CASE PASS ' + case in run.stdout
            results.append(dict(profile=profile, case=case, exit=run.returncode, passed=passed))
            print(('PASS ' if passed else 'FAIL ') + profile + ' ' + case, flush=True)
    unchanged = all(hashlib.sha256((root / p).read_bytes()).hexdigest() == digest
                    for p, digest in inputs.items())
    if not unchanged:
        print('FAIL source inputs changed during the run', flush=True)
    record = dict(scope=__doc__, inputs=inputs, inputs_unchanged=unchanged, cases=results,
                  verdict='PASS' if unchanged and all(r['passed'] for r in results) else 'FAIL')
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    return 0 if record['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
