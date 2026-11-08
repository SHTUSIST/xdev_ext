#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Check recovery assertions against isolated generated-C defects; never edit source."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('recovery_run', HERE / 'run.py')
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError('mutation anchor is not unique: ' + old)
    return text.replace(old, new, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=suite.ROOT)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.source_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    view = suite.materialize_view(root, root / 'build/recovery-view').root
    inputs = suite.generate(root, view, out)
    original = (out / 'unit.c').read_text()
    retire = '''err = b->producing ?
				xdev_ext_mech_life_fail_produce(l, b->life_token[pos]) :
				xdev_ext_mech_life_fail_put(l, b->life_token[pos]);'''
    mutations = [
        ('skip-claim-retirement', 'producer', retire, '(void)l; err = 0;'),
        ('reuse-old-generation', 'producer',
         '\t\t\tif (xdev_ext_mech_life_phase(&s->life[index]) !=',
         '\t\t\ts->life[index].ctrl = 0;\n'
         '\t\t\tif (xdev_ext_mech_life_phase(&s->life[index]) !='),
        ('clear-shared-pool', 'producer',
         '\tif (retained != s->ss.sequestered)',
         '\tmemset(s->life, 0, s->pool.nr_frames * sizeof(*s->life));\n'
         '\tif (retained != s->ss.sequestered)'),
        ('retire-before-full-validation', 'multi-frame-invalid',
         '\t\t\t/* A separate active consumer',
         '\t\t\tif (pos == 0 && b->nr_frames > 1)\n'
         '\t\t\t\txdev_ext_mech_life_fail_produce(l, claim);\n'
         '\t\t\t/* A separate active consumer'),
    ]
    facade = out / 'facade'
    facade.mkdir(exist_ok=True)
    for name in ('io_uring.h', 'rsrc.h'):
        (facade / name).write_text('/* OS boundary. */\n')
    includes = view / 'kernel/tools/testing/selftests/xdev_ext_umem'
    results = []
    for name, case, old, new in mutations:
        unit, binary = out / (name + '.c'), out / name
        unit.write_text(replace_once(original, old, new))
        command = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                   '-Werror', '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-sign-compare',
                   '-pthread', '-fsanitize=undefined', '-fno-sanitize-recover=all',
                   '-I' + str(facade), '-I' + str(includes / 'fake_include'), '-I' + str(includes),
                   str(unit), '-o', str(binary)]
        build = subprocess.run(command, capture_output=True, text=True)
        (out / (name + '-build.log')).write_text(build.stdout + build.stderr)
        if build.returncode:
            print('SETUP ' + name + '\n' + build.stderr)
            return 2
        run = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=20)
        log = run.stdout + run.stderr
        (out / (name + '.log')).write_text(log + '\nexit=%d\n' % run.returncode)
        # A crash/compiler error is not a successful assertion-based detection.
        detected = run.returncode == 1 and 'RECOVERY_ASSERT ' in log
        results.append(dict(mutation=name, case=case, exit=run.returncode, detected=detected))
        print(('DETECTED ' if detected else 'MISSED ') + name, flush=True)
    record = dict(inputs=inputs, mutations=results,
                  verdict='PASS' if all(r['detected'] for r in results) else 'FAIL')
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    return 0 if record['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
