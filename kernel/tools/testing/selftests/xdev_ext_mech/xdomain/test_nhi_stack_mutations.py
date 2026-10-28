#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Require observable failures from isolated NHI/XDOMAIN source mutations.

A compile error, signal, timeout or sanitizer report is not a semantic kill.
The unmodified composition must pass first, and the same independent C oracle
must reject each mutation after the production translation units compile.
"""
import argparse
import difflib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
FIXTURE = Path('tools/testing/selftests/xdev_ext_mech/xdomain')
NHI = Path('drivers/thunderbolt/nhi.c')
CLASS = Path('io_uring/xdomain/xdev_ext_xdomain_class.c')
MUTATIONS = (
    ('omit_batch_notify', 'batched_doorbells_wrap'),
    ('omit_poll_refill', 'no_interrupt_poll_refill'),
    ('request_irq_for_no_interrupt', 'no_interrupt_poll_refill'),
    ('omit_quarantine_key_unregister', 'poll_batch_retirement'),
    ('ack_implies_local_completion', 'production_ack_orders'),
    ('shift_nhi_descriptor_address', 'batched_doorbells_wrap'),
)


def load_local(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_inputs(kernel, dest):
    """Reuse the existing stack dependency closure, then add the real NHI seam."""
    here = kernel / FIXTURE
    existing = load_local('nhi_stack_existing_mutations', here / 'test_mutations.py')
    existing.copy_mutation_inputs(kernel, dest)
    extras = [NHI, Path('drivers/thunderbolt/nhi_regs.h'),
              Path('include/linux/thunderbolt.h')]
    extras += [FIXTURE / name for name in (
        'nhi_stack_test.py', 'nhi_stack_expected.json', 'stack_nhi_cases.c',
        'stack_nhi.c', 'stack_nhi_compat.h', 'stack_nhi_source.py',
        'test_nhi_stack_mutations.py')]
    extras += [FIXTURE.parent / 'peer_graph' / name for name in (
        'xdomain_ring_test.py', 'xdomain_fixture.py')]
    # Optional declaration-only support headers remain part of the fixture.
    extras += [path.relative_to(kernel) for path in here.glob('stack_nhi*.h')]
    for relative in sorted(set(extras)):
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(kernel / relative, target)


def replace_once(path, old, new):
    original = path.read_text()
    if original.count(old) != 1:
        raise ValueError('mutation anchor is not unique: ' + str(path) + ': ' + old)
    path.write_text(original.replace(old, new, 1))


def replace_in_function(kernel, path, name, old, new):
    """Use the existing comment-aware extractor to isolate a production body."""
    helper = kernel / FIXTURE.parent / 'peer_graph/xdomain_fixture.py'
    definition = load_local('nhi_stack_definition', helper).definition
    original = path.read_text()
    body = definition(original, name)
    if body.count(old) != 1 or original.count(body) != 1:
        raise ValueError('mutation function/anchor is not unique: ' + name)
    path.write_text(original.replace(body, body.replace(old, new, 1), 1))


def mutate(kernel, name):
    path = kernel / NHI
    if name == 'omit_batch_notify':
        replace_in_function(kernel, path, 'tb_ring_notify', '__ring_notify(ring);',
                            '(void)ring; /* mutation: batch never rings doorbell */')
    elif name == 'omit_poll_refill':
        replace_in_function(kernel, path, 'tb_ring_poll', 'ring_write_descriptors(ring, true);',
                            '(void)ring; /* mutation: freed poll slot is not replenished */')
    elif name == 'request_irq_for_no_interrupt':
        replace_once(path, 'if (!(flags & RING_FLAG_NO_INTERRUPT) &&\n\t    ring_request_msix(ring, flags & RING_FLAG_NO_SUSPEND))',
                     'if (ring_request_msix(ring, flags & RING_FLAG_NO_SUSPEND))')
    elif name == 'omit_quarantine_key_unregister':
        replace_in_function(kernel, path, 'tb_ring_free_quarantined',
                            'lockdep_unregister_key(&ring->lock_key);',
                            '(void)ring; /* mutation: key survives quarantine memset */')
    elif name == 'ack_implies_local_completion':
        replace_once(kernel / CLASS,
                     'e->acked = 1; if (!e->native_pending) e->terminal = XDEV_EXT_REL_COMPLETE;',
                     'e->acked = 1; if (!e->native_pending) e->terminal = XDEV_EXT_REL_COMPLETE;\n'
                     '\t\t\t\txdev_ext_netfam_publish_locked(ns, s, 0, false); /* mutation: ACK bypasses native completion */')
    elif name == 'shift_nhi_descriptor_address':
        replace_once(path, 'descriptor->phys = frame->buffer_phy;',
                     'descriptor->phys = frame->buffer_phy + 4096;')
    else:
        raise ValueError('unregistered mutation ' + name)


def run(kernel, out, case=None):
    command = [sys.executable, '-I', str(kernel / FIXTURE / 'nhi_stack_test.py'),
               '--kernel', str(kernel), '--keep-build', str(out)]
    if case:
        command += ['--case', case]
    result = subprocess.run(command, text=True, capture_output=True, timeout=360)
    (out / 'runner.log').write_text(result.stdout + result.stderr)
    return result


def execute(kernel, out):
    baseline_dir = out / 'baseline'
    baseline_dir.mkdir(parents=True, exist_ok=True)
    try:
        baseline = run(kernel, baseline_dir)
    except (OSError, subprocess.TimeoutExpired) as error:
        print('NHI_STACK_MUTATION_BASELINE_ERROR: ' + str(error), flush=True)
        return 2
    if baseline.returncode:
        print('NHI_STACK_MUTATION_BASELINE_NOT_GREEN: no mutation proof', flush=True)
        print(baseline.stdout + baseline.stderr, flush=True)
        return 2
    print('TAP version 13\n1..' + str(len(MUTATIONS)), flush=True)
    records = []
    for number, (name, case) in enumerate(MUTATIONS, 1):
        evidence = out / name
        evidence.mkdir(parents=True, exist_ok=True)
        record = dict(name=name, must_fail=case, status='fail')
        try:
            with tempfile.TemporaryDirectory(prefix='xdomain-nhi-stack-mutant-') as directory:
                private = Path(directory) / 'kernel'
                copy_inputs(kernel, private)
                mutate(private, name)
                difference = []
                for relative in (NHI, CLASS):
                    difference.extend(difflib.unified_diff(
                        (kernel / relative).read_text().splitlines(keepends=True),
                        (private / relative).read_text().splitlines(keepends=True),
                        fromfile='original/' + str(relative), tofile='mutated/' + str(relative)))
                (evidence / 'mutation.diff').write_text(''.join(difference))
                result = run(private, evidence, case)
                output = result.stdout + result.stderr
                manifest = json.loads((evidence / 'manifest.json').read_text())
                cases = manifest.get('cases', [])
                named = re.search(r'^STACK_ASSERT ' + re.escape(case) + r': ([^\n]+)', output, re.M)
                killed = (result.returncode == 1 and manifest.get('compile_exit') == 0 and
                          len(cases) == 1 and cases[0]['returncode'] == 1 and named and
                          'AddressSanitizer' not in output and 'runtime error:' not in output)
                record.update(status='pass' if killed else 'fail',
                              compile_exit=manifest.get('compile_exit'),
                              runner_exit=result.returncode,
                              assertion=named[1] if named else None)
                print(('ok ' if killed else 'not ok ') + str(number) + ' - ' + name +
                      ' -> ' + case, flush=True)
                if not killed:
                    print(output, flush=True)
        except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
            record['error'] = str(error)
            print('not ok ' + str(number) + ' - ' + name + ': ' + str(error), flush=True)
        records.append(record)
    failed = any(row['status'] != 'pass' for row in records)
    (out / 'mutations.json').write_text(json.dumps(dict(
        scope='host-nhi-xdomain-composition', hardware='none',
        baseline='pass', status='fail' if failed else 'pass', mutations=records), indent=2) + '\n')
    return int(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, default=HERE.parents[4])
    parser.add_argument('--keep-build', type=Path)
    args = parser.parse_args()
    if args.keep_build:
        args.keep_build.mkdir(parents=True, exist_ok=True)
        return execute(args.kernel.resolve(), args.keep_build.resolve())
    with tempfile.TemporaryDirectory(prefix='xdomain-nhi-stack-mutations-') as directory:
        return execute(args.kernel.resolve(), Path(directory))


if __name__ == '__main__':
    raise SystemExit(main())
