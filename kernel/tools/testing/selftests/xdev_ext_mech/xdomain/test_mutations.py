#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Kill five semantic full-production mutations in isolated source copies.

A baseline failure, compile failure, crash, missing wrapper or timeout is never
accepted as mutation sensitivity. Every mutation must reach a named independent
STACK_ASSERT in the same stack_cases.c used by the passing baseline.
"""
import argparse
import difflib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
RING = 'io_uring/xdomain/xdev_ext_xdomain_ring.c'
CLASS = 'io_uring/xdomain/xdev_ext_xdomain_class.c'


def copy_mutation_inputs(kernel, dest):
    """Copy actual project inputs, independent of a prepared upstream tree."""
    kernel = kernel.resolve()
    here = kernel / HERE.relative_to(HERE.parents[4])
    expected = json.loads((here / 'stack_expected.json').read_text())
    pending = [kernel.parent / name for name in expected['source_units']]
    # Exact production dependencies of retention and descriptor-byte accounting.
    pending += [kernel / name for name in (
        'io_uring/family/xdev_ext_requester_retention.c',
        'drivers/thunderbolt/nhi.c', 'drivers/thunderbolt/nhi_regs.h',
        'include/linux/thunderbolt.h')]
    pending += [here.parent / 'peer_graph' / name for name in (
        'xdomain_retention_fixture.py', 'xdomain_ring_test.py',
        'xdomain_fixture.py')]
    pending += [here / name for name in expected['wrappers']]
    pending += [here / name for name in ('stack_cases.c', 'stack_kernel_compat.h',
                                        'stack_expected.json', 'stack_test.py', 'test_mutations.py')]
    inputs = set()
    include = re.compile(r'^\s*#\s*include\s*[<"]([^>"\n]+)[>"]', re.M)
    while pending:
        source = pending.pop().resolve()
        relative = source.relative_to(kernel)
        if relative in inputs:
            continue
        if not source.is_file():
            raise FileNotFoundError('missing actual stack input: ' + str(source))
        inputs.add(relative)
        if source.suffix not in ('.c', '.h'):
            continue
        for name in include.findall(source.read_text()):
            if 'xdev_ext' not in Path(name).name:
                continue  # Environmental headers are supplied by the facade/system UAPI.
            candidates = (source.parent / name, kernel / name, kernel / 'include' / name,
                          kernel / 'include/uapi' / name, kernel / 'tools/xdev_ext_mech' / name)
            dependency = next((path for path in candidates if path.is_file()), None)
            if dependency is None:
                raise FileNotFoundError('missing project include: ' + name)
            pending.append(dependency)
    dest.mkdir(parents=True)
    for relative in sorted(inputs):
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(kernel / relative, target)


def replace_once(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise ValueError('mutation anchor is not unique: ' + str(path) + ': ' + old)
    path.write_text(text.replace(old, new, 1))


def mutate(kernel, name):
    ring, cls = kernel / RING, kernel / CLASS
    if name == 'disconnect_actual_vtable':
        text = ring.read_text()
        text += '\n'  # insertion before actual vtable, all production remains
        anchor = 'const struct xdev_ext_net_dev_ops xdev_ext_xd_dev_ops = {'
        helper = ('static int stack_mutation_no_post(void *lk, struct xdev_ext_net_elem *e, u32 n)\n'
                  '{ (void)lk; (void)e; (void)n; return -67; }\n')
        if text.count(anchor) != 1:
            raise ValueError('actual vtable anchor missing')
        ring.write_text(text.replace(anchor, helper + anchor, 1))
        replace_once(ring, '.post_tx = xdev_ext_xd_post_tx,', '.post_tx = stack_mutation_no_post,')
    elif name == 'bypass_x4_dispatch':
        replace_once(ring, 'xdev_ext_xd_class_ctl(ep->st, &m);', '(void)m; /* mutation: omit actual X4 dispatch */')
    elif name == 'replace_native_callback':
        anchor = 'static int xdev_ext_xd_post(void *lk,'
        helper = ('static void stack_mutation_callback(struct tb_ring *r, struct ring_frame *f, bool canceled)\n'
                  '{ (void)r; (void)f; (void)canceled; }\n')
        replace_once(ring, anchor, helper + anchor)
        replace_once(ring, '.callback = rx ? xdev_ext_xd_rx_cb : xdev_ext_xd_tx_cb,',
                     '.callback = rx ? xdev_ext_xd_rx_cb : stack_mutation_callback,')
    elif name == 'shift_mapping_offset':
        replace_once(ring, '.buffer_phy = e[i].lease.lease.dma_address,',
                     '.buffer_phy = e[i].lease.lease.dma_address + 128,')
    elif name == 'omit_batch_release':
        anchor = 'static void xdev_ext_xd_class_batch_release('
        helper = ('static void stack_mutation_no_release(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b, bool s)\n'
                  '{ (void)st; (void)b; (void)s; }\n')
        replace_once(cls, anchor, helper + anchor)
        replace_once(cls, '.batch_release = xdev_ext_xd_class_batch_release,',
                     '.batch_release = stack_mutation_no_release,')
    else:
        raise ValueError('unregistered mutation ' + name)


def run(script, out, name=None):
    command = [sys.executable, '-I', str(script), '--keep-build', str(out)]
    if name:
        command += ['--case', name]
    result = subprocess.run(command, text=True, capture_output=True, timeout=240)
    (out / 'runner.log').write_text(result.stdout + result.stderr)
    return result


def execute(out):
    expected = json.loads((HERE / 'stack_expected.json').read_text())
    baseline_dir = out / 'baseline'
    baseline_dir.mkdir(parents=True, exist_ok=True)
    baseline = run(HERE / 'stack_test.py', baseline_dir)
    if baseline.returncode:
        print('MUTATION_BASELINE_NOT_GREEN: no mutation proof', flush=True)
        print(baseline.stdout + baseline.stderr, flush=True)
        return 2
    print('TAP version 13\n1..' + str(len(expected['mutations'])), flush=True)
    failed = False
    kernel = HERE.parents[4]
    for number, item in enumerate(expected['mutations'], 1):
        evidence = out / item['name']
        evidence.mkdir(parents=True, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(prefix='xdomain-stack-mutation-') as temp:
                private_kernel = Path(temp) / 'kernel'
                copy_mutation_inputs(kernel, private_kernel)
                mutate(private_kernel, item['name'])
                differences = []
                for relative in (RING, CLASS):
                    differences.extend(difflib.unified_diff(
                        (kernel / relative).read_text().splitlines(keepends=True),
                        (private_kernel / relative).read_text().splitlines(keepends=True),
                        fromfile='original/' + relative, tofile='mutated/' + relative))
                (evidence / 'mutation.diff').write_text(''.join(differences))
                script = private_kernel / HERE.relative_to(kernel) / 'stack_test.py'
                result = run(script, evidence, item['must_fail'])
                text = result.stdout + result.stderr
                named = 'STACK_ASSERT ' + item['must_fail'] + ':'
                killed = (result.returncode == 1 and named in text and
                          'STACK_COMPILE_FAILURE' not in text and
                          'STACK_MISSING_COMPOSITION_RED' not in text and
                          'AddressSanitizer' not in text and
                          'runtime error:' not in text)
                print(('ok ' if killed else 'not ok ') + str(number) + ' - ' + item['name'] +
                      ' -> ' + item['must_fail'], flush=True)
                if not killed:
                    failed = True
                    print(text, flush=True)
        except (ValueError, subprocess.TimeoutExpired) as error:
            print('not ok ' + str(number) + ' - ' + item['name'] + ': ' + str(error), flush=True)
            failed = True
    return int(failed)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--keep-build', type=Path)
    args = parser.parse_args()
    if args.keep_build:
        args.keep_build.mkdir(parents=True, exist_ok=True)
        return execute(args.keep_build.resolve())
    with tempfile.TemporaryDirectory(prefix='xdomain-stack-mutation-results-') as temp:
        return execute(Path(temp))


if __name__ == '__main__':
    sys.exit(main())
