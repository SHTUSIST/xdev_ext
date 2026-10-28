#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Six scoped behavioral mutations of actual d2 echo source, with a full baseline.

Ordinary copies isolate all edits. The existing C++ oracle remains unchanged.
Compile errors, signals, sanitizers and timeout never count as a detected bug.
Host execution certifies branch arithmetic/order only, not GPU ordering or DMA.
"""
import argparse
import contextlib
import difflib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys

BENCH = 'tests/benchmarks/tp/'
ORACLE = 'tests/compute/tp/echo_gpu_boundary.cc'
RUNNER = 'tests/compute/tp/echo_gpu_boundary_test.py'
MUTATIONS = (
    dict(name='remove_visibility', file='echo_gpu.h', count=2,
         before='NATIVE(xdev_ext_cuda_receive_visible(view.rx_consumer,owner.stream));',
         after='/* mutation: receive visibility omitted */', case='success', rank=1,
         assertion='actual consume kernel follows RX visibility'),
    dict(name='capture_constant_seed', file='verify.cu', count=2,
         before='tp_echo_byte(offset+j,s->invocation)',
         after='tp_echo_byte(offset+j,0)', case='success', rank=0,
         assertion='every TX byte includes fresh seed and short tail'),
    dict(name='release_rx_before_copy', file='echo_gpu.h', count=1,
         before='NATIVE(xdev_ext_cuda_user_wait(view.tx_producer,owner.stream,tx));kernel(consume);\n'
                '   NATIVE(xdev_ext_cuda_user_done(view.rx_consumer,owner.stream,rx));',
         after='NATIVE(xdev_ext_cuda_user_wait(view.tx_producer,owner.stream,tx));\n'
               '   NATIVE(xdev_ext_cuda_user_done(view.rx_consumer,owner.stream,rx));kernel(consume);',
         case='success', rank=1,
         assertion='rank1 copies all RX bytes before RX done'),
    dict(name='ignore_bad_payload', file='verify.cu', count=1,
         before='if(p[j]!=tp_echo_byte(offset+j,s->invocation))++s->mismatch;',
         after='if(false)++s->mismatch;', case='bad_payload', rank=0,
         assertion='real device validation publishes negative RX status'),
    dict(name='skip_both_session_end', file='echo_gpu.h', count=1,
         before='wait_native_complete(iteration+1);',
         after='/* mutation: both native END prefix waits omitted */',
         case='success', rank=0,
         assertion='both replay intervals follow both native END prefixes'),
    dict(name='free_state_before_graph', file='echo_gpu.h', count=1,
         before='  if(exec){CU(cuGraphExecDestroy(exec));exec=nullptr;}\n'
                '  if(graph){CU(cuGraphDestroy(graph));graph=nullptr;}\n'
                '  CU(cuStreamSynchronize(owner.stream));\n'
                '  if(state){CU(cuMemFree(state));state=0;}',
         after='  if(state){CU(cuMemFree(state));state=0;}\n'
               '  if(exec){CU(cuGraphExecDestroy(exec));exec=nullptr;}\n'
               '  if(graph){CU(cuGraphDestroy(graph));graph=nullptr;}\n'
               '  CU(cuStreamSynchronize(owner.stream));',
         case='success', rank=0,
         assertion='device state not freed while graph or GPU owns it'),
)
FORBIDDEN = ('AddressSanitizer', 'UndefinedBehaviorSanitizer', 'LeakSanitizer',
             'runtime error:', 'DEADLYSIGNAL', 'Segmentation fault', 'Assertion `')


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def ordinary_export(root, target):
    """Copy just the actual runner's dependency closure, with no Git fallback."""
    manifest = json.loads((root / 'source-layout.json').read_text())
    names = {'source-layout.json', 'tools/layout.py',
             'tests/core/admission_report/run.py', ORACLE, RUNNER,
             'tests/compute/tp/driver_boundary.h'}
    names.update(BENCH + name for name in ('options.h', 'owner.h', 'echo.h',
                                          'echo_gpu.h', 'echo_device.h',
                                          'verify.cu', 'driver.cc'))
    names.update(entry['source'] for entry in manifest['files']
                 if entry['source'].endswith('.h') and entry['source'].startswith(
                     ('src/lib/', 'src/compute/cuda/', 'src/core/include/uapi/')))
    for name in sorted(names):
        relative = PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('unsafe source inventory path: ' + name)
        source = root / name
        if source.is_symlink() or source.resolve() != source:
            raise ValueError('ordinary export refuses symlink source: ' + name)
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    return len(names)


def run_existing(source, build, cases=None):
    """Compile actual copied source with the unchanged existing runner/oracle."""
    spec = importlib.util.spec_from_file_location('echo_mutation_boundary', source / RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if cases is not None:
        module.CASES = cases
    original_argv = sys.argv
    stream = io.StringIO()
    try:
        sys.argv = [str(source / RUNNER), '--source-root', str(source), '--output', str(build)]
        with contextlib.redirect_stdout(stream):
            status = module.main()
    finally:
        sys.argv = original_argv
    (build / 'runner.log').write_text(stream.getvalue())
    receipt = json.loads((build / 'result.json').read_text())
    receipt['runner_exit'] = status
    return receipt


def isolated_compile(receipt, source, build):
    command = receipt.get('compile_command', [])
    if receipt.get('compile_exit') != 0 or str(source / ORACLE) not in command:
        return False
    # Every actual benchmark macro is the isolated copy or generated kernel/
    # driver fragment; none may address the original canonical worktree.
    definitions = [arg.split('=', 1)[1].strip('"') for arg in command
                   if arg.startswith('-DTP_ECHO_')]
    return len(definitions) == 6 and all(
        Path(path).is_relative_to(source) or Path(path).is_relative_to(build)
        for path in definitions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.source_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)  # Preserve any earlier original.
    result = dict(scope='host actual-source branch arithmetic and ordering only; '
                        'no SDK/GPU/memory-model/DMA/performance qualification', mutations=[])
    try:
        baseline = out / 'baseline' / 'source'
        result['exported_files'] = ordinary_export(root, baseline)
        result['source_root'] = str(root)
        result['baseline_argv'] = [sys.executable, str(baseline / RUNNER),
                                   '--source-root', str(baseline),
                                   '--output', str(out / 'baseline' / 'build')]
        baseline_receipt = run_existing(baseline, out / 'baseline' / 'build')
        if (baseline_receipt['runner_exit'] != 0 or baseline_receipt['state'] != 'SCOPED_PASS'
                or len(baseline_receipt['cases']) != 68
                or any(case['exit'] for case in baseline_receipt['cases'])
                or not isolated_compile(baseline_receipt, baseline, out / 'baseline' / 'build')):
            raise RuntimeError('full isolated baseline did not compile and pass 68/68')
        result['baseline'] = dict(state='SCOPED_PASS', cases=68, compile_exit=0)
        oracle = (baseline / ORACLE).read_bytes()
        for mutation in MUTATIONS:
            directory = out / mutation['name']
            source, build = directory / 'source', directory / 'build'
            shutil.copytree(baseline, source)
            path = source / BENCH / mutation['file']
            original = path.read_text()
            if original.count(mutation['before']) != mutation['count']:
                raise RuntimeError(mutation['name'] + ': exact mutation site count changed')
            changed = original.replace(mutation['before'], mutation['after'])
            path.write_text(changed)
            (directory / 'mutation.diff').write_text(''.join(difflib.unified_diff(
                original.splitlines(True), changed.splitlines(True),
                fromfile='a/' + BENCH + mutation['file'], tofile='b/' + BENCH + mutation['file'])))
            unchanged = (source / ORACLE).read_bytes() == oracle
            receipt = run_existing(source, build, (mutation['case'],))
            actual_input = build / 'actual-gpu-kernels.inc' if mutation['file'] == 'verify.cu' else path
            input_text = actual_input.read_text() if actual_input.is_file() else ''
            actual_mutation = (input_text.count(mutation['after']) == mutation['count']
                               and mutation['before'] not in input_text)
            entry = dict(name=mutation['name'], oracle_unchanged=unchanged,
                         compiled_mutation_verified=actual_mutation,
                         mutation_source=str(path), actual_compile_input=str(actual_input),
                         source_root=str(source), compile_exit=receipt.get('compile_exit'),
                         compile_command=receipt.get('compile_command'),
                         selected_case=mutation['case'], rank=mutation['rank'],
                         required_assertion='FAIL ' + mutation['assertion'])
            if not unchanged or not actual_mutation or not isolated_compile(receipt, source, build):
                entry.update(state='SETUP_ERROR', reason='oracle changed, mutation missing from compile input, or isolated compilation failed')
            else:
                command = [str(build / 'echo-gpu-boundary'), mutation['case'], str(mutation['rank'])]
                entry['argv'] = command
                try:
                    run = subprocess.run(command, text=True, capture_output=True, timeout=10)
                    output = run.stdout + run.stderr
                    (directory / 'selected-case.log').write_text(output)
                    entry['exit'] = run.returncode
                    if run.returncode == 1 and entry['required_assertion'] in output and not any(
                            word in output for word in FORBIDDEN):
                        entry['state'] = 'BEHAVIOR_DETECTED'
                    else:
                        entry.update(state='COVERAGE_GAP', reason='requires exact exit1 and named behavior assertion without crash/sanitizer')
                except subprocess.TimeoutExpired as error:
                    (directory / 'selected-case.log').write_text(str(error))
                    entry.update(state='SETUP_ERROR', reason='timeout is not mutation detection')
            write_json(directory / 'result.json', entry)
            result['mutations'].append(entry)
            print(mutation['name'] + ': ' + entry['state'])
        result['exit'] = int(any(entry['state'] != 'BEHAVIOR_DETECTED' for entry in result['mutations']))
        result['state'] = 'SCOPED_PASS' if result['exit'] == 0 else 'MUTATION_GATE_FAILED'
    except Exception as error:
        result.update(exit=2, state='SETUP_ERROR', error=str(error))
        print(error)
    write_json(out / 'result.json', result)
    return result['exit']


if __name__ == '__main__':
    raise SystemExit(main())
