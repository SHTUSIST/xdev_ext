#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run existing FANOUT host regressions and report guest availability separately.

Results must be outside the checkout so a later exact-source KVM build can use
the same committed tree. A successful host campaign never marks guest PASS.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
MECH = HERE.parent


def capture(command, log, timeout=600):
    try:
        run = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=timeout)
        output, code = run.stdout, run.returncode
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b''
        if isinstance(output, bytes):
            output = output.decode(errors='replace')
        output += '\nTIMEOUT\n'
        code = 124
    log.write_text(output)
    return dict(command=[str(x) for x in command], returncode=code,
                status='PASS' if code == 0 else 'FAIL', log=log.name,
                log_sha256=hashlib.sha256(output.encode()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--before-header', type=Path, help='exact historical header for shallow clones')
    parser.add_argument('--guest-scratch', type=Path,
                        help='opt in to existing KVM harness; private /tmp/xdev-ext-e2e.XXXXXX directory')
    parser.add_argument('--groups', type=int, default=4)
    parser.add_argument('--depth', type=int, default=2)
    args = parser.parse_args()
    out = args.results.resolve()
    if out == ROOT or ROOT in out.parents:
        parser.error('--results must be outside the checkout')
    out.mkdir(parents=True, exist_ok=False)
    git = lambda *a: subprocess.check_output(['git', '-C', str(ROOT), *a], text=True).strip()
    diff = subprocess.check_output(['git', '-C', str(ROOT), 'diff', 'HEAD', '--binary'])
    report = dict(schema='xdev_ext.fanout_verification.v1',
                  time_utc=datetime.now(timezone.utc).isoformat(),
                  source_commit=git('rev-parse', 'HEAD'),
                  source_dirty=bool(git('status', '--porcelain')),
                  diff_sha256=hashlib.sha256(diff).hexdigest(),
                  host_kernel=platform.release(), host=[],
                  physical_dma=dict(status='NOT_RUN', reason='no physical-device campaign requested'))
    counter = [sys.executable, str(HERE / 'fanout_bind_counterfactual.py'),
               '--output', str(out / 'counterfactual.json')]
    if args.before_header:
        counter += ['--before-header', str(args.before_header.resolve())]
    tests = [
        ('bind_counterfactual', counter),
        ('scheduler', [sys.executable, str(MECH / 'fanout_scheduler/run.py'),
                       '--json-output', str(out / 'scheduler.json')]),
    ]
    for name, path in (
        ('produced', 'fanout_scheduler/produced_test.py'),
        ('recycle', 'fanout_scheduler/recycle_test.py'),
        ('recycle_input', 'lifecycle_runtime/recycle_input_test.py'),
        ('guest_image_harness', 'lifecycle_runtime/guest_harness_test.py'),
        ('trace_rejection_controls', 'lifecycle_runtime/fanout_trace_test.py'),
        ('verdict_rejection_controls', 'lifecycle_runtime/fanout_validate_test.py'),
        ('poll', 'poll/run.py'),
        ('refs', 'refs_suite.py'),
        ('provider_faults', 'provider/faults/run.py'),
        ('frame_release', 'core_lifecycle/frames_release_test.py'),
    ):
        tests.append((name, [sys.executable, str(MECH / path)]))
    # Include the broader standalone gate; preserve an unrelated baseline
    # failure as FAIL instead of hiding it behind focused-test successes.
    tests.append(('standalone_host', [sys.executable, str(ROOT / 'scripts/test_host.py')]))
    for name, command in tests:
        print('RUN ' + name, flush=True)
        item = capture(command, out / (name + '.log'))
        item['name'] = name
        report['host'].append(item)
        print(item['status'] + ' ' + name, flush=True)
    kvm = Path('/dev/kvm')
    qemu = Path('/usr/local/bin/qemu-system-x86_64')  # existing harness contract
    blockers = []
    if not kvm.exists() or not os.access(kvm, os.R_OK | os.W_OK):
        blockers.append('/dev/kvm unavailable or inaccessible')
    if not qemu.is_file() or not os.access(qemu, os.X_OK):
        blockers.append('existing harness QEMU binary unavailable: ' + str(qemu))
    if not (ROOT / 'kernel/Makefile').is_file():
        blockers.append('full pinned Linux source has not been prepared')
    report['environment'] = dict(kvm_available=kvm.exists(),
                                 qemu_in_path=shutil.which('qemu-system-x86_64'),
                                 tun_available=Path('/dev/net/tun').exists(),
                                 tun_required=False,
                                 guest_network='two virtio-net devices on private QEMU hub')
    report['guest'] = dict(status='NOT_RUN', reasons=blockers or ['--guest-scratch not supplied'])
    if args.guest_scratch and not blockers:
        command = ['bash', str(ROOT / 'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'),
                   '--source', str(ROOT / 'kernel'), '--scratch', str(args.guest_scratch.resolve()),
                   '--lifecycle', '--groups', str(args.groups), '--depth', str(args.depth)]
        report['guest'] = capture(command, out / 'guest-harness.log', timeout=7200)
        evidence = args.guest_scratch / 'evidence/fanout-result.json'
        if evidence.exists():
            report['guest']['validation'] = json.loads(evidence.read_text())
        if report['guest'].get('validation', {}).get('status') != 'PASS':
            report['guest']['status'] = 'FAIL'
    failures = [item['name'] for item in report['host'] if item['status'] != 'PASS']
    report['host_status'] = 'FAIL' if failures else 'PASS'
    report['failed_host_checks'] = failures
    report['fanout_host_status'] = 'FAIL' if any(name != 'standalone_host' for name in failures) else 'PASS'
    report['multi_device_execution_verified'] = report['guest']['status'] == 'PASS'
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in
                      ('fanout_host_status', 'host_status', 'guest', 'multi_device_execution_verified')}))
    return bool(failures) or report['guest']['status'] == 'FAIL'


if __name__ == '__main__':
    sys.exit(main())
