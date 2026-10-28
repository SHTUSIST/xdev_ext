#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real retraction/worker/STOP bodies over an explicit RCU scheduler boundary.

This checks cancellation cause, first-error precedence and reference decisions,
not hardware timing, actual DMA, or kernel RCU/lock implementation correctness.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('KERNEL_SRC', str(HERE.parents[4]))).resolve()


def function(text, name):
    match = re.search(r'^[A-Za-z_][^;{}=()]*?\b' + re.escape(name) +
                      r'\s*\([^;{}]*\)\s*\{', text, re.M)
    if not match:
        raise AssertionError('missing production definition: ' + name)
    start, depth = match.start(), 0
    for index in range(text.index('{', start), len(text)):
        depth += {'{': 1, '}': -1}.get(text[index], 0)
        if not depth:
            return text[start:index + 1]
    raise AssertionError('unbalanced production definition: ' + name)


def generate(kernel=ROOT):
    core = (kernel / 'io_uring/xdev_ext_mech.c').read_text()
    ops = (kernel / 'io_uring/xdev_ext_mech_ops.c').read_text()
    registry = (kernel / 'io_uring/xdev_ext_ops_core.c').read_text()
    header = (kernel / 'io_uring/xdev_ext_ops_core.h').read_text()
    mech_header = (kernel / 'include/linux/xdev_ext_mech.h').read_text()
    source = (HERE / 'detach_generation_fixture.c.in').read_text()
    source = source.replace('struct xdev_ext_mech_session{',
                            'static u64 ktime_get_boottime_ns(void){return 0;}\n'
                            'struct xdev_ext_mech_session{\n u64 stop_started_ns;\n'
                            ' bool create_pending_publish,start_ordered;\n'
                            ' struct xdev_ext_mech_start_queue *start_queue;', 1)
    source = '#define smp_load_acquire(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)\n' + source
    # Compile the actual common ops layout: these default-generation tokens
    # now pass through the PRIVATE discriminator before global retraction.
    layout = re.search(r'^#define XDEV_EXT_MECH_OPS_TYPE\(name\).*?^}',
                       mech_header, re.M | re.S)
    if layout is None:
        raise AssertionError('production struct_ops layout missing')
    source = source.replace('/* ACTUAL_MECH_OPS_LAYOUT */',
                            layout.group() + '\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_nvme_mech_ops);')
    private_dependencies = 'xdev_ext_mech_instance_unregister' in function(ops, 'xdev_ext_mech_unreg')
    if private_dependencies:
        # This fixture exercises existing defaults only. Unexpected entry to
        # a PRIVATE path is a failure, not a replacement registry model.
        source = source.replace('/* PRIVATE_DEFAULT_ONLY_BOUNDARY */', r'''static bool xdev_ext_mech_instance_unregister(u32 class_id, const void *ops, struct bpf_link *link) {
 (void)class_id;(void)ops;(void)link;abort();
}
static bool xdev_ext_mech_instance_current(const struct xdev_ext_mech_instance *instance) {
 (void)instance;abort();
}
''')
    start = header.index('struct xdev_ext_ops_registry {')
    source = source.replace('@REGISTRY_STRUCT@', header[start:header.index('\n};', start) + 3])
    names = [(header, 'xdev_ext_ops_is_current'), (registry, 'xdev_ext_ops_retract'),
             (ops, 'xdev_ext_mech_ops_current'), (ops, 'xdev_ext_mech_unreg')]
    if re.search(r'\bxdev_ext_mech_programs_current\([^;{}]*\)\s*\{', core):
        names.append((core, 'xdev_ext_mech_programs_current'))
    names += [(core, name) for name in (
        'xdev_ext_mech_session_admits', 'xdev_ext_mech_settle_locked',
        'xdev_ext_mech_set_err_locked', 'xdev_ext_mech_stop_reason',
        'xdev_ext_mech_session_stop', 'xdev_ext_mech_notify_locked',
        'xdev_ext_mech_generation_gone', 'xdev_ext_mech_batch_run')]
    bodies = [function(text, name) for text, name in names]
    reliable = (kernel / 'net/xdp/xsk_xdev_ext_mech_reliable.inc').read_text()
    source = source.replace('/* ACTUAL_RELIABLE_SUBMIT */', function(reliable, 'xsk_rel_submit'))
    source = source.replace('/* ACTUAL_PROTOTYPES */', '\n'.join(
        body[:body.index('{')].strip() + ';' for body in bodies))
    functions = '\n'.join(bodies)
    if private_dependencies:
        # Adapt the historical two-argument caller to the link-aware native
        # signature without changing any default withdrawal expectation.
        functions += ('\n#define xdev_ext_mech_unreg(class_id,kdata) '
                      'xdev_ext_mech_unreg(class_id,kdata,NULL)\n')
    return source.replace('/* ACTUAL_FUNCTIONS */', functions)


class DetachGeneration(unittest.TestCase):
    def test_retraction_reason_and_accepted_drain(self):
        with tempfile.TemporaryDirectory(prefix='xdev-detach-generation-') as tmp:
            path = Path(tmp)
            source = path / 'detach.c'
            source.write_text(generate())
            for reference in (False, True):
                with self.subTest(c_reference=reference):
                    executable = path / ('reference' if reference else 'pinned')
                    command = shlex.split(os.environ.get('CC', 'gcc')) + [
                        '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', '-fsanitize=undefined',
                        '-fno-sanitize-recover=undefined', '-I', str(ROOT)]
                    if reference:
                        command += ['-DCONFIG_XDEV_EXT_MECH_C_REFERENCE=1']
                    command += [str(source), '-o', str(executable)]
                    build = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
                    run = subprocess.run([str(executable)], capture_output=True,
                                         text=True, timeout=10)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    self.assertIn('failures=0', run.stdout)
                    print(run.stdout, end='')


if __name__ == '__main__':
    unittest.main(verbosity=2)
