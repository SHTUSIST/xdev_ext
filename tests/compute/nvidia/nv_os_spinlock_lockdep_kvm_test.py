#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host checks of the os_spinlock lockdep change and of its KVM test's verdict.

The KVM run (nv_os_spinlock_lockdep_kvm.py) shows the behaviour under a lockdep
kernel; here: the shipped os-interface.c is the pinned upstream file plus only
the CONFIG_DEBUG_LOCK_ALLOC nesting annotation, the annotated release is the
upstream release, and the KVM verdict cannot pass on a console that does not
show every required property.
"""
import hashlib
import importlib.util
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
# Source view (gpu/tests) or canonical tree (tests/compute/nvidia).
CANDIDATES = (HERE.parent / 'kernel-open/nvidia/os-interface.c',
              HERE.parents[2] / 'src/compute/nvidia/kernel-open/nvidia/os-interface.c')
OS_INTERFACE = next((path for path in CANDIDATES if path.is_file()), CANDIDATES[-1])
# kernel-open/nvidia/os-interface.c of open-gpu-kernel-modules 590.48.01
# (2ccbad25e1af6a6ee6f38cf569f89f8b65d658ab, third_party/sources.lock.json).
UPSTREAM_SHA256 = 'e387b9decd4ef4a897d7beea1b6b341d1348e19a3dfcf3b0ec1153f427ae85da'


def runner():
    spec = importlib.util.spec_from_file_location('lockdep_kvm', HERE / 'nv_os_spinlock_lockdep_kvm.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def without_nesting(text):
    """The file as a kernel without CONFIG_DEBUG_LOCK_ALLOC sees it."""
    text = re.sub(r'(?ms)^#if defined\(CONFIG_DEBUG_LOCK_ALLOC\) && !defined\(CONFIG_PREEMPT_RT\)\n'
                  r'.*?^#endif\n\n', '', text, count=1)
    # Line by line (no DOTALL): a branch never spans another directive.
    text = re.sub(r'(?m)^#if defined\(NV_OS_SPINLOCK_NESTING\)\n(?:(?!#).*\n)*?#else\n'
                  r'((?:(?!#).*\n)*?)#endif\n', r'\1', text)
    return re.sub(r'(?m)^#if defined\(NV_OS_SPINLOCK_NESTING\)\n(?:(?!#).*\n)*?#endif\n', '', text)


def function(text, name):
    start = text.index('NV_API_CALL ' + name + '(')
    return text[start:text.index('\n}\n', start) + 3]


class SourceChange(unittest.TestCase):
    def setUp(self):
        self.text = OS_INTERFACE.read_text()

    def test_kernels_without_lockdep_build_the_pinned_upstream_file(self):
        self.assertIn('NV_OS_SPINLOCK_NESTING', self.text)
        self.assertEqual(hashlib.sha256(without_nesting(self.text).encode()).hexdigest(), UPSTREAM_SHA256)

    def test_annotated_release_is_the_upstream_release(self):
        # spin_unlock_irqrestore restores interrupts before it re-enables
        # preemption; unlocking first would postpone a pending reschedule.
        body = function(self.text, 'os_release_spinlock')
        self.assertEqual(body.count('NV_SPIN_UNLOCK_IRQRESTORE(&os_spinlock->lock, eflags);'), 1)
        self.assertNotIn('local_irq_restore', body)
        self.assertNotRegex(body, r'\bspin_unlock\(')
        self.assertLess(body.index('__this_cpu_dec(os_spinlock_depth);'),
                        body.index('NV_SPIN_UNLOCK_IRQRESTORE'))

    def test_annotated_acquire_counts_depth_with_interrupts_off(self):
        body = function(self.text, 'os_acquire_spinlock')
        nesting = body[body.index('#if defined(NV_OS_SPINLOCK_NESTING)'):body.index('#else')]
        self.assertLess(nesting.index('local_irq_save(eflags);'),
                        nesting.index('__this_cpu_inc_return(os_spinlock_depth)'))
        self.assertLess(nesting.index('__this_cpu_inc_return(os_spinlock_depth)'),
                        nesting.index('spin_lock_nested(&os_spinlock->lock,'))
        self.assertIn('MAX_LOCKDEP_SUBCLASSES - 1', nesting)


GREEN = '''OS_SPINLOCK_GUEST=boot
[    1.72] OS_SPINLOCK_TEST step=nested begin
[    1.72] OS_SPINLOCK_TEST step=nested end irqs_enabled=1
[    1.73] OS_SPINLOCK_TEST step=irq begin
[    1.77] OS_SPINLOCK_TEST step=irq end ticks=2000 depth_left=0 depth_checked=1
[    1.77] OS_SPINLOCK_TEST debug_locks=1
[    1.77] OS_SPINLOCK_TEST step=inversion begin
[    1.77] ======================================================
[    1.77] WARNING: possible circular locking dependency detected
[    1.84] OS_SPINLOCK_TEST step=inversion end
OS_SPINLOCK_GUEST=insmod rc=0
'''


class Verdict(unittest.TestCase):
    def setUp(self):
        self.judge = runner().judge

    def problems(self, console, nesting=True):
        return self.judge(console, nesting=nesting)['problems']

    def test_a_console_showing_every_property_passes(self):
        self.assertEqual(self.problems(GREEN), [])

    def test_each_missing_property_fails(self):
        cases = {
            'module never ran': '',
            'recursive report while nesting': GREEN.replace(
                'nested begin\n', 'nested begin\n[ 1.7] WARNING: possible recursive locking detected\n'),
            'interrupts left disabled': GREEN.replace('irqs_enabled=1', 'irqs_enabled=0'),
            'depth left behind': GREEN.replace('depth_left=0', 'depth_left=1'),
            'depth never checked': GREEN.replace('depth_checked=1', 'depth_checked=0'),
            'timer never ran': GREEN.replace('ticks=2000', 'ticks=0'),
            'lockdep already off': GREEN.replace('debug_locks=1', 'debug_locks=0'),
            'real inversion not reported': GREEN.replace(
                'WARNING: possible circular locking dependency detected', ''),
            'report during the timer step': GREEN.replace(
                'irq begin\n', 'irq begin\n[ 1.7] WARNING: inconsistent lock state\n'),
        }
        for name, console in cases.items():
            with self.subTest(name):
                self.assertNotEqual(self.problems(console), [], name)

    def test_unannotated_code_needs_no_depth_check(self):
        self.assertEqual(self.problems(GREEN.replace('depth_checked=1', 'depth_checked=0'), nesting=False), [])


if __name__ == '__main__':
    unittest.main()
