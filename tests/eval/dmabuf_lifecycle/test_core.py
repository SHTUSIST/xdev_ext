#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual benchmark core + bounded API shim. NOT kernel runtime or performance.

The same natural header must be included by the real kernel module. This suite
checks state/callback/ref behavior, not Linux scheduling, RCU, or DMA behavior.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class BenchmarkCore(unittest.TestCase):
    def invoke(self, scenario, arm='fence'):
        core = HERE / 'lifecycle_core.h'
        self.assertTrue(core.is_file(), 'missing actual shared benchmark lifecycle_core.h')
        for compiler in ('gcc', 'clang'):
            with self.subTest(compiler=compiler, arm=arm):
                self.assertIsNotNone(shutil.which(compiler), compiler + ' required for host contract')
                with tempfile.TemporaryDirectory(prefix='.core-contract-', dir=HERE) as tmp:
                    binary = Path(tmp) / 'core-contract'
                    build = subprocess.run([compiler, '-std=gnu11', '-O1', '-Wall', '-Wextra',
                                            '-Werror', '-I' + str(HERE / 'fixtures'),
                                            '-I' + str(HERE), str(HERE / 'fixtures' / 'core_driver.c'),
                                            '-o', str(binary)], capture_output=True, text=True, timeout=30)
                    self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
                    run = subprocess.run([str(binary), scenario, arm], capture_output=True,
                                         text=True, timeout=15)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    self.assertEqual(run.stdout.strip(),
                                     'host-contract: non-kernel-runtime; no timing evidence')

    def test_t1_two_phase_visibility_and_recycle_are_equal(self):
        for arm in ('life', 'fence'):
            self.invoke('two-phase', arm)

    def test_t2_signaled_before_add_callback_is_consumed_once(self):
        for arm in ('life', 'fence'):
            self.invoke('signal-first', arm)

    def test_t3_stale_identity_does_not_advance_another_operation(self):
        for arm in ('life', 'fence'):
            self.invoke('identity', arm)

    def test_t4_duplicate_does_not_recycle_or_count_twice(self):
        for arm in ('life', 'fence'):
            self.invoke('duplicate', arm)

    def test_t4_held_reference_blocks_cleanup_and_reinitialization(self):
        self.invoke('held-reference')

    def test_t5_interleaved_frames_have_no_pool_barrier_host_only(self):
        for arm in ('life', 'fence'):
            self.invoke('independent-frames', arm)

    def test_t6_first_callback_registration_failure_cleans_up(self):
        self.invoke('callback-failure-1')

    def test_t6_second_callback_registration_failure_removes_first_callback(self):
        self.invoke('callback-failure-2')

    def test_t7_invalid_operation_parameters_rejected_before_init(self):
        self.invoke('invalid')

    def test_real_module_and_core_bind_to_actual_kernel_apis(self):
        module = HERE / 'lifecycle_bench.c'
        core = HERE / 'lifecycle_core.h'
        self.assertTrue(module.is_file(), 'missing real Linux kernel benchmark module')
        self.assertTrue(core.is_file(), 'missing shared actual core')
        text = core.read_text()
        self.assertIn('#include <linux/dma-fence.h>', text)
        self.assertIn('kernel/io_uring/xdev_ext_mech_lifecycle.h', text)
        self.assertNotIn('#define XDEV_EXT_MECH_LIFE_LEGACY', text)
        for function in ('claim', 'publish', 'acquire', 'put'):
            self.assertIn('xdev_ext_mech_life_' + function + '(', text)
        self.assertIn('"lifecycle_core.h"', module.read_text())
        for path in (HERE / 'Kbuild', HERE / 'Makefile'):
            self.assertTrue(path.is_file(), 'missing real kernel build entry: ' + path.name)


if __name__ == '__main__':
    unittest.main()
