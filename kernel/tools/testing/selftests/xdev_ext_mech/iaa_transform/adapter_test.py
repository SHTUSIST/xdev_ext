#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual IAA adapter scheduling against a controlled CryptoAPI boundary.

This proves dispatch, dlen propagation and core callback ownership; no shim
performs compression or implements the adapter's scheduling/error policy.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from acquire_red_test import function
from lease_test import FUNCTIONS

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
ADAPTER_FUNCTIONS = ('xdev_ext_iaa_crypto_done', 'xdev_ext_iaa_sg',
                     'xdev_ext_iaa_submit', 'xdev_ext_iaa_mark_dead')
ACCESSORS = ('xdev_ext_mech_session_layout', 'xdev_ext_mech_session_pool',
             'xdev_ext_mech_batch_slot', 'xdev_ext_mech_batch_nr_frames',
             'xdev_ext_mech_batch_bytes', 'xdev_ext_mech_batch_frame',
             'xdev_ext_mech_batch_ticket')


def build_source(adapter, core):
    # Reuse only the existing fixture's kernel boundary types and helpers.
    # Its production placeholders are still replaced by the current real code.
    shared = (HERE / 'lease_fixture.c').read_text().split('int main(', 1)[0]
    shared = shared.replace('const struct xdev_ext_mech_class_ops *cls;};',
                            'const struct xdev_ext_mech_class_ops *cls;void *priv;};')
    shared = shared.replace('struct xdev_ext_mech_session {\n',
                            'struct xdev_ext_mech_session {\n struct xdev_ext_mech_layout layout;struct xdev_ext_mech_batch *batches;\n')
    for name in FUNCTIONS:
        shared = shared.replace('/* ' + name + ' */', function(core, name))
    source = (HERE / 'adapter_fixture.c').read_text().replace('/* LEASE_BOUNDARY */', shared)
    structures = []
    for name in ('xdev_ext_iaa_request', 'xdev_ext_iaa_stage'):
        match = re.search(r'^struct ' + name + r' \{\n.*?^\};', adapter, re.M | re.S)
        if not match:
            raise RuntimeError('missing production adapter struct: ' + name)
        structures.append(match[0])
    source = source.replace('/* ADAPTER_STRUCTS */', '\n'.join(structures))
    for name in ACCESSORS:
        source = source.replace('/* ' + name + ' */', function(core, name))
    for name in ADAPTER_FUNCTIONS:
        source = source.replace('/* ' + name + ' */', function(adapter, name))
    return source


class AdapterScheduling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = Path(os.environ.get('XDEV_EXT_IAA_ADAPTER_SOURCE', ROOT / 'io_uring/iaa/xdev_ext_mech_iaa.c')).read_text()
        cls.core = Path(os.environ.get('XDEV_EXT_IAA_ADAPTER_CORE_SOURCE', ROOT / 'io_uring/xdev_ext_mech.c')).read_text()
        cls.temp = tempfile.TemporaryDirectory(prefix='xdev_ext-iaa-adapter-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = cls.compile(build_source(cls.adapter, cls.core), 'adapter')

    @classmethod
    def compile(cls, source, name):
        path = Path(cls.temp.name)
        (path / (name + '.c')).write_text(source)
        binary = path / name
        result = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra',
                                 '-Werror', '-Wno-unused-function', '-fsanitize=undefined',
                                 '-fno-sanitize-recover=undefined', '-I' + str(ROOT),
                                 str(path / (name + '.c')), '-o', str(binary)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return binary

    def probe(self, case, binary=None):
        result = subprocess.run([str(binary or self.binary), case], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_synchronous_compress_uses_terminal_dlen_and_real_scatterlists(self):
        self.probe('sync')

    def test_decompress_dispatches_separate_crypto_operation(self):
        self.probe('decompress')

    def test_einprogress_retains_both_sets_until_terminal_callback(self):
        self.probe('async')

    def test_may_backlog_ebusy_is_accepted_and_promotion_is_not_terminal(self):
        self.probe('backlog')

    def test_inline_terminal_callback_wins_later_submit_return(self):
        self.probe('inline_callback')

    def test_synchronous_eagain_is_one_terminal_failure_not_preaccept_retry(self):
        self.probe('eagain')

    def test_synchronous_native_error_discards_nonzero_dlen(self):
        self.probe('sync_error')

    def test_async_terminal_error_discards_nonzero_dlen(self):
        self.probe('async_error')

    def test_zero_and_over_capacity_terminal_lengths_fail_without_publication(self):
        for case in ('zero', 'overcap'):
            with self.subTest(case=case):
                self.probe(case)

    def test_invalid_callback_status_normalizes_to_eio(self):
        for case in ('positive_error', 'invalid_errno'):
            with self.subTest(case=case):
                self.probe(case)

    def test_late_terminal_after_stage_stop_keeps_lease_until_actual_completion(self):
        self.probe('late_stop')
        self.probe('late_stop_error')

    def test_same_request_can_be_reused_after_its_single_terminal_is_consumed(self):
        self.probe('sequential_reuse')

    def test_dead_stage_refuses_before_crypto_or_destination_acquisition(self):
        self.probe('dead')

    def test_mutation_publishing_backlog_promotion_is_detected(self):
        mutated, count = re.subn(r'if \(err == -EINPROGRESS\) return;',
                                  'if (err == -EINPROGRESS) err = 0;', self.adapter, count=1)
        self.assertEqual(count, 1)
        binary = self.compile(build_source(mutated, self.core), 'promotion-mutant')
        run = subprocess.run([str(binary), 'backlog'], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0, 'the real scheduling test accepted promotion as terminal')
        self.assertIn('promotion', run.stderr)

    def test_mutation_replacing_actual_dlen_with_capacity_is_detected(self):
        mutated, count = re.subn(r'READ_ONCE\(r->req->dlen\)', '1536', self.adapter, count=1)
        self.assertEqual(count, 1)
        binary = self.compile(build_source(mutated, self.core), 'dlen-mutant')
        run = subprocess.run([str(binary), 'sync'], capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0, 'the real scheduling test accepted fixed-capacity produced')
        self.assertIn('produced', run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
