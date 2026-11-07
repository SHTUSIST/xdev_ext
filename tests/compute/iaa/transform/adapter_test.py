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
from acquire_red_test import function, session_helpers
from lease_test import FUNCTIONS, start_queue_closure
from transform_source import (TransformSource, read_native, select_core,
                              owned_dependency, source_root, verify_entry,
                              compiler_headers, native_path)

HERE = Path(__file__).resolve().parent
verify_entry(__file__, 'tests/compute/iaa/transform/adapter_test.py')
ROOT = source_root(__file__, os.environ.get('KERNEL_SRC'))
ADAPTER_FUNCTIONS = ('xdev_ext_iaa_crypto_done', 'xdev_ext_iaa_sg',
                     'xdev_ext_iaa_bind', 'xdev_ext_iaa_unbind',
                     'xdev_ext_iaa_submit', 'xdev_ext_iaa_mark_dead')
# Helpers factored out of bind/submit; absent from older adapters.
OPTIONAL_ADAPTER_FUNCTIONS = ('xdev_ext_iaa_output', 'xdev_ext_iaa_hw_admit')
ACCESSORS = ('xdev_ext_mech_session_layout', 'xdev_ext_mech_session_pool',
             'xdev_ext_mech_session_depth',
             'xdev_ext_mech_batch_slot', 'xdev_ext_mech_batch_nr_frames',
             'xdev_ext_mech_batch_bytes', 'xdev_ext_mech_batch_frame',
             'xdev_ext_mech_batch_ticket')
# A frame window may be split at page_split; the tail lives in a distinct,
# non-adjacent page that no other frame uses, so splitting creates no alias.
FRAME_PAGE = '''static struct page *xdev_ext_mech_frame_page(struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f,u32 off,u32 *po,u32 *len) {
 if(f->index>=p->nr_frames || off>=FS)return NULL;
 *po=off;*len=FS-off;return &pages[page_map[f->index]];
}'''
SPLIT_FRAME_PAGE = '''static u32 page_split;
static struct page split_pages[N];
static struct page *xdev_ext_mech_frame_page(struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f,u32 off,u32 *po,u32 *len) {
 if(f->index>=p->nr_frames || off>=FS)return NULL;
 if(page_split && off<page_split){*po=off;*len=page_split-off;return &pages[page_map[f->index]];}
 if(page_split){*po=off-page_split;*len=FS-off;split_pages[page_map[f->index]].id=N+page_map[f->index];return &split_pages[page_map[f->index]];}
 *po=off;*len=FS-off;return &pages[page_map[f->index]];
}'''


def build_source(adapter, core):
    # Reuse only the existing fixture's kernel boundary types and helpers.
    # Its production placeholders are still replaced by the current real code.
    selected = TransformSource(core, lambda path: read_native(ROOT, path), function)
    production = selected.text
    shared = start_queue_closure(owned_dependency(
        __file__, 'tests/compute/iaa/transform/lease_fixture.c').read_text().split('int main(', 1)[0], production)
    shared = shared.replace('const struct xdev_ext_mech_class_ops *cls;};',
                            'const struct xdev_ext_mech_class_ops *cls;void *priv;};')
    shared = shared.replace('struct xdev_ext_mech_session {\n',
                            'struct xdev_ext_mech_session {\n struct xdev_ext_mech_layout layout;struct xdev_ext_mech_batch *batches;u32 depth;\n')
    shared = shared.replace('struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;u32 index,direction,class_id;',
                            'struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;u32 index,direction,class_id,flags;')
    if FRAME_PAGE not in shared:
        raise RuntimeError('lease fixture frame_page boundary changed')
    shared = shared.replace(FRAME_PAGE, SPLIT_FRAME_PAGE)
    bodies = [function(production, name) for name in FUNCTIONS]
    helpers = []
    if selected.split:
        handoff = function(production, 'xdev_ext_mech_transform_handoff')
        shared = selected.storage(shared)
        shared = shared.replace('struct xdev_ext_mech_batch {',
                                selected.types + '\nstruct xdev_ext_mech_batch {', 1)
        helpers = selected.helpers(bodies + [handoff])
        shared = shared.replace('/* xdev_ext_mech_frames_move */',
                                '\n'.join(helpers) + '\n/* xdev_ext_mech_frames_move */', 1)
        shared = shared.replace('/* xdev_ext_mech_batch_handoff */',
                                handoff + '\n/* xdev_ext_mech_batch_handoff */', 1)
    names = session_helpers(production, bodies) + list(FUNCTIONS)
    for name in names:
        shared = shared.replace('/* ' + name + ' */', function(production, name))
    source = owned_dependency(__file__, 'tests/compute/iaa/transform/adapter_fixture.c').read_text().replace('/* LEASE_BOUNDARY */', shared)
    structures = []
    for name in ('xdev_ext_iaa_request', 'xdev_ext_iaa_stage'):
        match = re.search(r'^struct ' + name + r' \{\n.*?^\};', adapter, re.M | re.S)
        if not match:
            raise RuntimeError('missing production adapter struct: ' + name)
        structures.append(match[0])
    source = source.replace('/* ADAPTER_STRUCTS */', '\n'.join(structures))
    for name in ACCESSORS:
        accessor = function(core, name)
        # Split transform helpers may already require this exact core getter
        # before the lease functions (notably batch_bytes). Emit it only once.
        source = source.replace('/* ' + name + ' */', '' if accessor in helpers else accessor)
    for name in ADAPTER_FUNCTIONS:
        source = source.replace('/* ' + name + ' */', function(adapter, name))
    for name in OPTIONAL_ADAPTER_FUNCTIONS:
        if re.search(r'\b' + name + r'\(', adapter):
            source = source.replace('/* ' + name + ' */', function(adapter, name))
    return source


class AdapterScheduling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        adapter_path = native_path(ROOT, 'io_uring/iaa/xdev_ext_mech_iaa.c')
        override = os.environ.get('XDEV_EXT_IAA_ADAPTER_SOURCE')
        if override is not None and Path(override).resolve() != adapter_path.resolve():
            raise RuntimeError('adapter override is not the selected source owner')
        cls.adapter = read_native(ROOT, 'io_uring/iaa/xdev_ext_mech_iaa.c')
        cls.core = select_core(ROOT, os.environ.get('XDEV_EXT_IAA_ADAPTER_CORE_SOURCE'))
        cls.temp = tempfile.TemporaryDirectory(prefix='xdev_ext-iaa-adapter-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = cls.compile(build_source(cls.adapter, cls.core), 'adapter')

    @classmethod
    def compile(cls, source, name):
        path = Path(cls.temp.name)
        (path / (name + '.c')).write_text(source)
        binary = path / name
        include_root = compiler_headers(ROOT, path / (name + '-include'), source)
        result = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra',
                                 '-Werror', '-Wno-unused-function', '-fsanitize=undefined',
                                 '-fno-sanitize-recover=undefined', '-I' + str(include_root),
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

    def test_synchronous_eagain_before_acceptance_is_backpressure_then_retried_once(self):
        # deflate-iaa returns -EAGAIN synchronously when idxd_submit_desc() could
        # not enqueue on a shared work queue; no callback follows and its DMA
        # mappings are already undone, so the core restores both leases and retries.
        self.probe('eagain')

    def test_hardware_create_refuses_windows_mapping_to_several_segments(self):
        # Upstream iaa_comp_acompress()/adecompress() fail with -EIO when
        # dma_map_sg() returns more than one segment for either side.
        for case in ('bind_hw_multi_dst', 'bind_hw_multi_src', 'bind_hw_split_window'):
            with self.subTest(case=case):
                self.probe(case)

    def test_hardware_create_admits_single_segment_and_software_any_shape(self):
        for case in ('bind_hw_single', 'bind_sw_multi'):
            with self.subTest(case=case):
                self.probe(case)

    def test_hardware_batch_outside_admitted_shape_never_enters_cryptoapi(self):
        for case in ('hw_multi_dst', 'hw_multi_src'):
            with self.subTest(case=case):
                self.probe(case)

    def test_hardware_single_segment_batch_submits_one_entry_per_side(self):
        self.probe('hw_single')

    def test_physically_contiguous_pieces_share_one_scatterlist_entry(self):
        self.probe('contiguous')

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
