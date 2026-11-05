#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production NVMe map/submit/completion with deterministic OS shims."""
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
import unittest
import sys
import json

HERE = Path(__file__).resolve().parent
_LAYOUT_FILE = next(p / 'tools/layout.py' for p in Path(__file__).resolve().parents
                    if (p / 'tools/layout.py').is_file())
ROOT = runpy.run_path(str(_LAYOUT_FILE))['canonical_root'](Path(__file__))
_LEGACY = runpy.run_path(str(ROOT / 'tests/storage/nvme/_legacy_storfam_fixture.py'))
LegacySelection, pool_fixture = (_LEGACY[name] for name in ('LegacySelection', 'pool_fixture'))
HELPERS = runpy.run_path(str(ROOT / 'tests/integration/peer_graph/nvme_peer_async_test.py'))
def native(path):
    return HELPERS['read_native'](ROOT, path)


def declaration(source, name, struct=False):
    pattern = (r'^struct ' + name + r'\s*\{.*?^};' if struct else
               r'^[A-Za-z_][^;{}]*\b' + name + r'\([^;]*?\)\s*\{.*?^}')
    match = re.search(pattern, source, re.M | re.S)
    if not match:
        raise AssertionError('production declaration missing: ' + name)
    return match[0]




class NvmePool(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = native('drivers/nvme/host/xdev_ext_mech_nvme.c')
        cls.temp = tempfile.TemporaryDirectory(prefix='xdev_ext-nvme-pool-')
        cls.addClassCleanup(cls.temp.cleanup)
        fixture = (HERE / 'xdev_ext_mech_nvme_pool_fixture.c').read_text()
        if 'return xdev_ext_storfam_submit(&p->family, b, &bp->family);' in source:
            selected=LegacySelection(ROOT)
            profile='bounce' if getattr(cls,'bounce',False) else 'strict'
            fixture,records=pool_fixture(selected,fixture,profile)
            path=Path(cls.temp.name)
            (path/'probe.c').write_text(fixture)
            (path/'assembly.json').write_text(json.dumps(selected.report(),indent=2))
            (path/'fixture-edits.json').write_text(json.dumps(records,indent=2))
            cls.probe=path/'probe'
            command=[os.environ.get('CC','cc'),'-std=gnu11','-O1','-g',
                     '-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function',
                     '-fsanitize=undefined','-fno-sanitize-recover=undefined',
                     ('-DCONFIG_XDEV_EXT_MECH_KVM_BOUNCE' if getattr(cls,'bounce',False)
                      else '-DCONFIG_XDEV_EXT_MECH_ZEROCOPY'),
                     '-I'+str(HELPERS['host_headers'](selected.root,path/'headers')),
                     str(path/'probe.c'),'-o',str(cls.probe)]
            selected.verify()
            subprocess.run(command,check=True)
            return
        names = ['nvme_xdev_ext_mech_stage', 'nvme_xdev_ext_mech_batch',
                 'nvme_xdev_ext_mech_slot']
        definitions = '\n'.join(declaration(source, name, True) for name in names)
        functions = ['nvme_xdev_ext_class_resources_free', 'nvme_xdev_ext_class_resources_init',
                     'nvme_xdev_ext_class_slot_get', 'nvme_xdev_ext_class_slot_put',
                     'nvme_xdev_ext_class_validate',
                     'nvme_xdev_ext_class_walk', 'nvme_xdev_ext_class_map',
                     'nvme_xdev_ext_poll_opf', 'nvme_xdev_ext_poll_check',
                     'nvme_xdev_ext_poll_arm',
                     'nvme_xdev_ext_class_complete', 'nvme_xdev_ext_class_ready',
                     'nvme_xdev_ext_class_end_io', 'nvme_xdev_ext_class_submit',
                     'nvme_xdev_ext_class_fill_cqe']
        dependencies = ''
        if 'xdev_ext_stor_block_preflight(' in source:
            functions.remove('nvme_xdev_ext_class_walk')
            block = native('io_uring/family/xdev_ext_storfam_block.c')
            dependencies += '\n\n'.join(declaration(block, name) for name in (
                'xdev_ext_stor_block_caps', 'xdev_ext_stor_block_walk',
                'xdev_ext_stor_block_preflight', 'xdev_ext_stor_block_append'))
            # OS queue facts previously supplied by class_caps; the real family
            # caps function now captures these same literal external limits.
            external = r'''
#define SECTOR_SHIFT 9
struct request_queue { struct { unsigned unused; } limits; };
static unsigned long queue_virt_boundary(struct request_queue *q) { (void)q; return 0; }
#define blk_lim_dma_alignment_and_pad(l) ((void)(l), 0U)
static unsigned queue_max_segments(struct request_queue *q) { (void)q; return 256; }
static unsigned queue_max_segment_size(struct request_queue *q) { (void)q; return 1U << 20; }
static unsigned queue_max_hw_sectors(struct request_queue *q) { (void)q; return 2048; }
'''
            start = fixture.index('static struct nvme_xdev_ext_queue_caps nvme_xdev_ext_class_caps(')
            end = fixture.index('\nstatic int nvme_xdev_ext_class_bounce(', start)
            fixture = fixture[:start] + external + fixture[end:]
        if 'xdev_ext_stor_block_poll_opf(' in source:
            functions = [name for name in functions if not name.startswith('nvme_xdev_ext_poll_')]
            helper = ROOT / 'tests/integration/peer_graph/nvme_peer_async_test.py'
            dependencies += '\n\n' + runpy.run_path(str(helper))['storage_poll_runtime'](ROOT)
        functions = storage_runtime(ROOT) + '\n\n' + dependencies + '\n\n' + '\n\n'.join(
            declaration(source, name) for name in functions)
        if 'struct xdev_ext_stor_stage family;' in source:
            fixture = fixture.replace('/* IDENTITY_OS_TYPES */', HELPERS['identity_boundary']())
            fixture = fixture.replace('/* FAMILY_TYPES */', HELPERS['family_types'](ROOT))
            functions = HELPERS['worker_runtime'](ROOT, source) + '\n' + HELPERS['worker_fixture_init']() + '\n' + functions
        fixture = fixture.replace('/* PRODUCTION_TYPES */', definitions)
        fixture = fixture.replace('/* PRODUCTION_FUNCTIONS */', functions)
        block = native('block/blk-mq.c')
        fixture = fixture.replace('/* BLOCK_BATCH_COMPLETION */',
                                  declaration(block, 'blk_complete_request'))
        fixture = fixture.replace('/* POOL_INIT */',
                'rc = nvme_xdev_ext_class_resources_init(&st);')
        fixture = fixture.replace('/* POOL_COUNT */',
                'for(i=0;i<p.nr_slots;i++)retained+=p.slots[i].runtime.busy;')
        fixture = fixture.replace('/* POOL_FREE */',
                'nvme_xdev_ext_class_resources_free(&p);')
        path = Path(cls.temp.name)
        (path / 'probe.c').write_text(fixture)
        cls.probe = path / 'probe'
        command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g',
                   '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-unused-function',
                   '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                   ('-DCONFIG_XDEV_EXT_MECH_KVM_BOUNCE' if getattr(cls, 'bounce', False)
                    else '-DCONFIG_XDEV_EXT_MECH_ZEROCOPY'), '-I' + str(HELPERS['host_headers'](ROOT, path / 'headers')),
                   str(path / 'probe.c'), '-o', str(cls.probe)]
        subprocess.run(command, check=True)

    def run_case(self, mode):
        result = subprocess.run([str(self.probe), mode], capture_output=True,
                                text=True, check=True, timeout=5)
        return dict((key, int(value)) for key, value in
                    (item.split('=') for item in result.stdout.split()))

    def test_long_flow_has_no_hot_metadata_allocation(self):
        result = self.run_case('flow')
        self.assertEqual(result['rc'], 0, result)
        self.assertEqual(result['submitted'], 256, result)
        self.assertEqual(result['completed'], 256, result)
        self.assertEqual(result['hot_allocs'], 0, result)

    def test_native_tag_pressure_is_preaccept_retry(self):
        result = self.run_case('tags')
        self.assertEqual(result['rc'], -11, result)
        self.assertEqual(result['submitted'], 0, result)
        self.assertEqual(result['hot_allocs'], 0, result)

    def test_short_map_never_submits(self):
        result = self.run_case('short-map')
        self.assertNotEqual(result['rc'], 0, result)
        self.assertEqual(result['submitted'], 0, result)
        self.assertEqual(result['hot_allocs'], 0, result)

    def test_pool_capacity_tracks_native_ownership(self):
        result = self.run_case('capacity')
        self.assertEqual(result['rc'], 0, result)
        self.assertEqual(result['denied'], 1, result)
        self.assertEqual(result['submitted'], 3, result)
        self.assertEqual(result['completed'], 3, result)
        self.assertEqual(result['retained'], 0, result)
        self.assertEqual(result['hot_allocs'], 0, result)
        self.assertEqual(result['live'], 0, result)

    def test_create_allocation_failure_unwinds_every_slot(self):
        result = self.run_case('init-fail')
        self.assertEqual(result['rc'], -12, result)
        self.assertEqual(result['live'], 0, result)
        self.assertEqual(result['submitted'], 0, result)

    def test_stale_completion_cannot_publish_again(self):
        result = self.run_case('stale')
        self.assertEqual(result['submitted'], 2, result)
        self.assertEqual(result['completed'], 2, result)
        self.assertEqual(result['hot_allocs'], 0, result)
        self.assertEqual(result['live'], 0, result)

    def test_real_block_batch_completion_is_not_a_short_native_transfer(self):
        result = self.run_case('batch')
        self.assertEqual(result['bio_endios'], 1, result)
        self.assertEqual(result['status'], 0, result)
        self.assertEqual(result['uncertain'], 0, result)
        self.assertEqual(result['retained'], 0, result)
        self.assertEqual(result['live'], 0, result)

    def test_short_or_foreign_preserved_bio_keeps_its_lease(self):
        for mode in ('batch-short', 'batch-foreign'):
            with self.subTest(mode=mode):
                result = self.run_case(mode)
                self.assertEqual(result['bio_endios'], 1, result)
                self.assertEqual(result['uncertain'], 1, result)
                self.assertEqual(result['retained'], 1, result)
                self.assertGreater(result['live'], 0, result)

    def test_error_without_host_residual_releases_drained_slot(self):
        result = self.run_case('host-error')
        self.assertEqual(result['status'], 0x182, result)
        self.assertEqual(result['uncertain'], 0, result)
        self.assertEqual(result['retained'], 0, result)
        self.assertEqual(result['submitted'], 1, result)
        self.assertEqual(result['completed'], 1, result)
        self.assertEqual(result['live'], 0, result)

    def test_short_native_completion_keeps_its_lease(self):
        result = self.run_case('short-native')
        self.assertEqual(result['submitted'], 1, result)
        self.assertEqual(result['completed'], 1, result)
        self.assertEqual(result['uncertain'], 1, result)
        self.assertEqual(result['retained'], 1, result)
        self.assertGreater(result['live'], 0, result)


def storage_runtime(root):
    content = HELPERS['read_native'](root, 'io_uring/family/xdev_ext_storfam.c')
    found = []
    for name in ('xdev_ext_stor_slot_add', 'xdev_ext_stor_slot_get',
                 'xdev_ext_stor_slot_put', 'xdev_ext_stor_done'):
        match = re.search(r'^[A-Za-z_][^;{}]*\b' + name +
                          r'\([^;{}]*\)\s*\{.*?^\}', content, re.M | re.S)
        if not match:
            raise AssertionError('production storage runtime symbol missing: ' + name)
        found.append(match[0])
    return '\n\n'.join(found)


class NvmePoolBounce(NvmePool):
    """The explicitly marked compatibility build reserves its pages at CREATE."""
    bounce = True


if __name__ == '__main__':
    unittest.main(verbosity=2)
