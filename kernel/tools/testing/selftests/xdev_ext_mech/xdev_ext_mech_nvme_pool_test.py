#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production NVMe map/submit/completion with deterministic OS shims."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def declaration(source, name, struct=False):
    pattern = (r'^struct ' + name + r'\s*\{.*?^};' if struct else
               r'^static [^;{}]*\b' + name + r'\([^;]*?\)\s*\{.*?^}')
    match = re.search(pattern, source, re.M | re.S)
    return match[0] if match else ''


class NvmePool(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / 'drivers/nvme/host/xdev_ext_mech_nvme.c').read_text()
        cls.temp = tempfile.TemporaryDirectory(prefix='xdev_ext-nvme-pool-')
        cls.addClassCleanup(cls.temp.cleanup)
        fixture = (HERE / 'xdev_ext_mech_nvme_pool_fixture.c').read_text()
        names = ['nvme_xdev_ext_mech_stage', 'nvme_xdev_ext_mech_batch',
                 'nvme_xdev_ext_mech_completion', 'nvme_xdev_ext_mech_slot']
        definitions = '\n'.join(declaration(source, name, True) for name in names)
        functions = ['nvme_xdev_ext_class_resources_free', 'nvme_xdev_ext_class_resources_init',
                     'nvme_xdev_ext_class_slot_get', 'nvme_xdev_ext_class_slot_put',
                     'nvme_xdev_ext_class_walk', 'nvme_xdev_ext_class_map',
                     'nvme_xdev_ext_class_end_io', 'nvme_xdev_ext_class_submit',
                     'nvme_xdev_ext_class_fill_cqe']
        functions = '\n\n'.join(declaration(source, name) for name in functions)
        prealloc = bool(declaration(source, 'nvme_xdev_ext_class_resources_init'))
        fixture = fixture.replace('/* PRODUCTION_TYPES */', definitions)
        fixture = fixture.replace('/* PRODUCTION_FUNCTIONS */', functions)
        block = (ROOT / 'block/blk-mq.c').read_text()
        fixture = fixture.replace('/* BLOCK_BATCH_COMPLETION */',
                                  declaration(block, 'blk_complete_request'))
        fixture = fixture.replace('/* POOL_INIT */',
                'rc = nvme_xdev_ext_class_resources_init(&st);' if prealloc else 'rc = 0;')
        fixture = fixture.replace('/* POOL_COUNT */',
                'for(i=0;i<p.nr_slots;i++)retained+=p.slots[i].busy;' if prealloc else '')
        fixture = fixture.replace('/* POOL_FREE */',
                'nvme_xdev_ext_class_resources_free(&p);' if prealloc else '')
        path = Path(cls.temp.name)
        (path / 'probe.c').write_text(fixture)
        cls.probe = path / 'probe'
        command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g',
                   '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                   '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                   ('-DCONFIG_XDEV_EXT_MECH_KVM_BOUNCE' if getattr(cls, 'bounce', False)
                    else '-DCONFIG_XDEV_EXT_MECH_ZEROCOPY'), '-I' + str(ROOT),
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

    def test_short_native_completion_keeps_its_lease(self):
        result = self.run_case('short-native')
        self.assertEqual(result['submitted'], 1, result)
        self.assertEqual(result['completed'], 1, result)
        self.assertEqual(result['uncertain'], 1, result)
        self.assertEqual(result['retained'], 1, result)
        self.assertGreater(result['live'], 0, result)


class NvmePoolBounce(NvmePool):
    """The explicitly marked compatibility build reserves its pages at CREATE."""
    bounce = True


if __name__ == '__main__':
    unittest.main(verbosity=2)
