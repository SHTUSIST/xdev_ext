#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the unified IAA operation's provider handling on the host.

The actual declarations and function bodies of kernel/io_uring/iaa/xdev_ext_iaa.c
(transform lookup, reuse, release, terminal accounting, driver selection and
served-driver statistics) are compiled into unified_provider_fixture.c, whose
shims only record CryptoAPI/lock/workqueue calls. Nothing is compressed and no
device is emulated, so a pass says nothing about IAA hardware execution.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = Path(os.environ.get('XDEV_EXT_IAA_UNIFIED_SOURCE',
                             ROOT / 'kernel/io_uring/iaa/xdev_ext_iaa.c'))
HEADER = ROOT / 'kernel/io_uring/iaa/xdev_ext_iaa.h'
REQUIRED = ('io_xdev_ext_iaa_runtime_prepare_provider', 'io_xdev_ext_iaa_release_resources',
            'io_xdev_ext_iaa_update_stats', 'io_xdev_ext_iaa_finish_terminal')
# Present once the transform is cached and the driver is selectable.
OPTIONAL = ('io_xdev_ext_iaa_tfm_put', 'io_xdev_ext_iaa_served_slot', 'io_xdev_ext_iaa_tfm_alloc',
            'io_xdev_ext_iaa_tfm_get', 'io_xdev_ext_iaa_tfm_invalidate', 'io_xdev_ext_iaa_tfm_idle',
            'io_xdev_ext_iaa_provider_failed', 'io_xdev_ext_iaa_record_served',
            'io_xdev_ext_iaa_driver_set', 'io_xdev_ext_iaa_driver_get', 'io_xdev_ext_iaa_served_get')
DECLARATIONS = (
    r'^#define IO_XDEV_EXT_IAA_\w+ [^\n]*$',
    r'^struct io_xdev_ext_iaa_(?:async|served|tfm) \{\n.*?^\};',
    r'^struct io_xdev_ext_iaa_tfm;$',
    r'^static (?:DEFINE_SPINLOCK|DEFINE_MUTEX|DECLARE_DELAYED_WORK)\([^\n]*\);$',
    r'^static [^(){};=\n]*\bio_xdev_ext_iaa_\w+(?:\[[^\]\n]*\])?(?: = [^;\n]*)?;$',
    r'^static const struct kernel_param_ops \w+ = \{\n.*?^\};',
)


def function(text, name):
    match = re.search(r'^\w[^;{}]*\b' + name + r'\([^;{}]*\)\n\{\n.*?^\}', text, re.M | re.S)
    return match


def build_source(text):
    items = []
    for pattern in DECLARATIONS:
        items += [(m.start(), m[0]) for m in re.finditer(pattern, text, re.M | re.S)]
    names = list(REQUIRED) + [n for n in OPTIONAL if re.search(r'\b' + n + r'\(', text)]
    for name in names:
        match = function(text, name)
        if not match:
            raise RuntimeError('missing production function: ' + name)
        items.append((match.start(), match[0]))
        prototype = re.search(r'^static [^;{}\n]*\b' + name + r'\([^;{}\n]*\);$', text, re.M)
        if prototype:
            items.append((prototype.start(), prototype[0]))
    header = HEADER.read_text()
    params = re.search(r'^struct io_xdev_ext_iaa_params \{\n.*?^\};', header, re.M | re.S)
    stats = re.search(r'^typedef [^;]*io_xdev_ext_iaa_stats_fn[^;]*;', header, re.M | re.S)
    if not params or not stats:
        raise RuntimeError('missing production interface in xdev_ext_iaa.h')
    body = '\n'.join([params[0], stats[0]] + [code for _, code in sorted(set(items))])
    fixture = (HERE / 'unified_provider_fixture.c').read_text()
    return fixture.replace('/* PRODUCTION_DECLARATIONS */\n/* PRODUCTION_FUNCTIONS */', body)


class UnifiedProvider(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = SOURCE.read_text()
        cls.temp = tempfile.TemporaryDirectory(prefix='xdev_ext-iaa-unified-')
        cls.addClassCleanup(cls.temp.cleanup)
        path = Path(cls.temp.name)
        (path / 'probe.c').write_text(build_source(text))
        cls.binary = path / 'probe'
        defines = []
        if 'io_xdev_ext_iaa_tfm_get(' in text:
            defines.append('-DHAVE_TFM_CACHE')
        if 'io_xdev_ext_iaa_driver_ops' in text:
            defines.append('-DHAVE_SELECTION')
        result = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                 '-Wno-unused-function', '-Wno-unused-parameter',
                                 '-fsanitize=undefined,address', '-fno-sanitize-recover=all',
                                 '-I' + str(HERE), *defines, str(path / 'probe.c'),
                                 '-o', str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def probe(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_sequential_operations_reuse_one_transform(self):
        self.probe('reuse')

    def test_failed_lookup_is_not_cached_so_a_later_provider_is_used(self):
        self.probe('lookup_retry')

    def test_concurrent_requests_share_the_transform_until_last_release(self):
        self.probe('concurrent')

    def test_provider_failure_forces_lookup_but_content_errors_do_not(self):
        self.probe('provider_failure')

    def test_idle_cache_is_released_so_the_provider_is_not_pinned(self):
        self.probe('idle')

    def test_selected_software_driver_serves_and_is_attributed(self):
        self.probe('select')

    def test_algorithm_selection_is_attributed_to_the_actual_driver(self):
        self.probe('algorithm')

    def test_invalid_or_non_deflate_selection_is_refused(self):
        self.probe('refusal')


if __name__ == '__main__':
    unittest.main(verbosity=2)
