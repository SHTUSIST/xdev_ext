#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""loc_report.py on a fixture Git overlay with a fixture upstream base."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('loc_report', HERE / 'loc_report.py')
lr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lr)

ENV = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t',
           GIT_COMMITTER_EMAIL='t@t', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)

C_FILE = """// SPDX-License-Identifier: GPL-2.0
/*
 * A provider.
 */
#include <linux/types.h>

static int f(void)
{
	return 1;	/* trailing comment */
}
"""
BASE_PCI = "line a\nline b\nline c\n"
OVERLAY_PCI = "line a\n#ifdef CONFIG_X\nhook();\n#endif\nline c\n"


def git(cwd, *args):
    return subprocess.run(['git', '-C', str(cwd), *args], check=True, env=ENV,
                          capture_output=True, text=True).stdout


def fixture(base):
    base = Path(base)
    upstream = base / 'upstream'
    upstream.mkdir()
    git(upstream, 'init', '-q')
    (upstream / 'drivers/nvme/host').mkdir(parents=True)
    (upstream / 'drivers/nvme/host/pci.c').write_text(BASE_PCI)
    git(upstream, 'add', '.')
    git(upstream, 'commit', '-qm', 'base')
    commit = git(upstream, 'rev-parse', 'HEAD').strip()
    repo = base / 'repo'
    for rel, text in {'kernel/io_uring/xdev_ext_mech_dma.c': C_FILE,
                      'kernel/io_uring/xdev_ext_mech_dma_core.h': '#define A 1\n\n',
                      'kernel/drivers/nvme/host/pci.c': OVERLAY_PCI,
                      'kernel/drivers/nvme/host/xdev_ext_mech_nvme.c': C_FILE,
                      'kernel/lib/stray_own.c': 'int x;\n',
                      'kernel/tools/testing/selftests/x/test.c': 'int t;\n'}.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    (repo / 'sources.lock.json').write_text(json.dumps(dict(schema=1, components=dict(
        linux=dict(url='u', ref='refs/tags/x', commit=commit, path='kernel')))))
    git(repo, 'init', '-q')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'overlay')
    catalog = {
        'dma': dict(own=['kernel/io_uring/xdev_ext_mech_dma*.[ch]'], hooks=[]),
        'nvme': dict(own=['kernel/drivers/nvme/host/xdev_ext_mech_nvme.c'],
                     hooks=['kernel/drivers/nvme/host/pci.c']),
    }
    return repo, upstream / '.git', commit, catalog


class Counting(unittest.TestCase):
    def test_c_lines(self):
        self.assertEqual(lr.count_lines(C_FILE, 'c'),
                         dict(total=10, blank=1, comment=4, code=5))

    def test_hash_comment_lines(self):
        self.assertEqual(lr.count_lines('# c\nobj-y += a.o\n\n', 'make'),
                         dict(total=3, blank=1, comment=1, code=1))

    def test_hunk_lines(self):
        self.assertEqual(lr.hunk_lines(BASE_PCI, OVERLAY_PCI), dict(added=3, removed=1))


class Report(unittest.TestCase):
    def test_classes_hooks_and_unclassified(self):
        with tempfile.TemporaryDirectory() as t:
            repo, upstream, commit, catalog = fixture(t)
            r = lr.report(repo, catalog, {'linux': upstream})
        dma = r['classes']['dma']
        self.assertEqual([f['path'] for f in dma['own']],
                         ['kernel/io_uring/xdev_ext_mech_dma.c',
                          'kernel/io_uring/xdev_ext_mech_dma_core.h'])
        self.assertEqual(dma["own_code_lines"], 5 + 1)
        self.assertEqual(dma['hook_added_lines'], 0)
        nvme = r['classes']['nvme']
        self.assertEqual(nvme['hooks'], [dict(path='kernel/drivers/nvme/host/pci.c',
                                              base=commit, added=3, removed=1)])
        self.assertEqual(nvme['hook_added_lines'], 3)
        self.assertEqual(nvme['hooks_without_base'], 0)
        self.assertEqual(r['unclassified'], ['kernel/lib/stray_own.c'])
        self.assertEqual(r['missing'], [])
        self.assertEqual(r['upstream'], {'linux': commit})

    def test_missing_upstream_base_is_reported_not_guessed(self):
        with tempfile.TemporaryDirectory() as t:
            repo, _, _, catalog = fixture(t)
            r = lr.report(repo, catalog, {'linux': Path(t) / 'nowhere.git'})
        hook = r['classes']['nvme']['hooks'][0]
        self.assertIsNone(hook['added'])
        self.assertIn('upstream', hook['reason'])
        self.assertEqual(r['classes']['nvme']['hooks_without_base'], 1)
        self.assertIsNone(r['upstream']['linux'])

    def test_catalog_entry_without_tracked_file_fails(self):
        with tempfile.TemporaryDirectory() as t:
            repo, upstream, _, catalog = fixture(t)
            catalog['iaa'] = dict(own=['kernel/io_uring/iaa/*.c'], hooks=['kernel/x.c'])
            r = lr.report(repo, catalog, {'linux': upstream})
            self.assertEqual(r['missing'], ['kernel/io_uring/iaa/*.c', 'kernel/x.c'])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = lr.main(['--repo', str(repo), '--upstream-git', 'linux=' + str(upstream),
                                '--json'], catalog=catalog)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())['missing'], r['missing'])


class LiveTree(unittest.TestCase):
    def test_product_catalog_matches_tracked_files(self):
        root = HERE.parents[2]
        if not (root / '.git').exists():
            self.skipTest('not a Git checkout')
        r = lr.report(root, lr.CATALOG, {})
        self.assertEqual(r['missing'], [], 'catalog names files Git does not track')
        for name in ('nvme', 'afxdp', 'ce', 'dma', 'iaa', 'socket', 'net_peer'):
            self.assertGreater(r['classes'][name]['own_code_lines'], 0, name)


if __name__ == '__main__':
    unittest.main()
