#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Git facts, including staged/unstaged/untracked and cross-boundary renames."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'tools/analysis/responsibility.py'

class Responsibility(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        for path in ('examples/app.c', 'src/storage/device.c', 'src/core/engine.c',
                     'examples/storage/base.bpf.c', 'docs/readme.md', 'odd|name.c',
                     'examples/tab\tline\nname.c'):
            self.write(path, 'old\n' * 40)
        (self.repo/'old.bin').write_bytes(b'\0old')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')
        self.base = self.git('rev-parse', 'HEAD').strip()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True)

    def write(self, path, data):
        p = self.repo / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data)

    def run_report(self, *args):
        return subprocess.run(['python3', str(SCRIPT), '--repo', str(self.repo),
                               '--base', self.base, *args], text=True, capture_output=True)

    def test_worktree_paths_and_rename_keep_both_responsibilities(self):
        self.write('examples/app.c', 'application\n')
        self.write('src/core/engine.c', 'core\n')
        self.git('mv', 'src/storage/device.c', 'examples/device.c')
        self.write('examples/storage/new.bpf.c', 'bpf\n')
        self.write('src/storage/new.c', 'backend\n')
        self.write('odd|name.c', 'other\n')
        p = self.run_report('--working-tree', '--format', 'json')
        self.assertEqual(p.returncode, 0, p.stderr)
        result = json.loads(p.stdout)
        by_path = {x['path']: x for x in result['changes']}
        self.assertEqual(by_path['src/core/engine.c']['categories'], ['core'])
        self.assertEqual(by_path['examples/app.c']['categories'], ['application'])
        self.assertEqual(by_path['examples/storage/new.bpf.c']['categories'], ['BPF'])
        self.assertEqual(by_path['src/storage/new.c']['categories'], ['backend'])
        renamed = by_path['examples/device.c']
        self.assertEqual(renamed['old_path'], 'src/storage/device.c')
        self.assertEqual(renamed['categories'], ['application', 'backend'])
        self.assertEqual(by_path['odd|name.c']['categories'], ['other'])
        self.assertIn('added', renamed, 'raw Git numstat fields are required')
        self.assertEqual((renamed['added'], renamed['deleted']), (0, 0))
        self.assertEqual((by_path['src/core/engine.c']['added'], by_path['src/core/engine.c']['deleted']), (1, 40))
        untracked = by_path['src/storage/new.c']
        self.assertIsNone(untracked['added'])
        self.assertIsNone(untracked['deleted'])
        self.assertEqual(untracked['numstat_kind'], 'untracked')

    def test_commit_pair_excludes_later_untracked_changes(self):
        self.write('src/core/engine.c', 'new\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'change')
        self.write('examples/storage/new.bpf.c', 'untracked\n')
        p = self.run_report('--head', 'HEAD', '--format', 'json')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual([x['path'] for x in json.loads(p.stdout)['changes']], ['src/core/engine.c'])

    def test_markdown_preserves_scope_and_unknown_counts(self):
        self.git('rm', '-q', 'examples/app.c')
        (self.repo/'new.bin').write_bytes(b'\0\1\2')
        p = self.run_report('--working-tree')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('examples/app.c', p.stdout)
        self.assertIn('new.bin', p.stdout)
        self.assertIn('application', p.stdout)
        self.assertIn('not establish contribution', p.stdout)
        self.assertIn('untracked; counts unavailable', p.stdout)
        self.assertIn('+0/-40', p.stdout)

    def test_numstat_text_add_delete_edited_rename_and_special_path(self):
        self.write('examples/app.c', 'replacement\n')
        self.git('rm', '-q', 'docs/readme.md')
        self.git('mv', 'src/storage/device.c', 'examples/device.c')
        self.write('examples/device.c', 'old\n' * 40 + 'tail\n')
        self.write('examples/new.c', 'first\nsecond\n')
        special = 'examples/tab\tline\nname.c'
        self.write(special, 'old\n' * 39 + 'replacement\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'numstat fixture')
        p = self.run_report('--head', 'HEAD', '--format', 'json')
        self.assertEqual(p.returncode, 0, p.stderr)
        by_path = {x['path']: x for x in json.loads(p.stdout)['changes']}
        for path, want in [('examples/app.c', (1, 40)), ('docs/readme.md', (0, 40)),
                           ('examples/device.c', (1, 0)), ('examples/new.c', (2, 0)),
                           (special, (1, 1))]:
            with self.subTest(path=path):
                self.assertIn('added', by_path[path], 'raw Git numstat fields are required')
                self.assertEqual((by_path[path]['added'], by_path[path]['deleted']), want)
                self.assertEqual(by_path[path]['numstat_kind'], 'text')
        self.assertEqual(by_path['examples/device.c']['old_path'], 'src/storage/device.c')

    def test_numstat_binary_modification_and_deletion_are_unknown(self):
        (self.repo/'old.bin').write_bytes(b'\0new')
        p = self.run_report('--working-tree', '--format', 'json')
        self.assertEqual(p.returncode, 0, p.stderr)
        change = next(x for x in json.loads(p.stdout)['changes'] if x['path'] == 'old.bin')
        self.assertIn('added', change, 'raw Git numstat fields are required')
        self.assertIsNone(change['added'])
        self.assertIsNone(change['deleted'])
        self.assertEqual(change['numstat_kind'], 'binary')
        self.git('rm', '-qf', 'old.bin')
        p = self.run_report('--working-tree', '--format', 'json')
        self.assertEqual(p.returncode, 0, p.stderr)
        change = next(x for x in json.loads(p.stdout)['changes'] if x['path'] == 'old.bin')
        self.assertEqual(change['status'], 'D')
        self.assertIn('added', change, 'raw Git numstat fields are required')
        self.assertIsNone(change['added'])
        self.assertIsNone(change['deleted'])
        self.assertEqual(change['numstat_kind'], 'binary')

    def test_numstat_rename_keeps_tabs_and_newlines_in_both_paths(self):
        old = 'examples/tab\tline\nname.c'
        new = 'src/storage/moved\tline\nname.c'
        self.git('mv', old, new)
        p = self.run_report('--working-tree', '--format', 'json')
        self.assertEqual(p.returncode, 0, p.stderr)
        change = next(x for x in json.loads(p.stdout)['changes'] if x['path'] == new)
        self.assertEqual(change['old_path'], old)
        self.assertEqual((change['added'], change['deleted']), (0, 0))
        self.assertEqual(change['categories'], ['application', 'backend'])

    def test_bad_revision_fails_instead_of_empty_report(self):
        p = self.run_report('--head', 'does-not-exist', '--format', 'json')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout, '')

if __name__ == '__main__':
    unittest.main()
