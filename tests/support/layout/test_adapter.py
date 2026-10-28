#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Small offline fixtures for changed layout behavior; no upstream download."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import layout


class Adapter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.files = [dict(source='src/core/body.c', component='linux', native_path='io_uring/body.c'),
                      dict(source='tests/core/probe.py', logical_path='kernel/tools/testing/probe.py')]
        self.write('src/core/body.c', 'canonical body\n')
        self.write('tests/core/probe.py', 'raise SystemExit(23)\n')
        self.write('third_party/sources.lock.json', json.dumps(dict(schema=2, components={
            'linux': dict(url='file:///fixture', ref='refs/heads/main', commit='1' * 40)})))
        self.manifest()
        self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.STDOUT)

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def manifest(self):
        self.write('source-layout.json', json.dumps(dict(schema=1, files=self.files)))

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD').decode().strip()

    def test_view_copies_are_isolated_and_refresh_current_bytes(self):
        view = layout.materialize_view(self.repo)
        copy = view.kernel / 'io_uring/body.c'
        original = self.repo / 'src/core/body.c'
        self.assertNotEqual(copy.stat().st_ino, original.stat().st_ino)
        self.assertFalse(copy.is_symlink())
        copy.write_text('mutation\n')
        self.assertEqual(original.read_text(), 'canonical body\n')
        layout.materialize_view(self.repo)
        self.assertEqual(copy.read_text(), original.read_text())
        receipt = json.loads((view.root / 'view.json').read_text())
        self.assertEqual(receipt['canonical_root'], str(self.repo))
        self.assertEqual(layout.canonical_root(view.kernel), self.repo)
        self.assertFalse((view.root / '.git').exists())
        legacy = json.loads((view.root / 'sources.lock.json').read_text())
        self.assertEqual(legacy['schema'], 1)
        self.assertEqual(legacy['components']['linux']['path'], 'kernel')

    def test_duplicate_native_and_escape_rejected_before_output(self):
        self.files.append(dict(source='src/core/other.c', component='linux', native_path='io_uring/body.c'))
        self.manifest()
        with self.assertRaises(layout.LayoutError):
            layout.materialize_view(self.repo)
        self.assertFalse((self.repo / 'build/source-view').exists())
        self.files[-1]['native_path'] = '../outside'
        self.manifest()
        with self.assertRaises(layout.LayoutError):
            layout.materialize_view(self.repo)

    def test_missing_or_symlink_source_rejected_before_output(self):
        (self.repo / 'src/core/body.c').unlink()
        with self.assertRaises(layout.LayoutError):
            layout.materialize_view(self.repo)
        self.assertFalse((self.repo / 'build/source-view').exists())
        os.symlink(self.repo / 'tests/core/probe.py', self.repo / 'src/core/body.c')
        with self.assertRaises(layout.LayoutError):
            layout.materialize_view(self.repo)
        self.assertFalse((self.repo / 'build/source-view').exists())

    def test_revisions_use_their_own_mapping_and_never_current_decoy(self):
        first = self.git('rev-parse', 'HEAD').decode().strip()
        (self.repo / 'src/core/body.c').rename(self.repo / 'src/core/moved.c')
        self.files[0]['source'] = 'src/core/moved.c'
        self.manifest()
        self.write('src/core/moved.c', 'new snapshot\n')
        second = self.commit()
        self.write('src/core/body.c', 'root decoy\n')
        self.write('src/core/moved.c', 'dirty worktree\n')
        self.assertEqual(layout.read_source(self.repo, 'linux', 'io_uring/body.c', first), b'canonical body\n')
        self.assertEqual(layout.read_source(self.repo, 'linux', 'io_uring/body.c', second), b'new snapshot\n')
        self.assertEqual(layout.read_source(self.repo, 'linux', 'io_uring/body.c'), b'dirty worktree\n')
        with self.assertRaises(layout.LayoutError):
            layout.read_source(self.repo, 'linux', 'io_uring/body.c', 'not-a-revision')

    def test_schema1_history_is_read_from_historical_lock(self):
        self.write('sources.lock.json', json.dumps(dict(schema=1, components={'linux': {'path': 'old-kernel'}})))
        self.write('old-kernel/io_uring/body.c', 'old tree\n')
        (self.repo / 'source-layout.json').unlink()
        old = self.commit()
        self.manifest()
        self.assertEqual(layout.read_source(self.repo, 'linux', 'io_uring/body.c', old), b'old tree\n')

    def test_unowned_output_and_symlink_parent_are_rejected(self):
        out = self.repo / 'build/unowned'
        out.mkdir(parents=True)
        (out / 'valuable').write_text('keep')
        with self.assertRaises(layout.LayoutError):
            layout.materialize_view(self.repo, out)
        self.assertEqual((out / 'valuable').read_text(), 'keep')
        os.symlink(out, self.repo / 'build/link')
        with self.assertRaises(layout.LayoutError):
            layout.materialize_view(self.repo, self.repo / 'build/link/view')

    def test_manifest_append_preserves_view_and_refuses_unregistered_destination(self):
        view = layout.materialize_view(self.repo)
        self.write('tests/core/added.py', 'new support input\n')
        self.files.append(dict(source='tests/core/added.py', logical_path='tests/added.py'))
        self.manifest()
        layout.materialize_view(self.repo)
        self.assertEqual((view.root / 'tests/added.py').read_text(), 'new support input\n')
        self.write('tests/core/collision.py', 'canonical collision input\n')
        target = view.root / 'tests/collision.py'
        target.write_text('unregistered output must survive\n')
        self.files.append(dict(source='tests/core/collision.py', logical_path='tests/collision.py'))
        self.manifest()
        with self.assertRaises(layout.LayoutError):
            layout.materialize_view(self.repo)
        self.assertEqual(target.read_text(), 'unregistered output must survive\n')

    def test_manifest_append_parent_file_conflict_precedes_all_writes(self):
        view = layout.materialize_view(self.repo)
        before_marker = (view.root / 'view.json').read_bytes()
        before_source = (view.kernel / 'io_uring/body.c').read_bytes()
        self.write('src/core/body.c', 'new canonical bytes\n')
        self.write('tests/core/new.py', 'new support input\n')
        self.files.append(dict(source='tests/core/new.py', logical_path='extra/new.py'))
        self.manifest()
        (view.root / 'extra').write_text('existing unregistered parent file\n')
        with self.assertRaises(layout.LayoutError):
            layout.materialize_view(self.repo)
        self.assertEqual((view.kernel / 'io_uring/body.c').read_bytes(), before_source)
        self.assertEqual((view.root / 'view.json').read_bytes(), before_marker)

    def test_offline_full_assembly_copies_overlays_and_preserves_upstream(self):
        sys.path.insert(0, str(ROOT / 'tools/build'))
        import prepare_sources
        upstream_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(upstream_tmp.cleanup)
        upstream = Path(upstream_tmp.name)
        subprocess.run(['git', '-C', str(upstream), 'init', '-q'], check=True)
        subprocess.run(['git', '-C', str(upstream), 'config', 'user.name', 'Fixture'], check=True)
        subprocess.run(['git', '-C', str(upstream), 'config', 'user.email', 'fixture@example.invalid'], check=True)
        for name in prepare_sources.REQUIRED['linux'] + ('upstream-only.h', 'io_uring/body.c'):
            path = upstream / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('upstream ' + name + '\n')
        subprocess.run(['git', '-C', str(upstream), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(upstream), 'commit', '-qm', 'upstream'], check=True)
        commit = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD']).decode().strip()
        ref = subprocess.check_output(['git', '-C', str(upstream), 'symbolic-ref', 'HEAD']).decode().strip()
        self.write('third_party/sources.lock.json', json.dumps(dict(schema=2, components={
            'linux': dict(url=upstream.as_uri(), ref=ref, commit=commit)})))
        cache = self.repo / 'build/object-cache'
        prepare_sources.prepare(self.repo, 'linux', cache)
        output = self.repo / 'build/assembled/linux'
        self.assertEqual((output / 'io_uring/body.c').read_text(), 'canonical body\n')
        self.assertEqual((output / 'upstream-only.h').read_text(), 'upstream upstream-only.h\n')
        self.assertFalse((self.repo / 'src/core/upstream-only.h').exists())
        prepare_sources.prepare(self.repo, 'linux', cache, check=True)
        (output / 'io_uring/body.c').write_text('unexpected local edit\n')
        with self.assertRaises(prepare_sources.PreparationError):
            prepare_sources.prepare(self.repo, 'linux', cache)


if __name__ == '__main__':
    unittest.main()
