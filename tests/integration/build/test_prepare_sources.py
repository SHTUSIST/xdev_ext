# SPDX-License-Identifier: GPL-2.0-only
"""Offline source-assembly regressions using tiny local Git repositories."""
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'prepare_sources.py'


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


class PrepareSourcesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='xdev-ext-prepare-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.upstream = self.base / 'upstream'
        self.project = self.base / 'project'
        self.upstream.mkdir()
        self.project.mkdir()
        for path in (self.upstream, self.project):
            git(path, 'init', '-q')
            git(path, 'config', 'user.name', 'Fixture')
            git(path, 'config', 'user.email', 'fixture@example.invalid')
        for name, data in {'Makefile': 'base make\n', 'Kconfig': 'base config\n',
                           'scripts/Makefile.build': 'rules\n',
                           'include/linux/types.h': 'types\n',
                           'keep.txt': 'upstream\n', 'missing.txt': 'fill me\n'}.items():
            p = self.upstream / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(data)
        git(self.upstream, 'add', '.')
        git(self.upstream, 'commit', '-qm', 'fixture base')
        git(self.upstream, 'tag', 'fixture-v1')
        self.commit = git(self.upstream, 'rev-parse', 'HEAD')
        self.overlay = self.project / 'src/core'
        self.overlay.mkdir(parents=True)
        (self.overlay / 'keep.txt').write_text('project overlay\n')
        self.component = self.project / 'build/assembled/linux'
        self.component.mkdir(parents=True)
        (self.component / 'keep.txt').write_text('project overlay\n')
        git(self.project, 'add', 'src/core/keep.txt')
        git(self.project, 'commit', '-qm', 'project fixture')
        self.lock = {'schema': 2, 'components': {'linux': {
            'url': str(self.upstream), 'ref': 'refs/tags/fixture-v1',
            'commit': self.commit}}}
        self.write_lock()

    def write_layout(self):
        entries = [dict(source=p.relative_to(self.project).as_posix(), component='linux', native_path=p.name)
                   for p in sorted(self.overlay.iterdir())]
        (self.project / 'source-layout.json').write_text(json.dumps(dict(schema=1, files=entries)))
        # Register a deliberately incomplete owned assembly fixture. This keeps
        # the original before-fill conflict/space cases without treating an
        # arbitrary nonempty directory as a project-owned assembly.
        spec = self.lock['components']['linux']
        marker = dict(schema=2, kind='full-assembly', component='linux', **spec,
                      canonical_root=str(self.project), output=str(self.component),
                      source_origins={e['native_path']: e['source'] for e in entries},
                      overlay_sha256={e['native_path']: hashlib.sha256((self.component / e['native_path']).read_bytes()).hexdigest()
                                      for e in entries if (self.component / e['native_path']).is_file()})
        (self.component / '.xdev-ext-source.json').write_text(json.dumps(marker))

    def write_lock(self):
        path = self.project / 'third_party/sources.lock.json'
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(self.lock))
        self.write_layout()

    def run_prepare(self, *args, component='linux'):
        self.assertTrue(SCRIPT.is_file(), 'source preparation script is not implemented')
        target = self.project / 'tools/build' / SCRIPT.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SCRIPT, target)
        shutil.copyfile(SCRIPT.parents[1] / 'tools/layout.py', self.project / 'tools/layout.py')
        return subprocess.run([sys.executable, str(target), '--component', component, *args],
                              cwd=self.project, text=True, capture_output=True)

    def test_missing_files_overlay_and_idempotence(self):
        first = self.run_prepare()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual((self.component / 'missing.txt').read_text(), 'fill me\n')
        self.assertEqual((self.component / 'keep.txt').read_text(), 'project overlay\n')
        before = (self.component / 'missing.txt').stat().st_mtime_ns
        second = self.run_prepare()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual((self.component / 'missing.txt').stat().st_mtime_ns, before)
        check = self.run_prepare('--check')
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_pinned_commit_mismatch_refused_before_fill(self):
        self.lock['components']['linux']['commit'] = '0' * 40
        self.write_lock()
        result = self.run_prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('commit', result.stderr.lower())
        self.assertFalse((self.component / 'missing.txt').exists())

    def test_tag_drift_refused_even_with_cached_original(self):
        self.assertEqual(self.run_prepare().returncode, 0)
        (self.upstream / 'missing.txt').write_text('new upstream\n')
        git(self.upstream, 'add', '.')
        git(self.upstream, 'commit', '-qm', 'tag drift')
        git(self.upstream, 'tag', '-f', 'fixture-v1')
        result = self.run_prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('commit', result.stderr.lower())
        self.assertEqual((self.component / 'missing.txt').read_text(), 'fill me\n')

    def test_conflict_preserved_and_explicit_replace(self):
        (self.component / 'missing.txt').write_text('user edit\n')
        result = self.run_prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('conflict', result.stderr.lower())
        self.assertEqual((self.component / 'missing.txt').read_text(), 'user edit\n')
        self.assertFalse((self.component / 'Makefile').exists())
        result = self.run_prepare('--replace-base')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.component / 'missing.txt').read_text(), 'fill me\n')
        self.assertEqual((self.component / 'keep.txt').read_text(), 'project overlay\n')

    def test_check_requires_marker_and_required_files(self):
        self.assertNotEqual(self.run_prepare('--check').returncode, 0)
        self.assertEqual(self.run_prepare().returncode, 0)
        (self.component / 'Makefile').unlink()
        self.assertNotEqual(self.run_prepare('--check').returncode, 0)

    def test_existing_parent_symlink_refused(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.component / 'include').symlink_to(outside, target_is_directory=True)
        result = self.run_prepare('--replace-base')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((outside / 'linux').exists())

    def test_custom_cache(self):
        cache = self.base / 'cache'
        result = self.run_prepare('--cache', str(cache))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((cache / 'linux.git').is_dir())

    def test_archive_rejects_escape_and_hardlinks(self):
        self.assertTrue(SCRIPT.is_file(), 'source preparation script is not implemented')
        spec = importlib.util.spec_from_file_location('prepare_sources', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name, kind, link in [('../escape', 'file', ''), ('/escape', 'file', ''),
                                  ('link', 'symlink', '../../escape'),
                                  ('link', 'symlink', '/escape'),
                                  ('link', 'hardlink', '../escape'),
                                  ('.git/config', 'file', '')]:
            with self.subTest(name=name, kind=kind, link=link):
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode='w') as archive:
                    entry = tarfile.TarInfo(name)
                    if kind == 'symlink':
                        entry.type, entry.linkname = tarfile.SYMTYPE, link
                    elif kind == 'hardlink':
                        entry.type, entry.linkname = tarfile.LNKTYPE, link
                    else:
                        entry.size = 1
                    archive.addfile(entry, io.BytesIO(b'x') if kind == 'file' else None)
                raw.seek(0)
                with tarfile.open(fileobj=raw, mode='r|') as archive:
                    with self.assertRaises(module.PreparationError):
                        module.process_archive(archive, self.component, set(), False, False)
                self.assertFalse((self.base / 'escape').exists())

    def test_archive_does_not_retain_every_member(self):
        self.assertTrue(SCRIPT.is_file(), 'source preparation script is not implemented')
        spec = importlib.util.spec_from_file_location('prepare_sources', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            for index in range(200):
                entry = tarfile.TarInfo('entry' + str(index))
                entry.size = 1
                archive.addfile(entry, io.BytesIO(b'x'))
        raw.seek(0)
        with tarfile.open(fileobj=raw, mode='r|') as archive:
            module.process_archive(archive, self.component, set(), False, False)
            self.assertLessEqual(len(archive.members), 1)

    def test_insufficient_space_refuses_before_filling(self):
        self.assertTrue(SCRIPT.is_file(), 'source preparation script is not implemented')
        spec = importlib.util.spec_from_file_location('prepare_sources', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        usage = shutil.disk_usage(self.project)
        marker = self.component / '.xdev-ext-source.json'
        before_marker = marker.read_bytes()
        with mock.patch.object(module.shutil, 'disk_usage', return_value=usage._replace(free=0)):
            with self.assertRaisesRegex(module.PreparationError, '[Ss]pace'):
                module.prepare(self.project, 'linux', self.base / 'cache')
        self.assertFalse((self.component / 'Makefile').exists())
        self.assertEqual(marker.read_bytes(), before_marker)

    def test_failed_fetch_does_not_fill_from_old_cache(self):
        self.assertEqual(self.run_prepare().returncode, 0)
        (self.component / 'missing.txt').unlink()
        self.upstream.rename(self.base / 'unavailable-upstream')
        result = self.run_prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse((self.component / 'missing.txt').exists())
        self.assertEqual((self.component / 'keep.txt').read_text(), 'project overlay\n')

    def test_annotated_tag_is_peeled_to_pinned_commit(self):
        git(self.upstream, 'tag', '-d', 'fixture-v1')
        git(self.upstream, 'tag', '-a', '-m', 'annotated fixture', 'fixture-v1')
        result = self.run_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.component / 'missing.txt').read_text(), 'fill me\n')

    def test_locally_modified_tracked_overlay_stays_untouched(self):
        (self.overlay / 'keep.txt').write_text('local overlay edit\n')
        (self.overlay / 'only-project.txt').write_text('project-only\n')
        git(self.project, 'add', 'src/core/only-project.txt')
        self.write_layout()
        result = self.run_prepare('--replace-base')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.component / 'keep.txt').read_text(), 'local overlay edit\n')
        self.assertEqual((self.component / 'only-project.txt').read_text(), 'project-only\n')

    def test_nvidia_component_and_offline_check(self):
        for name in ('kernel-open/Makefile', 'kernel-open/Kbuild'):
            path = self.upstream / name
            path.parent.mkdir(exist_ok=True)
            path.write_text('driver rules\n')
        git(self.upstream, 'add', '.')
        git(self.upstream, 'commit', '-qm', 'driver fixture')
        git(self.upstream, 'tag', '-f', 'fixture-v1')
        self.lock['components']['nvidia'] = dict(self.lock['components']['linux'],
            commit=git(self.upstream, 'rev-parse', 'HEAD'))
        self.write_lock()
        self.assertEqual(self.run_prepare(component='nvidia').returncode, 0)
        shutil.rmtree(self.upstream)
        result = self.run_prepare('--check', component='nvidia')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_symlink_chain_cannot_escape(self):
        self.assertTrue(SCRIPT.is_file(), 'source preparation script is not implemented')
        spec = importlib.util.spec_from_file_location('prepare_sources', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # Each target is lexically in-tree; the combination resolves outside.
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            for name, target in [('b', 'dir/a/../..'), ('dir/a', '..')]:
                entry = tarfile.TarInfo(name)
                entry.type, entry.linkname = tarfile.SYMTYPE, target
                archive.addfile(entry)
        raw.seek(0)
        with tarfile.open(fileobj=raw, mode='r|') as archive:
            with self.assertRaises(module.PreparationError):
                module.process_archive(archive, self.component, set(), False, False)

        (self.component / 'existing').symlink_to(self.base, target_is_directory=True)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            entry = tarfile.TarInfo('b')
            entry.type, entry.linkname = tarfile.SYMTYPE, 'existing'
            archive.addfile(entry)
        raw.seek(0)
        with tarfile.open(fileobj=raw, mode='r|') as archive:
            with self.assertRaises(module.PreparationError):
                module.process_archive(archive, self.component, set(), False, False)

    def test_safe_relative_symlink_is_filled(self):
        (self.upstream / 'link').symlink_to('missing.txt')
        git(self.upstream, 'add', 'link')
        git(self.upstream, 'commit', '-qm', 'safe symlink')
        git(self.upstream, 'tag', '-f', 'fixture-v1')
        self.lock['components']['linux']['commit'] = git(self.upstream, 'rev-parse', 'HEAD')
        self.write_lock()
        result = self.run_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(os.readlink(self.component / 'link'), 'missing.txt')


if __name__ == '__main__':
    unittest.main()
