#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Explicit offline assembly uses real pinned Git objects without transport."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
GIT = shutil.which('git')


class OfflineSources(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='xdev-offline-sources-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.project = self.base / 'project'
        self.donor = self.base / 'official-donor'
        self.cache = self.base / 'cache'
        for repo in (self.project, self.donor):
            repo.mkdir()
            self.git(repo, 'init', '-q')
            self.git(repo, 'config', 'user.name', 'Fixture')
            self.git(repo, 'config', 'user.email', 'fixture@example.invalid')
        for name in ('Makefile', 'Kconfig', 'scripts/Makefile.build',
                     'include/linux/types.h', 'base.txt', 'body.c'):
            self.write(self.donor / name, 'official ' + name + '\n')
        self.git(self.donor, 'add', '.')
        self.git(self.donor, 'commit', '-qm', 'official pin')
        self.pin = self.git(self.donor, 'rev-parse', 'HEAD')
        self.git(self.donor, 'tag', 'official-v1')
        self.write(self.project / 'src/core/body.c', 'authored body\n')
        self.write(self.project / 'source-layout.json', json.dumps(dict(schema=1, files=[
            dict(source='src/core/body.c', component='linux', native_path='body.c')])))
        self.lock = dict(schema=2, components={'linux': dict(
            url=self.donor.as_uri(), ref='refs/tags/official-v1', commit=self.pin)})
        self.write_lock()
        self.git(self.project, 'add', '.')
        self.git(self.project, 'commit', '-qm', 'authored overlay')
        for name in ('tools/build/prepare_sources.py', 'tools/layout.py'):
            self.write(self.project / name, (ROOT / name).read_text())
        self.output = self.project / 'build/assembled/linux'
        self.marker = self.output / '.xdev-ext-source.json'
        self.cache.mkdir()
        self.git(self.cache, 'clone', '--bare', '-q', str(self.donor), 'linux.git')
        self.repository = self.cache / 'linux.git'
        (self.repository / 'FETCH_HEAD').unlink(missing_ok=True)
        self.log = self.base / 'git-calls.jsonl'
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        wrapper = self.bin / 'git'
        self.write(wrapper, '#!' + sys.executable + '\n'
                   'import json, os, sys\n'
                   'args = sys.argv[1:]\n'
                   'if os.environ.get("GIT_NO_LAZY_FETCH") != "1":\n'
                   '    sys.stderr.write("offline object access must disable lazy fetch\\n")\n'
                   '    sys.exit(98)\n'
                   'with open(os.environ["GIT_CALL_LOG"], "a") as log:\n'
                   '    log.write(json.dumps(args) + "\\n")\n'
                   'if any(arg in {"fetch", "clone", "ls-remote", "remote", "submodule", "init"} for arg in args):\n'
                   '    sys.stderr.write("transport or cache creation forbidden in test\\n")\n'
                   '    sys.exit(97)\n'
                   'os.execv(' + repr(GIT) + ', [' + repr(GIT) + '] + args)\n')
        wrapper.chmod(0o755)

    @staticmethod
    def write(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    @staticmethod
    def git(repo, *args):
        return subprocess.check_output([GIT, '-C', str(repo), *args],
                                       stderr=subprocess.PIPE, text=True).strip()

    def write_lock(self):
        self.write(self.project / 'third_party/sources.lock.json', json.dumps(self.lock))

    def run_prepare(self, *args, forbid_transport=True):
        env = os.environ.copy()
        if forbid_transport:
            env.update(PATH=str(self.bin) + os.pathsep + env['PATH'], GIT_CALL_LOG=str(self.log))
        return subprocess.run([sys.executable, '-B', str(self.project / 'tools/build/prepare_sources.py'),
                               '--component', 'linux', '--cache', str(self.cache), *args],
                              cwd=self.project, env=env, capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    @staticmethod
    def snapshot(root):
        return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                for p in root.rglob('*') if p.is_file()}

    def test_offline_assembles_exact_pin_without_fetch_head_or_live_ref(self):
        # A cached ref may drift; only the locked full commit determines input.
        self.write(self.donor / 'base.txt', 'new upstream bytes\n')
        self.git(self.donor, 'add', '.')
        self.git(self.donor, 'commit', '-qm', 'ref drift')
        drift = self.git(self.donor, 'rev-parse', 'HEAD')
        self.git(self.repository, 'fetch', '-q', str(self.donor), 'HEAD')
        self.git(self.repository, 'update-ref', 'refs/tags/official-v1', drift)
        for fetch_head in (None, '', drift + '\t\twrong ref\n'):
            with self.subTest(fetch_head=fetch_head):
                if fetch_head is None:
                    (self.repository / 'FETCH_HEAD').unlink(missing_ok=True)
                else:
                    (self.repository / 'FETCH_HEAD').write_text(fetch_head)
                result = self.run_prepare('--offline')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.output / 'base.txt').read_text(), 'official base.txt\n')
                self.assertEqual((self.output / 'body.c').read_text(), 'authored body\n')
                marker = json.loads(self.marker.read_text())
                self.assertEqual(marker['commit'], self.pin)
                self.assertEqual(marker['source_transport'], 'local-cache-no-live-ref-check')
                self.assertIn('no live ref check', result.stdout)
        self.assertTrue(self.calls(), 'the real Git object/archive path must run')
        self.assertFalse(any('fetch' in call for call in self.calls()))

    def test_offline_missing_cache_fails_without_creating_or_writing(self):
        shutil.rmtree(self.cache)
        before = self.snapshot(self.project)
        result = self.run_prepare('--offline')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cache', result.stderr.lower())
        self.assertFalse(self.cache.exists())
        self.assertFalse(self.output.exists())
        self.assertEqual(self.snapshot(self.project), before)

    def test_offline_nonbare_cache_is_rejected_before_assembly(self):
        shutil.rmtree(self.repository)
        self.git(self.cache, 'clone', '-q', str(self.donor), 'linux.git')
        result = self.run_prepare('--offline')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('bare', result.stderr.lower())
        self.assertFalse(self.output.exists())

    def test_offline_absent_or_noncommit_pin_is_rejected_before_assembly(self):
        blob = self.git(self.repository, 'rev-parse', self.pin + ':base.txt')
        for invalid in ('0' * 40, blob):
            with self.subTest(pin=invalid):
                self.lock['components']['linux']['commit'] = invalid
                self.write_lock()
                before = self.snapshot(self.project)
                result = self.run_prepare('--offline')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('cached commit', result.stderr.lower())
                self.assertFalse(self.output.exists())
                self.assertEqual(self.snapshot(self.project), before)

    def test_check_is_readonly_with_old_and_offline_markers_without_cache(self):
        result = self.run_prepare('--offline')
        self.assertEqual(result.returncode, 0, result.stderr)
        shutil.rmtree(self.cache)
        for old_marker in (False, True):
            with self.subTest(old_marker=old_marker):
                if old_marker:
                    marker = json.loads(self.marker.read_text())
                    marker.pop('source_transport')
                    self.marker.write_text(json.dumps(marker))
                before = self.snapshot(self.project)
                self.log.unlink(missing_ok=True)
                result = self.run_prepare('--offline', '--check')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.snapshot(self.project), before)
                self.assertFalse(self.cache.exists())
                self.assertEqual(self.calls(), [])

    def test_default_online_fetches_and_rejects_ref_drift_despite_cached_pin(self):
        result = self.run_prepare(forbid_transport=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('source_transport', json.loads(self.marker.read_text()))
        before = self.snapshot(self.output)
        self.write(self.donor / 'base.txt', 'new upstream bytes\n')
        self.git(self.donor, 'add', '.')
        self.git(self.donor, 'commit', '-qm', 'official ref drift')
        self.git(self.donor, 'tag', '-f', 'official-v1')
        result = self.run_prepare(forbid_transport=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Pinned commit mismatch', result.stderr)
        self.assertEqual(self.snapshot(self.output), before)


if __name__ == '__main__':
    unittest.main()
