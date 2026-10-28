#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Userspace must select project ABI without exporting raw kernel Linux headers.

Plan: copy only the real project/io_uring headers and userspace sources into a
private tree, poison its raw linux/types.h, run the actual guest Makefile and
actual epoch fixture with GCC, and inspect included project header bytes. The
SDK builder and CUDA-dependent fixture use an explicit source search-argument
contract, not a synthetic CUDA SDK or a claim of SDK compilation.

A whole raw kernel UAPI -I would let unexported types/fs/stddef replace libc's
exported Linux headers. A narrowed export or quoted project-only lookup must
continue to select the actual xdev/io_uring ABI with -Werror enabled.
"""
import ast
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
GUEST = ROOT / 'kernel/tools/testing/selftests/xdev_ext_peer/guest'
ABI_HEADERS = ('xdev_ext_peer.h', 'xdev_ext_mech.h', 'xdev_ext_policy.h',
               'xdev_ext_binding.h', 'io_uring.h')


class UapiSearch(unittest.TestCase):
    def private_tree(self):
        temporary = tempfile.TemporaryDirectory(prefix='uapi-search-', dir=ROOT.parent)
        self.addCleanup(temporary.cleanup)
        tree = Path(temporary.name)
        source = tree / 'tests/eval/xdomain'
        source.mkdir(parents=True)
        for path in HERE.iterdir():
            if path.is_file() and path.suffix in ('.c', '.h', '.cc', '.py'):
                shutil.copyfile(path, source / path.name)
        headers = tree / 'kernel/include/uapi/linux'
        headers.mkdir(parents=True)
        for name in ABI_HEADERS:
            shutil.copyfile(ROOT / 'kernel/include/uapi/linux' / name, headers / name)
        # The complete prepared tree has many unrelated unexported headers.
        # This representative header must never enter the userspace search.
        (headers / 'types.h').write_text('#error RAW_KERNEL_UAPI_TYPES_MUST_NOT_SHADOW_SYSTEM\n')
        guest = tree / 'kernel/tools/testing/selftests/xdev_ext_peer/guest'
        guest.mkdir(parents=True)
        for name in ('Makefile', 'peer_session_e2e.c', 'sw_provider_uapi.h'):
            shutil.copyfile(GUEST / name, guest / name)
        return tree, source, guest

    def run_command(self, command, **kwargs):
        result = subprocess.run(list(map(str, command)), capture_output=True,
                                text=True, timeout=60, **kwargs)
        self.assertEqual(result.returncode, 0,
                         'actual GCC build must isolate raw kernel UAPI:\n' +
                         result.stdout + result.stderr)
        self.assertNotIn('RAW_KERNEL_UAPI_TYPES_MUST_NOT_SHADOW_SYSTEM',
                         result.stdout + result.stderr)
        return result

    def test_guest_makefile_builds_real_epoch_helper_with_only_project_abi(self):
        tree, source, guest = self.private_tree()
        result = self.run_command([
            'make', '-C', guest, 'peer_session_e2e', 'CC=gcc',
            'CFLAGS=-O1 -g -std=gnu11 -Wall -Wextra -Werror -H',
            'KERNEL_SRC=' + str(tree / 'kernel'),
            'EPOCH_HELPER_DIR=' + str(source)])
        self.assertTrue((guest / 'peer_session_e2e').is_file())
        included = []
        for line in result.stderr.splitlines():
            match = re.match(r'^\.+ (.+)$', line)
            if match:
                path = Path(match[1])
                if not path.is_absolute():
                    path = guest / path
                if path.is_file():
                    included.append(path)
        for name in ABI_HEADERS:
            candidates = [path for path in included if path.name == name]
            expected = (ROOT / 'kernel/include/uapi/linux' / name).read_bytes()
            self.assertTrue(any(path.read_bytes() == expected for path in candidates),
                            'GCC must use actual project ABI bytes: ' + name)

    def test_actual_epoch_fixture_compiles_and_runs_in_prepared_tree(self):
        _, source, _ = self.private_tree()
        self.run_command([sys.executable, '-I', source / 'test_epoch_control.py'],
                         env={**os.environ, 'HOST_CC': 'gcc'})

    def test_all_userspace_entrypoints_exclude_raw_uapi_from_angle_search(self):
        # Explicit source wiring contract for SDK/CUDA entries unavailable on
        # this host. Trace the argument expression and its local path bindings;
        # do not require a particular export-directory or variable spelling.
        for filename in ('build.py', 'test_epoch_control.py', 'test_stop_report.py',
                         'test_owner_close.py'):
            with self.subTest(entrypoint=filename):
                syntax = ast.parse((HERE / filename).read_text())
                bindings = {}
                for node in ast.walk(syntax):
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                bindings[target.id] = node.value

                def raw_path(node, seen=frozenset()):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str):
                        return node.value.rstrip('/').endswith('kernel/include/uapi')
                    if isinstance(node, ast.Name) and node.id in bindings and node.id not in seen:
                        return raw_path(bindings[node.id], seen | {node.id})
                    return any(raw_path(child, seen) for child in ast.iter_child_nodes(node))

                unsafe = []
                for node in ast.walk(syntax):
                    if not isinstance(node, (ast.List, ast.Tuple)):
                        continue
                    for index, item in enumerate(node.elts):
                        if isinstance(item, ast.Constant) and item.value in ('-I', '-isystem'):
                            if index + 1 < len(node.elts) and raw_path(node.elts[index + 1]):
                                unsafe.append(item.lineno)
                        if (isinstance(item, ast.BinOp) and isinstance(item.op, ast.Add)
                                and isinstance(item.left, ast.Constant)
                                and item.left.value in ('-I', '-isystem') and raw_path(item.right)):
                            unsafe.append(item.lineno)
                self.assertFalse(unsafe, filename + ': raw unexported UAPI reaches system-header search at ' + str(unsafe))
                # No suppression may replace isolation from the raw tree.
                forbidden = ('-Wno-error', '-D__EXPORTED_HEADERS__', '-D__EXPORTED_HEADERS')
                strings = [node.value for node in ast.walk(syntax)
                           if isinstance(node, ast.Constant) and isinstance(node.value, str)]
                self.assertFalse(any(flag in value for flag in forbidden for value in strings),
                                 filename + ': header contamination was suppressed instead of isolated')


if __name__ == '__main__':
    unittest.main(verbosity=2)
