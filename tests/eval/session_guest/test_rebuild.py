#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build actual guest artifacts twice; header changes must not reuse old code.

No guest, device or arm execution. The private source copy changes only the
mechanism ABI define; the BPF struct_ops data must expose the new value.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
HARNESS = REPO/'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'
FILES = ('chain_bench', 'chain_plan.bpf.o', 'session_nvme_ce', 'session_gpu_nic',
         'eval_session_oracle', 'xdev_ext_eval_session_guest.sh')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(path, files):
    path.write_text(''.join(digest(f)+'  '+str(f)+'\n' for f in files))


class GuestRebuild(unittest.TestCase):
    def test_header_only_abi_change_rebuilds_nested_binary_and_bpf(self):
        with tempfile.TemporaryDirectory(prefix='.rebuild-', dir=HERE) as directory:
            base = Path(directory)
            source, output, identity = (base/n for n in ('source', 'output', 'identity'))
            source.mkdir(); identity.mkdir()
            # Copy tracked code only: prepared upstream sources, build outputs
            # and the caller's evidence are not inputs to this regression.
            tracked = subprocess.check_output(['git', '-C', str(REPO), 'ls-files', '-z',
                                                '--', 'kernel', 'tests/eval']).split(b'\0')
            for raw in filter(None, tracked):
                relative = os.fsdecode(raw)
                destination = source/relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO/relative, destination)
            command = ['make', '-C', str(source/'tests/eval/session_guest'), 'guest',
                       'GUEST_OUT='+str(output), 'CC='+os.environ.get('CC', 'cc'),
                       'CLANG='+os.environ.get('CLANG', 'clang')]
            for setting in ('LIBBPF_CFLAGS', 'LIBBPF_LIBS'):
                if setting in os.environ:
                    command.append(setting+'='+os.environ[setting])

            def build():
                result = subprocess.run(command, capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

            def bpf_abi():
                dumped = subprocess.run(['readelf', '-x', '.struct_ops.link',
                                         str(output/'chain_plan.bpf.o')],
                                        capture_output=True, text=True, check=True)
                row = re.search(r'^\s*0x[0-9a-f]+\s+([0-9a-f]{8})', dumped.stdout, re.M)
                self.assertIsNotNone(row, dumped.stdout)
                return struct.unpack('<I', bytes.fromhex(row.group(1)))[0]

            build()
            before = {name: digest(output/name) for name in FILES[:2]}
            self.assertEqual(bpf_abi(), 1)
            header = source/'kernel/include/uapi/linux/xdev_ext_mech.h'
            original = header.read_text()
            changed, count = re.subn(r'(#define XDEV_EXT_MECH_ABI_VERSION\s+)1U\b',
                                     r'\g<1>2U', original)
            self.assertEqual(count, 1, 'regression requires the actual ABI 1 define')
            header.write_text(changed)
            build()
            reused = {name: digest(output/name) for name in FILES[:2]}
            for name in FILES[:2]:
                with self.subTest(artifact=name):
                    self.assertNotEqual(before[name], reused[name],
                                        name+' reused ABI 1 after the source changed to ABI 2')
            self.assertEqual(bpf_abi(), 2, 'actual compiled struct_ops still has the old ABI')

            # Reproduce the reviewer's identity setup: its newly recorded
            # manifest may be accepted only after actual objects are current.
            subprocess.run(['git', 'init', '-q', str(source)], check=True)
            subprocess.run(['git', '-C', str(source), 'add', '--', 'kernel', 'tests/eval'], check=True)
            symbols = ('MODULES', 'MODULE_UNLOAD', 'XDEV_EXT_MECH', 'XDEV_EXT_MECH_ZEROCOPY',
                       'XDEV_EXT_MECH_CE', 'XDEV_EXT_MECH_DMA', 'XDEV_EXT_MECH_IAA',
                       'CRYPTO_ACOMP2', 'CRYPTO_DEFLATE')
            (identity/'.config').write_text(''.join('CONFIG_'+s+'=y\n' for s in symbols))
            mode = identity/'xdev-ext-eval-session-mode.txt'
            mode.write_text('eval_session=1\n')
            text = HARNESS.read_text()

            def function(name):
                match = re.search(r'^'+name+r'\(\) \{\n.*?^\}', text, re.M | re.S)
                self.assertIsNotNone(match)
                return match.group()

            env = dict(os.environ, SOURCE_GIT_ROOT=str(source), BUILD=str(identity),
                       EVAL_SESSION_OUT=str(output), EVAL_SESSION_VALIDATOR=str(
                           source/'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_eval_session_validate.py'))
            recorded = subprocess.run(['bash', '-euo', 'pipefail', '-c',
                                       function('record_eval_session_sources')+'\nrecord_eval_session_sources'],
                                      env=env, capture_output=True, text=True)
            self.assertEqual(recorded.returncode, 0, recorded.stdout+recorded.stderr)
            manifest(identity/'xdev-ext-artifacts.sha256', [output/n for n in FILES]+[
                mode, identity/'xdev-ext-eval-session-source.sha256', Path(env['EVAL_SESSION_VALIDATOR'])])
            checked = subprocess.run(['bash', '-euo', 'pipefail', '-c',
                                      function('verify_eval_session_identity')+'\nverify_eval_session_identity'],
                                     env=env, capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stdout+checked.stderr)

            # The same build after removing the two nested outputs must give
            # identical code; no recorded receipt substitutes for rebuilding.
            for name in FILES[:2]:
                (output/'chains'/name).unlink()
            build()
            fresh = {name: digest(output/name) for name in FILES[:2]}
            self.assertEqual(reused, fresh)


if __name__ == '__main__':
    unittest.main(verbosity=2)
