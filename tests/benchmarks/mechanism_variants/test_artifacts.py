# SPDX-License-Identifier: GPL-2.0
"""Host transport corruption selfchecks, never guest/provider evidence."""
import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
HERE=Path(__file__).resolve().parent

class Artifacts(unittest.TestCase):
    def setUp(self):
        path=HERE/'artifacts.py'
        self.assertTrue(path.is_file(),'bounded artifact extractor missing')
        spec=importlib.util.spec_from_file_location('artifacts',path)
        self.module=importlib.util.module_from_spec(spec); spec.loader.exec_module(self.module)
    def exported(self,root):
        (root/'source-window.bin').write_bytes(bytes(range(256)))
        (root/'raw.trace').write_text('actual artifact transport fixture, no guest claim\n')
        env=dict(os.environ,E2_PRIVATE_GUEST='yes')
        result=subprocess.run(['sh',str(HERE/'export_artifacts.sh'),str(root)],env=env,
                              text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        return result.stdout
    def test_real_export_roundtrip_and_corruptions_reject(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/'source'; source.mkdir()
            wire=self.exported(source)
            self.module.extract(wire,root/'output')
            self.assertEqual((root/'output/source-window.bin').read_bytes(),bytes(range(256)))
            variants=[wire.replace('name=source-window.bin','name=../escape'),
                      wire.replace('E2_ARTIFACT_END name=source-window.bin',''),
                      wire.replace('E2_ARTIFACT_SET_END','BROKEN_SET_END'),
                      wire+wire,
                      wire.replace('E2_ARTIFACT_DATA AAECAw','E2_ARTIFACT_DATA BAECAw',1)]
            for i,bad in enumerate(variants):
                with self.subTest(case=i),self.assertRaises(ValueError):
                    self.module.extract(bad,root/f'bad{i}')
    def test_reject_missing_total_and_duplicate_file(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/'source'; source.mkdir(); wire=self.exported(source)
            first=wire[wire.index('E2_ARTIFACT_BEGIN'):wire.index('E2_ARTIFACT_END')]
            with self.assertRaises(ValueError): self.module.extract(first,root/'missing')
            with self.assertRaises(ValueError): self.module.extract(wire.replace('E2_ARTIFACT_SET_END',first+'E2_ARTIFACT_SET_END'),root/'duplicate')
class StrictArtifacts(unittest.TestCase):
    setUp = Artifacts.setUp
    exported = Artifacts.exported
    def strict_extract(self, wire, out):
        import inspect
        parameters=inspect.signature(self.module.extract).parameters
        if 'strict' not in parameters:
            # Run the old real parser too: RED must expose accepted pollution,
            # rather than stop at an absent keyword/TypeError.
            self.module.extract(wire,out)
            self.fail('dedicated transport accepted without strict extraction support')
        self.assertIs(parameters['strict'].default,False,
                      'legacy serial compatibility must remain the default')
        return self.module.extract(wire, out, strict=True)

    def test_strict_complete_set_and_serial_compatibility(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/'source'; source.mkdir(); wire=self.exported(source)
            self.strict_extract(wire,root/'strict')
            self.assertEqual((root/'strict/source-window.bin').read_bytes(), bytes(range(256)))
            self.module.extract('ordinary console before\n'+wire+'ordinary console after\n', root/'compat')

    def test_strict_rejects_all_nonprotocol_bytes_without_output(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/'source'; source.mkdir(); wire=self.exported(source)
            first_data=wire.index('E2_ARTIFACT_DATA')
            variants = {
                'prefix': 'Linux boot\n'+wire,
                'within': wire[:first_data]+'rcu: INFO: rcu_preempt detected stalls on CPUs/tasks\n'+wire[first_data:],
                'suffix': wire+'trailing garbage\n',
                'blank': wire+'\n',
                'non-ascii': wire+'\u00ff\n',
                'empty': '',
            }
            for name,bad in variants.items():
                with self.subTest(case=name):
                    output=root/name
                    with self.assertRaises(ValueError): self.strict_extract(bad,output)
                    self.assertFalse(output.exists())

    def test_strict_preserves_all_corruption_manifest_and_limit_refusals(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/'source'; source.mkdir(); wire=self.exported(source)
            # All mutations operate on a real exporter result; the decoder is
            # never replaced and no expected digest is computed by it.
            first=wire[:wire.index('E2_ARTIFACT_END')]
            variants={
                'truncated': wire[:wire.rindex('E2_ARTIFACT_SET_END')],
                'hash': wire.replace('E2_ARTIFACT_DATA AAECAw', 'E2_ARTIFACT_DATA BAECAw', 1),
                'duplicate': wire+wire,
                'missing-end': first,
                'oversize': wire.replace('name=source-window.bin bytes=256 ', 'name=source-window.bin bytes=8388609 '),
                'path': wire.replace('name=source-window.bin', 'name=../escape'),
                'manifest-name': wire.replace('name=raw.trace', 'name=unlisted.trace'),
                'set-count': wire.replace('E2_ARTIFACT_SET_END files=3 ', 'E2_ARTIFACT_SET_END files=2 '),
                'extra-data': wire+'E2_ARTIFACT_DATA AA==\n',
            }
            for name,bad in variants.items():
                with self.subTest(case=name):
                    output=root/name
                    with self.assertRaises(ValueError): self.strict_extract(bad, output)
                    self.assertFalse(output.exists())

    def framed_fixture(self, payloads, manifest):
        import base64
        import hashlib
        import textwrap
        # Independent wire fixture generation, not the production encoder or
        # decoder. Used only to reach manifest checks with valid outer hashes.
        payloads=dict(payloads, **{'export.manifest':manifest})
        frames=[]
        for name,data in payloads.items():
            digest=hashlib.sha256(data).hexdigest()
            frames.append(f'E2_ARTIFACT_BEGIN name={name} bytes={len(data)} sha256={digest}\n')
            frames.extend('E2_ARTIFACT_DATA '+line+'\n' for line in
                          textwrap.wrap(base64.b64encode(data).decode('ascii'),76))
            frames.append('E2_ARTIFACT_END name='+name+'\n')
        frames.append(f'E2_ARTIFACT_SET_END files={len(payloads)} bytes={sum(map(len,payloads.values()))} '
                      f'manifest_sha256={hashlib.sha256(manifest).hexdigest()}\n')
        return ''.join(frames)

    def test_strict_checks_manifest_content_even_with_valid_outer_hashes(self):
        import hashlib
        payload={'a.bin':b'host transport fixture'}
        digest=hashlib.sha256(payload['a.bin']).hexdigest()
        entry=f'a.bin 22 {digest}\n'
        manifests={
            'unlisted':b'',
            'missing-file':(entry+f'absent.bin 0 {digest}\n').encode(),
            'duplicate-entry':(entry+entry).encode(),
            'wrong-size':f'a.bin 23 {digest}\n'.encode(),
            'wrong-digest':('a.bin 22 '+'0'*64+'\n').encode(),
            'unsafe-path':f'../a.bin 22 {digest}\n'.encode(),
            'self-entry':(entry+f'export.manifest 0 {digest}\n').encode(),
        }
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for name,manifest in manifests.items():
                with self.subTest(case=name):
                    with self.assertRaises(ValueError):
                        self.strict_extract(self.framed_fixture(payload,manifest),root/name)
                    self.assertFalse((root/name).exists())

    def test_strict_file_count_limit_cannot_be_bypassed_by_empty_files(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            payload={f'f{i}.bin':b'' for i in range(97)}
            wire=self.framed_fixture(payload,b'')
            with self.assertRaises(ValueError): self.strict_extract(wire,root/'capture')
            self.assertFalse((root/'capture').exists())

if __name__=='__main__': unittest.main()
