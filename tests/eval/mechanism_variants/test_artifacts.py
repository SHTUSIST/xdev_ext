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
if __name__=='__main__': unittest.main()
