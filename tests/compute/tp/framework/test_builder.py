# SPDX-License-Identifier: GPL-2.0
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
BUILDER = ROOT / 'tools/build/tp_framework.py'


class BuildEntryTests(unittest.TestCase):
    def test_real_dependency_build_entry_exists(self):
        self.assertTrue(BUILDER.is_file(), 'real ATen Driver-only build entry absent')

    def load(self):
        self.assertTrue(BUILDER.is_file(), 'real ATen Driver-only build entry absent')
        spec = importlib.util.spec_from_file_location('tp_framework_builder', BUILDER)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_cpp_inventory_excludes_cuda_runtime_compilation(self):
        module = self.load()
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            p = Path(directory); (p/'include').mkdir()
            (p/'include/cuda.h').write_text('/* unit fixture header, no SDK evidence */')
            (p/'libxdev_tp.so').write_bytes(b'\x7fELF' + bytes(60))
            config = module.build_configuration(ROOT, p, p/'libxdev_tp.so')
            self.assertEqual(config['sources'], [str(ROOT/'src/compute/torch/bridge.cc')])
            self.assertFalse(any(s.endswith('.cu') for s in config['sources']))
            self.assertIn(str(p/'include'), config['include_dirs'])
            self.assertEqual(config['include_dirs'][0],
                str(ROOT/'build/source-view/kernel/tools/xdev_ext_mech/lib'))
            self.assertEqual(config['extra_objects'], [str(p/'libxdev_tp.so')])
            self.assertEqual(config['libraries'], ['cuda'])
            self.assertFalse(config['runtime_library_dirs'])

    def test_missing_official_header_fails_closed(self):
        module = self.load()
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            p = Path(directory)
            with self.assertRaises(FileNotFoundError):
                module.build_configuration(ROOT, p, p/'missing.so')

    def test_mismatched_torch_version_is_rejected(self):
        module = self.load()
        with self.assertRaises(RuntimeError): module.validate_torch_version('2.9.0+cu130')
        module.validate_torch_version('2.8.0+cu128')

if __name__ == '__main__': unittest.main(verbosity=2)
