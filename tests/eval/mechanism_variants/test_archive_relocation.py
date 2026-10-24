# SPDX-License-Identifier: GPL-2.0
"""Execute the production result-location expression through a real archive copy."""
import ast
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
class Archive(unittest.TestCase):
    def test_actual_result_bytes_remain_identical_after_evidence_relocation(self):
        path=HERE/'validate_e2.py'
        spec=importlib.util.spec_from_file_location('validate_e2',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        # Use the actual result field expression, rather than a test-side
        # replacement for the production metadata's location semantics.
        fields=[node.value for node in ast.walk(ast.parse(path.read_text()))
                if isinstance(node,ast.keyword) and node.arg=='capture_directory']
        self.assertEqual(len(fields),1)
        expression=compile(ast.fix_missing_locations(ast.Expression(fields[0])),str(path),'eval')
        with tempfile.TemporaryDirectory() as td:
            live=Path(td)/'live/evidence'; frozen=Path(td)/'frozen/evidence'
            (live/'e2-capture').mkdir(parents=True)
            def result(evidence):
                scope=dict(module.__dict__,capture=evidence/'e2-capture',evidence=evidence)
                return dict(capture_directory=eval(expression,scope),capture_sha256='a'*64,status='pass')
            module.write_derived(live/'e2-validation.json',result(live))
            shutil.copytree(live,frozen)
            original=(frozen/'e2-validation.json').read_bytes()
            module.write_derived(frozen/'e2-validation.json',result(frozen))
            self.assertEqual((frozen/'e2-validation.json').read_bytes(),original)
if __name__=='__main__':unittest.main()
