# SPDX-License-Identifier: GPL-2.0
"""Synthetic pool/descriptor correlation selfchecks, not NIC execution."""
import importlib.util
from pathlib import Path
import unittest
from test_decode import row
HERE=Path(__file__).resolve().parent
class Driver(unittest.TestCase):
    def setUp(self):
        self.assertTrue((HERE/'driver_audit.py').is_file(),'session-zero native driver audit missing')
        spec=importlib.util.spec_from_file_location('driver_audit',HERE/'driver_audit.py')
        self.d=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.d)
    def positive(self):
        bind=row('descriptor_bind',8,2,11,9000,stage=1,ts=10)
        submit=row('native_submit',0,0,0,9000,stage=0,ts=20).replace('session_id=7','session_id=0').replace('class_id=3','class_id=2').replace('sequence=0','sequence=1')
        complete=submit.replace('phase=native_submit','phase=native_complete').replace('ts_ns=20','ts_ns=30')
        end=row('downstream_complete',8,2,11,0,stage=1,ts=40)
        return '\n'.join((bind,submit,complete,end))
    def test_pool_binding_attaches_zero_session_to_actual_record(self):
        result=self.d.audit(self.positive(),7)
        self.assertEqual(result['native_submits'],1);self.assertEqual(result['native_completes'],1)
        self.assertEqual(result['bindings'][0]['batch_id'],1)
    def test_failed_actual_pool_row_cannot_hide_as_unrelated_session(self):
        raw=self.positive()
        for corrupt in (raw.replace('phase=native_complete','phase=trace_invalid'),
                        raw.replace('ts_ns=30','ts_ns=30').replace('status=0 cookie=9000 address=2080 bytes=4096 aux=1794 sequence=1 ts_ns=30','status=-5 cookie=9000 address=2080 bytes=4096 aux=1794 sequence=1 ts_ns=30'),
                        raw.replace('phase=native_complete','phase=unexpected_driver_phase'),
                        raw.replace('address=2080 bytes=4096 aux=1794 sequence=1 ts_ns=30','address=9999 bytes=512 aux=1794 sequence=1 ts_ns=30'),
                        raw+'\n'+raw.splitlines()[1]):
            with self.subTest(corrupt=corrupt[-80:]),self.assertRaises(ValueError): self.d.audit(corrupt,7)
    def test_other_pool_failure_is_excluded_with_actual_raw_receipt(self):
        raw=self.positive()+'\n'+row('trace_invalid',0,0,0,1234,stage=0,status=-5,ts=50).replace('session_id=7','session_id=0').replace('class_id=3','class_id=2')
        result=self.d.audit(raw,7)
        self.assertTrue(result['excluded_other_pool_rows'])
if __name__=='__main__':unittest.main()
