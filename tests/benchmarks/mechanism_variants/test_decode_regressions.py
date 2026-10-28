#!/usr/bin/env python3
"""Independent synthetic fail-closed assertions against frozen 1a0341e."""
from pathlib import Path
import sys
import unittest
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import decode_trace as d
import test_decode as fixture
row=fixture.row

class Counterexamples(unittest.TestCase):
    def test_u64_ticket_overflow_is_rejected(self):
        raw=self.positive().replace("ticket=10", "ticket=18446744073709551616")
        with self.assertRaises(ValueError): d.decode(raw,"nvme_nic")

    def positive(self): return fixture.Decode().positive()
    def test_unrelated_session_is_explicitly_excluded_and_recorded(self):
        audit={}
        other=row('unknown_failure_phase',8,1,10,4096,status=-5,ts=70).replace('session_id=7','session_id=99')
        events=d.decode(self.positive()+'\n'+other,'nvme_nic',session_id=7,audit=audit)
        self.assertEqual(len(events),5)
        self.assertEqual(audit['excluded'][-1]['session_id'],99)
    def test_known_successful_diagnostic_is_retained_in_audit(self):
        audit={}
        diagnostic=row('descriptor_bind',8,2,11,9000,stage=1,ts=35)
        d.decode(self.positive()+'\n'+diagnostic,'nvme_nic',session_id=7,audit=audit)
        self.assertEqual(audit['excluded'][-1]['phase'],'descriptor_bind')
    def test_rejected_plan_rows_must_describe_one_same_plan(self):
        raw='\n'.join(row('class_validate',i,0,0,0,status=-34,ts=i+1) for i in (8,9))
        with self.assertRaises(ValueError): d.decode_negative(raw.replace('address=2080','address=9999',1))
    def test_validation_logical_key_cannot_change_before_acceptance(self):
        raw='\n'.join(line.replace('batch_key=1','batch_key=999') if 'phase=class_validate ' in line else line for line in self.positive().splitlines())
        with self.assertRaises(ValueError): d.decode(raw,'nvme_nic')

    def test_unknown_kernel_phase_is_rejected(self):
        raw=self.positive()+'\n'+row('unknown_failure_phase',8,1,10,4096,status=-5,ts=70)
        with self.assertRaises(ValueError): d.decode(raw,'nvme_nic')
    def test_failed_downstream_native_submit_is_rejected(self):
        raw=self.positive()+'\n'+row('native_submit',8,2,11,0,stage=1,status=-5,ts=35)
        with self.assertRaises(ValueError): d.decode(raw,'nvme_nic')
    def test_native_completion_span_must_match_accept(self):
        lines=self.positive().splitlines()
        raw='\n'.join(l.replace('address=2080','address=9999').replace('bytes=4096','bytes=512') if 'phase=native_complete ' in l else l for l in lines)
        with self.assertRaises(ValueError): d.decode(raw,'nvme_nic')
    def test_native_completion_logical_key_must_match_accept(self):
        raw='\n'.join(l.replace('batch_key=1','batch_key=999') if 'phase=native_complete ' in l else l for l in self.positive().splitlines())
        with self.assertRaises(ValueError): d.decode(raw,'nvme_nic')
    def test_negative_rejection_cannot_be_at_non_nvme_stage(self):
        raw='\n'.join(row('class_validate',i,0,0,0,status=-34,ts=i+1).replace('stage=0','stage=1') for i in (8,9))
        with self.assertRaises(ValueError): d.decode_negative(raw)
    def test_negative_duplicate_validation_row_is_rejected(self):
        raw='\n'.join(row('class_validate',i,0,0,0,status=-34,ts=i+1) for i in (8,9))
        with self.assertRaises(ValueError): d.decode_negative(raw+'\n'+raw.splitlines()[0])
    def test_overflowed_u64_native_identity_is_rejected(self):
        raw=self.positive().replace("ticket=10", "ticket=18446744073709551626")
        with self.assertRaises(ValueError): d.decode(raw,"nvme_nic")
    def test_incomplete_loss_statistics_is_rejected(self):
        fmt='xdev-native-v1-nvme-xsk-batch u64 ticket; u64 cookie; u64 generation; u64 ts_ns;'
        with self.assertRaises(ValueError): d.audit_collection(fmt,'overrun: 0\n')
if __name__=='__main__': unittest.main(verbosity=2)
