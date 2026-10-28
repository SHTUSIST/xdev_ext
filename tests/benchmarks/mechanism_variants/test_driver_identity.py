# SPDX-License-Identifier: GPL-2.0
"""Regression counterparts of the independent three native-identity probes."""
import unittest
import test_driver_audit as fixture
import driver_audit as driver
class Identity(unittest.TestCase):
    def test_unbound_terminal_frame_cannot_pass_native_audit(self):
        extra=fixture.row('downstream_complete',9,2,11,0,stage=1,ts=41)
        with self.assertRaises(ValueError):driver.audit(fixture.Driver().positive()+'\n'+extra,7)
    def test_duplicate_binding_cannot_authorize_second_native_submission(self):
        lines=fixture.Driver().positive().splitlines()
        second_bind=lines[0].replace('ts_ns=10','ts_ns=11')
        second_submit=lines[1].replace('sequence=1','sequence=2').replace('ts_ns=20','ts_ns=21')
        second_complete=lines[2].replace('sequence=1','sequence=2').replace('ts_ns=30','ts_ns=31')
        duplicate='\n'.join(lines+[second_bind,second_submit,second_complete])
        # A separate frame legitimately shares its batch's ticket/pool/claim.
        distinct='\n'.join(lines+[
            second_bind.replace('frame_id=8','frame_id=9').replace('address=32774','address=36870'),
            second_submit.replace('address=32774','address=36870'),
            second_complete.replace('address=32774','address=36870'),
            lines[3].replace('frame_id=8','frame_id=9').replace('address=32856','address=36952').replace('ts_ns=40','ts_ns=41')])
        self.assertEqual(driver.audit(distinct,7)['native_submits'],2)
        with self.assertRaises(ValueError):driver.audit(duplicate,7)
    def test_binding_ticket_matches_terminal_operation(self):
        with self.assertRaises(ValueError):driver.audit(fixture.Driver().positive().replace('ticket=11','ticket=99',1),7)
    def test_binding_generation_matches_terminal_operation(self):
        with self.assertRaises(ValueError):driver.audit(fixture.Driver().positive().replace('generation=2','generation=99',1),7)
    def test_binding_frame_belongs_to_terminal_cohort(self):
        with self.assertRaises(ValueError):driver.audit(fixture.Driver().positive().replace('frame_id=8','frame_id=99',1),7)
if __name__=='__main__':unittest.main(verbosity=2)
