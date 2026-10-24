# SPDX-License-Identifier: GPL-2.0
"""Regression counterparts of the independent three native-identity probes."""
import unittest
import test_driver_audit as fixture
import driver_audit as driver
class Identity(unittest.TestCase):
    def test_unbound_terminal_frame_cannot_pass_native_audit(self):
        extra=fixture.row('downstream_complete',9,2,11,0,stage=1,ts=41)
        with self.assertRaises(ValueError):driver.audit(fixture.Driver().positive()+'\n'+extra,7)
    def test_binding_ticket_matches_terminal_operation(self):
        with self.assertRaises(ValueError):driver.audit(fixture.Driver().positive().replace('ticket=11','ticket=99',1),7)
    def test_binding_generation_matches_terminal_operation(self):
        with self.assertRaises(ValueError):driver.audit(fixture.Driver().positive().replace('generation=2','generation=99',1),7)
    def test_binding_frame_belongs_to_terminal_cohort(self):
        with self.assertRaises(ValueError):driver.audit(fixture.Driver().positive().replace('frame_id=8','frame_id=99',1),7)
if __name__=='__main__':unittest.main(verbosity=2)
