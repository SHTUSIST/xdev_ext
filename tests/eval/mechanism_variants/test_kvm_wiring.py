# SPDX-License-Identifier: GPL-2.0
"""Actual shell option refusal paths, no KVM execution claim."""
from pathlib import Path
import subprocess
import unittest
HERE=Path(__file__).resolve().parent
HARNESS=HERE.parents[2]/'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'
class Wiring(unittest.TestCase):
    def test_mode_refuses_other_campaigns_before_touching_scratch(self):
        for args in (['--ce-sim'],['--compat'],['--reliable'],['--fault','drop-middle'],['--groups','257']):
            run=subprocess.run(['bash',str(HARNESS),'--mechanism-variants',*args],capture_output=True,text=True)
            self.assertEqual(run.returncode,2)
            self.assertIn('mechanism-variants',run.stderr)
            self.assertNotIn('unknown option',run.stderr)
    def test_timeout_requires_dedicated_mode(self):
        run=subprocess.run(['bash',str(HARNESS),'--mechanism-variants-timeout','300'],capture_output=True,text=True)
        self.assertEqual(run.returncode,2)
        self.assertIn('requires --mechanism-variants',run.stderr)
if __name__=='__main__': unittest.main()
