#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the policy campaign driver with the existing recording boundary."""
import importlib.util
from pathlib import Path
import unittest
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('matrix_contract',HERE.parent/'xdev_ext_integration/xdev_ext_mech_zc_matrix_test.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
class PolicyMatrix(unittest.TestCase):
 execute=base.MatrixCampaigns.execute
 def test_policy_cases_and_evidence(self):
  base.MATRIX=HERE/'matrix_policy_cases.sh'
  run,scratch,source,calls=self.execute()
  self.assertEqual(run.returncode,0,run.stderr)
  names=['window1','window8','every-n','delayed','exponential','oldest','round-robin']
  self.assertEqual(len(calls),7)
  self.assertEqual([c['args'][c['args'].index('--rel-policy')+1] for c in calls],names)
  self.assertEqual({p.name for p in (scratch/'policy-campaigns').iterdir()},set(names))
  self.assertIn('XDEV_EXT_REL_POLICY_MATRIX=PASS cases=7',run.stdout)
 def test_policy_failure_stops_and_keeps_evidence(self):
  base.MATRIX=HERE/'matrix_policy_cases.sh'
  run,scratch,source,calls=self.execute('none')
  self.assertEqual(run.returncode,7)
  self.assertEqual(len(calls),1)
  self.assertEqual((scratch/'policy-campaigns/window1/policy.exit').read_text(),'7\n')
  self.assertNotIn('MATRIX=PASS',run.stdout)
if __name__=='__main__':unittest.main(verbosity=2)
