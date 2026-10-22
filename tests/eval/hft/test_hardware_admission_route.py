#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Legacy correctness entry cannot initiate a physical workload or weak gate."""
import sys
import unittest
from unittest import mock

import run as runner


class CentralAdmissionRouteTests(unittest.TestCase):
    def test_legacy_session_and_raw_baselines_refuse_before_gate_artifacts_or_io(self):
        provision=['--source-block','/dev/fixture-nvme','--source-ng','/dev/fixture-ng',
            '--slba','8','--nlb','4096','--ifname','fixture0','--queue','0',
            '--local-ip','192.0.2.1','--peer-ip','192.0.2.2',
            '--local-mac','02:00:00:00:00:01','--peer-mac','02:00:00:00:00:02',
            '--local-port','19000','--peer-port','19001','--bpf-object','fixture.bpf.o',
            '--kernel-config','fixture.config']
        for backend in ('session','posix','uring-fixed-zc'):
            with self.subTest(backend=backend):
                with mock.patch.object(sys,'argv',['run.py','--backend',backend,*provision]):
                    args,profile=runner.parse()
                def forbidden(*_args,**_kwargs):
                    raise AssertionError('legacy physical route reached weak gate or workload')
                with mock.patch.object(runner,'native_gate',side_effect=forbidden,create=True), \
                     mock.patch.object(runner.socket,'socket',side_effect=forbidden), \
                     mock.patch.object(runner.subprocess,'Popen',side_effect=forbidden), \
                     mock.patch.object(runner.subprocess,'run',side_effect=forbidden), \
                     mock.patch.object(runner.tempfile,'TemporaryDirectory',side_effect=forbidden), \
                     mock.patch.object(runner.oracle,'generate',side_effect=forbidden):
                    with self.assertRaises(runner.Failure) as raised:
                        runner.execute(args,profile)
                self.assertEqual(raised.exception.code,4)
                self.assertIn('hardware_measure.py',raised.exception.message)


if __name__=='__main__':unittest.main()
