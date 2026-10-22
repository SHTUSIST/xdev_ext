#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent fresh-run wire identity regression; real POSIX/UDP only."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

import oracle
import run as runner

HERE=Path(__file__).resolve().parent


def parsed_profile(actors=4):
    argv=['run.py','--backend','posix','--actors',str(actors),'--burst','3',
          '--bursts','2','--depth','4','--seed','9']
    with mock.patch.object(sys,'argv',argv):
        return runner.parse()


class FreshManifestTests(unittest.TestCase):
    def test_each_parse_has_nonzero_fresh_bounded_actor_session_window(self):
        profiles=[parsed_profile()[1] for _ in range(16)]
        bases=[p['session_base'] for p in profiles]
        self.assertEqual(len(set(bases)),len(bases),'new runs reuse a wire session')
        for p in profiles:
            self.assertIs(type(p['session_base']),int)
            self.assertGreater(p['session_base'],0)
            self.assertLessEqual(p['session_base']+p['actors']-1,2**64-1)
        payloads=[b''.join(oracle.payload(p,a,g) for a in range(p['actors'])
                    for g in range(p['burst_packets']*p['bursts'])) for p in profiles]
        self.assertEqual(len({hashlib.sha256(x).hexdigest() for x in payloads}),1,
                         'wire identity must not change the reproducible source payload')


class ActualRunIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='.isolation-test-',dir=HERE)
        cls.directory=Path(cls.temp.name)
        cls.runs=[]
        original_verify=oracle.verify
        for index in range(2):
            args,p=parsed_profile()
            captured=cls.directory/('run-'+str(index)+'.capture')
            def observe(profile,path,destination=captured):
                destination.write_bytes(Path(path).read_bytes())
                return original_verify(profile,path)
            with mock.patch.object(runner.oracle,'verify',side_effect=observe):
                result=runner.execute(args,p)
            cls.runs.append((dict(p),captured,result))
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def test_actual_two_runs_get_distinct_wire_sessions_and_same_source(self):
        first,second=self.runs
        self.assertNotEqual(first[0]['session_base'],second[0]['session_base'],
                            'two actual runs reused their wire session')
        self.assertEqual(first[2]['source_sha'],second[2]['source_sha'])
        self.assertEqual(first[2]['validated_packets'],24)
        self.assertEqual(second[2]['validated_packets'],24)
        for p,capture,result in self.runs:
            raw=capture.read_bytes()
            length=struct.unpack('!I',raw[:4])[0]
            packet=raw[4:4+length]
            session=struct.unpack('!Q',packet[8:16])[0]
            self.assertIn(session,range(p['session_base'],p['session_base']+p['actors']))
            self.assertEqual(original_fields(result),original_fields(first[2]))
    def test_previous_actual_run_capture_is_rejected_by_next_run_manifest(self):
        previous,current=self.runs
        with self.assertRaisesRegex(ValueError,'foreign|session'):
            oracle.verify(current[0],previous[1])


def original_fields(result):
    # Public success schema stays exactly the existing frozen contract.
    from test_contract import FIELDS
    if set(result)!=FIELDS:
        raise AssertionError('freshness changed public result schema')
    return set(result)


if __name__=='__main__':
    unittest.main()
