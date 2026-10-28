# SPDX-License-Identifier: GPL-2.0
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[3] / 'benchmarks/tp/accounting.py'

class AccountingTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('tp_accounting', MODULE)
        self.assertTrue(MODULE.is_file(), 'production accounting is missing')
        self.a = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.a)
        self.meta = dict(communicator=7, epoch=9, rank=0, clock=1,
                         trace_dropped=0, requested_depth=16)

    def events(self):
        return [dict(sequence=s, timestamp=t, kind=k, clock=1, rank=0,
                     payload_bytes=64, wire_bytes=128, logical_inflight=n)
                for s,t,k,n in [(1,10,1,1),(2,20,1,2),(1,30,3,2),
                                (1,40,4,2),(1,50,5,1),(2,60,3,1),
                                (2,70,4,1),(2,90,5,0)]]

    def validations(self):
        return [dict(sequence=s, rank=0, direction='rx', payload_bytes=64, valid=True)
                for s in (1,2)]

    def test_counts_unique_validated_bytes_and_complete_lifetime(self):
        v=self.validations()
        result=self.a.analyze(self.events(), v+[v[0]], self.meta)
        self.assertEqual(result['payload_bytes_by_direction'], {'rx':128})
        self.assertEqual(result['logical_inflight_high_water'], 2)
        self.assertEqual(result['occupied_time_ns'], 110)
        self.assertEqual(result['duration_ns'], 80)
        self.assertEqual(result['payload_bytes_per_second_by_direction']['rx'], 1.6e9)

    def test_trace_drop_unreleased_and_wrong_depth_are_invalid(self):
        for events, meta in [(self.events(),dict(self.meta,trace_dropped=1)),
                             (self.events()[:-1],self.meta),
                             ([dict(e,logical_inflight=16) if i==0 else e
                               for i,e in enumerate(self.events())],self.meta)]:
            with self.assertRaises(ValueError): self.a.analyze(events,self.validations(),meta)

    def test_unvalidated_or_failed_payload_is_not_throughput(self):
        for validations in [self.validations()[:1],
                            [dict(v,valid=False) for v in self.validations()]]:
            with self.assertRaises(ValueError): self.a.analyze(self.events(),validations,self.meta)

    def test_e6_requires_local_clock_result_and_custody(self):
        interval=dict(start=100,end=190,rank=0,clock=1,kind='allreduce',
                      completed=True,custody_released=True)
        result=self.a.analyze(self.events(),self.validations(),self.meta,[interval])
        self.assertEqual(result['durations_ns'],[dict(kind='allreduce',rank=0,clock=1,duration_ns=90)])
        for bad in [dict(interval,clock=2),dict(interval,rank=1),
                    dict(interval,custody_released=False),dict(interval,end=99)]:
            with self.assertRaises(ValueError): self.a.analyze(self.events(),self.validations(),self.meta,[bad])

if __name__=='__main__': unittest.main()
