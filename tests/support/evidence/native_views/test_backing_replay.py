#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Raw replay and edited-JSON negatives; fixtures cannot certify hardware."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import contract

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('native_backing_raw_fixture', HERE.parent / 'native_trace/test_native_backing.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class BackingReplay(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.plan, self.rows, self.meta = fixture.fixture(self.path)
        self.receipt = dict(status='ok', returncode=0, artifacts={})
        self.receipt['artifacts']['journal'] = self.meta['journal_artifact']
        self.write('raw_trace', fixture.text(self.rows))
        self.write('events', ''.join(json.dumps(r)+'\n' for r in
            fixture.collector.decode_trace(self.plan, fixture.text(self.rows), self.meta)))
        self.write('trace_metadata', json.dumps(self.meta))
        self.proof = fixture.collector.derive_native_backing(self.plan, fixture.text(self.rows), self.meta)
        self.write('zero_copy', json.dumps(self.proof))
        self.write('mapped_manifest', json.dumps(fixture.collector.derive_mapped_manifest(
            self.plan, fixture.text(self.rows), self.meta)))

    def write(self, name, value):
        path = self.path / (name+'.txt')
        path.write_text(value)
        self.receipt['artifacts'][name] = fixture.collector.artifact(path)

    def errors(self):
        return contract.inspect_collection(self.plan, self.receipt)['errors']

    def test_valid_observed_proof_replays_even_when_other_campaign_artifacts_are_missing(self):
        self.assertEqual([e for e in self.errors() if e.startswith('zero_copy')], [])
        self.assertIs(self.plan['physical'], False)

    def test_edited_proof_with_recomputed_hash_cannot_self_certify(self):
        for alteration in ('physical', 'frame', 'extra', 'bool'):
            with self.subTest(alteration=alteration):
                proof = copy.deepcopy(self.proof)
                if alteration == 'physical': proof['frames'][0]['physical_ranges'][0][0] += 1
                elif alteration == 'frame': proof['frames'][0]['backing_id'] = 'invented'
                elif alteration == 'extra': proof['frames'].append(copy.deepcopy(proof['frames'][0]))
                else: proof['payload_copy_bytes'] = False
                self.write('zero_copy', json.dumps(proof))
                self.assertTrue(any('zero_copy' in e and 'replay' in e for e in self.errors()))

    def test_missing_raw_map_cannot_be_replaced_by_well_formed_hashed_json(self):
        self.rows = [r for r in self.rows if r['phase'] != 'dma_seal']
        self.write('raw_trace', fixture.text(self.rows))
        self.write('events', ''.join(json.dumps(r)+'\n' for r in
            fixture.collector.decode_trace(self.plan, fixture.text(self.rows), self.meta)))
        self.assertTrue(any('zero_copy' in e and 'replay' in e for e in self.errors()))


if __name__ == '__main__':
    unittest.main()
