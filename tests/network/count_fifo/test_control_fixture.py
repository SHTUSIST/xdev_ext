"""SOURCE-authored transformation and independent acceptance gate tests.

Root runs these only after the source-review/freeze gate; this module executes
neither a producer nor a compiler.
"""
import copy
import json
import unittest
from pathlib import Path
from control_fixture import migrate, invert, FixtureContractError, TRANSFORMS, _apply
from typed_fixture import migrate as migrate_v1
from control_expected import (load_frozen, ExpectedSetupError, compare_stdout,
                              _semantic, SEMANTIC_KEYS, PUBLIC_RECORD_IDS,
                              _match_field_metadata, _root_hashes)

RAW = Path(__file__).with_name('test_count.c').read_bytes()


class ControlFixtureTests(unittest.TestCase):
    def test_complete_inverse_and_v1_unchanged(self):
        old_generated, old_receipt = migrate_v1(RAW)
        generated, receipt = migrate(RAW)
        self.assertEqual(invert(generated, receipt), RAW)
        self.assertEqual(migrate_v1(RAW), (old_generated, old_receipt))
        self.assertEqual(receipt['forward_count'], len(TRANSFORMS))
        self.assertEqual(receipt['inverse_count'], len(TRANSFORMS))

    def test_changed_raw_and_v1_as_raw_are_setup(self):
        for source in (RAW + b'\n', migrate_v1(RAW)[0]):
            with self.assertRaises(FixtureContractError):
                migrate(source)

    def test_changed_generated_and_receipt_are_setup(self):
        generated, receipt = migrate(RAW)
        with self.assertRaises(FixtureContractError):
            invert(generated + b'\n', receipt)
        changed = copy.deepcopy(receipt)
        changed['forward'][0]['offset'] += 1
        with self.assertRaises(FixtureContractError):
            invert(generated, changed)

    def test_missing_duplicate_or_moved_named_span_is_setup(self):
        v1 = migrate_v1(RAW)[0]
        _, _, before, _ = TRANSFORMS[0]
        for source in (v1.replace(before, b' ', 1),
                       v1.replace(before, before + before, 1),
                       v1.replace(before, b' ', 1) + before):
            with self.assertRaises(FixtureContractError):
                _apply(source)

    def test_untouched_functions_are_byte_exact(self):
        from typed_fixture import _function_bounds
        generated, _ = migrate(RAW)
        for name in ('public_three_native_pending', 'public_errors',
                     'public_fallback', 'valid_public_wakeup_prefix',
                     'ordinary_32_frames', 'pure_literal_edges',
                     'pure_sequences', 'pure_explore'):
            a, b = _function_bounds(RAW, name)
            c, d = _function_bounds(generated, name)
            self.assertEqual(RAW[a:b], generated[c:d], name)

    def test_missing_frozen_artifact_is_hard_setup(self):
        with self.assertRaises(ExpectedSetupError):
            load_frozen(Path('/__absent_control_preproducer__.json'))

    def test_missing_root_owned_freeze_source_is_hard_setup(self):
        with self.assertRaisesRegex(ExpectedSetupError, 'ROOT control_freeze.py missing'):
            _root_hashes(Path('/__absent_root_control_freeze__.py'))

    def test_closed_exact_stdout_no_masks(self):
        frozen = {'expected_stdout': b'COUNT literal\n'}
        self.assertEqual(compare_stdout(b'COUNT literal\n', frozen), [])
        for observed in (b'', b'COUNT literal\nEXTRA\n', b'COUNT  literal\n'):
            self.assertTrue(compare_stdout(observed, frozen))

    def test_semantic_unknown_missing_duplicate_and_format_are_setup(self):
        # Shape-only test values are not case expectations or a producer golden.
        record = dict(zip(SEMANTIC_KEYS, [None] * len(SEMANTIC_KEYS)))
        record.update(id='shape-only', ret=None, preserved=-1, packet_ok=1,
                      ring=[0]*6, state=[0]*2, busy=[0]*2, uncertain=[0]*2,
                      meta=[[0]*6 for _ in range(2)], refs=[0]*2,
                      completion=[[0]*7 for _ in range(2)], cas_try=0,
                      cas_ok=0, return_ok=0, puts=[0]*2, dev=[], cpu=[],
                      ops=0, payload_bytes=0, dead=[])
        extra = copy.deepcopy(record)
        extra['unknown'] = 1
        missing = copy.deepcopy(record)
        del missing['dead']
        for rows in ([extra], [missing], [record, record]):
            source = b''.join(json.dumps(r, separators=(',', ':')).encode() + b'\n' for r in rows)
            with self.assertRaises(ExpectedSetupError):
                _semantic(source)

    def test_full_length_unknown_or_reordered_middle_ids_are_setup(self):
        # These neutral values test schema mechanics only, never case outcomes.
        shape = dict(zip(SEMANTIC_KEYS, [None] * len(SEMANTIC_KEYS)))
        shape.update(ret=None, preserved=-1, packet_ok=1, ring=[0]*6,
                     state=[0]*2, busy=[0]*2, uncertain=[0]*2,
                     meta=[[0]*6 for _ in range(2)], refs=[0]*2,
                     completion=[[0]*7 for _ in range(2)], cas_try=0,
                     cas_ok=0, return_ok=0, puts=[0]*2, dev=[], cpu=[],
                     ops=0, payload_bytes=0, dead=[])
        rows = []
        for identifier in PUBLIC_RECORD_IDS:
            row = copy.deepcopy(shape)
            row['id'] = identifier
            rows.append(row)
        def encode(values):
            return b''.join(json.dumps(row, separators=(',', ':')).encode() + b'\n' for row in values)
        self.assertEqual(tuple(_semantic(encode(rows))), PUBLIC_RECORD_IDS)
        wrong = copy.deepcopy(rows)
        wrong[30]['id'] = 'unknown-middle-identity'
        reordered = copy.deepcopy(rows)
        reordered[30], reordered[31] = reordered[31], reordered[30]
        for values in (wrong, reordered):
            with self.assertRaisesRegex(ExpectedSetupError, 'complete closed ordered semantic ID'):
                _semantic(encode(values))

    def test_closed_field_metadata_rejects_whole_row_and_unknown_atoms(self):
        # Byte values are unused here: this exercises the metadata-only gate.
        atom = {'clause': 'fixed-source-clause', 'current_local_end': 0,
                'current_local_start': 0, 'expected_b64': '',
                'mode': 'old_byte_equal', 'name': 'd.addr', 'old_b64': '',
                'old_end': 0, 'old_start': 0}
        row = {'current_end': 0, 'current_start': 0, 'disposition': 'field_exact',
               'expected_b64': '', 'fields': [atom], 'kind': 'S', 'old_b64': '',
               'old_end': 0, 'old_line': 1, 'old_start': 0}
        part = {'id': 'shape-part', 'mode': 'field_contract', 'rows': [row]}
        closed = {'id': 'shape-part', 'mode': 'field_contract', 'rows': [{
            'atoms': [{'category': 'tuple_component', 'clause': 'fixed-source-clause',
                       'component': 'addr', 'format_ordinal': None,
                       'mode': 'old_byte_equal', 'name': 'd.addr',
                       'ordinal': 0, 'parent': 'd'}],
            'disposition': 'field_exact', 'insertion_ordinal': None,
            'kind': 'S', 'old_line': 1, 'row_ordinal': 0}]}
        _match_field_metadata(part, closed)
        wrong = []
        for key, value in (('name', 'whole-DATA-row'), ('mode', 'independent_literal'),
                           ('clause', 'unreviewed-clause')):
            changed = copy.deepcopy(part)
            changed['rows'][0]['fields'][0][key] = value
            wrong.append(changed)
        changed = copy.deepcopy(part)
        changed['rows'][0]['kind'] = 'unknown-row'
        wrong.append(changed)
        changed = copy.deepcopy(part)
        changed['id'] = 'unknown-outer'
        wrong.append(changed)
        for changed in wrong:
            with self.assertRaises(ExpectedSetupError):
                _match_field_metadata(changed, closed)


if __name__ == '__main__':
    unittest.main()
