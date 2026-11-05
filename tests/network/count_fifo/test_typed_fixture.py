"""Transform behavior only; no extractor, production import or compiler invocation."""
import copy
import hashlib
from pathlib import Path
import unittest

from typed_fixture import FixtureContractError, _replace_scoped, invert, migrate


class TypedFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = Path(__file__).with_name('test_count.c').read_bytes()

    def test_round_trip_preserves_complete_raw_and_records_four_each_way(self):
        generated, receipt = migrate(self.raw)
        self.assertNotEqual(generated, self.raw)
        self.assertEqual(invert(generated, receipt), self.raw)
        self.assertEqual([r['id'] for r in receipt['forward']], ['T1', 'T2', 'T3', 'T4'])
        self.assertEqual([r['id'] for r in receipt['inverse']], ['T4', 'T3', 'T2', 'T1'])
        self.assertEqual(receipt['raw_sha256'],
                         '1efa6aa4cd946dd5bfeaa8d37ed794ce1e69933aff14157181502c92f9fdb8f2')
        for record in receipt['forward'] + receipt['inverse']:
            self.assertEqual((record['before_count'], record['after_count']), (1, 0))
            self.assertEqual((record['result_before_count'], record['result_after_count']), (0, 1))

    def test_wrong_raw_identity_and_already_migrated_input_are_rejected(self):
        with self.assertRaises(FixtureContractError):
            migrate(self.raw + b'\n')
        generated, _ = migrate(self.raw)
        with self.assertRaises(FixtureContractError):
            migrate(generated)

    def test_missing_and_duplicate_anchors_fail_in_named_scope(self):
        for body in (b'', b'old;\nold;\n'):
            with self.subTest(body=body), self.assertRaises(FixtureContractError):
                _replace_scoped(b'static void sample(void)\n{\n' + body + b'}\n',
                                'T', 'sample', b'old;', b'new;')

    def test_anchor_in_other_function_cannot_supply_missing_named_anchor(self):
        source = b'static void sample(void)\n{\n}\nstatic void other(void)\n{\nold;\n}\n'
        with self.assertRaises(FixtureContractError):
            _replace_scoped(source, 'T', 'sample', b'old;', b'new;')

    def test_duplicate_function_or_existing_new_span_is_rejected(self):
        for source in (b'static void sample(void)\n{old;}\n' * 2,
                       b'static void sample(void)\n{old;new;}\n'):
            with self.subTest(source=source), self.assertRaises(FixtureContractError):
                _replace_scoped(source, 'T', 'sample', b'old;', b'new;')

    def test_inverse_rejects_changed_generated_source_and_receipt(self):
        generated, receipt = migrate(self.raw)
        with self.assertRaises(FixtureContractError):
            invert(generated.replace(b'tb.batch=&batch;batch.nr_frames=count;',
                                      b'tb.batch=NULL;batch.nr_frames=count;', 1), receipt)
        changed_source = generated.replace(b'tb.batch=&batch;batch.nr_frames=count;',
                                           b'tb.batch=NULL;batch.nr_frames=count;', 1)
        changed = copy.deepcopy(receipt)
        changed['generated_sha256'] = hashlib.sha256(changed_source).hexdigest()
        with self.assertRaises(FixtureContractError):
            invert(changed_source, changed)
        changed = copy.deepcopy(receipt)
        changed['forward'][0]['offset'] += 1
        with self.assertRaises(FixtureContractError):
            invert(generated, changed)
        changed = copy.deepcopy(receipt)
        changed['inverse'].pop()
        with self.assertRaises(FixtureContractError):
            invert(generated, changed)

    def test_data_counts_are_exact_and_control_facts_are_preserved(self):
        generated, _ = migrate(self.raw)
        self.assertIn(b'control ? 22 : (u64)i*4096+22,58,0', generated)
        self.assertIn(b'if (!control) {\n   tb.batch=&batch;batch.nr_frames=count;', generated)
        self.assertIn(b'count_ops==(control?0:count)&&count_bytes==(control?0:16*count)', generated)
        # Every unrelated function, including actual CONTROL callers, stays byte-exact.
        start = self.raw.index(b'static void reliable_real_callers(void)')
        end = self.raw.index(b'static void public_wrap_mixed(void)')
        self.assertIn(self.raw[start:end], generated)
        tail = self.raw[self.raw.index(b'static void valid_public_wakeup_prefix(void)'):]
        self.assertTrue(generated.endswith(tail))
        self.assertIn(b'b={.control=true};struct xdp_desc pair[2]={{22,58,0},{4118,58,0}};', generated)


if __name__ == '__main__':
    unittest.main()
