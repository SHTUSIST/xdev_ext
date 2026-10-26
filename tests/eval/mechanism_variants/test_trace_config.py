# SPDX-License-Identifier: GPL-2.0
"""Independent fixed-profile trace-config qualification, without guest claims."""
from pathlib import Path
import tempfile
import unittest

import validate_e2


CASES = ('reverse', 'gray', 'outside_window', 'reserved_cdw2')
CONFIG = 'buffer_size_kb=4099\ncurrent_tracer=nop\ntrace_clock=local [mono] global\n'


class TraceConfig(unittest.TestCase):
    def fixture(self, root, text=CONFIG):
        for name in CASES:
            (root/(name+'-trace-config.txt')).write_text(text)
        return root

    def validate(self, capture):
        helper = getattr(validate_e2, 'validate_trace_configs', None)
        self.assertTrue(callable(helper), 'production trace-config qualification API is missing')
        return helper(capture)

    def test_integer_readback_rounding_is_bounded_and_normalized(self):
        for size in (4096, 4097, 4098, 4099):
            for clock in ('mono', '[mono]', 'local [mono] global'):
                with self.subTest(size=size, clock=clock), tempfile.TemporaryDirectory() as td:
                    root = self.fixture(Path(td), 'buffer_size_kb='+str(size)+
                        '\ncurrent_tracer=nop\ntrace_clock='+clock+'\n')
                    self.assertEqual(self.validate(root),
                        {'buffer_size_kb': size, 'current_tracer': 'nop', 'trace_clock': 'mono'})

    def test_out_of_profile_and_noninteger_readbacks_are_rejected(self):
        for value in ('4095', '4100', '0', '9999', 'X', '', '4099x', '4096.0', '-4096'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as td:
                root = self.fixture(Path(td), CONFIG.replace('4099', value))
                with self.assertRaises(ValueError):
                    self.validate(root)

    def test_every_case_must_have_the_same_actual_buffer_size(self):
        for name in CASES:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as td:
                root = self.fixture(Path(td))
                (root/(name+'-trace-config.txt')).write_text(CONFIG.replace('4099', '4098'))
                with self.assertRaises(ValueError):
                    self.validate(root)

    def test_each_case_requires_complete_unambiguous_keys_nop_and_selected_mono(self):
        invalid = {
            'missing-size': 'current_tracer=nop\ntrace_clock=[mono]\n',
            'missing-tracer': 'buffer_size_kb=4099\ntrace_clock=[mono]\n',
            'missing-clock': 'buffer_size_kb=4099\ncurrent_tracer=nop\n',
            'unknown-key': CONFIG+'requested_buffer_size_kb=4096\n',
            'duplicate-key': CONFIG+'buffer_size_kb=4099\n',
            'malformed-line': CONFIG+'unparseable\n',
            'function-tracer': CONFIG.replace('current_tracer=nop', 'current_tracer=function'),
            'empty-tracer': CONFIG.replace('current_tracer=nop', 'current_tracer='),
            'other-selected-clock': CONFIG.replace('local [mono] global', '[global] mono'),
            'two-selected-clocks': CONFIG.replace('local [mono] global', '[mono] [global]'),
            'empty-clock': CONFIG.replace('local [mono] global', ''),
            'different-clock': CONFIG.replace('local [mono] global', '[mono_raw]'),
        }
        for name in CASES:
            for problem, text in invalid.items():
                with self.subTest(case=name, problem=problem), tempfile.TemporaryDirectory() as td:
                    root = self.fixture(Path(td))
                    (root/(name+'-trace-config.txt')).write_text(text)
                    with self.assertRaises(ValueError):
                        self.validate(root)
            with self.subTest(case=name, problem='missing-file'), tempfile.TemporaryDirectory() as td:
                root = self.fixture(Path(td))
                (root/(name+'-trace-config.txt')).unlink()
                with self.assertRaises((OSError, ValueError)):
                    self.validate(root)


if __name__ == '__main__':
    unittest.main()
