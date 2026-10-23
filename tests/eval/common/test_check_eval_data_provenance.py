#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""check_eval_data_provenance.py against synthetic CSV fixtures."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    'provenance', HERE / 'check_eval_data_provenance.py')
pv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pv)

SHA = '0123456789abcdef0123456789abcdef01234567'
GOOD = f"""# provenance: source_sha={SHA} harness=tests/eval/nvme_nic/run.py run_dir=results/nvme-nic-4k-20261022
size_bytes,linux_us,session_us
4096,10.0,8.0
"""
SPLIT = f"""# source_sha: {SHA[:12]}
# harness: tests/eval/gds/run.py
# run_dir: results/gds-compat
size_bytes,gds_us
4096,79.9
"""
NO_HEADER = """size_bytes,baseline_us,system_us
4096,10,8
"""
COMMENTED_NO_KEYS = """# Clean measured micro run on a quiesced box.
size_bytes,a,b
1,2,3
"""
PREVIEW = f"""# provenance: source_sha={SHA} harness=x.py run_dir=r
# CE-DMA preview model for layout; replace with processed run data.
size_bytes,a
1,2
"""
EST_COLUMNS = """workload,linux_gbps_est,system_gbps,estimate_basis
ingest,4.7,9.9,preview_class
"""
PROJECTION = """# Remaining projection: one arm still calibrated.
a,b
1,2
"""


def write(directory, files):
    for name, text in files.items():
        (Path(directory) / name).write_text(text)


class Inspect(unittest.TestCase):
    def test_complete_header_inline_and_split(self):
        for text in (GOOD, SPLIT):
            r = pv.inspect('x.csv', text)
            self.assertEqual(r['missing'], [], text)
            self.assertEqual(r['estimate_signals'], [])
            self.assertTrue(r['ok'])
        self.assertEqual(pv.inspect('x.csv', SPLIT)['provenance']['source_sha'], SHA[:12])

    def test_missing_keys(self):
        self.assertEqual(pv.inspect('x.csv', NO_HEADER)['missing'],
                         ['source_sha', 'harness', 'run_dir'])
        # Prose saying "measured" is not provenance.
        self.assertEqual(pv.inspect('x.csv', COMMENTED_NO_KEYS)['missing'],
                         ['source_sha', 'harness', 'run_dir'])
        short = GOOD.replace(SHA, 'abc12')
        self.assertIn('source_sha', pv.inspect('x.csv', short)['missing'])

    def test_estimate_signals(self):
        signals = pv.inspect('x.csv', PREVIEW)['estimate_signals']
        self.assertIn('comment: preview', signals)
        self.assertIn('comment: model', signals)
        self.assertIn('comment: replace with', signals)
        self.assertFalse(pv.inspect('x.csv', PREVIEW)['ok'])
        cols = pv.inspect('x.csv', EST_COLUMNS)['estimate_signals']
        self.assertIn('column: linux_gbps_est', cols)
        self.assertIn('column: estimate_basis', cols)
        self.assertIn('comment: projection', pv.inspect('x.csv', PROJECTION)['estimate_signals'])
        self.assertIn('file name: estimated',
                      pv.inspect('three_device_estimated.csv', NO_HEADER)['estimate_signals'])
        self.assertIn('file name: preview',
                      pv.inspect('macro_preview_20260607.csv', NO_HEADER)['estimate_signals'])
        # A substring inside a longer word is not a signal.
        self.assertEqual(pv.inspect('x.csv', 'models_supported,best\n1,2\n')['estimate_signals'],
                         [])


class Scan(unittest.TestCase):
    def test_scan_marks_plot_inputs_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as t:
            data = Path(t) / 'eval_data'
            data.mkdir()
            write(data, {'good.csv': GOOD, 'bare.csv': NO_HEADER, 'preview.csv': PREVIEW})
            plot = Path(t) / 'plot.py'
            plot.write_text('A = "bare.csv"\nB = pd.read_csv(DATA / "good.csv")\n')
            rows = pv.scan(data, plot)
            self.assertEqual([r['file'] for r in rows], ['bare.csv', 'good.csv', 'preview.csv'])
            self.assertEqual([r['used_by_plot'] for r in rows], [True, True, False])
            before = {p.name: p.read_bytes() for p in data.iterdir()}
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = pv.main(['--data-dir', str(data), '--plot-script', str(plot), '--json'])
            self.assertEqual(code, 1)
            report = json.loads(out.getvalue())
            self.assertEqual(report['summary'], dict(files=3, ok=1, missing_provenance=1,
                                                     self_declared_estimate=1))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pv.main(['--data-dir', str(data), '--report-only']), 0)
            # Read only: the scanned files are byte-identical afterwards.
            self.assertEqual(before, {p.name: p.read_bytes() for p in data.iterdir()})
            (data / 'bare.csv').unlink()
            (data / 'preview.csv').unlink()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pv.main(['--data-dir', str(data)]), 0)

    def test_empty_or_missing_directory(self):
        with tempfile.TemporaryDirectory() as t:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(pv.main(['--data-dir', str(Path(t) / 'none')]), 2)
                self.assertEqual(pv.main(['--data-dir', t]), 2)


if __name__ == '__main__':
    unittest.main()
