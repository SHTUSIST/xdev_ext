#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the actual matrix wrapper with a recording harness boundary.

This checks campaign selection, argv, failure propagation and evidence copies;
the recording harness is not a guest execution or a data-path simulation.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
MATRIX = HERE / "xdev_ext_mech_zc_matrix.sh"
LEGACY = {"legacy-normal": "none", "legacy-drop-middle": "drop-middle",
          "legacy-duplicate-middle": "duplicate-middle"}
ORIGINAL = {"normal", "reliable-drop-data", "reliable-drop-ack",
            "reliable-duplicate-ack", "reliable-replay-group", "reliable-reorder-group",
            "reliable-budget-unknown", "credit-window-one", "provider-short", "provider-ambiguous"}


def source_layout():
    """Use the real layout API from canonical or ordinary logical-view paths."""
    for parent in HERE.parents:
        tooling = parent / 'tools/layout.py'
        if tooling.is_file():
            spec = importlib.util.spec_from_file_location('_legacy_matrix_layout', tooling)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            repo = module.canonical_root(HERE)
            return repo, module.load_layout(repo)
    raise RuntimeError('matrix test requires a canonical or logical source layout')


class MatrixCampaigns(unittest.TestCase):
    def execute(self, fail_fault=""):
        tmp = tempfile.TemporaryDirectory(prefix="xdev-matrix-contract-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        scratch = root / "scratch"
        scratch.mkdir(mode=0o700)
        repo, layout = source_layout()
        setup_path = repo / 'tests/integration/session/source_setup/fixture.py'
        spec = importlib.util.spec_from_file_location('_legacy_matrix_setup', setup_path)
        setup = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(setup)
        fixture = setup.Fixture()
        self.addCleanup(fixture.cleanup)
        archive_native = 'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_archive.py'
        archive_source = layout.by_native[('linux', archive_native)]
        fixture.entries.append(dict(source=archive_source, component='linux',
                                    native_path=archive_native))
        setup.write(fixture.repo / archive_source, (repo / archive_source).read_bytes())
        setup.write_json(fixture.repo / 'source-layout.json', fixture.manifest)
        harness = fixture.repo / setup.HARNESS
        harness.write_text("""#!/bin/sh
set -eu
python3 - "$@" <<'PYRECORD'
import json, os, pathlib, sys
args = sys.argv[1:]
scratch = pathlib.Path(args[args.index('--scratch') + 1])
calls = scratch/'calls.jsonl'
previous = calls.read_text().splitlines() if calls.exists() else []
record = dict(ordinal=len(previous), args=args)
with calls.open('a') as output:
    output.write(json.dumps(record)+'\\n')
evidence = scratch/'evidence'
evidence.mkdir(exist_ok=True)
(evidence/'guest.log').write_text(json.dumps(record)+'\\n')
fault = args[args.index('--fault') + 1] if '--fault' in args else 'none'
raise SystemExit(7 if fault == os.environ.get('MATRIX_FAKE_FAIL_FAULT') else 0)
PYRECORD
""")
        # Commit the recording boundary before real preparation: the copied
        # harness and archive helper must match clean canonical Git bytes.
        fixture.sha = fixture.commit(fixture.repo)
        source = fixture.repo / 'build/matrix-source/linux'
        fixture.prepare(source)
        env = dict(os.environ, MATRIX_FAKE_FAIL_FAULT=fail_fault)
        run = subprocess.run(["bash", str(MATRIX), str(scratch), str(source)],
                             env=env, capture_output=True, text=True, timeout=20)
        calls = [json.loads(line) for line in (scratch / "calls.jsonl").read_text().splitlines()]
        return run, scratch, source, calls

    def test_matrix_preserves_original_ten_and_adds_three_legacy_campaigns(self):
        run, scratch, _, calls = self.execute()
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(len(calls), 13, "matrix must run all original ten and three legacy guests")
        self.assertEqual({p.name for p in (scratch / "campaigns").iterdir()}, ORIGINAL | LEGACY.keys())
        self.assertIn("XDEV_EXT_ZC_MATRIX=PASS campaigns=13", run.stdout)

    def test_legacy_argv_omits_reliable_and_keeps_long_stream_geometry(self):
        run, scratch, source, _ = self.execute()
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        for name, fault in LEGACY.items():
            evidence = scratch / "campaigns" / name / "guest.log"
            self.assertTrue(evidence.exists(), "missing actual wrapper invocation of " + name)
            args = json.loads(evidence.read_text())["args"]
            self.assertNotIn("--reliable", args)
            for option in ("--run-only", "--ce-sim", "--rx-ce"):
                self.assertIn(option, args)
            for option, value in (("--groups", "257"), ("--depth", "8"), ("--ce-slots", "8"),
                                  ("--ce-delay-us", "10000"), ("--fault", fault),
                                  ("--scratch", str(scratch)), ("--source", str(source))):
                self.assertEqual(args[args.index(option) + 1], value)

    def test_each_campaign_keeps_its_own_evidence_and_original_modes(self):
        run, scratch, _, calls = self.execute()
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        ordinals = set()
        for name in ORIGINAL | LEGACY.keys():
            evidence = scratch / "campaigns" / name
            self.assertTrue(evidence.exists(), "missing evidence for " + name)
            record = json.loads((evidence / "guest.log").read_text())
            ordinals.add(record["ordinal"])
            self.assertEqual((evidence / "matrix.exit").read_text(), "0\n")
            if name in ORIGINAL and not name.startswith("provider-"):
                self.assertIn("--reliable", record["args"])
        self.assertEqual(ordinals, set(range(13)))
        self.assertEqual(len(calls), 13)

    def test_legacy_failure_is_archived_and_stops_matrix_without_success_marker(self):
        run, scratch, _, _ = self.execute("drop-middle")
        self.assertEqual(run.returncode, 7, "legacy failure must terminate the matrix")
        evidence = scratch / "campaigns/legacy-drop-middle"
        self.assertTrue((evidence / "guest.log").is_file())
        self.assertEqual((evidence / "matrix.exit").read_text(), "7\n")
        self.assertFalse((scratch / "campaigns/legacy-duplicate-middle").exists())
        self.assertNotIn("XDEV_EXT_ZC_MATRIX=PASS", run.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
