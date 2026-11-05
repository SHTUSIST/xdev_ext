#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the real NVMe submit body under deterministic native API shims.

Run directly with python3. XDEV_EXT_NVME_TEST_SOURCE may select a source file
only with its matching XDEV_EXT_NVME_TEST_ROOT dependency owner.
"""

import errno
import os
from pathlib import Path

import re
import runpy
import shutil
import subprocess
import tempfile
import unittest
import json
# Resolve the authored tools through the official canonical/view contract.
_LAYOUT_FILE = next(p / 'tools/layout.py' for p in Path(__file__).resolve().parents
                    if (p / 'tools/layout.py').is_file())
ROOT = runpy.run_path(str(_LAYOUT_FILE))['canonical_root'](Path(__file__))
_LEGACY = runpy.run_path(str(ROOT / 'tests/storage/nvme/_legacy_storfam_fixture.py'))
selected_source, nowait_fixture = (_LEGACY[name] for name in ('selected_source', 'nowait_fixture'))


HERE = Path(__file__).resolve().parent
RELATIVE_SOURCE = "drivers/nvme/host/xdev_ext_mech_nvme.c"


class NvmeNowait(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if not compiler:
            raise unittest.SkipTest("C compiler unavailable")
        source_path = Path(os.environ.get("XDEV_EXT_NVME_TEST_SOURCE",
                                          str(ROOT / RELATIVE_SOURCE)))
        if 'XDEV_EXT_NVME_TEST_SOURCE' in os.environ and 'XDEV_EXT_NVME_TEST_ROOT' not in os.environ:
            raise ValueError('SETUP XDEV_EXT_NVME_TEST_SOURCE requires XDEV_EXT_NVME_TEST_ROOT')
        selected = selected_source(Path(os.environ.get('XDEV_EXT_NVME_TEST_ROOT', ROOT)),
                                   source_path if 'XDEV_EXT_NVME_TEST_SOURCE' in os.environ else None)
        if "XDEV_EXT_NVME_TEST_SOURCE" not in os.environ:
            source = selected.read(RELATIVE_SOURCE)
        elif source_path.is_file():
            source = selected.read(RELATIVE_SOURCE)
        else:
            raise ValueError('SETUP selected NVMe source missing')
        # Retain every statement in the real function; only dependencies are faked.
        function = re.search(r"^static int nvme_xdev_ext_class_submit\([^)]*\)\s*"
                             r"\{.*?^\}", source, re.MULTILINE | re.DOTALL)
        if function is None:
            raise RuntimeError("production nvme_xdev_ext_class_submit function missing")
        cls.temp = tempfile.TemporaryDirectory(prefix="xdev_ext-nvme-nowait-")
        cls.addClassCleanup(cls.temp.cleanup)
        path = Path(cls.temp.name)
        fixture = (HERE / "xdev_ext_mech_nvme_nowait_fixture.c").read_text()
        repo = selected.root
        family = 'struct xdev_ext_stor_stage family;' in source
        if 'return xdev_ext_storfam_submit(&p->family, b, &bp->family);' not in source:
            # Compatibility readers permit a native-tree hint fallback. Require
            # each reached dependency from this selected owner before using them.
            if family or 'xdev_ext_stor_block_poll_opf(' in source:
                selected.read('include/linux/xdev_ext_storfam_block.h')
                selected.read('io_uring/family/xdev_ext_storfam_block.c')
            if family:
                selected.read('drivers/nvme/host/nvme.h')
        helper = ROOT / 'tests/integration/peer_graph/nvme_peer_async_test.py'
        helpers_api = runpy.run_path(str(helper))
        include_root = helpers_api['host_headers'](repo, path / 'headers')
        if 'return xdev_ext_storfam_submit(&p->family, b, &bp->family);' in source:
            generated, records = nowait_fixture(selected, fixture)
            (path / 'submit.c').write_text(generated)
            (path / 'assembly.json').write_text(json.dumps(selected.report(), indent=2))
            (path / 'fixture-edits.json').write_text(json.dumps(records, indent=2))
            cls.probe = path / 'probe'
            selected.verify()
            build = subprocess.run([compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                                    '-DCONFIG_XDEV_EXT_MECH_ZEROCOPY', '-I'+str(include_root), str(path/'submit.c'),
                                    '-o', str(cls.probe)], text=True, capture_output=True)
            if build.returncode:
                raise RuntimeError('host shim compile failed:\n'+build.stdout+build.stderr)
            return
        if family:
            fixture = fixture.replace('/* IDENTITY_OS_TYPES */', helpers_api['identity_boundary']())
            fixture = '#define FIXTURE_MEMBER_FAMILY 1\n' + fixture
            fixture = fixture.replace('/* FAMILY_TYPES */', helpers_api['family_types'](repo))
        else:
            fixture = fixture.replace('/* IDENTITY_OS_TYPES */', 'struct nvme_ns { void *queue; };')
        # The stage-polling helpers the submit calls, verbatim, before it.
        helpers = [re.search(r"^static [^;{}]*\b" + name + r"\([^)]*\)\s*\{.*?^\}",
                             source, re.MULTILINE | re.DOTALL)
                   for name in ("nvme_xdev_ext_poll_opf", "nvme_xdev_ext_poll_check",
                                "nvme_xdev_ext_poll_arm")]
        if 'xdev_ext_stor_block_poll_opf(' in source:
            polling = helpers_api['storage_poll_runtime'](repo)
        else:
            if not all(helpers):
                raise RuntimeError("production stage-polling helpers missing")
            polling = "\n".join(h[0] for h in helpers)
        validate = re.search(r"^static int nvme_xdev_ext_class_validate\([^;{}]*\)\s*"
                             r"\{.*?^\}", source, re.MULTILINE | re.DOTALL)
        if validate is None:
            raise RuntimeError("production NVMe validation function missing")
        production = ((helpers_api['worker_runtime'](repo, source) + "\n" + helpers_api['worker_fixture_init']()) if family else '')
        production += "\n" + validate[0] + "\n" + polling + "\n" + function[0]
        generated = path / "submit.c"
        generated.write_text(fixture.replace("/* PRODUCTION_SUBMIT */", production))
        cls.probe = path / "probe"
        selected.verify()
        build = subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                                "-DCONFIG_XDEV_EXT_MECH_ZEROCOPY", "-I" + str(include_root), str(generated),
                                "-o", str(cls.probe)], text=True, capture_output=True)
        if build.returncode:
            raise RuntimeError("host shim compile failed:\n" + build.stdout + build.stderr)

    def run_submit(self, mode):
        p = subprocess.run([str(self.probe), mode], text=True, capture_output=True,
                           timeout=3, check=True)
        return {key: int(value) for key, value in
                (field.split("=", 1) for field in p.stdout.split())}

    def assert_no_native_work(self, result):
        for key in ("done_allocs", "maps", "handoffs", "completions"):
            self.assertEqual(result[key], 0, result)

    def test_full_tags_return_retry_without_wait_or_native_work(self):
        result = self.run_submit("full")
        self.assertEqual(result["rc"], -errno.EAGAIN, result)
        self.assertEqual(result["blocked"], 0, result)
        self.assertTrue(result["flags"] & 1, result)
        self.assertEqual(result["tag_calls"], 1, result)
        self.assert_no_native_work(result)

    def test_real_allocator_error_is_preserved_without_native_work(self):
        result = self.run_submit("nodev")
        self.assertEqual(result["rc"], -errno.ENODEV, result)
        self.assertEqual(result["tag_calls"], 1, result)
        self.assert_no_native_work(result)

    def test_success_hands_off_exactly_once(self):
        result = self.run_submit("success")
        self.assertEqual(result["rc"], 0, result)
        self.assertEqual(result["blocked"], 0, result)
        self.assertEqual(result["done_allocs"], 0, result)
        for key in ("tag_calls", "maps", "handoffs", "completions"):
            self.assertEqual(result[key], 1, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
