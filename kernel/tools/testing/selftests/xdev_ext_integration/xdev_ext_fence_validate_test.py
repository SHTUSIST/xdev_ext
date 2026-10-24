#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host-only evidence rejection controls. Synthetic documents are not runtime evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import re
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
HARNESS = HERE / 'xdev_ext_mech_zc_kvm.sh'
VALIDATOR = HERE / 'xdev_ext_fence_validate.py'
NONCE = 'a' * 31


def request():
    return dict(exact_sha='b' * 40, lifecycle_header_sha256='c' * 64,
                module_sha256='d' * 64, kernel_release='test-kernel',
                nonce_prefix=NONCE, iterations=8)


def raw_report():
    report = dict(schema_version=1, experiment_kind='kernel_sync_primitive',
                  exact_sha='b' * 40, lifecycle_header_sha256='c' * 64,
                  run_nonce=NONCE + '0', mode='check', status='ok', iterations=8,
                  execution_context='serial-process', kernel_runtime=True,
                  evidence_kind='kernel-runtime', oracle_in_timing=False,
                  oracle_checked_operations=16,
                  concurrent_check=dict(executed=True, contexts=2),
                  checks={k: 'pass' for k in ('two_phase', 'signal_before_add', 'identity',
                      'duplicates', 'held_reference', 'independent_frames',
                      'allocation_failure', 'callback_failure', 'teardown')})
    arm = dict(attempted=8, successful=8, produced=8, consumed=8, recycled=8,
               valid_len_checks=8, errors=0, allocations_setup=1,
               allocations_steady=0, cleanup_complete=True)
    report['arms'] = dict(life=copy.deepcopy(arm), dma_fence=copy.deepcopy(arm))
    report['arms']['dma_fence'].update(fence_objects=16, fence_releases=16)
    return report


def console(report=None):
    lines = ['XDEV_EXT_FENCE_IDENTITY kernel_release=test-kernel module_sha256=' + 'd' * 64,
             f'XDEV_EXT_FENCE_BEGIN nonce={NONCE}0 mode=check iterations=8 '
             f'sysfs_nonce={NONCE}0 sysfs_mode=check sysfs_iterations=8',
             'XDEV_EXT_FENCE_JSON_BEGIN', json.dumps(report or raw_report()),
             'XDEV_EXT_FENCE_JSON_END',
             f'XDEV_EXT_FENCE_CASE=check nonce={NONCE}0 mode=check iterations=8 '
             'load_rc=0 unload_rc=0 module=absent debugfs=absent']
    for i, name in enumerate(('alloc1', 'alloc2', 'callback1', 'callback2'), 1):
        lines.append(f'XDEV_EXT_FENCE_CASE={name} nonce={NONCE}{i} mode=check iterations=8 '
                     'load_rc=1 unload_rc=not-loaded module=absent debugfs=absent')
    lines += ['XDEV_EXT_FENCE_DONE=5/5 performance_claim=none', 'XDEV_EXT_ZC_GUEST_EXIT=0']
    return '\n'.join(lines) + '\n'


class FenceValidation(unittest.TestCase):
    def setUp(self):
        self.assertTrue(VALIDATOR.exists(), 'fence guest evidence validator is missing')
        spec = importlib.util.spec_from_file_location('fence_validate', VALIDATOR)
        self.v = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.v)

    def test_complete_evidence(self):
        self.assertEqual(self.v.validate(console(), 0, request())['cases'], 5)

    def test_missing_negative_and_duplicate(self):
        lines = console().splitlines()
        for text in ('\n'.join(x for x in lines if 'CASE=alloc1 ' not in x),
                     console().replace('XDEV_EXT_FENCE_DONE=', lines[5] + '\nXDEV_EXT_FENCE_DONE=')):
            with self.assertRaises(ValueError):
                self.v.validate(text, 0, request())

    def test_marker_only_never_accepts(self):
        with self.assertRaises(ValueError):
            self.v.validate('XDEV_EXT_FENCE_DONE=5/5 performance_claim=none\nXDEV_EXT_ZC_GUEST_EXIT=0\n', 0, request())

    def test_outer_exit_and_kernel_diagnostic(self):
        for text, rc in ((console(), 124), (console().replace('GUEST_EXIT=0', 'GUEST_EXIT=1'), 0),
                         (console() + '[ 1.0] BUG: KASAN: use-after-free\n', 0),
                         (console() + 'WARNING: suspicious state\n', 0)):
            with self.assertRaises(ValueError):
                self.v.validate(text, rc, request())

    def test_raw_producer_count_identity_and_schema(self):
        for key, value in (('iterations', 9), ('exact_sha', 'e' * 40),
                           ('lifecycle_header_sha256', 'f' * 64),
                           ('run_nonce', 'f' * 32), ('kernel_runtime', False),
                           ('evidence_kind', 'host-contract'), ('execution_context', 'fixture'), ('mode', 'time'),
                           ('schema_version', True)):
            r = raw_report(); r[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.v.validate(console(r), 0, request())
        for mutation in (lambda r: r['arms']['life'].update(successful=True),
                         lambda r: r.update(timing={'life': {'prepare_ns': 1}}),
                         lambda r: r.update(unknown=[{'secret_ns': 1}]),
                         lambda r: r['concurrent_check'].update(executed=False)):
            r = raw_report(); mutation(r)
            with self.assertRaises(ValueError):
                self.v.validate(console(r), 0, request())

    def test_duplicate_json_key_and_truncated_document(self):
        raw = json.dumps(raw_report())
        for value in ('{"status":"failed",' + raw[1:], raw[:-4]):
            with self.assertRaises(ValueError):
                self.v.validate(console().replace(raw, value), 0, request())

    def test_negative_load_and_teardown_required(self):
        for before, after in (('load_rc=1', 'load_rc=0'), ('module=absent', 'module=present'),
                              ('debugfs=absent', 'debugfs=present'), ('unload_rc=0', 'unload_rc=1'),
                              ('sysfs_mode=check', 'sysfs_mode=time'),
                              ('sysfs_iterations=8', 'sysfs_iterations=9'),
                              ('CASE=alloc1 nonce=' + NONCE + '1', 'CASE=alloc1 nonce=' + NONCE + '0')):
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.v.validate(console().replace(before, after), 0, request())


class HarnessWiring(unittest.TestCase):
    def test_fresh_provenance_does_not_write_uncreated_initroot(self):
        s = HARNESS.read_text()
        start = s.index("printf 'date_utc=")
        end = s.index("printf 'source_slba=", start)
        with tempfile.TemporaryDirectory() as t:
            p = Path(t); (p / 'evidence').mkdir()
            names = 'CE_SIM CE_DELAY_US RX_CE RELIABLE DEPTH GROUP_COUNT CE_SLOTS REMOTE_WINDOW COMPAT LIFECYCLE PEER DEBUG_LOCKING TIMEOUT_FACTOR CLI_TIMEOUT_MS RX_TIMEOUT_MS QEMU_TIMEOUT_SECONDS FENCE_CHECK EVAL_SESSION'
            env = ' '.join(k + '=0' for k in names.split())
            cmd = f'ROOT={p}/initroot; EV={p}/evidence; SCRATCH={p}; FAULT=none; REL_POLICY=default; PROVIDER_CASE=normal; {env};\n' + s[start:end]
            r = subprocess.run(['bash', '-eu', '-c', cmd], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse((p / 'initroot').exists())

    def test_env_default_lifecycle_and_fence(self):
        s = HARNESS.read_text()
        start = s.index("printf 'groups=%s\\nwindow_nlb=")
        end = s.index('# --- Track S', start)
        for lifecycle, fence in ((0, 0), (1, 0), (0, 1), (1, 1)):
            with tempfile.TemporaryDirectory() as t:
                p = Path(t); (p / 'opt/xdev_ext').mkdir(parents=True)
                names = 'CE_SIM CE_DELAY_US RX_CE RELIABLE DEPTH GROUP_COUNT CE_SLOTS REMOTE_WINDOW COMPAT PEER DEBUG_LOCKING TIMEOUT_FACTOR CLI_TIMEOUT_MS RX_TIMEOUT_MS SOURCE_SLBA RX_SLBA CE_SLBA EVAL_SESSION'
                env = ' '.join(k + '=0' for k in names.split())
                cmd = f'ROOT={p}; FAULT=none; FAULT_CAMPAIGN=; REL_POLICY=default; PROVIDER_CASE=normal; {env}; LIFECYCLE={lifecycle}; FENCE_CHECK={fence}; FENCE_NONCE_PREFIX={NONCE};\n' + s[start:end]
                r = subprocess.run(['bash', '-eu', '-c', cmd], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                values = dict(x.split('=', 1) for x in (p/'opt/xdev_ext/zc.env').read_text().splitlines())
                self.assertEqual(values.get('lifecycle'), str(lifecycle))
                self.assertEqual(values.get('fence_check'), str(fence))
                self.assertEqual(values.get('fence_nonce_prefix'), NONCE)

    def test_explicit_option_and_campaign_rejection(self):
        r = subprocess.run(['bash', str(HARNESS), '--fence-check', '--fault-campaign', 'create-failure'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn('fence-check cannot accompany fault-campaign', r.stderr)

    def test_missing_genuine_symbols_cannot_reuse_or_stage(self):
        s = HARNESS.read_text()
        function = re.search(r'(verify_fence_identity\(\) \{.*?^\})', s, re.S | re.M).group(1)
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            (p/'.config').write_text(''.join('CONFIG_' + k + '=y\n' for k in
                ('MODULES', 'MODULE_UNLOAD', 'DMA_SHARED_BUFFER', 'DEBUG_FS')))
            (p/'xdev-ext-artifacts.sha256').write_text('')
            # Deliberately absent Module.symvers: no fabricated export table.
            cmd = f'BUILD={p}; FENCE_OUT={p}; FENCE_RUNNER={p}/run.py; SRC={p}; FENCE_GUEST={p}/guest; FENCE_VALIDATOR={p}/validator; DEBUG_HELPER={p}/debug;\n' + function + '\nverify_fence_identity'
            r = subprocess.run(['bash', '-eu', '-c', cmd], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('artifact/dependency identity absent', r.stderr)
            # The exact required config check must fail before touching loaders.
            (p/'.config').write_text('CONFIG_MODULES=y\nCONFIG_DEBUG_FS=y\n')
            r = subprocess.run(['bash', '-eu', '-c', cmd], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('requires CONFIG_MODULE_UNLOAD=y', r.stderr)

    def test_debug_console_dependency_is_bound(self):
        s = HARNESS.read_text()
        function = re.search(r'(verify_fence_identity\(\) \{.*?^\})', s, re.S | re.M).group(1)
        self.assertIn('"$DEBUG_HELPER"', function)
        manifest = s[s.index('if (( FENCE_CHECK )); then\n        sha256sum'):]
        self.assertIn('"$DEBUG_HELPER"', manifest.split('>>"$BUILD/xdev-ext-artifacts.sha256"')[0])

    def test_real_reuse_hash_command_rejects_changed_dependency(self):
        s = HARNESS.read_text()
        start = s.index('if (( RUN_ONLY )); then\n')
        block = s[start:s.index('\nlowprio()', start)]
        debug = HERE/'xdev_ext_mech_zc_debug.py'
        with tempfile.TemporaryDirectory() as t:
            p = Path(t); (p/'evidence').mkdir()
            (p/'.config').write_text('CONFIG_MODULES=y\n')
            (p/'xdev-ext-source.commit').write_text('b' * 40 + '\n')
            dependency = p/'guest.sh'; dependency.write_bytes((HERE/'xdev_ext_fence_guest.sh').read_bytes())
            manifest = subprocess.check_output(['sha256sum', str(dependency)], text=True)
            (p/'xdev-ext-artifacts.sha256').write_text(manifest)
            subprocess.run(['python3', str(debug), 'record', str(p/'.config'), str(p/'xdev-ext-debug-profile.json'), '0'], check=True)
            cmd = f'RUN_ONLY=1; EVAL_SESSION=0; DEBUG_LOCKING=0; DEBUG_HELPER={debug}; BUILD={p}; EV={p}/evidence; SOURCE_COMMIT=' + 'b' * 40 + ';\n' + block
            r = subprocess.run(['bash', '-eu', '-c', cmd], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            dependency.write_text(dependency.read_text() + '# changed dependency\n')
            r = subprocess.run(['bash', '-eu', '-c', cmd], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('artifact hash mismatch', r.stderr)

    def test_guest_rejects_invalid_arguments_without_loading(self):
        for args in ([], ['/never-a-module', 'bad', '8'], ['/never-a-module', NONCE, '9']):
            r = subprocess.run(['sh', str(HERE/'xdev_ext_fence_guest.sh'), *args], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)

    def test_guest_check_before_network_and_ce(self):
        s = HARNESS.read_text()
        self.assertIn('--fence-check)', s)
        self.assertIn('kmake M="$FENCE_OUT"', s)
        self.assertIn('verify_fence_identity', s)
        init = s[s.index("cat >\"$ROOT/init\" <<'GUEST'"):]
        self.assertLess(init.index('sh /opt/xdev_ext/xdev_ext_fence_guest.sh'), init.index('ip link set lo up'))
        guest = (HERE/'xdev_ext_fence_guest.sh').read_text()
        self.assertNotIn('python', guest.lower())
        self.assertNotIn('mode=time', guest)
        for value in ('fail_alloc_at=1', 'fail_alloc_at=2', 'fail_callback_at=1', 'fail_callback_at=2'):
            self.assertIn(value, guest)
        self.assertIn('run_nonce=', guest)
        self.assertIn('rmmod lifecycle_bench', guest)


if __name__ == '__main__':
    unittest.main()
