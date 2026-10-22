#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the optional compatibility guest's exact-build identity gate."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HARNESS = Path(__file__).with_name('xdev_ext_mech_zc_kvm.sh')
PRELOAD_GUEST = HARNESS.parent.parent/'xdev_ext_preload/xdev_ext_preload_mech_guest.sh'
SYMBOLS = ('XDEV_EXT_MECH_SOCKET', 'IO_URING_XDEV_EXT_IAA', 'EXT4_FS', 'VIRTIO_BLK')
ARTIFACTS = ('socket/socket_runtime', 'socket/ce_observe.bpf.o',
             'tools/socket_sink.bpf.o', 'preload/libio_uring_unified.so',
             'preload/xdev_ext_preload_mech_workload',
             'preload/xdev_ext_preload_socket_smoke',
             'preload/xdev_ext_preload_db_workload')


class CompatibilityIdentity(unittest.TestCase):
    def gate(self, missing_symbol=None, missing_file=None, missing_record=None):
        match = re.search(r'^verify_compat_identity\(\) \{\n.*?^\}', HARNESS.read_text(), re.M | re.S)
        self.assertIsNotNone(match, 'compatibility guest must reject stale builds')
        with tempfile.TemporaryDirectory(prefix='xdev-compat-identity-') as directory:
            root = Path(directory)
            build = root/'build'
            build.mkdir()
            (build/'.config').write_text(''.join(f'CONFIG_{s}=y\n' for s in SYMBOLS if s != missing_symbol))
            records = []
            for name in ARTIFACTS:
                path = root/name
                path.parent.mkdir(exist_ok=True)
                if name != missing_file:
                    path.write_text('identity fixture\n')
                if name != missing_record:
                    records.append('0'*64+'  '+str(path))
            (build/'xdev-ext-artifacts.sha256').write_text('\n'.join(records)+'\n')
            return subprocess.run(['bash', '-euc', match.group()+'\nverify_compat_identity'],
                env=dict(os.environ, BUILD=str(build), TOOLS=str(root/'tools'),
                         SOCKET_OUT=str(root/'socket'), PRELOAD_OUT=str(root/'preload')),
                text=True, capture_output=True)

    def test_complete(self):
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_config_required(self):
        for name in SYMBOLS:
            with self.subTest(name=name):
                self.assertNotEqual(self.gate(missing_symbol=name).returncode, 0)

    def test_each_artifact_and_identity_required(self):
        for name in ARTIFACTS:
            with self.subTest(name=name):
                self.assertNotEqual(self.gate(missing_file=name).returncode, 0)
                self.assertNotEqual(self.gate(missing_record=name).returncode, 0)


class CompatibilityFailureLogs(unittest.TestCase):
    """Run the real guest shell; only unavailable custom-kernel apps are fixtures."""
    names = ('compat-udp.log', 'mech-socket-base.log', 'mech-ce-socket-base.log',
             'mech-socket-lifecycle.log', 'mech-ce-socket-lifecycle.log',
             'mech-socket-threads.log', 'mech-ce-socket-threads.log',
             'mech-socket-processes.log', 'mech-ce-socket-processes.log',
             'compat-dio-off.log', 'compat-dio-on.log')

    def run_guest(self, fail='', bad_udp=False, shell=('sh',), cat_failure=False):
        with tempfile.TemporaryDirectory(prefix='xdev-compat-logs-') as directory:
            root = Path(directory)
            bin_dir = root/'bin'
            bin_dir.mkdir()
            if cat_failure:
                (bin_dir/'cat').write_text('#!/bin/sh\nexit 53\n')
                (bin_dir/'cat').chmod(0o700)
            # A harmless preload library lets these shell fixtures run under
            # the exact LD_PRELOAD environment without loader warnings.
            subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o',
                            str(bin_dir/'libio_uring_unified.so')],
                           input='int compat_log_fixture;\n', text=True, check=True,
                           capture_output=True)
            app = '''#!/bin/sh
case "${0##*/}" in
 xdev_ext_preload_socket_smoke) name=compat-udp.log ;;
 xdev_ext_preload_mech_workload)
  if [ -n "${XDEV_EXT_PRELOAD_SOCKET_CE_DEVICE:-}" ]; then arm=ce-socket; else arm=socket; fi
  mode=$1
  if [ "$mode" = concurrency ]; then
   if [ "$3" = 1 ]; then mode=threads; else mode=processes; fi
  fi
  name=mech-$arm-$mode.log ;;
 *) if [ "$XDEV_EXT_PRELOAD_ENABLED" = 1 ]; then mode=on; else mode=off; fi
  name=compat-dio-$mode.log ;;
esac
echo "fixture workload=$name"
if [ "$FAIL_STEP" = "$name" ]; then printf 'fixture failed=%s' "$name" >&2; exit 37; fi
case "$name" in
 compat-udp.log)
  if [ "$BAD_UDP" = 0 ]; then echo 'XDEV_EXT_TRANSPARENT_SOCKET_PAYLOAD=PASS sends=3 bytes=25'; fi
  echo 'XDEV_EXT_PRELOAD_REPORT custom_send_count=3 custom_send_bytes=25 custom_send_errors=0' ;;
 compat-dio-*) echo 'XDEV_EXT_DB_WORKLOAD_RESULT=PASS fixture=equal' ;;
esac
'''
            for name in ('xdev_ext_preload_socket_smoke',
                         'xdev_ext_preload_mech_workload', 'xdev_ext_preload_db_workload'):
                path = bin_dir/name
                path.write_text(app)
                path.chmod(0o700)
            return subprocess.run([*shell, str(PRELOAD_GUEST), str(bin_dir),
                                   str(root/'logs'), str(root/'file')],
                env=dict(os.environ, PATH=str(bin_dir)+':'+os.environ['PATH'],
                         FAIL_STEP=fail, BAD_UDP=str(int(bad_udp)),
                         XDEV_EXT_PRELOAD_SOCKET_CE_DEVICE='/dev/fixture-unused',
                         XDEV_EXT_PRELOAD_SOCKET_CE_ADDR='0',
                         XDEV_EXT_PRELOAD_SOCKET_CE_LEN='65536',
                         XDEV_EXT_PRIVATE_FIXTURE_SECRET='must-not-print-env'),
                capture_output=True, text=True, timeout=20)

    def assert_framed_once(self, result, names):
        self.assertEqual(result.stderr, '')
        for name in self.names:
            count = int(name in names)
            self.assertEqual(result.stdout.splitlines().count(
                'XDEV_EXT_PRELOAD_LOG_BEGIN name='+name), count, result.stdout)
            self.assertEqual(result.stdout.splitlines().count(
                'XDEV_EXT_PRELOAD_LOG_END name='+name), count, result.stdout)
        self.assertNotIn('must-not-print-env', result.stdout)

    def test_success_publishes_each_log_once(self):
        result = self.run_guest()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assert_framed_once(result, self.names)
        self.assertEqual(result.stdout.count('XDEV_EXT_PRELOAD_GUEST_EXECUTION=PASS'), 1)

    def test_each_failed_workload_keeps_logs_and_original_status(self):
        for index, name in enumerate(self.names):
            with self.subTest(workload=name):
                result = self.run_guest(fail=name)
                self.assertEqual(result.returncode, 37, result.stdout+result.stderr)
                self.assert_framed_once(result, self.names[:index+1])
                self.assertIn('fixture failed='+name, result.stdout)
                self.assertIn('XDEV_EXT_PRELOAD_STEP=FAIL name='+name+' exit=37', result.stdout)
                self.assertNotIn('XDEV_EXT_PRELOAD_GUEST_EXECUTION=PASS', result.stdout)

    def test_failed_content_check_keeps_log_and_failure(self):
        result = self.run_guest(bad_udp=True)
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assert_framed_once(result, self.names[:1])
        self.assertIn('XDEV_EXT_PRELOAD_STEP=FAIL name=compat-udp.log exit=1', result.stdout)
        self.assertNotIn('XDEV_EXT_PRELOAD_GUEST_EXECUTION=PASS', result.stdout)

    def test_busybox_guest_shell_preserves_failure(self):
        result = self.run_guest(fail='mech-ce-socket-base.log',
                                shell=('/bin/busybox', 'sh'))
        self.assertEqual(result.returncode, 37, result.stdout+result.stderr)
        self.assert_framed_once(result, self.names[:3])
        self.assertIn('XDEV_EXT_PRELOAD_STEP=FAIL name=mech-ce-socket-base.log exit=37',
                      result.stdout)

    def test_log_read_failure_is_nonzero_without_masking_workload_failure(self):
        result = self.run_guest(cat_failure=True)
        self.assertEqual(result.returncode, 53, result.stdout+result.stderr)
        self.assertIn('XDEV_EXT_PRELOAD_STEP=FAIL name=publish-log:compat-udp.log exit=53',
                      result.stdout)
        self.assertNotIn('XDEV_EXT_PRELOAD_GUEST_EXECUTION=PASS', result.stdout)
        result = self.run_guest(fail='compat-udp.log', cat_failure=True)
        self.assertEqual(result.returncode, 37, result.stdout+result.stderr)
        self.assertIn('XDEV_EXT_PRELOAD_STEP=FAIL name=compat-udp.log exit=37', result.stdout)
        self.assertNotIn('XDEV_EXT_PRELOAD_GUEST_EXECUTION=PASS', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
