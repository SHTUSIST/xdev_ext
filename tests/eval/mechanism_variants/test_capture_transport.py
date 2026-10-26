# SPDX-License-Identifier: GPL-2.0
"""Execute capture/transport boundaries on host files, never guest evidence."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class CaptureTransport(unittest.TestCase):
    def run_script(self, name, args, env):
        return subprocess.run(['sh', str(HERE/name), *map(str, args)],
                              env=dict(os.environ, E2_PRIVATE_GUEST='yes', **env),
                              capture_output=True, timeout=30)

    def port(self, root, index, name='xdev-e2-artifacts', device=True):
        port = root/'sys'/f'vport0p{index}'
        port.mkdir(parents=True)
        (port/'name').write_text(name+'\n')
        dev = root/'dev'/port.name
        if device:
            dev.touch()
        return dev

    def export_fixture(self, root):
        source = root/'source'; source.mkdir()
        (root/'dev').mkdir()
        (root/'sys').mkdir()
        (source/'payload.bin').write_bytes(bytes(range(256))*12289)
        env = dict(E2_EXPORT_TRANSPORT='virtio', E2_PORT_SYSFS=str(root/'sys'),
                   E2_DEV_ROOT=str(root/'dev'))
        return source, env

    def test_named_port_exports_three_mib_without_uart_payload(self):
        # Routing back to stdout loses isolation from printk and must fail here.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); source, env = self.export_fixture(root)
            other = self.port(root, 0, 'xdev-fanout-native')
            other.write_bytes(b'unchanged-other-channel')
            target = self.port(root, 1)
            run = self.run_script('export_artifacts.sh', [source], env)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            self.assertFalse(b'E2_ARTIFACT_DATA' in run.stdout, 'artifact payload leaked to UART/stdout')
            self.assertEqual(other.read_bytes(), b'unchanged-other-channel')
            spec = importlib.util.spec_from_file_location('capture_artifacts', HERE/'artifacts.py')
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            module.extract(target.read_text('ascii'), root/'capture', strict=True)
            self.assertEqual((root/'capture/payload.bin').read_bytes(),
                             (source/'payload.bin').read_bytes())

    def test_unusable_named_port_fails_without_fallback_or_device_creation(self):
        for case in ('missing', 'wrong', 'multiple', 'sysfs-only', 'unwritable', 'symlink'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                root = Path(td); source, env = self.export_fixture(root)
                if case == 'wrong':
                    self.port(root, 0, 'xdev-fanout-native')
                elif case == 'multiple':
                    self.port(root, 0); self.port(root, 1)
                elif case == 'sysfs-only':
                    self.port(root, 0, device=False)
                elif case == 'unwritable':
                    self.port(root, 0).chmod(0o400)
                elif case == 'symlink':
                    outside = root/'outside'; outside.write_bytes(b'do-not-touch')
                    self.port(root, 0, device=False).symlink_to(outside)
                before = {p.name: p.read_bytes() for p in (root/'dev').iterdir()}
                run = self.run_script('export_artifacts.sh', [source], env)
                self.assertNotEqual(run.returncode, 0, case)
                self.assertFalse(b'E2_ARTIFACT_DATA' in run.stdout, 'artifact payload leaked to UART/stdout')
                self.assertEqual({p.name: p.read_bytes() for p in (root/'dev').iterdir()}, before)
                if case == 'symlink':
                    self.assertEqual(outside.read_bytes(), b'do-not-touch')

    def trace_fixture(self, root):
        tracefs = root/'tracefs'; out = root/'capture'; shims = root/'bin'
        out.mkdir(); shims.mkdir(); (tracefs/'instances').mkdir(parents=True)
        fmt = tracefs/'events/xdev_ext/native_event/format'
        fmt.parent.mkdir(parents=True); fmt.write_text('name: native_event\nID: 999\n')
        # tracefs creates control files on mkdir and removes them on rmdir.
        # This shim replaces that external filesystem behavior only.
        (shims/'mkdir').write_text('''#!/usr/bin/env python3
import os,pathlib,subprocess,sys
subprocess.run(['/bin/mkdir',*sys.argv[1:]],check=True)
p=pathlib.Path(sys.argv[-1])
if p.parent == pathlib.Path(os.environ['E2_TRACEFS_ROOT'])/'instances':
    for name,value in {'current_tracer':'function\\n','trace_clock':'local [mono] global\\n','buffer_size_kb':'1\\n','tracing_on':'0\\n','trace':'','trace_marker':''}.items():
        (p/name).write_text(value)
    (p/'available_tracers').write_text('nop function function_graph\\n')
    e=p/'events/xdev_ext/native_event'; e.mkdir(parents=True)
    (e/'enable').write_text('0\\n')
    (e/'filter').write_text('none\\n')
    (e/'format').write_text('name: native_event\\nID: 999\\n')
    for cpu in range(4):
        c=p/'per_cpu'/('cpu'+str(cpu)); c.mkdir(parents=True)
        (c/'stats').write_text('entries: 0\\noverrun: 0\\ncommit overrun: 0\\ndropped events: 0\\n')
''')
        (shims/'rmdir').write_text('''#!/usr/bin/env python3
import os,pathlib,shutil,sys
p=pathlib.Path(sys.argv[1])
assert p.parent == pathlib.Path(os.environ['E2_TRACEFS_ROOT'])/'instances'
shutil.rmtree(p)
''')
        for path in shims.iterdir(): path.chmod(0o700)
        return tracefs, out, dict(E2_TRACEFS_ROOT=str(tracefs), PATH=str(shims)+':'+os.environ['PATH'])

    def test_trace_begin_budget_and_actual_capture_settings(self):
        for name in ('reverse', 'gray', 'outside_window', 'reserved_cdw2'):
            with self.subTest(case=name), tempfile.TemporaryDirectory() as td:
                root = Path(td); tracefs, out, env = self.trace_fixture(root)
                run = self.run_script('trace_ctl.sh', ['begin', name, out], env)
                self.assertEqual(run.returncode, 0, run.stderr.decode())
                instance = Path((out/('.'+name+'.trace-instance')).read_text().strip())
                self.assertGreaterEqual(int((instance/'buffer_size_kb').read_text())*1024, 8806*256)
                self.assertLessEqual(int((instance/'buffer_size_kb').read_text()), 8192)
                self.assertEqual((instance/'current_tracer').read_text().strip(), 'nop')
                self.assertEqual((instance/'trace_clock').read_text().strip(), 'mono')
                self.assertEqual((instance/'events/xdev_ext/native_event/filter').read_text(), 'none\n')
                config = (out/(name+'-trace-config.txt')).read_text()
                for actual in ('4096', 'nop', 'mono'):
                    self.assertIn(actual, config)

    def test_trace_end_rejects_each_loss_counter_and_preserves_raw_files(self):
        for counter in (None, 'overrun', 'commit overrun', 'dropped events'):
            with self.subTest(counter=counter), tempfile.TemporaryDirectory() as td:
                root = Path(td); tracefs, out, env = self.trace_fixture(root)
                begin = self.run_script('trace_ctl.sh', ['begin', 'gray', out], env)
                self.assertEqual(begin.returncode, 0, begin.stderr.decode())
                instance = Path((out/'.gray.trace-instance').read_text().strip())
                raw = b'host-fixture native_event: host-only-loss-control\n'
                (instance/'trace').write_bytes(raw)
                if counter:
                    stats = instance/'per_cpu/cpu3/stats'
                    stats.write_text(stats.read_text().replace(counter+': 0\n', counter+': 1\n'))
                end = self.run_script('trace_ctl.sh', ['end', 'gray', out], env)
                self.assertEqual(end.returncode == 0, counter is None, end.stderr.decode())
                self.assertEqual((out/'gray.trace').read_bytes(), raw)
                archived = (out/'gray-trace-stats.txt').read_text()
                for cpu in range(4): self.assertIn(f'cpu{cpu}/stats', archived)
                if counter: self.assertIn(counter+': 1', archived)


if __name__ == '__main__': unittest.main(verbosity=2)
