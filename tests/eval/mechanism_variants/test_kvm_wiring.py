# SPDX-License-Identifier: GPL-2.0
"""Actual shell option refusal paths, no KVM execution claim."""
from pathlib import Path
import subprocess
import unittest
HERE=Path(__file__).resolve().parent
HARNESS=HERE.parents[2]/'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'
class Wiring(unittest.TestCase):
    def test_mode_refuses_other_campaigns_before_touching_scratch(self):
        for args in (['--ce-sim'],['--compat'],['--reliable'],['--fault','drop-middle'],['--groups','257']):
            run=subprocess.run(['bash',str(HARNESS),'--mechanism-variants',*args],capture_output=True,text=True)
            self.assertEqual(run.returncode,2)
            self.assertIn('mechanism-variants',run.stderr)
            self.assertNotIn('unknown option',run.stderr)
    def test_timeout_requires_dedicated_mode(self):
        run=subprocess.run(['bash',str(HARNESS),'--mechanism-variants-timeout','300'],capture_output=True,text=True)
        self.assertEqual(run.returncode,2)
        self.assertIn('requires --mechanism-variants',run.stderr)
class CaptureWiring(unittest.TestCase):
    def shell(self, code, root, **variables):
        import os
        env=dict(os.environ, **{key:str(value) for key,value in variables.items()})
        return subprocess.run(['bash','-euc',code],cwd=root,env=env,
                              capture_output=True,text=True,timeout=20)

    def test_actual_qemu_argument_builder_gives_e2_its_own_port(self):
        import tempfile
        text=HARNESS.read_text()
        # Execute the production argument builder, without starting QEMU.
        start=text.index('destination_drive=')
        stop=text.index("printf '%q '", start)
        fragment=text[start:stop]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'.config').write_text('CONFIG_VIRTIO_CONSOLE=y\n')
            for mode in ('e2','fanout'):
                with self.subTest(mode=mode):
                    run=self.shell('wire_args=();\n'+fragment+'\nprintf "%s\\n" "${args[@]}"', root,
                        SCRATCH=root,BUILD=root,EV=root,DESTINATION_READONLY=0,
                        MECHANISM_VARIANTS=int(mode=='e2'),LIFECYCLE=int(mode=='fanout'),COMPAT=0,PEER=0)
                    self.assertEqual(run.returncode,0,run.stderr)
                    args=run.stdout.splitlines()
                    if mode=='e2':
                        self.assertIn('virtio-serial-pci',args)
                        self.assertIn('file,id=e2_artifacts,path='+str(root/'e2-artifacts.raw.log'),args)
                        self.assertIn('virtserialport,chardev=e2_artifacts,name=xdev-e2-artifacts',args)
                        self.assertNotIn('virtserialport,chardev=fanout_native,name=xdev-fanout-native',args)
                    else:
                        self.assertIn('virtserialport,chardev=fanout_native,name=xdev-fanout-native',args)

    def test_actual_qemu_e2_capture_path_resolves_evidence_aliases(self):
        import tempfile
        text=HARNESS.read_text()
        start=text.index('destination_drive=')
        stop=text.index("printf '%q '",start)
        fragment=text[start:stop]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'.config').write_text('CONFIG_VIRTIO_CONSOLE=y\n')
            evidence=root/'actual evidence'; evidence.mkdir()
            for name in ('evidence-alias','evidence alias with spaces'):
                with self.subTest(alias=name):
                    alias=root/name; alias.symlink_to(evidence,target_is_directory=True)
                    run=self.shell('wire_args=();\n'+fragment+'\nprintf "%s\\n" "${args[@]}"',root,
                        SCRATCH=root,BUILD=root,EV=alias,DESTINATION_READONLY=0,
                        MECHANISM_VARIANTS=1,LIFECYCLE=0,COMPAT=0,PEER=0)
                    self.assertEqual(run.returncode,0,run.stderr)
                    args=run.stdout.splitlines()
                    self.assertEqual(args[args.index('-chardev')+1],
                        'file,id=e2_artifacts,path='+str(evidence.resolve()/'e2-artifacts.raw.log'))

    def test_actual_build_config_calls_enable_e2_virtio_console(self):
        import tempfile
        text=HARNESS.read_text(); start=text.index('\tcfg()')
        stop=text.index('\tkmake olddefconfig',start)
        fragment=text[start:stop]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'scripts').mkdir(); config=root/'scripts/config'
            # Replace only the external scripts/config executable. The actual
            # production cfg function and conditional config calls execute.
            config.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$CONFIG_CALLS"\n')
            config.chmod(0o700)
            run=self.shell(fragment,root,SRC=root,BUILD=root,MECHANISM_VARIANTS=1,
                CE_SIM=0,PROVIDER_CASE='normal',LIFECYCLE=0,FENCE_CHECK=0,SOCKET_REQUIRED=0,
                COMPAT=0,PEER=0,XDOMAIN=0,DEBUG_LOCKING=1,CONFIG_CALLS=root/'calls')
            self.assertEqual(run.returncode,0,run.stderr)
            calls=(root/'calls').read_text().splitlines()
            self.assertTrue(any(calls[i:i+2]==['-e','VIRTIO_CONSOLE'] for i in range(len(calls)-1)),
                            'actual E2 build never enables VIRTIO_CONSOLE')

    def identity_fixture(self, root):
        import hashlib
        import tempfile
        tools=root/'tools'; out=tools/'e2'; out.mkdir(parents=True)
        build=root/'build'; build.mkdir(); ev=root/'evidence'; ev.mkdir()
        src=root/'kernel'; hook=src/'include/trace/events/xdev_ext.h'
        hook.parent.mkdir(parents=True); hook.write_text('xdev-native-v1-nvme-xsk-batch\n')
        symbols=('TRACING','FTRACE','BPF_EVENTS','XDEV_EXT_MECH','XDEV_EXT_MECH_ZEROCOPY')
        (build/'.config').write_text(''.join('CONFIG_'+s+'=y\n' for s in symbols))
        (build/'xdev-ext-e2-mode.txt').write_text('mechanism_variants=1\nsource_commit=host-fixture\n')
        def receipt(path): return hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path)+'\n'
        artifacts=[]
        for name in ('mv_ctl','mv_sink','bpftool','nvme_reverse.bpf.o','nvme_gray.bpf.o',
                     'guest_run.sh','trace_ctl.sh','kvm_guest.sh','export_artifacts.sh'):
            p=out/name; p.write_text('host identity fixture '+name+'\n'); artifacts.append(p)
        (build/'xdev-ext-e2-sources.sha256').write_text(receipt(hook))
        artifacts += [build/'xdev-ext-e2-mode.txt',build/'xdev-ext-e2-sources.sha256']
        # The run-only identity contract also requires a retained actual-core
        # export. Require the real GCC exporter to succeed before indexing it.
        parent=Path(tempfile.mkdtemp(prefix='software-old-ticket.',dir=out))
        capture=parent/'capture'
        subprocess.run(['python3','-B',str(HERE/'export_old_ticket.py'),
                        str(HERE.parents[2]/'kernel'),str(capture),'--cc','gcc'],
                       check=True,capture_output=True,text=True,timeout=60)
        selected=build/'xdev-ext-e2-old-ticket.path'
        selected.write_text(str(capture.resolve())+'\n')
        artifacts += [selected,*sorted(capture.iterdir())]
        (build/'xdev-ext-artifacts.sha256').write_text(''.join(receipt(p) for p in artifacts))
        return dict(SRC=src,TOOLS=tools,BUILD=build,EV=ev,SOURCE_COMMIT='host-fixture')

    def test_run_only_identity_rejects_old_config_without_virtio_console(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); env=self.identity_fixture(root)
            code='source "$E2_MODE"\ne2_verify_identity\n'
            env['E2_MODE']=HERE/'kvm_mode.sh'
            old=self.shell(code,root,**env)
            self.assertNotEqual(old.returncode,0,'old E2 config silently reused without port driver')
            config=env['BUILD']/'.config'; config.write_text(config.read_text()+'CONFIG_VIRTIO_CONSOLE=y\n')
            current=self.shell(code,root,**env)
            self.assertEqual(current.returncode,0,current.stderr)

    def test_actual_guest_forces_virtio_and_keeps_export_failure(self):
        import shutil
        import tempfile
        text=(HERE/'kvm_guest.sh').read_text()
        fragment=text[text.index('export E2_PRIVATE_GUEST='):text.index('trap finish_e2 EXIT')]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); out=root/'capture'; out.mkdir(); binary=root/'bin'; binary.mkdir()
            (root/'sys').mkdir(); (root/'dev').mkdir()
            shutil.copyfile(HERE/'export_artifacts.sh',binary/'export_artifacts.sh')
            for name in ('nvme_reverse.bpf.o','nvme_gray.bpf.o','nxp_mech.bpf.o','nvme_s0.bpf.o'):
                (binary/name).write_bytes(b'host fixture, never loaded')
            # Force the EXIT path through the real exporter with no named
            # device. Ordinary filesystem copy failures are incidental and
            # cannot replace the required export failure or payload isolation.
            run=self.shell(fragment+'\nfinish_e2\n',root,bin=binary,out=out,
                source_block='/dev/e2-nonexistent-host-fixture',
                E2_PORT_SYSFS=root/'sys',E2_DEV_ROOT=root/'dev',E2_EXPORT_TRANSPORT='serial')
            self.assertNotEqual(run.returncode,0,'actual E2 guest fell back to serial')
            self.assertIn('E2_GUEST_CAPTURE_EXIT=1',run.stdout)
            self.assertNotIn('E2_ARTIFACT_DATA',run.stdout)


class FinalCaptureGate(unittest.TestCase):
    MARKERS=('XDEV_EXT_ZC_GUEST_EXIT=0\nE2_GUEST_CAPTURE_EXIT=0\n'
             'E2_EXECUTION_COMPLETE=PASS scope=guest-correctness performance_claim=none\n')

    def fixture(self, root):
        import os
        scratch=root/'scratch'; scratch.mkdir(); ev=root/'evidence'; ev.mkdir()
        for stem in ('source','destination'):
            for suffix in ('.raw','-before.raw'):
                (scratch/(stem+suffix)).write_bytes(b'unchanged host-only disk fixture')
        source=root/'artifacts'; source.mkdir()
        (source/'source-window.bin').write_bytes(bytes(range(256))*128)
        run=subprocess.run(['sh',str(HERE/'export_artifacts.sh'),str(source)],
                           env=dict(os.environ,E2_PRIVATE_GUEST='yes'),capture_output=True,check=True)
        (ev/'e2-artifacts.raw.log').write_bytes(run.stdout)
        (ev/'guest.log').write_text('Linux boot\n'+self.MARKERS)
        (ev/'qemu.exit').write_text('0\n')
        # Deliberately wrong source identity is a later-boundary sentinel,
        # never a fabricated successful capture or build.
        build=scratch/'build'; build.mkdir()
        (build/'xdev-ext-source.commit').write_text('deliberately-invalid-source-identity\n')
        (build/'.config').write_text('CONFIG_VIRTIO_CONSOLE=y\n')
        (ev/'qemu.command').write_text('qemu-system-x86_64 -device virtio-serial-pci '
            '-chardev file,id=e2_artifacts,path='+str(ev/'e2-artifacts.raw.log')+' '
            '-device virtserialport,chardev=e2_artifacts,name=xdev-e2-artifacts\n')
        return scratch,ev,run.stdout

    def validate(self, scratch, ev):
        return subprocess.run(['python3','-B',str(HERE/'validate_e2.py'),'--source-root',str(HERE.parents[2]),
                               '--scratch',str(scratch),'--evidence',str(ev)],
                              text=True,capture_output=True,timeout=20)

    def test_real_final_validator_feeds_port_bytes_to_strict_extractor(self):
        import importlib.util
        import sys
        import tempfile
        # Observe the real extraction boundary, retaining its implementation
        # and exceptions. This catches a strict helper never used by E2.
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); scratch,ev,wire=self.fixture(root)
            sys.path.insert(0,str(HERE))
            try:
                spec=importlib.util.spec_from_file_location('e2_actual_gate',HERE/'validate_e2.py')
                module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
                original=module.extract; calls=[]
                def observe(*args, **kwargs):
                    calls.append((args,kwargs))
                    return original(*args,**kwargs)
                module.extract=observe
                with self.assertRaises((OSError,ValueError)):
                    module.validate(HERE.parents[2],scratch,ev)
                self.assertTrue(calls,'actual validator never called the bounded extractor')
                self.assertTrue(calls[0][0][0] == wire.decode('ascii'),
                                 'actual E2 gate still extracts console instead of dedicated port')
                self.assertIs(calls[0][1].get('strict'),True,
                              'actual E2 gate did not enable strict transport validation')
            finally:
                sys.path.pop(0)

    def test_clean_transport_reaches_later_source_identity_gate(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); scratch,ev,wire=self.fixture(root)
            run=self.validate(scratch,ev)
            self.assertNotEqual(run.returncode,0)
            self.assertIn('actual build source SHA differs',run.stderr,
                          'valid dedicated transport did not reach independent source gate')

    def test_final_gate_checks_whole_console_rcu_and_shared_diagnostics(self):
        import tempfile
        reports=('rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:',
                 'rcu: rcu_preempt kthread starved for 26027 jiffies!',
                 'rcu: INFO: rcu_preempt self-detected stall on CPU',
                 'rcu: INFO: rcu_sched detected expedited stalls on CPUs/tasks:',
                 'INFO: lockdep is turned off.')
        for diagnostic in reports:
            for position in ('before','during','after'):
                with self.subTest(diagnostic=diagnostic,position=position), tempfile.TemporaryDirectory() as td:
                    root=Path(td); scratch,ev,wire=self.fixture(root)
                    lines=['Linux boot\n','E2_EXPORT_STARTED\n',self.MARKERS]
                    lines.insert({'before':0,'during':2,'after':3}[position],diagnostic+'\n')
                    (ev/'guest.log').write_text(''.join(lines))
                    before=(ev/'guest.log').read_bytes(),(ev/'e2-artifacts.raw.log').read_bytes()
                    run=self.validate(scratch,ev)
                    self.assertNotEqual(run.returncode,0)
                    self.assertRegex(run.stderr,r'(?i)diagnostic|rcu|lockdep')
                    self.assertFalse((ev/'e2-validation.json').exists())
                    self.assertEqual(before,((ev/'guest.log').read_bytes(),(ev/'e2-artifacts.raw.log').read_bytes()))

    def test_completion_markers_never_replace_real_strict_transport(self):
        import tempfile
        for case in ('missing','empty','truncated','polluted','trailing','duplicate','hash','uart','symlink'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                root=Path(td); scratch,ev,wire=self.fixture(root); port=ev/'e2-artifacts.raw.log'
                if case=='missing': port.unlink()
                elif case=='empty': port.write_bytes(b'')
                elif case=='truncated': port.write_bytes(wire[:wire.rindex(b'E2_ARTIFACT_SET_END')])
                elif case=='polluted': port.write_bytes(b'Linux printk pollution\n'+wire)
                elif case=='trailing': port.write_bytes(wire+b'trailing junk\n')
                elif case=='duplicate': port.write_bytes(wire+wire)
                elif case=='hash': port.write_bytes(wire.replace(b'E2_ARTIFACT_DATA AAECAw',b'E2_ARTIFACT_DATA BAECAw',1))
                elif case=='uart': (ev/'guest.log').write_bytes(self.MARKERS.encode()+wire)
                elif case=='symlink':
                    target=root/'wire'; port.rename(target); port.symlink_to(target)
                before=(ev/'guest.log').read_bytes()
                run=self.validate(scratch,ev)
                self.assertNotEqual(run.returncode,0,case)
                self.assertRegex(run.stderr,r'(?i)artifact|transport|symlink|uart|serial|protocol|frame')
                self.assertFalse((ev/'e2-validation.json').exists())
                self.assertEqual((ev/'guest.log').read_bytes(),before)


if __name__=='__main__': unittest.main()
