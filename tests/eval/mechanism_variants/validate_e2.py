#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Validate actual E2-only KVM transport, CREATE, native trace and full bytes.

Never substitutes fixture rows for guest evidence. The old-ticket observation
is separately archived actual-core host-fixture evidence from the same source.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import shlex
from artifacts import extract
from decode_trace import audit_collection,decode,decode_negative
from guard import verify as verify_guards
from driver_audit import audit as audit_driver
from inspect_create import inspect


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for piece in iter(lambda:stream.read(1024*1024),b''): h.update(piece)
    return h.hexdigest()


def require(condition,message):
    if not condition: raise ValueError(message)


def write_derived(path,data):
    if not isinstance(data,bytes): data=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode()
    if path.exists(): require(path.read_bytes()==data,'changed archived derived artifact: '+path.name)
    else: path.write_bytes(data)


def validate(source,scratch,evidence):
    source=source.resolve();scratch=scratch.resolve();evidence=evidence.resolve()
    console=(evidence/'guest.log').read_text()
    # Use the production shared detector on the entire console, including
    # reports emitted before, during, or after artifact export.
    debug_path=source/'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_debug.py'
    debug_spec=importlib.util.spec_from_file_location('e2_debug',debug_path)
    debug=importlib.util.module_from_spec(debug_spec);debug_spec.loader.exec_module(debug)
    debug.check_console(console)
    require('E2_ARTIFACT_' not in console,'artifact framing/payload found on UART console')
    require((evidence/'qemu.exit').read_text().strip()=='0','QEMU did not exit successfully')
    for marker in ('XDEV_EXT_ZC_GUEST_EXIT=0','E2_GUEST_CAPTURE_EXIT=0',
                   'E2_EXECUTION_COMPLETE=PASS scope=guest-correctness performance_claim=none'):
        require(console.splitlines().count(marker)==1,'missing/duplicate actual completion marker: '+marker)
    require('E2 STOP failed' not in console,'guest STOP diagnostic failure')
    for stem in ('source','destination'):
        before=scratch/(stem+'-before.raw');after=scratch/(stem+'.raw')
        require(before.stat().st_size==after.stat().st_size and sha(before)==sha(after),'whole private '+stem+' image changed')
    capture=evidence/'e2-capture'
    transport=evidence/'e2-artifacts.raw.log'
    require(not transport.is_symlink(),'artifact transport source is a symlink')
    require(transport.is_file() and transport.stat().st_size<=72*1024*1024,'missing/oversized artifact transport')
    stream=transport.read_bytes().decode('ascii')
    with tempfile.TemporaryDirectory(prefix='.e2-reextract-',dir=evidence) as td:
        extracted=Path(td)/'capture'
        files=extract(stream,extracted,strict=True)
        if capture.exists():
            for name,data in files.items(): require((capture/name).read_bytes()==data,'archived guest artifact differs from transport bytes: '+name)
        else:
            capture.mkdir(mode=0o700)
            for name,data in files.items(): (capture/name).write_bytes(data)
    sha_source=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    require((scratch/'build/xdev-ext-source.commit').read_text().strip()==sha_source,'actual build source SHA differs')
    require((scratch/'build/xdev-ext-e2-mode.txt').read_text().splitlines()==['mechanism_variants=1','source_commit='+sha_source],'dedicated build identity missing')
    subprocess.run(['sha256sum','-c',str(scratch/'build/xdev-ext-artifacts.sha256')],check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    subprocess.run(['sha256sum','-c',str(scratch/'build/xdev-ext-e2-sources.sha256')],check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    config_lines=(scratch/'build/.config').read_text().splitlines()
    require('CONFIG_VIRTIO_CONSOLE=y' in config_lines,'E2 kernel lacks built-in virtio console')
    # The archived command is shell-quoted by the harness; parse its actual
    # arguments rather than searching a substring that might occur in a path.
    qemu_args=shlex.split((evidence/'qemu.command').read_text())
    for option,value in (('-device','virtio-serial-pci'),
                         ('-chardev','file,id=e2_artifacts,path='+str(evidence/'e2-artifacts.raw.log')),
                         ('-device','virtserialport,chardev=e2_artifacts,name=xdev-e2-artifacts')):
        require(sum(a==option and b==value for a,b in zip(qemu_args,qemu_args[1:]))==1,
                'missing/ambiguous actual E2 virtio transport argument: '+value)
    for name in ('reverse','gray','outside_window','reserved_cdw2'):
        actual=dict(line.split('=',1) for line in (capture/(name+'-trace-config.txt')).read_text().splitlines())
        clock=actual.get('trace_clock','').split()
        require(actual.get('buffer_size_kb')=='4096' and actual.get('current_tracer')=='nop'
                and ('[mono]' in clock or clock==['mono']),
                'actual trace capture configuration differs: '+name)
    window=(capture/'source-window.bin').read_bytes()
    require(len(window)==32768,'missing complete real source window')
    with (scratch/'source-before.raw').open('rb') as image:
        image.seek(2048*512);require(image.read(32768)==window,'guest source window differs from actual seeded source-before')
    require(int((capture/'source-lba-size.txt').read_text())==512,'target LBA size is not the fixed E2 geometry')
    software=evidence/'e2-software'
    negative=json.loads((software/'old_ticket.json').read_text())
    ledger=json.loads((software/'source.json').read_text())
    require(negative.get('evidence_kind')=='actual-core-host-fixture' and ledger.get('evidence_kind')=='actual-core-host-fixture','old ticket has no explicit software boundary')
    require(ledger['kernel_git_sha']==sha_source,'software completion fixture is from another source SHA')
    for path,digest in ledger['source_sha256'].items(): require(sha(source/'kernel'/path)==digest,'old-ticket production/fixture source changed: '+path)
    raw_old=(software/'old-ticket.log').read_text()
    observations=[json.loads(line.split(' ',1)[1]) for line in raw_old.splitlines() if line.startswith('E2_OLD_TICKET_SNAPSHOT ')]
    require(len(observations)==2 and [x['phase'] for x in observations]==['before','after'],'no actual old-ticket snapshots')
    before,after=observations
    for phase,state in (('before',before),('after',after)):
        require(negative['current_state_'+phase]==state['state'],'old-ticket JSON differs from actual '+phase+' snapshot')
        require(negative['accepted_'+phase]==state['accepted'] and negative['published_'+phase]==state['published'],'old-ticket counters differ from actual snapshot')
    require(negative['old_ticket']==before['old_ticket'] and negative['current_ticket']==before['current_ticket'],'old-ticket identity differs from actual output')
    require(negative['old_ticket']!=negative['current_ticket'] and before['state']==after['state'],'old ticket changed actual custody')
    write_derived(capture/'old-ticket.log',raw_old.encode())
    write_derived(capture/'old-ticket-source.json',ledger)
    runs={};guards={};drivers={};setup=[];policies=[]
    policy_initial=json.loads((capture/'net-policy.initial.json').read_text())
    require(bool(policy_initial),'no actual shared-plan initial map images')
    require('XDEV_EXT_MECH_ATTACH=PASS map=nxp_afxdp_ops ' in (capture/'net-attach.log').read_text(),'shared AF_XDP plan was not attached')
    for variant in ('reverse','gray'):
        create=inspect(capture/(variant+'-create'))
        fmt=(capture/(variant+'-event-format.txt')).read_text();stats=(capture/(variant+'-trace-stats.txt')).read_text()
        audit_collection(fmt,stats)
        audit=dict(create_session=create['actual_session_id'],excluded=[])
        raw_trace=(capture/(variant+'.trace')).read_text()
        events=decode(raw_trace,'nvme_nic',create['actual_session_id'],audit)
        drivers[variant]=audit_driver(raw_trace,create['actual_session_id'])
        audit['session_zero_driver_audit']=variant+'-driver-audit.json'
        write_derived(capture/(variant+'-driver-audit.json'),drivers[variant])
        ids=[e['request_id'] for e in events if e['event']=='provider_accept']
        require(len(ids)==16 and ids==list(range(ids[0],ids[0]+16)) and ids[0] in (0,1),'actual callback sequence is not sixteen consecutive IDs')
        programs=json.loads((capture/(variant+'-programs.json')).read_text())
        chosen=[p for p in programs if p.get('name')=='mv_nvme_build' and p.get('type')=='struct_ops']
        require(len(chosen)==1 and chosen[0]['id']>0,'actual loaded variant BUILD program is missing/ambiguous')
        maps=json.loads((capture/(variant+'-maps.json')).read_text())
        attached_maps=[m['id'] for m in maps if m.get('name')=='mv_nvme_ops' and m.get('type')=='struct_ops']
        links=json.loads((capture/(variant+'-links.json')).read_text())
        require(len(attached_maps)==1 and any(l.get('type')=='struct_ops' and l.get('map_id')==attached_maps[0] for l in links),'selected NVMe struct_ops map has no actual link')
        require('XDEV_EXT_MECH_ATTACH=PASS map=mv_nvme_ops ' in (capture/(variant+'-attach.log')).read_text(),'actual selected attach did not return success')
        require((capture/(variant+'-verifier.log')).stat().st_size>0,'actual successful verifier buffer is missing')
        runlog=(capture/(variant+'-run.log')).read_text()
        require(re.search(r'^XDEV_EXT_MECH_READY mode=source .* xsk=zc$',runlog,re.M),'actual sender did not bind AF_XDP ZC')
        require('last_err=0 batches_done=16 batches_abort=0' in runlog,'actual sender final counters failed')
        shared=sorted(p['id'] for p in programs if p.get('name','').startswith('nxp_afxdp_') and p.get('type')=='struct_ops')
        require(bool(shared),'actual shared AF_XDP program identity missing')
        policy=dict(shared_afxdp_program_ids=shared,actual_initial_map_images=policy_initial,nxp_object_sha256=sha(capture/'nxp_mech.bpf.o'))
        layout=create['create']['layout'];st=create['create']['stages'][0]
        config=dict(kernel_git_sha=sha_source,core_sha256=sha(source/'kernel/io_uring/xdev_ext_mech.c'),
                    nvme_provider_sha256=sha(source/'kernel/drivers/nvme/host/xdev_ext_mech_nvme.c'),
                    kernel_image_sha256=sha(scratch/'build/arch/x86/boot/bzImage'),kernel_config_sha256=sha(scratch/'build/.config'),
                    input_sha256=hashlib.sha256(window).hexdigest(),create=create['create'],policy=policy,
                    nvme=dict(window_slba=st['arg0'],window_nlb=st['arg1'],group_bytes=layout['group_bytes'],lba_shift=9,direction='read' if st['direction']==2 else 'unsupported'))
        require(st['class_id']==3 and len(create['create']['stages'])==2 and create['create']['stages'][1]['class_id']==2,'actual CREATE is not the configured NVMe-to-NIC chain')
        guards[variant]=verify_guards(capture/(variant+'-guards'),events,create['actual_session_id'],layout)
        write_derived(capture/(variant+'-events.json'),events);write_derived(capture/(variant+'-events.audit.json'),audit)
        write_derived(capture/(variant+'-create-audit.json'),create);write_derived(capture/(variant+'-guard-audit.json'),guards[variant])
        runs[variant]=dict(configuration=config,request_ids=ids,bpf_object=variant+'.bpf.o',bpf_sha256=sha(capture/(variant+'.bpf.o')),
            verifier_log=variant+'-verifier.log',program_id=chosen[0]['id'],verifier_accepted=True,
            raw_trace=variant+'.trace',events=variant+'-events.json',sink=variant+'-sink.bin')
        setup.append(create['create']);policies.append(policy)
    require(setup[0]==setup[1] and policies[0]==policies[1],'actual A/B CREATE or shared immutable plan changed')
    negatives={'old_ticket':negative}
    for name,expected in (('outside_window',-34),('reserved_cdw2',-1)):
        create=inspect(capture/(name+'-create'))
        audit_collection((capture/(name+'-event-format.txt')).read_text(),(capture/(name+'-trace-stats.txt')).read_text())
        actual=decode_negative((capture/(name+'.trace')).read_text(),create['actual_session_id'])
        require(actual['result']==expected and actual['accepted_during_capture']==0,'actual full-class negative result differs')
        require((capture/(name+'-exit.txt')).read_text().strip()!='0','illegal class plan unexpectedly returned success')
        negatives[name]=dict(entry='class_validate',result=actual['result'],accepted_before=0,accepted_after=actual['accepted_during_capture'],
             counter_scope='new CREATE session native_submit trace rows',trace=name+'.trace')
    manifest=dict(schema='xdev-ext-e2-v1',evidence_kind='guest-correctness',timing_claim='none',chain='nvme_nic',
                  source='source-window.bin',runs=runs,negatives=negatives)
    write_derived(capture/'capture.json',manifest)
    frozen=source/'tests/eval/mechanism_variants/tests/test_guest_capture.py'
    spec=importlib.util.spec_from_file_location('e2_frozen_capture',frozen);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    os.environ['E2_CAPTURE_DIR']=str(capture)
    report=io.StringIO();result=unittest.TextTestRunner(stream=report,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(module.GuestCapture))
    if not (evidence/'e2-frozen-gate.log').exists(): (evidence/'e2-frozen-gate.log').write_text(report.getvalue())
    require(result.wasSuccessful(),'independent frozen guest gate failed; see e2-frozen-gate.log')
    validation=dict(schema='xdev-ext-e2-validation-v1',status='pass',evidence_kind='guest-correctness',timing_claim='none',
        source_disk='whole-image unchanged',destination_disk='whole-image unchanged',umem_guards=guards,native_driver=drivers,
        old_ticket_scope='actual-core-host-fixture',kernel_git_sha=sha_source,capture_directory=capture.relative_to(evidence).as_posix(),
        capture_sha256=sha(capture/'capture.json'))
    write_derived(evidence/'e2-validation.json',validation)
    return validation


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',required=True,type=Path);p.add_argument('--scratch',required=True,type=Path);p.add_argument('--evidence',required=True,type=Path)
    a=p.parse_args()
    try:validate(a.source_root,a.scratch,a.evidence)
    except (OSError,ValueError,KeyError,AssertionError,subprocess.SubprocessError) as exc:p.exit(1,f'XDEV_EXT_E2_KVM=FAIL reason={exc}\n')
    print('XDEV_EXT_E2_KVM=PASS scope=guest-correctness old_ticket=actual-core-host-fixture performance_claim=none')
if __name__=='__main__':main()
