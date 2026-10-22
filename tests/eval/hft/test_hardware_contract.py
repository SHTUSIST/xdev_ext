#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Offline hardware-entry contract: refusals and pure fixtures, never performance."""
import copy
import importlib.util
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
ENTRY=HERE/'hardware_measure.py'
ARMS=('posix','uring-fixed-zc','session')
PROFILE=dict(schema=1,record_bytes=64,payload_bytes=512,burst_packets=2,
             depth=2,bursts=2,actors=1,seed=9)


def admission(role='producer'):
    value=dict(schema=1,role=role,product_sha='d'*40,
        environment=dict(kind='physical',verified=True,hypervisor=False,
                         evidence=['synthetic positive DMI/PCI observation; fixture only']),
        kernel=dict(release='fixture-kernel',config_release='fixture-kernel',
                    config_sha256='1'*64,strict_zero_copy=role=='producer'),
        nic=dict(ifname='fixture0',pci_bdf='0000:01:00.0',driver='fixture-driver',
                 mtu=1500,queue=0,zero_copy=role=='producer',copy_mode=False))
    if role=='producer':
        value['source']=dict(block_namespace='fixture-ns1',ng_namespace='fixture-ns1',
            read_only=True,slba=8,nlb=6,lba_bytes=512,capacity_bytes=2**20,
            dio_mem_align=512,dio_offset_align=512,payload_bytes=512,groups=6,
            observed_sha256='a'*64,reference_sha256='a'*64)
        value['bpf']=dict(object_sha256='b'*64,btf_sha256='c'*64,
                         source_sha256='e'*64,target_matches=True)
    return value


def independent_order(pairs,seed):
    rng=random.Random(seed)
    result=[]
    for _ in range(pairs):
        order=list(ARMS);rng.shuffle(order);result.append(order)
    return result


def independent_summary(trials):
    result=[]
    for pair in sorted({trial['pair'] for trial in trials}):
        rows=sorted((t for t in trials if t['pair']==pair),key=lambda t:t['order'])
        totals={t['backend']:sum(s['elapsed_ns'] for s in t['samples']) for t in rows}
        result.append(dict(pair=pair,order=[t['backend'] for t in rows],
            total_completion_ns=totals,
            ratio_posix_over_session=totals['posix']/totals['session'],
            ratio_fixed_over_session=totals['uring-fixed-zc']/totals['session']))
    return result


def observed_result_fixture():
    """Synthetic metadata/timestamp fixture; never emitted by a workload CLI."""
    trials=[]
    for pair,order in enumerate(independent_order(2,4)):
        for position,backend in enumerate(order):
            index=len(trials);base=1000000+index*10000
            durations={'posix':100,'uring-fixed-zc':200,'session':300}
            samples=[]
            for burst in range(PROFILE['bursts']):
                start=base+200+burst*1000;duration=durations[backend]+pair
                samples.append(dict(burst=burst,first_generation=(1+burst)*2+1,
                    packet_count=2,validated_packets=2,validated_bytes=1024,
                    read_submissions=2,send_submissions=2,started_ns=start,
                    local_release_ns=start+duration-10,peer_receipt_ns=start+duration,
                    completed_ns=start+duration,elapsed_ns=duration,
                    local_release_complete=True,receiver_receipt=True,guards_ok=True))
            trials.append(dict(pair=pair,order=position,backend=backend,
                session_base=10000+index*16,source_sha='a'*64,profile=dict(PROFILE),
                setup_started_ns=base,setup_completed_ns=base+100,
                teardown_started_ns=base+2000,teardown_completed_ns=base+2100,
                registration_calls=None if backend=='posix' else 1,
                stop_ret=0 if backend=='session' else None,
                correctness_verified=True,samples=samples))
    return dict(schema=1,status='ok',scenario='hft_replay',mode='performance',
        scope='physical-paired-roundtrip',profile=dict(PROFILE),order_seed=4,pairs=2,
        warmup_bursts=1,admission=dict(producer=admission(),peer=admission('peer')),
        trials=trials,paired_summary=independent_summary(trials))


def module():
    if not ENTRY.is_file():
        raise AssertionError('missing actual hardware_measure.py entry, not hardware-ready')
    spec=importlib.util.spec_from_file_location('hft_hardware_contract_target',ENTRY)
    target=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=target
    spec.loader.exec_module(target)
    return target


class HardwareCLIContractTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='.hardware-contract-',dir=HERE)
        self.root=Path(self.temp.name)
        self.sentinel=self.root/'existing';self.sentinel.write_bytes(b'unchanged')
    def tearDown(self): self.temp.cleanup()
    def invoke(self,args):
        result=subprocess.run([sys.executable,str(ENTRY),*args,'--directory',str(self.root)],
            text=True,capture_output=True,timeout=15)
        self.assertTrue(ENTRY.is_file(),'missing actual hardware measurement entry')
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),['existing'])
        self.assertEqual(self.sentinel.read_bytes(),b'unchanged')
        return result
    def test_help_identifies_real_measure_and_peer_interface(self):
        result=self.invoke(['--help'])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('measure',result.stdout);self.assertIn('peer',result.stdout)
    def test_invalid_cli_rejected_before_io(self):
        cases=[['measure','--records','0'],['measure','--pairs','0'],
            ['measure','--pairs','101'],['measure','--pairs','+1'],
            ['measure','--pairs','1e1'],['measure','--pairs','1','--pairs','2'],
            ['measure','--depth','0'],['measure','--warmup-bursts','33'],
            ['measure','--warmup-bursts','32','--bursts','1'],
            ['measure','--backend','posix'],['measure','--unknown'],
            ['peer','--bind','not-an-ip:12']]
        for args in cases:
            with self.subTest(args=args):
                result=self.invoke(args)
                self.assertEqual(result.returncode,2,result.stdout+result.stderr)
                self.assertEqual(result.stdout,'')
    def test_unprovisioned_measure_and_peer_refuse_without_network_or_subprocess(self):
        script='''import importlib.util,pathlib,socket,subprocess,sys
path=pathlib.Path(sys.argv[1]);spec=importlib.util.spec_from_file_location('hardware_target',path)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
def forbidden(*a,**k): raise AssertionError('unprovisioned CLI attempted network/subprocess')
socket.socket=forbidden;subprocess.Popen=forbidden;subprocess.run=forbidden
sys.argv=[str(path),sys.argv[2],'--directory',sys.argv[3]]
raise SystemExit(m.main())
'''
        for action in ('measure','peer'):
            with self.subTest(action=action):
                self.assertTrue(ENTRY.is_file(),'missing executable refusal gate')
                result=subprocess.run([sys.executable,'-c',script,str(ENTRY),action,str(self.root)],
                    text=True,capture_output=True,timeout=15)
                self.assertEqual(result.returncode,4,result.stdout+result.stderr)
                self.assertEqual(result.stdout,'')
                receipt=json.loads(result.stderr)
                self.assertIn(receipt['status'],('not_run_hardware','not_run_capability'))
                self.assertIs(receipt['start_issued'],False)
                self.assertEqual(sorted(p.name for p in self.root.iterdir()),['existing'])


class PureHardwareAdmissionTests(unittest.TestCase):
    def test_valid_producer_and_ordinary_udp_peer_metadata_only(self):
        target=module()
        for role in ('producer','peer'):
            target.validate_admission(admission(role),role)
    def test_producer_gate_rejects_unknown_virtual_copy_identity_window_and_bytes(self):
        target=module()
        mutations=[('environment','kind','unknown'),('environment','verified',False),
            ('environment','hypervisor',True),('environment','evidence',[]),
            ('kernel','config_release','other-kernel'),('kernel','strict_zero_copy',False),
            ('kernel','config_sha256','unknown'),('nic','zero_copy',False),
            ('nic','copy_mode',True),('nic','pci_bdf',''),('nic','mtu',512),
            ('source','ng_namespace','other-ns'),('source','read_only',False),
            ('source','slba',2**64-1),('source','nlb',0),('source','nlb',5),
            ('source','lba_bytes',4096),('source','dio_mem_align',4096),
            ('source','dio_offset_align',4096),('source','observed_sha256','f'*64),
            ('source','groups',True),('bpf','target_matches',False)]
        for section,key,value in mutations:
            mutant=admission();mutant[section][key]=value
            with self.subTest(section=section,key=key),self.assertRaises(ValueError):
                target.validate_admission(mutant,'producer')
        for key in admission():
            mutant=admission();del mutant[key]
            with self.subTest(missing=key),self.assertRaises(ValueError):
                target.validate_admission(mutant,'producer')


class PurePairedResultTests(unittest.TestCase):
    def test_local_random_schedule_matches_seeded_independent_permutations(self):
        target=module();before=random.getstate()
        self.assertEqual(target.paired_order(8,41),independent_order(8,41))
        self.assertEqual(random.getstate(),before)
        for pairs,seed in ((0,1),(101,1),(True,1),(1,-1),(1,True)):
            with self.subTest(pairs=pairs,seed=seed),self.assertRaises(ValueError):
                target.paired_order(pairs,seed)
    def test_accepts_complete_fixture_and_keeps_slower_session_ratios(self):
        target=module();result=observed_result_fixture()
        target.validate_result(result)
        actual=target.paired_summary(result['trials'])
        self.assertEqual(actual,independent_summary(result['trials']))
        self.assertLess(actual[0]['ratio_posix_over_session'],1)
    def test_rejects_false_completion_early_end_bad_counts_and_warmup_leak(self):
        target=module()
        for key,value in [('local_release_complete',False),('receiver_receipt',False),
            ('guards_ok',False),('packet_count',1),('validated_packets',1),
            ('validated_bytes',1),('read_submissions',1),('send_submissions',1),
            ('first_generation',1),('elapsed_ns',1),('completed_ns',1),
            ('peer_receipt_ns',2**60),('local_release_ns',2**60),('started_ns',True)]:
            mutant=observed_result_fixture();mutant['trials'][0]['samples'][0][key]=value
            with self.subTest(field=key),self.assertRaises(ValueError):
                target.validate_result(mutant)
    def test_rejects_unpaired_changed_window_nonce_profile_registration_stop_and_schema(self):
        target=module()
        mutations=[]
        value=observed_result_fixture();value['trials'].pop();mutations.append(value)
        value=observed_result_fixture();value['trials'][1]['session_base']=value['trials'][0]['session_base'];mutations.append(value)
        value=observed_result_fixture();value['trials'][0]['profile']['payload_bytes']=1024;mutations.append(value)
        value=observed_result_fixture();value['trials'][0]['source_sha']='f'*64;mutations.append(value)
        value=observed_result_fixture();value['trials'][0]['correctness_verified']=False;mutations.append(value)
        value=observed_result_fixture();value['trials'][0]['setup_completed_ns']=2**60;mutations.append(value)
        value=observed_result_fixture();value['trials'][0]['teardown_started_ns']=0;mutations.append(value)
        for backend,key,replacement in [('session','stop_ret',1),('uring-fixed-zc','registration_calls',2),('session','registration_calls',2)]:
            value=observed_result_fixture();next(t for t in value['trials'] if t['backend']==backend)[key]=replacement;mutations.append(value)
        value=observed_result_fixture();value['paired_summary'][0]['ratio_posix_over_session']=100;mutations.append(value)
        value=observed_result_fixture();value['made_up']='field';mutations.append(value)
        for index,value in enumerate(mutations):
            with self.subTest(mutant=index),self.assertRaises(ValueError):
                target.validate_result(value)
        trials=observed_result_fixture()['trials']
        for rows in ([],trials[:-1],[trials[0],trials[0],*trials[2:]]):
            with self.subTest(unpaired=rows),self.assertRaises(ValueError):
                target.paired_summary(rows)


if __name__=='__main__': unittest.main()
