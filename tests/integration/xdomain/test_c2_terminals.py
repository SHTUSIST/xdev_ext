# SPDX-License-Identifier: GPL-2.0
"""C2 SPEC regressions: action admission, recovery and terminal causality.

Requirements: C2-design, closure SDD 19:48 and root's close-pair freeze.
Real subprocesses below own only pipes/files. Their explicit test-only teardown
must never become production recovery for a native/GPU resource owner.
"""
import copy
import json
import os
from pathlib import Path
import signal
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import action_provider
import case_registry
import check_protocol
import two_host_check
from platform_facts import collect_platform_facts
from test_native_barrier import FORMAT, row
from test_platform_facts import Capture, BUILD, NHI


IDLE = dict(scope="this-owner", prepared=False, session_id=0,
            native_payload_owners=0)


def ident(role, case, request, run="c2-terminal"):
    return dict(version=1, run_id=run, sha="a" * 40, role=role, case=case,
                direction="a-to-b", epoch=3, request_id=request)


def record(role, case, command, request, payload, *, phase, fate="ACTIVE",
           error=0, held=False, permissions=0, evidence=None):
    return dict(identity=ident(role, case, request), command=command,
                phase=phase, fate=fate, error=error, held=held,
                cleanup_permissions=permissions, evidence=evidence or {},
                payload=payload, part_index=0, part_count=1)


def stats(session, fault=False):
    return dict(session_id=session, batches_done=0 if fault else 1,
                batches_abort=1 if fault else 0, rejects=0, recycled=0,
                held=1 if fault else 0, sequestered=1 if fault else 0,
                timeouts=0, inflight=1 if fault else 0, native_publish=1,
                protocol_err=0, published=1, submitted=[1, 0, 0, 0],
                completed=[0 if fault else 1, 0, 0, 0],
                last_err=-67 if fault else 0, state=0)


def transport(session):
    return dict(v3=dict(v2=dict(v1=dict(size=216, version=4, session_id=session,
                    native_controls=0, pending_acks=0, uncertain_controls=0, rsvd=0),
                    retransmits=0, dup_suppressed=0, held_acks=0,
                    held_unacked=0, rsvd2=0), nic_copy_ops=0, nic_copy_bytes=0,
                    nic_zc_ops=0, nic_zc_bytes=0),
                rel_policy=dict(version=1, size=96, window=1, initial_credit=1,
                    rto_ns=1000000, rto_max_ns=10000000, backoff=1,
                    max_attempts=2, ack_rule=0, ack_every=1, ack_delay_ns=0,
                    resend_order=0, flags=0, bad_field=0, rsvd0=0, rsvd=[0]*6))


def terminal(session, fault=False):
    return dict(stats_valid=True, stats=stats(session, fault),
                transport_valid=True, transport=transport(session))


def stop(role, case, request=5):
    session = 101 if role == "tx" else 102
    return record(role, case, "stop", request,
                  dict(stop_proved=True, first_error=0, stop_error=0,
                       **terminal(session)), phase="DRAINED_SAFE", fate="SAFE",
                  permissions=1, evidence=dict(stop_action=dict(
                      boot_id="boot-" + role,
                      clock_domain="boot-" + role + ":CLOCK_MONOTONIC",
                      started_monotonic_ns=1056000000,
                      finished_monotonic_ns=1058000000)))


def prepare(role, case):
    session = 101 if role == "tx" else 102
    caps = dict(size=80, version=1, session_id=session, stage=0, family=11,
                export_authority=1, reachability=1, requester_mapping=1,
                native_queue=1, producer_visibility=1, last_use_quiescence=1,
                invalidation=1, backing=1, refused=0, p2p_distance=0)
    return record(role, case, "prepare", 2,
                  dict(session_id=session, registration_bytes=131072,
                       producer_sync_proved=True, guard_sync_proved=True,
                       create_error=0, stop_proved=False, stage_caps=caps,
                       admission={}), phase="SESSION_CREATED")


# This is a boundary peer, not a second implementation of the coordinator.
# It records actual received requests and only emits frozen response schemas.
AGENT = r'''
import copy, json, os, pathlib, struct, sys, time
role, root = sys.argv[1:3]
root = pathlib.Path(root)
policy = json.loads((root / 'policy.json').read_text())
templates = json.loads((root / 'responses.json').read_text())[role]
(root / ('launched-' + role)).write_text(str(os.getpid()))
while True:
    prefix = sys.stdin.buffer.read(4)
    if not prefix: break
    n = struct.unpack('!I', prefix)[0]
    q = json.loads(sys.stdin.buffer.read(n))
    with (root / ('commands-' + role + '.jsonl')).open('a') as f:
        f.write(json.dumps(q) + '\n')
    c = q['command']
    template = templates.get(c)
    if template is None:
        template = dict(phase='HELD',fate='HELD',error=-95,held=True,
                        cleanup_permissions=0,payload={})
    response = copy.deepcopy(template)
    response.update(identity=q['identity'], command=c, part_index=0,part_count=1)
    response['evidence'] = dict(owner_pid=os.getpid(),durable_path=str(root / ('owner-' + role)))
    if c == 'preflight':
        p = q['payload']
        response['payload']['raw_evidence']['observed_monotonic_ns'] = time.monotonic_ns()
        response['payload']['device_identity'].update(gpu_bdf=p['gpu_bdf'],nvidia_node=p['nvidia_node'])
        response['payload']['link_identity'].update(link_token=p['link_token'],channel=p['channel'])
        response['payload']['kernel_identity']['sha'] = q['identity']['sha']
    if c == 'close':
        receipts = q['payload'].get('stop_receipts')
        valid = type(receipts) is list and len(receipts)==2 and {r['identity']['role'] for r in receipts}=={'tx','rx'}
        if valid:
            valid = all(r['command']=='stop' and r['error']==0 and not r['held'] and r['fate']=='SAFE'
                        and r['payload']['stop_proved'] and r['payload']['stop_error']==0
                        and all(r['identity'][k]==q['identity'][k] for k in ('version','run_id','sha','case','direction','epoch'))
                        for r in receipts)
        if not valid:
            response.update(phase='HELD',fate='HELD',error=-1,held=True,cleanup_permissions=0,payload={})
    b = json.dumps(response).encode()
    sys.stdout.buffer.write(struct.pack('!I',len(b))+b)
    sys.stdout.buffer.flush()
    if c in ('cancel','close'): break
'''

PROVIDER = r'''
import json, os, pathlib, struct, sys, time
root = pathlib.Path(sys.argv[1])
n = struct.unpack('!I',sys.stdin.buffer.read(4))[0]
c = json.loads(sys.stdin.buffer.read(n))
(root / 'provider-challenge.json').write_text(json.dumps(c))
(root / 'provider-pid').write_text(str(os.getpid()))
(root / 'primitive.stdout').write_text('test-only primitive refused; no hardware action\n')
(root / 'primitive.stderr').write_text('independent refusal\n')
start = time.monotonic_ns()
r = dict(version=1,action_id=c['action_id'],identity=c['identity'],kind=c['kind'],
 target=c['target'],barrier=c['barrier'],attempted=False,completed=False,error=-95,
 started_monotonic_ns=start,finished_monotonic_ns=start+1,
 evidence=dict(argv=sys.argv,returncode=0,stdout_path=str(root / 'primitive.stdout'),
 stderr_path=str(root / 'primitive.stderr')))
b = json.dumps(r).encode()
sys.stdout.buffer.write(struct.pack('!I',len(b))+b)
sys.stdout.buffer.flush()
'''


class C2TerminalRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="c2-terminal-")
        self.root = Path(self.tmp.name)

    def tearDown(self):
        # Explicit test-only teardown: these subprocesses have no devices, CUDA
        # contexts or native registrations. Production must never do this.
        for entry in list(two_host_check._RETAINED):
            try:
                os.kill(entry.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            entry.process.wait(timeout=2)
            for fd in (entry.infd, entry.outfd):
                try:
                    os.close(fd)
                except OSError:
                    pass
            two_host_check._RETAINED.remove(entry)
        for entry in list(action_provider._RETAINED):
            proc = entry['process']
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=2)
            proc.retained = False
            for fd in entry['fds']:
                try:
                    os.close(fd)
                except OSError:
                    pass
            action_provider._RETAINED.remove(entry)
        self.tmp.cleanup()

    def coordinator(self, case="idle-suspend-resume"):
        root = self.root
        (root / 'agent.py').write_text(AGENT)
        (root / 'provider.py').write_text(PROVIDER)
        (root / 'policy.json').write_text('{}')
        responses = {}
        for role in ('tx', 'rx'):
            local, remote = (81, 82) if role == 'tx' else (82, 81)
            pre = dict(available=True, reason='',
                       device_identity=dict(gpu_bdf='', nvidia_node='', backing='gpu'),
                       link_identity=dict(link_token=71 if role=='tx' else 72,
                                          channel=0,local_inc=local,remote_inc=remote),
                       kernel_identity=dict(sha='a'*40,config='CONFIG_USB4=m\n'),
                       visibility='NATIVE_OWNER',raw_evidence=dict(
                           service_listing=['xdevext'],boot_id='boot-'+role,
                           nhi_bdf=NHI,clock_domain='boot-'+role+':CLOCK_MONOTONIC',
                           observed_monotonic_ns=1,idle=copy.deepcopy(IDLE)))
            st = stop(role, case, 3)
            st['payload']['stats']['batches_done'] = 0
            pr = prepare(role, case)
            pr['payload']['registration_bytes'] = 65536
            responses[role] = dict(preflight=record(role,case,'preflight',1,pre,
                    phase='NEW',fate='EMPTY'), prepare=pr, stop=st,
                    close=record(role,case,'close',4,dict(closed=True,retained_resources=[]),
                                 phase='CLOSED',fate='SAFE',permissions=15))
        config = dict(identity={k:v for k,v in ident('tx',case,1).items()
                                if k not in ('role','request_id')},
                      execution_mode='contract', geometry=dict(allocation_bytes=65536,
                      group_bytes=65536,frame_size=65536,seg_len=65536,depth=1,native_elems=16),
                      groups=1,first_seq=40,mode='single-group',seed=7,flags=0,channel=0,
                      gpu_bdf=dict(tx='0000:01:00.0',rx='0000:02:00.0'),
                      nvidia_node=dict(tx='/dev/nvidia0',rx='/dev/nvidia0'),
                      link_token=dict(tx=71,rx=72),deadline_ms=300,evidence_dir=str(root),
                      observer_object='/contract/observer.o',ptx_path='/contract/pattern.ptx',
                      action_provider=dict(argv=[sys.executable,str(root/'provider.py'),str(root)],timeout_ms=300))
        argv = {role:[sys.executable,str(root/'agent.py'),role,str(root)] for role in ('tx','rx')}
        return config, argv, responses

    def dispatch(self, config, argv, responses):
        (self.root/'responses.json').write_text(json.dumps(responses))
        return two_host_check.run(config, argv)

    def commands(self, role):
        p = self.root/('commands-'+role+'.jsonl')
        return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []

    def test_idle_actual_proofs_on_both_roles_precede_provider(self):
        """Catches fabricated idle barriers and checking evidence after action."""
        for case in ('idle-suspend-resume','idle-module-unload'):
            for role in ('tx','rx'):
                for bad in (None,dict(IDLE,native_payload_owners=1)):
                    with self.subTest(case=case,role=role,bad=bad):
                        config, argv, responses = self.coordinator(case)
                        raw = responses[role]['preflight']['payload']['raw_evidence']
                        if bad is None:
                            del raw['idle']
                        else:
                            raw['idle'] = bad
                        marker = self.root/'provider-challenge.json'
                        marker.unlink(missing_ok=True)
                        result = self.dispatch(config,argv,responses)
                        self.assertFalse(marker.exists(),
                            'provider ran before both actual scoped idle proofs were validated')
                        self.assertNotEqual(result['status'],'pass')
                        for endpoint in ('tx','rx'):
                            self.assertNotIn('prepare',[q['command'] for q in self.commands(endpoint)])

    def test_ordinary_override_bit_is_rejected_before_agent_launch(self):
        for case in ('functional-epochs','bringup','stop-inflight','cable-loss'):
            with self.subTest(case=case):
                config, argv, responses = self.coordinator(case)
                config['flags'] = 1
                for role in ('tx','rx'):
                    (self.root/('launched-'+role)).unlink(missing_ok=True)
                result = self.dispatch(config,argv,responses)
                self.assertNotEqual(result['status'],'pass')
                self.assertFalse(any((self.root/('launched-'+role)).exists() for role in ('tx','rx')),
                                 'ordinary case launched owners with allow-unverified bit')

    def test_incomplete_provider_keeps_challenge_and_exact_recovery_diagnostics(self):
        config, argv, responses = self.coordinator()
        result = self.dispatch(config,argv,responses)
        self.assertTrue((self.root/'provider-challenge.json').exists(),
                        'valid scoped idle proof must reach real provider boundary')
        challenge = json.loads((self.root/'provider-challenge.json').read_text())
        actions = result.get('actions',{})
        self.assertIn('tx',actions,'unknown action helper vanished from final recovery report')
        action = actions['tx']
        self.assertEqual(action['challenge'],challenge)
        self.assertEqual(action['status'],'incomplete')
        self.assertTrue(action['reason'])
        self.assertIsNone(action['receipt'])
        execution = action['execution']
        self.assertEqual(execution['pid'],int((self.root/'provider-pid').read_text()))
        self.assertEqual(execution['argv'],config['action_provider']['argv'])
        self.assertEqual(execution['ack_count'],1)
        self.assertIs(execution['timed_out'],False)
        self.assertIn('returncode',execution)
        for stream in ('stdout','stderr'):
            path = Path(execution[stream+'_path'])
            self.assertIn(challenge['action_id'],path.name)
            self.assertTrue(path.is_file())
        self.assertTrue(Path(execution['stdout_path']).read_bytes(), 'raw framed refusal was lost')

    def test_special_bringup_delivers_pair_proof_and_retains_close_receipts(self):
        config, argv, responses = self.coordinator('bringup')
        result = self.dispatch(config,argv,responses)
        self.assertEqual(result['status'],'pass',
                         'safe close must receive paired STOP receipts without GPU verification')
        evidence = result['case_evidence']
        self.assertEqual(set(evidence['close']),{'tx','rx'})
        for role in ('tx','rx'):
            close = next(q for q in self.commands(role) if q['command']=='close')
            self.assertEqual(set(close['payload']),{'stop_receipts'})
            self.assertEqual(close['payload']['stop_receipts'],
                             [evidence['stops']['tx'],evidence['stops']['rx']])
            self.assertEqual(evidence['close'][role]['phase'],'CLOSED')
            self.assertNotIn('verify',[q['command'] for q in self.commands(role)])

    def test_frozen_close_wire_accepts_complete_pair_and_rejects_unbound_pairs(self):
        pair = [stop('tx','bringup',3),stop('rx','bringup',3)]
        q = dict(identity=ident('tx','bringup',4),command='close',deadline_ms=300,
                 part_index=0,part_count=1,payload=dict(stop_receipts=pair))
        try:
            check_protocol.encode_record(q)
        except ValueError as error:
            self.fail('frozen close pair-proof request is not wired: '+str(error))
        for mutation in ('one-role','foreign-run','wrong-command','unsafe','missing-proof'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(q)
                r = bad['payload']['stop_receipts'][1]
                if mutation=='one-role': r['identity']['role']='tx'
                elif mutation=='foreign-run': r['identity']['run_id']='old'
                elif mutation=='wrong-command': r['command']='wait'
                elif mutation=='unsafe': r['fate']='ACTIVE'
                else: r['payload']['stop_proved']=False
                with self.assertRaises(ValueError):
                    check_protocol.encode_record(bad)

    def physical(self, case='bringup'):
        e = dict(platform_facts={},preflights={},prepare={},stops={},actions={},continued={},close={})
        captures = {}
        for role in ('tx','rx'):
            capture = Capture(self.root/case/role)
            identity = ident(role,case,1)
            capture.expected['identity'] = identity
            capture.receipt['identity'] = identity
            if role == 'rx':
                for index, item in enumerate(capture.records):
                    if 'XDEV_EXT_XDOMAIN_PATH' in item['message']:
                        capture.replace_message(index,item['message'].replace(
                            'local_inc=21 remote_inc=22','local_inc=22 remote_inc=21'))
            capture.write()
            facts = collect_platform_facts(str(capture.log),str(capture.receipt_path),
                    capture.expected,sysfs_root=str(capture.sys),proc_root=str(capture.proc))
            self.assertEqual(facts['status'],'complete',facts)
            captures[role] = capture
            local, remote = (21,22) if role=='tx' else (22,21)
            pre = dict(available=True,reason='',device_identity=dict(gpu_bdf='0000:01:00.0',
                    nvidia_node='/dev/nvidia0',backing='gpu'),
                    link_identity=dict(link_token=19,channel=3,local_inc=local,remote_inc=remote),
                    kernel_identity=dict(sha='a'*40,config='CONFIG_USB4=m\n'),
                    visibility='NATIVE_OWNER',raw_evidence=dict(service_listing=['xdevext'],
                    boot_id=facts['identity']['boot_id'],nhi_bdf=NHI,
                    clock_domain=facts['identity']['boot_id']+':CLOCK_MONOTONIC',
                    platform_facts=facts,idle=copy.deepcopy(IDLE)))
            e['platform_facts'][role]=facts
            e['preflights'][role]=record(role,case,'preflight',1,pre,phase='NEW',fate='EMPTY')
            e['prepare'][role]=prepare(role,case)
            e['stops'][role]=stop(role,case,3 if case=='bringup' else 5)
            e['close'][role]=record(role,case,'close',4 if case=='bringup' else 7,
                     dict(closed=True,retained_resources=[]),phase='CLOSED',fate='SAFE',permissions=15)
        return dict(execution_mode='physical',case_evidence=e), captures

    def evaluate(self, case, evidence):
        return case_registry.evaluate_case(case,evidence)

    def reject(self, case, evidence):
        result = self.evaluate(case,evidence)
        self.assertNotIn(result['status'],('pass','EXPECTED_RETAINED','UNVERIFIED_FORCED'),result)

    def test_registry_positive_bringup_uses_retained_raw_C1_and_closed_pair(self):
        evidence, _ = self.physical()
        self.assertEqual(self.evaluate('bringup',evidence)['status'],'pass')

    def test_registry_rejects_foreign_run_role_command_and_session_receipts(self):
        evidence, _ = self.physical()
        self.assertEqual(self.evaluate('bringup',evidence)['status'],'pass')
        for field in ('prepare','stops','close'):
            for mutation in ('run_id','sha','role','case','direction','epoch','request_id','command','session'):
                if field=='close' and mutation=='session':
                    continue
                with self.subTest(field=field,mutation=mutation):
                    bad=copy.deepcopy(evidence)
                    r=bad['case_evidence'][field]['tx']
                    if mutation=='command':
                        # Same shape? choose a complete valid response of another
                        # command; rejection must enforce causal command, not JSON shape.
                        bad['case_evidence'][field]['tx']=copy.deepcopy(evidence['case_evidence']['preflights']['tx'])
                    elif mutation=='session':
                        if field=='prepare':
                            r['payload']['session_id']=999
                            r['payload']['stage_caps']['session_id']=999
                        else:
                            r['payload']['stats']['session_id']=999
                            r['payload']['transport']['v3']['v2']['v1']['session_id']=999
                    else:
                        r['identity'][mutation]={'run_id':'old-run','sha':'b'*40,'role':'rx',
                            'case':'bulk-static','direction':'b-to-a','epoch':4,'request_id':1}[mutation]
                    self.reject('bringup',bad)

    def test_registry_rejects_missing_close_and_unproved_transport(self):
        evidence, _=self.physical()
        for mutation in ('missing-close','not-closed','transport-invalid','controls-pending'):
            with self.subTest(mutation=mutation):
                bad=copy.deepcopy(evidence)
                e=bad['case_evidence']
                if mutation=='missing-close': e.pop('close')
                elif mutation=='not-closed': e['close']['tx']['payload']['closed']=False
                elif mutation=='transport-invalid':
                    e['stops']['tx']['payload'].update(transport_valid=False,transport={})
                else:
                    e['stops']['tx']['payload']['transport']['v3']['v2']['v1']['native_controls']=1
                self.reject('bringup',bad)

    def test_registry_revalidates_retained_C1_raw_not_complete_labels(self):
        evidence,captures=self.physical()
        self.assertEqual(self.evaluate('bringup',evidence)['status'],'pass')
        with self.subTest(mutation='complete-label-only'):
            bad=copy.deepcopy(evidence)
            facts=bad['case_evidence']['platform_facts']['tx']
            bad['case_evidence']['platform_facts']['tx']={'status':'complete','identity':facts['identity']}
            self.reject('bringup',bad)
        with self.subTest(mutation='raw-bytes-changed-after-collection'):
            with captures['tx'].log.open('a') as out:
                out.write('changed retained raw evidence\n')
            self.reject('bringup',evidence)

    def add_native(self,evidence,case,role,fault=False,pending_only=False):
        e=evidence['case_evidence']
        pre=e['preflights'][role]
        raw=pre['payload']['raw_evidence']
        link=pre['payload']['link_identity']
        session=101 if role=='tx' else 102
        pending=ident(role,case,4)
        common=dict(identity=pending,boot_id=raw['boot_id'],kernel_build_id=BUILD,
                    source_commit='a'*40,clock_domain=raw['clock_domain'],nhi_bdf=NHI,
                    link_token=19,local_inc=link['local_inc'],remote_inc=link['remote_inc'])
        expected=dict(common,session_id=session,stage=0,batch_key=40,direction=1,
                      group_bytes=131072,max_age_ms=1000)
        receipt=dict(common,version=1,clock='CLOCK_MONOTONIC',create_begin_ns=1010000000,
                     create_end_ns=1020000000,capture_begin_ns=1000000000,
                     capture_end_ns=1065000000,captured_monotonic_ns=1065000000,
                     trace_dropped=0,formats={'xdev_ext:native_event':FORMAT},
                     raw_path=str(self.root/(role+'-continued.raw')))
        barrier=dict(native_accepted=True,inflight=1,session_id=session,batch_id=901,
                     group=17,acceptance_seq=1,local_inc=link['local_inc'],
                     remote_inc=link['remote_inc'],identity=pending,batch_key=40,
                     stage=0,ticket=90,boot_id=raw['boot_id'],clock_domain=raw['clock_domain'],
                     accepted_monotonic_ns=1050000000,observed_monotonic_ns=1055000000,
                     raw_path=str(self.root/(role+'-pending.raw')))
        pending_ledger=row(0,1040000000,session_id=session)+row(1,1050000000,session_id=session)
        pending_receipt=copy.deepcopy(receipt)
        pending_receipt.update(capture_end_ns=1055000000,
                               captured_monotonic_ns=1055000000,
                               raw_path=barrier['raw_path'])
        e.setdefault('pending',{})[role]=record(role,case,'wait',4,
                dict(native_trace=dict(raw_trace=pending_ledger,receipt=pending_receipt,
                                       expected=copy.deepcopy(expected))),
                phase='START_ACCEPTED',fate='ACTIVE')
        Path(barrier['raw_path']).write_text(pending_ledger)
        if pending_only:
            return
        ledger=pending_ledger
        if not fault:
            ledger+=row(0,1060000000,'native_complete',session_id=session)
            ledger+=row(1,1061000000,'native_complete',session_id=session)
        Path(receipt['raw_path']).write_text(ledger)
        target=dict(boot_id=raw['boot_id'],clock_domain=raw['clock_domain'],nhi_bdf=NHI,
                    link_token=19,local_inc=link['local_inc'],remote_inc=link['remote_inc'])
        action=dict(version=1,action_id=('b' if role=='tx' else 'c')*64,identity=pending,
                    kind=({'peer-reboot':'reboot'}.get(case,case) if fault else 'stop'),
                    target=target,barrier=barrier,
                    attempted=True,completed=True,error=0,started_monotonic_ns=1056000000,
                    finished_monotonic_ns=1058000000,evidence={})
        if not fault:
            st=e['stops'][role]
            st['evidence']['stop_action'].update(boot_id=raw['boot_id'],clock_domain=raw['clock_domain'])
            action['evidence']={'stop_response':st}
            e['actions'][role]=action
        else:
            out=self.root/'primitive.out';err=self.root/'primitive.err'
            out.write_text('fixture cable event; no hardware\n');err.write_text('')
            action['evidence']=dict(argv=['/test-only/cable-event'],returncode=0,
                                    stdout_path=str(out),stderr_path=str(err),operator_event=True)
            if case=='remove-on-resume':
                action['evidence'].update(suspended=True,resumed=True,nhi_removed=True,
                    going_away=True,upstream_still_running_warning=True)
            elif case=='peer-reboot':
                other='rx' if role=='tx' else 'tx'
                old=e['preflights'][other]['payload']['raw_evidence']['boot_id']
                action['evidence']['affected_peer']=dict(role=other,old_boot_id=old,
                        new_boot_id='fresh-peer-boot',new_incarnation=83)
            challenge={k:copy.deepcopy(action[k]) for k in
                       ('version','action_id','identity','kind','target','barrier')}
            challenge['deadline_monotonic_ns']=1070000000
            e['actions'][role]=dict(status='complete',reason='contract fixture',receipt=action,
                    challenge=challenge,execution=dict(argv=['/test-only/provider'],pid=999,
                    returncode=0,stdout_path=str(out),stderr_path=str(err),timed_out=False,ack_count=1))
        continuation=dict(native_trace=dict(raw_trace=ledger,receipt=receipt,expected=expected),
                          terminal=terminal(session,fault))
        e['continued'][role]=record(role,case,'wait',5 if fault else 6,continuation,
                phase='HELD' if fault else 'DRAINED_SAFE',fate='HELD' if fault else 'SAFE',
                error=-67 if fault else 0,held=fault,permissions=0 if fault else 1,
                evidence=dict(link_up=not fault))

    def test_registry_stop_inflight_requires_both_role_actions_and_continued_capture(self):
        evidence,_=self.physical('stop-inflight')
        for role in ('tx','rx'): self.add_native(evidence,'stop-inflight',role)
        self.assertEqual(self.evaluate('stop-inflight',evidence)['status'],'pass')
        for missing in ('actions','continued'):
            with self.subTest(missing=missing):
                bad=copy.deepcopy(evidence)
                del bad['case_evidence']['actions']['rx']
                if missing=='continued': del bad['case_evidence']['continued']['rx']
                self.reject('stop-inflight',bad)

    def test_registry_fault_requires_both_actual_session_bound_typed_terminals(self):
        case='cable-loss'
        evidence,_=self.physical(case)
        e=evidence['case_evidence']
        e['stops']={}
        e['close']={}
        self.add_native(evidence,case,'tx',fault=True)
        self.add_native(evidence,case,'rx',fault=True,pending_only=True)
        e['survivor_terminal']=record('rx',case,'wait',5,terminal(102,True),
                                      phase='HELD',fate='HELD',error=-67,held=True)
        self.assertEqual(self.evaluate(case,evidence)['status'],'EXPECTED_RETAINED')
        for role in ('tx','rx'):
            for mutation in ('missing-stats','wrong-session','untyped-count','no-posted-batch','no-quarantine'):
                with self.subTest(role=role,mutation=mutation):
                    bad=copy.deepcopy(evidence)
                    e=bad['case_evidence']
                    t=(e['continued']['tx']['payload']['terminal'] if role=='tx' else
                       e['survivor_terminal']['payload'])
                    if mutation=='missing-stats': t.clear()
                    elif mutation=='wrong-session':
                        t['stats']['session_id']=999
                        t['transport']['v3']['v2']['v1']['session_id']=999
                    elif mutation=='untyped-count': t['stats']['sequestered']=True
                    elif mutation=='no-posted-batch':
                        t['stats']['submitted']=[0]*4;t['stats']['published']=0
                        t['stats']['native_publish']=0
                    else: t['stats']['sequestered']=0
                    self.reject(case,bad)

    def test_registry_missing_pending_raw_cannot_pass(self):
        """Actual req4 responses are mandatory, not reconstructed action metadata."""
        evidence,_=self.physical('stop-inflight')
        for role in ('tx','rx'):
            self.add_native(evidence,'stop-inflight',role)
        evidence['case_evidence'].pop('pending',None)
        self.reject('stop-inflight',evidence)

    def test_registry_pending_raw_is_role_request_session_and_ledger_bound(self):
        for case in ('stop-inflight','cable-loss','remove-on-resume','peer-reboot'):
            with self.subTest(case=case,control='complete'):
                evidence,_=self.physical(case)
                e=evidence['case_evidence']
                if case=='stop-inflight':
                    for role in ('tx','rx'):
                        self.add_native(evidence,case,role)
                    self.assertEqual(self.evaluate(case,evidence)['status'],'pass')
                else:
                    e['stops']={};e['close']={}
                    if case=='peer-reboot':
                        self.add_native(evidence,case,'rx',fault=True)
                        e['survivor_terminal']=copy.deepcopy(e['continued']['rx'])
                    else:
                        self.add_native(evidence,case,'tx',fault=True)
                        self.add_native(evidence,case,'rx',fault=True,pending_only=True)
                        e['survivor_terminal']=record('rx',case,'wait',5,terminal(102,True),
                                phase='HELD',fate='HELD',error=-67,held=True)
                    self.assertEqual(self.evaluate(case,evidence)['status'],'EXPECTED_RETAINED')
            for role in (('rx',) if case=='peer-reboot' else ('tx','rx')):
                for mutation in ('missing-role','foreign-run','wrong-role','wrong-request',
                                 'wrong-session','wrong-ledger-ticket','unexpected-role'):
                    with self.subTest(case=case,role=role,mutation=mutation):
                        bad=copy.deepcopy(evidence)
                        p=bad['case_evidence']['pending'][role]
                        if mutation=='missing-role':
                            del bad['case_evidence']['pending'][role]
                        elif mutation=='foreign-run':p['identity']['run_id']='old-run'
                        elif mutation=='wrong-role':p['identity']['role']='rx' if role=='tx' else 'tx'
                        elif mutation=='wrong-request':p['identity']['request_id']=3
                        elif mutation=='wrong-session':
                            p['payload']['native_trace']['expected']['session_id']=999
                        elif mutation=='wrong-ledger-ticket':
                            p['payload']['native_trace']['raw_trace']=p['payload']['native_trace']['raw_trace'].replace(
                                'ticket=90','ticket=91',1)
                        else:
                            bad['case_evidence']['pending']['other']=copy.deepcopy(p)
                        self.reject(case,bad)

    def test_registry_saved_provider_challenge_has_exact_typed_nonce_schema(self):
        case='cable-loss'
        evidence,_=self.physical(case)
        e=evidence['case_evidence'];e['stops']={};e['close']={}
        self.add_native(evidence,case,'tx',fault=True)
        self.add_native(evidence,case,'rx',fault=True,pending_only=True)
        e['survivor_terminal']=record('rx',case,'wait',5,terminal(102,True),
                phase='HELD',fate='HELD',error=-67,held=True)
        self.assertEqual(self.evaluate(case,evidence)['status'],'EXPECTED_RETAINED')
        for mutation in ('short-nonce','boolean-version','unknown-challenge-field'):
            with self.subTest(mutation=mutation):
                bad=copy.deepcopy(evidence)
                action=bad['case_evidence']['actions']['tx']
                if mutation=='short-nonce':
                    action['receipt']['action_id']='x'
                    action['challenge']['action_id']='x'
                elif mutation=='boolean-version':
                    action['receipt']['version']=True
                    action['challenge']['version']=True
                else:
                    action['challenge']['unexpected']='unrecognized field'
                self.reject(case,bad)

    def test_registry_builtin_stop_has_typed_nonce_and_version(self):
        case='stop-inflight'
        evidence,_=self.physical(case)
        for role in ('tx','rx'):
            self.add_native(evidence,case,role)
        self.assertEqual(self.evaluate(case,evidence)['status'],'pass')
        for role in ('tx','rx'):
            for mutation in ('short-nonce','boolean-version'):
                with self.subTest(role=role,mutation=mutation):
                    bad=copy.deepcopy(evidence)
                    action=bad['case_evidence']['actions'][role]
                    if mutation=='short-nonce':action['action_id']='x'
                    else:action['version']=True
                    self.reject(case,bad)


if __name__=='__main__':
    unittest.main(verbosity=2)
