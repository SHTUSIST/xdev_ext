#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent case dispatch contract: real pipes, no hardware or CUDA calls.

The surrogate deliberately refuses at the first new proof boundary. Receiving
that refusal is never a hardware PASS. These tests prove the coordinator enters
actual command paths rather than merely looking up case registry entries.
"""
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_protocol
import two_host_check

NATIVE = ("stop-inflight", "cable-loss", "remove-on-resume", "peer-reboot")
EARLY = ("bringup", "strict-swiotlb", "strict-no-path",
         "explicit-unverified-override", "external-owner-refusal")
IDLE = ("idle-suspend-resume", "idle-module-unload")
FUNCTIONAL = ("functional-epochs", "bulk-static")

AGENT = r'''
import json, os, pathlib, struct, sys, time
role, root = sys.argv[1:3]
root = pathlib.Path(root)
phase = 'NEW'
def read():
    prefix = sys.stdin.buffer.read(4)
    if not prefix: return None
    n = struct.unpack('!I', prefix)[0]
    return json.loads(sys.stdin.buffer.read(n))
while True:
    q = read()
    if q is None: break
    with (root / ('commands-' + role + '.jsonl')).open('a') as f:
        f.write(json.dumps(q) + '\n')
    c, p = q['command'], q['payload']
    case = q['identity']['case']
    out, error, held, fate = {}, 0, False, 'EMPTY'
    if c == 'preflight':
        local, remote = (81, 82) if role == 'tx' else (82, 81)
        platform = json.loads((root / ('platform-' + role + '.json')).read_text())
        out = dict(available=True, reason='', device_identity=dict(gpu_bdf=p['gpu_bdf'],
                   nvidia_node=p['nvidia_node'], backing='gpu'),
                   link_identity=dict(link_token=p['link_token'], channel=p['channel'],
                                      local_inc=local, remote_inc=remote),
                   kernel_identity=dict(sha=q['identity']['sha'], config='CONFIG_USB4=m\n'),
                   visibility='NATIVE_OWNER', raw_evidence=dict(service_listing=['xdevext'],
                   nhi_bdf='0000:04:00.0', platform_facts=platform,
                   boot_id='contract-boot-' + role,
                   clock_domain='contract-boot-' + role + ':CLOCK_MONOTONIC',
                   observed_monotonic_ns=time.monotonic_ns(),
                   idle=dict(sessions=0, native_owners=0), evidence_scope='contract'))
    elif c == 'prepare' and case in ('functional-epochs','bulk-static','stop-inflight',
                                      'cable-loss','remove-on-resume','peer-reboot'):
        phase, fate = 'SESSION_CREATED', 'ACTIVE'
        out = dict(session_id=101 if role == 'tx' else 102,
                   registration_bytes=p['geometry']['allocation_bytes'],
                   producer_sync_proved=True, guard_sync_proved=True,
                   create_error=0, stop_proved=False)
    elif c == 'start':
        phase, fate = 'START_ACCEPTED', 'ACTIVE'
        out = dict(start_accepted=True, arm_error=0, start_error=0)
    else:
        # Deliberate boundary refusal: a dispatcher must preserve this error.
        phase, fate, error, held = 'HELD', 'HELD', -95, True
        out = dict(reason='independent fixture has no physical evidence')
    response = dict(identity=q['identity'], command=c, phase=phase, fate=fate,
                    error=error, held=held, cleanup_permissions=0,
                    evidence=dict(owner_pid=os.getpid(), durable_path=str(root / ('owner-' + role))),
                    payload=out, part_index=0, part_count=1)
    b = json.dumps(response, separators=(',', ':')).encode()
    sys.stdout.buffer.write(struct.pack('!I', len(b)) + b)
    sys.stdout.buffer.flush()
    if held: break
'''

PROVIDER = r'''
import json, pathlib, struct, sys, time
root = pathlib.Path(sys.argv[1])
n = struct.unpack('!I', sys.stdin.buffer.read(4))[0]
c = json.loads(sys.stdin.buffer.read(n))
(root / 'provider-challenge.json').write_text(json.dumps(c))
now = time.monotonic_ns()
(root / 'primitive.stdout').write_text('no physical operation attempted\n')
(root / 'primitive.stderr').write_text('')
r = dict(version=1, action_id=c['action_id'], identity=c['identity'], kind=c['kind'],
         target=c['target'], barrier=c['barrier'], attempted=False, completed=False,
         error=-95, started_monotonic_ns=now, finished_monotonic_ns=now + 1,
         evidence=dict(argv=sys.argv, returncode=0, stdout_path=str(root / 'primitive.stdout'),
                       stderr_path=str(root / 'primitive.stderr')))
b = json.dumps(r).encode()
sys.stdout.buffer.write(struct.pack('!I', len(b)) + b)
sys.stdout.buffer.flush()
'''


class CaseDispatchTests(unittest.TestCase):
    def setup_case(self, case):
        tmp = tempfile.TemporaryDirectory(prefix="c2-dispatch-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        agent = root / "agent.py"
        agent.write_text(AGENT)
        provider = root / "provider.py"
        provider.write_text(PROVIDER)
        identity = dict(version=1, run_id="c2-dispatch", sha="a" * 40,
                        case=case, direction="a-to-b", epoch=1)
        platform_evidence = {}
        for role in ("tx", "rx"):
            full = dict(identity, role=role, request_id=1)
            local, remote = (81, 82) if role == "tx" else (82, 81)
            log = root / ("platform-" + role + ".raw")
            receipt = root / ("platform-" + role + ".receipt")
            log.write_text("contract fixture; no physical provenance\n")
            receipt.write_text(json.dumps(dict(version=1, identity=full,
                boot_id="boot-" + role, kernel_build_id="1234abcd", complete=True,
                evidence_scope="contract")))
            expected = dict(identity=full, nhi_bdf="0000:04:00.0", domain=0,
                            link_token=71 if role == "tx" else 72,
                            channel=0, max_log_age_ms=1000)
            platform_evidence[role] = dict(log_path=str(log), receipt_path=str(receipt),
                                            expected=expected)
            facts = dict(status="complete", reason="", identity=dict(run=full,
                boot_id="boot-" + role, kernel_build_id="1234abcd", nhi_bdf="0000:04:00.0",
                domain=0, link_token=71 if role == "tx" else 72, channel=0),
                software_cm=dict(proved=True, records=[dict(raw="fixture")]),
                credits=[dict(scope=1, role="control", channel=0, port=1, reserved=8,
                              begin_seq=1,end_seq=4,record_seq=2)],
                iommu=dict(group="1",type="DMA",raw="fixture"), acs=[],
                evidence=dict(log_path=str(log),receipt_path=str(receipt),log_sha256="a"*64))
            (root / ("platform-" + role + ".json")).write_text(json.dumps(facts))
        config = dict(identity=identity, execution_mode="contract", platform_evidence=platform_evidence,
            geometry=dict(allocation_bytes=65536, group_bytes=65536, frame_size=65536,
                          seg_len=65536, depth=1, native_elems=16),
            groups=1, first_seq=40, mode="single-group", seed=7, flags=0, channel=0,
            gpu_bdf=dict(tx="0000:01:00.0",rx="0000:02:00.0"),
            nvidia_node=dict(tx="/dev/nvidia0",rx="/dev/nvidia0"),
            link_token=dict(tx=71,rx=72), deadline_ms=500, evidence_dir=str(root),
            observer_object="/contract/observer.o", ptx_path="/contract/pattern.ptx",
            action_provider=dict(argv=[sys.executable,str(provider),str(root)],timeout_ms=500))
        argv = {role: [sys.executable,str(agent),role,str(root)] for role in ("tx","rx")}
        return root, config, argv

    def commands(self, root):
        result = []
        for role in ("tx", "rx"):
            path = root / ("commands-" + role + ".jsonl")
            if path.exists():
                result += [(role, json.loads(line)) for line in path.read_text().splitlines()]
        return result

    def test_all_thirteen_cases_enter_their_actual_first_proof_path(self):
        for case in EARLY + NATIVE + IDLE + FUNCTIONAL:
            with self.subTest(case=case):
                root, config, argv = self.setup_case(case)
                result = two_host_check.run(config, argv)
                commands = self.commands(root)
                names = [q["command"] for _, q in commands]
                self.assertIn("preflight", names, "case was only registered, never dispatched")
                self.assertNotEqual(result["status"], "pass", "fixture refusal became functional PASS")
                self.assertFalse(result.get("physical_dma_proved", False))
                if case in IDLE:
                    self.assertNotIn("prepare", names, "idle action acquired a session")
                    self.assertTrue((root / "provider-challenge.json").exists(),
                                    "idle dispatcher never executed its action provider")
                    challenge = json.loads((root / "provider-challenge.json").read_text())
                    self.assertEqual(challenge["kind"], "unload" if case.endswith("unload") else "suspend-resume")
                else:
                    self.assertIn("prepare", names)
                if case in NATIVE + FUNCTIONAL:
                    self.assertIn("start", names)
                    waits = [q["payload"] for _, q in commands if q["command"] == "wait"]
                    self.assertTrue(waits)
                    if case in NATIVE:
                        self.assertEqual(waits[0].get("until"), "accepted-native-inflight")
                        self.assertFalse((root / "provider-challenge.json").exists(),
                                         "action ran after a refused native proof")
                    else:
                        self.assertEqual(waits[0], {})
                if case in EARLY:
                    self.assertNotIn("start", names)
                    self.assertNotIn("verify", names)

    def test_missing_provider_refuses_action_before_any_prepare(self):
        for case in ("cable-loss", "remove-on-resume", "peer-reboot") + IDLE:
            with self.subTest(case=case):
                root, config, argv = self.setup_case(case)
                del config["action_provider"]
                result = two_host_check.run(config, argv)
                self.assertEqual(result["status"], "incomplete")
                self.assertNotIn("prepare", [q["command"] for _, q in self.commands(root)])

    def test_physical_mode_missing_actual_C1_files_never_prepares(self):
        root, config, argv = self.setup_case("stop-inflight")
        config["execution_mode"] = "physical"
        del config["platform_evidence"]
        result = two_host_check.run(config, argv)
        self.assertEqual(result["status"], "incomplete")
        self.assertNotIn("prepare", [q["command"] for _, q in self.commands(root)])

    def test_pending_wait_request_is_allowed_without_settled_wait_semantics(self):
        identity = dict(version=1, run_id="c2-wire", sha="a"*40, role="tx",
                        case="stop-inflight", direction="a-to-b", epoch=1, request_id=3)
        request = dict(identity=identity, command="wait", deadline_ms=1000,
                       part_index=0, part_count=1,
                       payload=dict(until="accepted-native-inflight",max_age_ms=50))
        try:
            encoded = check_protocol.encode_record(request)
        except ValueError as error:
            self.fail("accepted-native WAIT extension is absent: " + str(error))
        self.assertEqual(check_protocol.decode_frame(encoded)["payload"], request["payload"])

    def test_pending_wait_does_not_advance_transport_done_or_grant_cleanup(self):
        identity = dict(version=1, run_id="c2-wire", sha="a"*40, role="tx",
                        case="stop-inflight", direction="a-to-b", epoch=1, request_id=3)
        response = dict(identity=identity, command="wait", phase="START_ACCEPTED",
                        fate="ACTIVE", error=0, held=False,cleanup_permissions=0,
                        evidence={},payload=dict(native_trace=dict(raw_trace="",receipt={},expected={})),
                        part_index=0,part_count=1)
        try:
            check_protocol.validate_record(response,dict(identity=identity,command="wait",phase="START_ACCEPTED"))
        except ValueError as error:
            self.fail("pending WAIT must preserve active phase without cleanup: " + str(error))
        response["cleanup_permissions"] = 1
        with self.assertRaises(ValueError):
            check_protocol.validate_record(response)


if __name__ == "__main__":
    unittest.main(verbosity=2)
