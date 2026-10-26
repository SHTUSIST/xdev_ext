# SPDX-License-Identifier: GPL-2.0
"""Hardware cases remain visible even when physical execution is unavailable."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    prerequisites: tuple
    action_barrier: str
    expected_terminal: str
    required_evidence: tuple


_NAMES = (
    "bringup",
    "strict-swiotlb",
    "strict-no-path",
    "explicit-unverified-override",
    "external-owner-refusal",
    "functional-epochs",
    "bulk-static",
    "stop-inflight",
    "cable-loss",
    "remove-on-resume",
    "peer-reboot",
    "idle-suspend-resume",
    "idle-module-unload",
)
CASES = {
    name: CaseSpec(
        name,
        ("exclusive-physical-hosts", "identity", "preflight"),
        (
            "accepted-native-inflight"
            if name
            in ("stop-inflight", "cable-loss", "remove-on-resume", "peer-reboot")
            else "idle-or-terminal"
        ),
        (
            "UNVERIFIED_FORCED"
            if name == "explicit-unverified-override"
            else (
                "strict-refusal"
                if name.startswith("strict-") or name == "external-owner-refusal"
                else "safe-or-retained"
            )
        ),
        ("identity", "create", "terminal"),
    )
    for name in _NAMES
}
GEOMETRY_REQUESTS = (
    (4096, 1, True),
    (4096, 4, True),
    (4096, 16, True),
    (65536, 1, True),
    (65536, 4, True),
    (262144, 1, True),
    (65536, 16, False),
    (262144, 4, False),
    (262144, 16, False),
)


def evaluate_case(case_id, evidence):
    if case_id not in CASES:
        raise ValueError("unknown hardware case")
    if "execution_mode" in evidence:
        return _evaluate_dispatch(case_id, evidence)

    def result(status, reason, outcome=None):
        d = {
            "case_id": case_id,
            "status": status,
            "reason": reason,
            "evidence_scope": "contract-evaluation",
            "physical_dma_proved": False,
        }
        if outcome is not None:
            d["outcome"] = outcome
        return d

    e = evidence
    if e.get("physical_execution") is not True:
        return result(
            "awaiting-physical-execution", "physical execution has not occurred"
        )
    try:
        p = e["prerequisites"]
        expected = e["expected_identity"]
        observed = e["observed_identity"]
        if expected != observed:
            return result("failed", "physical identity mismatch")
        required = (
            "service_listing",
            "software_connection_manager",
            "credits",
            "kernel_sha",
            "driver_sha",
            "config",
            "nhi",
            "gpu",
            "node",
            "bdf",
            "acs",
            "iommu",
            "link_token",
            "local_inc",
            "remote_inc",
            "admission",
        )
        if any(
            k not in p or p[k] is None or p[k] is False or p[k] == "" or p[k] == []
            for k in required
        ):
            return result("incomplete", "missing preflight prerequisite")
        if (
            p["kernel_sha"] != expected["sha"]
            or p["driver_sha"] != expected["sha"]
            or p["bdf"] != expected["gpu_bdf"]
            or p["nhi"] != expected["nhi_bdf"]
            or p["local_inc"] != expected["local_inc"]
            or p["remote_inc"] != expected["remote_inc"]
        ):
            return result("failed", "preflight identity mismatch")
        c = e.get("create", {})
        t = e["terminal"]
        if t.get("sequestered", 0) and t.get("freed"):
            return result("failed", "sequestered resources were freed")
        if t.get("unknown_callback") or t.get("callback_unknown"):
            return result("incomplete", "unknown callback cannot prove quiescence")
        refusals = {
            "strict-swiotlb": 2,
            "strict-no-path": 1,
            "external-owner-refusal": 32,
        }
        if case_id in refusals:
            a = e["admission"]
            if not c.get("attempted") or c.get("error", 0) >= 0:
                return result("failed", "strict request unexpectedly succeeded")
            if c.get("stage_caps_queried"):
                return result("failed", "STAGE_CAPS queried after failed CREATE")
            if a.get("status") != "matched" or not a.get("matched"):
                return result(
                    "incomplete", "strict refusal lacks associated diagnostic"
                )
            if not (a["matched"].get("refused", 0) & refusals[case_id]) or not (
                c.get("refused", 0) & refusals[case_id]
            ):
                return result("failed", "wrong refusal bit")
            return result("pass", "associated strict refusal observed", "REFUSED")
        if case_id == "explicit-unverified-override":
            if (
                c.get("error")
                or c.get("refused", 0) & ~1
                or c.get("reachability") not in ("UNVERIFIED_FORCED", 3)
            ):
                return result(
                    "failed", "override exceeded NO_P2P_PATH or lacks forced outcome"
                )
            return result(
                "UNVERIFIED_FORCED",
                "explicit unverified override recorded",
                "UNVERIFIED_FORCED",
            )
        if not case_id.startswith("idle-") and (c.get("error") or not c.get("attempted") or not c.get("stage_caps_queried")):
            return result("incomplete", "successful CREATE and STAGE_CAPS required")
        native = case_id in (
            "stop-inflight",
            "cable-loss",
            "remove-on-resume",
            "peer-reboot",
        )
        if native:
            b = e["barrier"]
            active = e["active_run"]
            if (
                b.get("native_accepted") is not True
                or type(b.get("inflight")) is not int
                or b["inflight"] <= 0
            ):
                return result(
                    "incomplete", "no actual accepted native work still inflight"
                )
            for k in (
                "session_id",
                "batch_id",
                "group",
                "acceptance_seq",
                "local_inc",
                "remote_inc",
                "identity",
            ):
                if k not in b or b[k] != active[k]:
                    return result("failed", "native acceptance identity mismatch")
            if not b["acceptance_seq"]:
                return result("incomplete", "no native acceptance sequence")
        if case_id in (
            "stop-inflight",
            "cable-loss",
            "remove-on-resume",
            "peer-reboot",
            "idle-suspend-resume",
            "idle-module-unload",
        ):
            a = e["action"]
            if a.get("ack_count") != 1:
                return result("incomplete", "action requires one acknowledgement")
            expected_action = {
                "stop-inflight": "stop",
                "cable-loss": "cable-loss",
                "remove-on-resume": "remove-on-resume",
                "peer-reboot": "reboot",
                "idle-suspend-resume": "suspend-resume",
                "idle-module-unload": "unload",
            }[case_id]
            if a.get("kind") != expected_action:
                return result("incomplete", "missing physical action event")
            if case_id == "cable-loss" and not (
                a.get("operator_event") or a.get("cable_event")
            ):
                return result("incomplete", "SSH disconnect is not cable evidence")
            if case_id == "peer-reboot":
                if (
                    not a.get("boot_id_after")
                    or a["boot_id_after"] == a.get("boot_id_before")
                    or not a.get("new_incarnation")
                    or a["new_incarnation"]
                    in (expected["local_inc"], expected["remote_inc"])
                ):
                    return result(
                        "incomplete", "reboot needs new boot identity and incarnation"
                    )
            if case_id == "remove-on-resume" and not all(
                a.get(k) is True
                for k in ("nhi_removed", "going_away", "upstream_still_running_warning")
            ):
                return result(
                    "incomplete", "missing native removal or upstream warning evidence"
                )
            if case_id == "idle-module-unload" and not (
                a.get("logout") is True and a.get("link_down") is True
            ):
                return result("incomplete", "unload needs LOGOUT and link-down")
        if t.get("sequestered", 0):
            if t.get("freed"):
                return result("failed", "sequestered resource freed")
            return result("incomplete", "resources retained; quiescence unproved")
        if not case_id.startswith("idle-") and (not t.get("stop_proved") or not t.get("quiesced")):
            return result("incomplete", "native release unproved")
        if case_id in ("functional-epochs", "bulk-static") and not t.get("verify_ok"):
            return result("failed", "payload verification absent or failed")
        return result("pass", "all required contract evidence present", "PASSED")
    except (KeyError, TypeError, ValueError):
        return result("incomplete", "missing or malformed physical evidence")



def _revalidate_c1(facts, preflight):
    """Replay retained target C1 bytes without substituting coordinator sysfs.

    The initial target collector owns the topology observation. Replay checks
    the retained snapshot shape/config bytes and recomputes raw CM/credit facts;
    it does not assert a new observation of a remote live topology.
    """
    import platform_facts as c1
    from check_protocol import keys, integer
    from action_provider import _same

    keys(facts, {'status', 'reason', 'identity', 'software_cm', 'credits', 'iommu', 'acs', 'evidence'})
    if facts['status'] != 'complete':
        raise ValueError('C1 collection incomplete')
    identity = facts['identity']
    keys(identity, {'run', 'boot_id', 'kernel_build_id', 'nhi_bdf', 'domain', 'link_token', 'channel'})
    raw = preflight['payload']['raw_evidence']; link = preflight['payload']['link_identity']
    if not _same(facts, raw.get('platform_facts')):
        raise ValueError('C1 report differs from actual preflight collector output')
    if identity['run'] != preflight['identity'] or identity['boot_id'] != raw['boot_id'] or identity['nhi_bdf'] != raw['nhi_bdf'] or raw['clock_domain'] != identity['boot_id'] + ':CLOCK_MONOTONIC' or any(identity[k] != link[k] for k in ('link_token', 'channel')):
        raise ValueError('C1 preflight binding mismatch')
    integer(identity['domain'], maximum=(1 << 32) - 1)
    keys(facts['evidence'], {'log_path', 'receipt_path', 'log_sha256'})
    receipt = c1._json(c1._read(facts['evidence']['receipt_path'], c1._LINE_LIMIT))
    keys(receipt, c1._RECEIPT_KEYS)
    c1._identity(receipt['identity'])
    if type(receipt['version']) is not int or receipt['version'] != 1 or receipt['complete'] is not True:
        raise ValueError('C1 receipt not complete')
    for k in ('cursor_seq', 'begin_ns', 'end_ns', 'captured_monotonic_ns', 'kmsg_lost'):
        integer(receipt[k])
    if receipt['kmsg_lost'] or not receipt['begin_ns'] <= receipt['end_ns'] <= receipt['captured_monotonic_ns']:
        raise ValueError('C1 receipt loss/chronology')
    if any(not _same(receipt[k], identity['run'] if k == 'identity' else identity[k]) for k in ('identity', 'boot_id', 'kernel_build_id', 'nhi_bdf', 'domain')):
        raise ValueError('C1 retained receipt identity mismatch')
    records, digest = c1._log(facts['evidence']['log_path'], receipt)
    if digest != facts['evidence']['log_sha256']:
        raise ValueError('C1 retained log changed')
    keys(facts['iommu'], {'group', 'type', 'raw'})
    group = facts['iommu']['group']; iommu_raw = facts['iommu']['raw']
    if type(group) is not str or not group.isascii() or not group.isdecimal() or type(iommu_raw) is not str or not iommu_raw.strip() or facts['iommu']['type'] != iommu_raw.strip():
        raise ValueError('C1 retained IOMMU observation absent')
    if type(facts['acs']) is not list or not 1 <= len(facts['acs']) <= 64:
        raise ValueError('C1 retained PCI ancestry absent')
    for acs in facts['acs']:
        keys(acs, {'bdf', 'capability', 'control', 'raw_config_hex'})
        if type(acs['bdf']) is not str or not c1._BDF.fullmatch(acs['bdf']) or type(acs['raw_config_hex']) is not str or len(acs['raw_config_hex']) > 8192:
            raise ValueError('C1 retained PCI configuration malformed')
        data = bytes.fromhex(acs['raw_config_hex'])
        if len(data) < 260:
            raise ValueError('C1 retained PCI configuration truncated')
        offset = 256; visited = set(); cap = control = None
        while offset < len(data):
            if offset < 256 or offset % 4 or offset + 4 > len(data) or offset in visited:
                raise ValueError('C1 retained PCI capability chain invalid')
            visited.add(offset)
            header = int.from_bytes(data[offset:offset+4], 'little')
            if header & 65535 in (0, 65535):
                break
            if header & 65535 == 13:
                if cap is not None or offset + 8 > len(data):
                    raise ValueError('C1 retained ACS ambiguous/truncated')
                cap = int.from_bytes(data[offset+4:offset+6], 'little')
                control = int.from_bytes(data[offset+6:offset+8], 'little')
            following = header >> 20
            if not following:
                break
            offset = following
        if not _same(acs['capability'], cap) or not _same(acs['control'], control):
            raise ValueError('C1 retained ACS scalars disagree with raw config')
    if facts['acs'][0]['bdf'] != identity['nhi_bdf']:
        raise ValueError('C1 retained ancestry does not begin at NHI')
    prefix = 'thunderbolt ' + identity['nhi_bdf'] + ': '
    cms = []; active = None; scopes = set(); latest = {}; devices = set()
    for record in records:
        message = record['message']
        if not message.startswith(prefix):
            continue
        body = message[len(prefix):]
        if body in ('using software connection manager', 'using firmware connection manager'):
            cms.append(record); continue
        marker = c1._MARKER.fullmatch(body); credit = c1._CREDIT.fullmatch(body)
        if body.startswith('XDEV_EXT_XDOMAIN_PATH') and marker is None:
            raise ValueError('C1 retained path marker malformed')
        if marker is None and credit is None:
            continue
        if record['seq'] <= receipt['cursor_seq'] or not receipt['begin_ns'] <= record['monotonic_ns'] <= receipt['end_ns']:
            raise ValueError('C1 retained scope outside capture')
        if marker is not None:
            phase, scope, token, local, remote, name, role, channel, outcome = marker.groups()
            scope, token, local, remote, channel = map(int, (scope, token, local, remote, channel))
            for value in (scope, token, local, remote): integer(value)
            integer(channel, maximum=(1 << 32) - 1)
            name_parts = c1._XD_NAME.fullmatch(name)
            if name_parts is None or int(name_parts[1]) != identity['domain'] or (phase == 'END') != (outcome is not None):
                raise ValueError('C1 retained path identity invalid')
            key = (scope, token, local, remote, name, role, channel)
            if phase == 'BEGIN':
                if active is not None or scope in scopes:
                    raise ValueError('C1 retained overlapping/reused scope')
                scopes.add(scope); active = {'key': key, 'begin': record['seq'], 'credits': []}
            else:
                if active is None or active['key'] != key:
                    raise ValueError('C1 retained mismatched scope END')
                active.update(end=record['seq'], result=int(outcome))
                if (role == 'control' and channel == 0) or (role == 'data' and channel == identity['channel']):
                    latest[(name, role, channel)] = active
                    if token == identity['link_token']: devices.add(name)
                active = None
        elif active is not None:
            route, port, reserved = credit.groups()
            port, reserved = int(port), int(reserved)
            integer(port, maximum=(1 << 32) - 1); integer(reserved, maximum=(1 << 32) - 1)
            active['credits'].append((record['seq'], port, reserved))
    if active is not None or len(devices) != 1 or not cms or cms[-1]['message'] != prefix + 'using software connection manager':
        raise ValueError('C1 retained latest software CM/path incomplete')
    device = next(iter(devices)); data = latest[(device, 'data', identity['channel'])]; control = latest[(device, 'control', 0)]
    if data['result'] or control['result'] or data['end'] >= control['begin'] or data['key'][1:5] != control['key'][1:5] or data['key'][1:4] != (identity['link_token'], link['local_inc'], link['remote_inc']):
        raise ValueError('C1 retained token/incarnation/data-control mismatch')
    credits = []
    for scoped in (data, control):
        if not any(n > 0 for _, _, n in scoped['credits']):
            raise ValueError('C1 retained scope has no actual positive credit')
        scope, _, _, _, _, role, channel = scoped['key']
        for seq, port, reserved in scoped['credits']:
            credits.append(dict(scope=scope, role=role, channel=channel, port=port, reserved=reserved, begin_seq=scoped['begin'], end_seq=scoped['end'], record_seq=seq))
    if not _same(facts['software_cm'], {'proved': True, 'records': cms}) or not _same(facts['credits'], credits):
        raise ValueError('C1 retained raw CM/credit facts disagree')
    return facts


def _evaluate_dispatch(case_id, evidence):
    from check_protocol import validate_record, validate_terminal, integer, keys, _identity
    from native_barrier import qualify_native_barrier
    from action_provider import validate_action_receipt, validate_action_binding, _same

    def result(status, reason, outcome=None):
        r = {'case_id': case_id, 'status': status, 'reason': reason,
             'evidence_scope': evidence.get('execution_mode', 'contract') + '-evaluation',
             'physical_dma_proved': False}
        if outcome: r['outcome'] = outcome
        return r

    mode = evidence.get('execution_mode')
    if mode not in ('contract', 'physical'): raise ValueError('execution mode')
    if mode == 'contract':
        return result('awaiting-physical-execution', 'contract invocation cannot prove physical execution')
    try:
        e = evidence['case_evidence']; pre = e['preflights']; platform = e['platform_facts']
        if set(pre) != {'tx', 'rx'} or set(platform) != {'tx', 'rx'}:
            raise ValueError('two role preflights/C1 observations required')
        baseline = pre['tx']['identity']
        _identity(baseline)
        if baseline['case'] != case_id or baseline['role'] != 'tx' or baseline['request_id'] != 1:
            raise ValueError('preflight base identity')

        def bound(record, role, command, request):
            expected = dict(baseline, role=role, request_id=request)
            validate_record(record, {'identity': expected, 'command': command})
            return record['payload']

        sessions = {}
        for role in ('tx', 'rx'):
            p = bound(pre[role], role, 'preflight', 1)
            if p['available'] is not True or p['kernel_identity'].get('sha') != baseline['sha'] or type(p['kernel_identity'].get('config')) is not str or not p['kernel_identity']['config'] or not p['raw_evidence'].get('service_listing'):
                raise ValueError('actual preflight unavailable')
            _revalidate_c1(platform[role], pre[role])
        links = {r: pre[r]['payload']['link_identity'] for r in pre}
        if links['tx']['local_inc'] != links['rx']['remote_inc'] or links['rx']['local_inc'] != links['tx']['remote_inc']:
            raise ValueError('preflight cross-incarnation mismatch')
        strict = {'strict-swiotlb': 2, 'strict-no-path': 1, 'external-owner-refusal': 32}
        idle = case_id.startswith('idle-')
        native = case_id in ('stop-inflight', 'cable-loss', 'remove-on-resume', 'peer-reboot')
        fault = case_id in ('cable-loss', 'remove-on-resume', 'peer-reboot')
        if idle:
            if e['prepare'] or e['stops'] or e.get('close'):
                raise ValueError('idle case contains CREATE/STOP/close')
            idle_proof = dict(scope='this-owner', prepared=False, session_id=0, native_payload_owners=0)
            for role in pre:
                if not _same(pre[role]['payload']['raw_evidence'].get('idle'), idle_proof):
                    raise ValueError('both actual scoped idle proofs required')
        elif case_id in strict:
            if len(e['prepare']) != 1 or e['stops'] or e.get('close') or e['actions'] or e['continued']:
                raise ValueError('one role-scoped strict CREATE and retained resources required')
            role, record = next(iter(e['prepare'].items())); q = bound(record, role, 'prepare', 2)
            from two_host_check import _admission
            admission = _admission(q)
            if record['phase'] != 'HELD' or record['error'] != -18 or q.get('create_error') != -18 or q.get('session_id') != 0 or q.get('stage_caps', 'missing') is not None or admission['status'] != 'matched' or not admission['matched']['refused'] & strict[case_id]:
                raise ValueError('actual retained strict refusal absent')
            return result('pass', 'associated actual CREATE refusal; owner remains retained', 'REFUSED')
        else:
            if set(e['prepare']) != {'tx', 'rx'}:
                raise ValueError('paired CREATE required')
            for role in ('tx', 'rx'):
                record = e['prepare'][role]; q = bound(record, role, 'prepare', 2)
                if record['phase'] != 'SESSION_CREATED' or record['error'] or record['held'] or q['create_error'] or q['stop_proved'] is not False:
                    raise ValueError('successful CREATE absent')
                sessions[role] = integer(q['session_id'], minimum=1)
                if not q['guard_sync_proved' if role == 'rx' else 'producer_sync_proved']:
                    raise ValueError('actual GPU synchronization absent')
                if case_id in ('bringup', 'explicit-unverified-override'):
                    caps = q['stage_caps']
                    if caps['session_id'] != sessions[role]: raise ValueError('STAGE_CAPS session mismatch')
                    if case_id == 'explicit-unverified-override' and (caps['reachability'] != 3 or caps['refused'] & ~1):
                        raise ValueError('override outcome not UNVERIFIED_FORCED')
        if not idle and not fault:
            if set(e['stops']) != {'tx', 'rx'} or set(e['close']) != {'tx', 'rx'}:
                raise ValueError('paired STOP and close receipts required')
            stop_request = 3 if case_id in ('bringup', 'explicit-unverified-override') else 5
            for role in ('tx', 'rx'):
                stop = e['stops'][role]; p = bound(stop, role, 'stop', stop_request)
                if stop['phase'] != 'DRAINED_SAFE' or stop['fate'] != 'SAFE' or stop['error'] or stop['held'] or p['stop_proved'] is not True or p['stop_error'] or p['first_error']:
                    raise ValueError('actual safe STOP absent')
                validate_terminal({k: p[k] for k in ('stats_valid', 'stats', 'transport_valid', 'transport')}, sessions[role], settled=True)
        kinds = {'stop-inflight': 'stop', 'cable-loss': 'cable-loss', 'remove-on-resume': 'remove-on-resume', 'peer-reboot': 'reboot', 'idle-suspend-resume': 'suspend-resume', 'idle-module-unload': 'unload'}
        actions = e['actions']; continued = e['continued']
        if case_id == 'stop-inflight':
            if set(actions) != {'tx', 'rx'} or set(continued) != {'tx', 'rx'}:
                raise ValueError('two native STOP actions and continued captures required')
        elif case_id in kinds:
            if len(actions) != 1 or (native and set(continued) != set(actions)) or (idle and continued):
                raise ValueError('exact action/continued role cardinality required')
        elif actions or continued:
            raise ValueError('unexpected case action/continued evidence')
        pending_barriers = {}
        if native:
            pending = e['pending']
            pending_roles = set(actions) if case_id == 'peer-reboot' else {'tx', 'rx'}
            if set(pending) != pending_roles:
                raise ValueError('actual pending WAIT role cardinality incomplete')
            for pending_role, pending_record in pending.items():
                payload = bound(pending_record, pending_role, 'wait', 4)
                keys(payload, {'native_trace'})
                if pending_record['phase'] != 'START_ACCEPTED' or pending_record['fate'] != 'ACTIVE' or pending_record['error'] or pending_record['held'] or pending_record['cleanup_permissions']:
                    raise ValueError('actual provisional pending WAIT phase invalid')
                trace = payload['native_trace']; expected = trace['expected']
                target = pre[pending_role]['payload']['raw_evidence']; link = links[pending_role]
                if expected['identity'] != dict(baseline, role=pending_role, request_id=4) or expected['session_id'] != sessions[pending_role] or expected['source_commit'] != baseline['sha'] or expected['kernel_build_id'] != platform[pending_role]['identity']['kernel_build_id'] or expected['boot_id'] != target['boot_id'] or expected['clock_domain'] != target['clock_domain'] or expected['nhi_bdf'] != target['nhi_bdf'] or any(expected[k] != link[k] for k in ('link_token','local_inc','remote_inc')):
                    raise ValueError('pending WAIT session/run/boot/build binding mismatch')
                qualified = qualify_native_barrier(trace['raw_trace'], trace['receipt'], expected, now_ns=trace['receipt']['captured_monotonic_ns'])
                if qualified['status'] != 'ready':
                    raise ValueError('actual pending native ledger incomplete: ' + qualified['reason'])
                pending_barriers[pending_role] = qualified['barrier']
        elif e.get('pending'):
            raise ValueError('unexpected pending native evidence')
        for role, action in actions.items():
            if role not in pre: raise ValueError('foreign action role')
            if case_id == 'stop-inflight':
                receipt = action; stop = e['stops'][role]
                keys(receipt, {'version','action_id','identity','kind','target','barrier','attempted','completed','error','started_monotonic_ns','finished_monotonic_ns','evidence'})
                validate_action_binding({k: receipt[k] for k in ('version', 'action_id', 'identity', 'kind', 'target', 'barrier')})
                if receipt['attempted'] is not True or receipt['completed'] is not True or type(receipt['error']) is not int or receipt['error'] != 0 or not _same(receipt['evidence']['stop_response'], stop):
                    raise ValueError('actual builtin STOP action absent')
                timing = stop['evidence']['stop_action']
                if any(not _same(receipt[k], timing[k]) for k in ('started_monotonic_ns','finished_monotonic_ns')):
                    raise ValueError('STOP invocation clock mismatch')
            else:
                receipt = action['receipt']; execution = action['execution']
                if action['status'] != 'complete' or type(execution['ack_count']) is not int or execution['ack_count'] != 1 or type(execution['returncode']) is not int or execution['returncode'] != 0 or execution['timed_out'] is not False:
                    raise ValueError('completed actual provider process required')
                validate_action_receipt(receipt, action['challenge'])
            if native and not _same(receipt['barrier'], pending_barriers[role]):
                raise ValueError('action barrier differs from actual pending WAIT ledger')
            if receipt['kind'] != kinds[case_id]: raise ValueError('action kind differs from selected case')
            expected_identity = dict(baseline, role=role, request_id=4 if native else 1)
            if not _same(receipt['identity'], expected_identity): raise ValueError('action identity/request mismatch')
            raw = pre[role]['payload']['raw_evidence']; link = links[role]
            target = dict(boot_id=raw['boot_id'], nhi_bdf=raw['nhi_bdf'], clock_domain=raw['clock_domain'], **{k:link[k] for k in ('link_token','local_inc','remote_inc')})
            if not _same(receipt['target'], target): raise ValueError('action target preflight mismatch')
            if native:
                record = continued[role]; payload = bound(record, role, 'wait', 6 if case_id == 'stop-inflight' else 5)
                keys(payload, {'native_trace', 'terminal'})
                trace = payload['native_trace']; expected = trace['expected']
                if expected['identity'] != expected_identity or expected['session_id'] != sessions[role] or expected['source_commit'] != baseline['sha'] or expected['kernel_build_id'] != platform[role]['identity']['kernel_build_id'] or expected['boot_id'] != target['boot_id'] or expected['clock_domain'] != target['clock_domain'] or expected['nhi_bdf'] != target['nhi_bdf'] or any(expected[k] != link[k] for k in ('link_token','local_inc','remote_inc')):
                    raise ValueError('native receipt session/run/boot/build binding mismatch')
                qualified = qualify_native_barrier(trace['raw_trace'], trace['receipt'], expected, now_ns=trace['receipt']['captured_monotonic_ns'], action=receipt)
                if qualified['status'] != 'ready': raise ValueError('continued native qualification: ' + qualified['reason'])
                validate_terminal(payload['terminal'], sessions[role], fault=fault, settled=not fault, stage=expected['stage'])
                if fault:
                    if record['phase'] != 'HELD' or record['error'] >= 0 or not record['held']:
                        raise ValueError('actual native fault/retention absent')
                elif record['phase'] != 'DRAINED_SAFE' or record['fate'] != 'SAFE' or record['error'] or record['held'] or record['cleanup_permissions'] != e['stops'][role]['cleanup_permissions'] or record['evidence'].get('link_up') is not True:
                    raise ValueError('continued STOP phase/link/release proof absent')
        if fault:
            if e['stops'] or e.get('close'):
                raise ValueError('fault case attempted safe release')
            role = next(iter(actions)); other = 'rx' if role == 'tx' else 'tx'
            survivor_role = role if case_id == 'peer-reboot' else other
            survivor = e['survivor_terminal']; payload = bound(survivor, survivor_role, 'wait', 5)
            if survivor['phase'] != 'HELD' or survivor['error'] >= 0 or not survivor['held']:
                raise ValueError('actual second endpoint retained fault absent')
            terminal = payload['terminal'] if case_id == 'peer-reboot' else payload
            stage = pending_barriers[survivor_role]['stage']
            validate_terminal(terminal, sessions[survivor_role], fault=True, stage=stage)
            if case_id == 'peer-reboot':
                affected = actions[role]['receipt']['evidence']['affected_peer']
                if survivor['error'] != -67 or affected['role'] != other or affected['old_boot_id'] != pre[other]['payload']['raw_evidence']['boot_id']:
                    raise ValueError('peer reboot boot/role/ENOLINK binding absent')
            return result('EXPECTED_RETAINED', 'actual session-bound fault and retained native custody proved', 'EXPECTED_RETAINED')
        if idle:
            if set(e['post_preflights']) != {'tx', 'rx'}: raise ValueError('two post-action service observations required')
            role = next(iter(actions))
            for r, post in e['post_preflights'].items(): bound(post, r, 'preflight', 2)
            after = e['post_preflights'][role]['payload']
            if case_id == 'idle-suspend-resume':
                if after['available'] is not True or after['link_identity']['local_inc'] == links[role]['local_inc'] or after['raw_evidence'].get('replugged') is not False:
                    raise ValueError('actual PM relogin/no-replug facts absent')
            elif after['raw_evidence'].get('module_absent') is not True:
                raise ValueError('actual module absence unproved')
            return result('pass', 'scoped idle and actual action/post-action observations proved', 'PASSED')
        if case_id in ('functional-epochs', 'bulk-static'):
            from oracle import build_expectations, validate_summary
            oc = e['oracle_config']
            for role in ('tx', 'rx'):
                if oc[role+'_session_id'] != sessions[role] or oc[role+'_local_inc'] != links[role]['local_inc'] or oc['link_token'][role] != links[role]['link_token']:
                    raise ValueError('oracle session/link identity mismatch')
            extents = build_expectations(e['records']['tx'], e['records']['rx'], oc)
            pages = (oc['groups'] + 31) // 32
            for role in ('tx', 'rx'):
                verification = e['verify'][role]; summary = bound(verification, role, 'verify', 6 + pages)
                if verification['error'] or verification['held'] or summary['visibility_error']: raise ValueError('allocation verification failed')
                expected = extents if role == 'rx' else [dict(dst_off=0,src_off=0,len=oc['allocation_bytes'],seed=oc['seed'],kind=1,reserved=0)]
                validate_summary(summary, expected, e['verify_launch_cookies'][role])
            close_request = 7 + pages
        else:
            close_request = 7 if native else 4
        for role in ('tx', 'rx'):
            close = e['close'][role]; payload = bound(close, role, 'close', close_request)
            if close['phase'] != 'CLOSED' or close['fate'] != 'SAFE' or close['error'] or close['held'] or payload['closed'] is not True or payload['retained_resources']:
                raise ValueError('actual closed pair proof absent')
        return result('pass', 'causal case-specific records and actual closed pair proved', 'UNVERIFIED_FORCED' if case_id == 'explicit-unverified-override' else 'PASSED')
    except (KeyError, TypeError, ValueError, OSError, OverflowError) as error:
        return result('incomplete', 'raw execution evidence rejected: ' + str(error))
