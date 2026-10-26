#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Two-host metadata coordinator; retained resource owners are never killed."""

import argparse
import json
import os
from pathlib import Path
import secrets
import select
import struct
import subprocess
import time

from check_protocol import (
    encode_record,
    decode_frame,
    validate_record,
    integer,
    keys,
    MAX_JSON,
    _identity,
    validate_terminal,
)
from oracle import build_expectations, validate_summary

_RETAINED = []  # Retain pipe/worker handles for manual recovery, including on failures.


class OwnerProcess(subprocess.Popen):
    retained = False

    def __del__(self):
        # Popen's default destructor polls waitpid. That is forbidden for a
        # retained resource owner, even as an interpreter-shutdown side effect.
        if not self.retained:
            super().__del__()


class Endpoint:
    def __init__(self, role, argv, config):
        if (
            type(argv) is not list
            or not argv
            or any(type(s) is not str or not s for s in argv)
        ):
            raise ValueError("argv must be a nonempty string array")
        self.role = role
        self.config = config
        self.phase = "NEW"
        self.seq = 0
        self.last = None
        self.owner_evidence = {}
        self.prepared = False
        self.identity = dict(config["identity"], role=role)
        child_input, self.infd = os.pipe()
        self.outfd, child_output = os.pipe()
        try:
            self.process = OwnerProcess(
                argv,
                stdin=child_input,
                stdout=child_output,
                stderr=subprocess.DEVNULL,
                shell=False,
                start_new_session=True,
                bufsize=0,
            )
        finally:
            os.close(child_input)
            os.close(child_output)
        os.set_blocking(self.infd, False)
        os.set_blocking(self.outfd, False)
        self.pending = bytearray()
        self.log = Path(config["evidence_dir"]) / (role + "-wire.jsonl")

    def _log(self, direction, record):
        with self.log.open("a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {"direction": direction, "record": record}, separators=(",", ":")
                )
                + "\n"
            )

    def _write(self, frame, deadline):
        off = 0
        while off < len(frame):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("agent write deadline")
            _, w, _ = select.select([], [self.infd], [], remaining)
            if not w:
                raise ValueError("agent write deadline")
            try:
                off += os.write(self.infd, frame[off:])
            except BlockingIOError:
                continue
            except (BrokenPipeError, OSError) as e:
                raise ValueError("agent input disconnected") from e

    def _read(self, deadline):
        while True:
            if len(self.pending) >= 4:
                size = struct.unpack("!I", self.pending[:4])[0]
                if not 1 <= size <= MAX_JSON:
                    raise ValueError("agent frame bound")
                if len(self.pending) >= size + 4:
                    frame = bytes(self.pending[: size + 4])
                    del self.pending[: size + 4]
                    return decode_frame(frame)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("agent response deadline")
            r, _, _ = select.select([self.outfd], [], [], remaining)
            if not r:
                raise ValueError("agent response deadline")
            try:
                data = os.read(self.outfd, 65536)
            except BlockingIOError:
                continue
            if not data:
                raise ValueError("agent output EOF")
            self.pending.extend(data)

    def command(self, command, payload, parts=None):
        self.seq += 1
        identity = dict(self.identity, request_id=self.seq)
        payloads = parts if parts is not None else [payload]
        deadline = time.monotonic() + self.config["deadline_ms"] / 1000
        for i, p in enumerate(payloads):
            request = {
                "identity": identity,
                "command": command,
                "deadline_ms": self.config["deadline_ms"],
                "part_index": i,
                "part_count": len(payloads),
                "payload": p,
            }
            self._log("request", request)
            self._write(encode_record(request), deadline)
        result = self._read(deadline)
        self._log("response", result)
        previous = self.last
        self.last = None
        validate_record(
            result, {"identity": identity, "command": command, "phase": self.phase}
        )
        if command == "wait" and result["phase"] == "DRAINED_SAFE" and "native_trace" in result["payload"]:
            if previous is None or previous["phase"] != "DRAINED_SAFE" or previous["fate"] != result["fate"] or previous["cleanup_permissions"] != result["cleanup_permissions"]:
                raise ValueError("continued capture changed STOP authority")
        self.last = result  # Only identity-validated responses are inspectable.
        evidence = result["evidence"]
        owner_pid = evidence.get("owner_pid")
        durable_path = evidence.get("durable_path")
        if (
            type(owner_pid) is int
            and owner_pid > 0
            and type(durable_path) is str
            and durable_path.startswith("/")
            and len(durable_path) <= 4096
        ):
            self.owner_evidence = dict(evidence)
        elif self.owner_evidence and "hold_reasons" in evidence:
            self.owner_evidence["hold_reasons"] = evidence["hold_reasons"]
        self.phase = result["phase"]
        if result["error"] or result["held"]:
            raise ValueError(role_reason(self.role, result))
        return result

    def retain(self, reason):
        # Do not close any pipes, poll/reap, signal, wait, or join a retained owner.
        self.process.retained = True
        _RETAINED.append(self)
        e = self.owner_evidence
        return {
            "owner_pid": e.get("owner_pid"),
            "durable_path": e.get("durable_path"),
            "transport_pid": self.process.pid,
            "coordinator_log_path": str(self.log),
            "evidence_incomplete": not bool(e) or self.phase != "HELD",
            "held_confirmed": self.phase == "HELD",
            "identity": self.identity,
            "phase": self.phase,
            "hold_reasons": e.get("hold_reasons", [reason]),
        }


def role_reason(role, response):
    return role + " returned " + response["phase"] + " error=" + str(response["error"])


def _geometry(config):
    g = config["geometry"]
    keys(
        g,
        {
            "allocation_bytes",
            "group_bytes",
            "frame_size",
            "seg_len",
            "depth",
            "native_elems",
        },
    )
    for v in g.values():
        integer(v, minimum=1)
    b = g["group_bytes"]
    elems = b // 4096
    if (
        b % 4096
        or g["frame_size"] != 65536
        or g["seg_len"] != min(b, 65536)
        or not 1 <= elems <= 64
        or g["native_elems"] != elems
        or g["depth"] * elems > 255
        or g["allocation_bytes"] % 65536
        or not b <= g["allocation_bytes"] <= 1024**3
    ):
        raise ValueError("unsupported geometry; request not clamped")
    integer(config["groups"], maximum=10000, minimum=1)
    integer(config["first_seq"])
    if config["first_seq"] + config["groups"] - 1 > (1 << 64) - 1:
        raise ValueError("sequence overflow")
    if config["mode"] == "single-group" and (config["groups"] != 1 or g["depth"] != 1):
        raise ValueError("single-group geometry")
    if config["mode"] not in ("single-group", "bulk-static"):
        raise ValueError("mode")


def _preflight(response, config, role):
    p = response["payload"]
    keys(
        p,
        {
            "available",
            "reason",
            "device_identity",
            "link_identity",
            "kernel_identity",
            "visibility",
            "raw_evidence",
        },
    )
    if p["available"] is not True:
        raise ValueError("preflight unavailable: " + str(p["reason"]))
    device = p["device_identity"]
    link = p["link_identity"]
    kernel = p["kernel_identity"]
    keys(device, {"gpu_bdf", "nvidia_node", "backing"})
    keys(link, {"link_token", "channel", "local_inc", "remote_inc"})
    keys(kernel, {"sha", "config"})
    if (
        kernel["sha"] != config["identity"]["sha"]
        or type(kernel["config"]) is not str
        or not kernel["config"]
    ):
        raise ValueError("actual kernel SHA/config mismatch")
    if (
        device["gpu_bdf"] != config["gpu_bdf"][role]
        or device["nvidia_node"] != config["nvidia_node"][role]
        or device["backing"] != "gpu"
    ):
        raise ValueError("actual GPU BDF/node/backing mismatch")
    if (
        link["link_token"] != config["link_token"][role]
        or link["channel"] != config["channel"]
    ):
        raise ValueError("link token/channel mismatch")
    for k in ("local_inc", "remote_inc"):
        integer(link[k], minimum=1)
    if not p["raw_evidence"].get("service_listing"):
        raise ValueError("actual service listing absent")
    return {"local_inc": link["local_inc"], "remote_inc": link["remote_inc"]}


def _settled(response, groups, session):
    p = response["payload"]
    if p.get("stats_valid") is not True or p.get("transport_valid") is not True:
        raise ValueError("missing actual terminal stats")
    s = p["stats"]
    tr = p["transport"]
    v1 = tr["v3"]["v2"]["v1"]
    if (
        s["session_id"] != session
        or s["batches_done"] != groups
        or any(
            s[k] != 0
            for k in (
                "batches_abort",
                "rejects",
                "held",
                "sequestered",
                "timeouts",
                "inflight",
                "protocol_err",
                "last_err",
            )
        )
    ):
        raise ValueError("terminal stats not settled")
    if (
        v1["size"] != 216
        or v1["version"] != 4
        or v1["session_id"] != session
        or any(
            v1[k] != 0
            for k in ("native_controls", "pending_acks", "uncertain_controls")
        )
    ):
        raise ValueError("transport not settled")


_ACTION_KINDS = {'cable-loss': 'cable-loss', 'remove-on-resume': 'remove-on-resume', 'peer-reboot': 'reboot', 'idle-suspend-resume': 'suspend-resume', 'idle-module-unload': 'unload'}
_NATIVE_CASES = {'stop-inflight', 'cable-loss', 'remove-on-resume', 'peer-reboot'}
_STRICT_CASES = {'strict-swiotlb': 2, 'strict-no-path': 1, 'external-owner-refusal': 32}


def _scope(config):
    return {'execution_mode': config.get('execution_mode', 'contract'),
            'evidence_scope': config.get('execution_mode', 'contract') + '-execution',
            'physical_dma_proved': False}


def _finish_special(config, endpoints, reason, *, status='incomplete', outcome=None, evidence=None, close=False):
    retained = []
    if close:
        evidence['close'] = {}
        pair = [evidence['stops']['tx'], evidence['stops']['rx']]
        for ep in endpoints.values():
            r = ep.command('close', {'stop_receipts': pair})
            evidence['close'][ep.role] = r
            if r['payload'].get('closed') is not True or r['payload'].get('retained_resources'):
                raise ValueError('special case close unproved')
        for ep in endpoints.values():
            os.close(ep.infd); os.close(ep.outfd)
            try:
                ep.process.wait(timeout=config['deadline_ms'] / 1000)
            except subprocess.TimeoutExpired:
                ep.process.retained = True
                _RETAINED.append(ep)
    else:
        for ep in endpoints.values():
            if ep.phase != 'HELD':
                try:
                    ep.command('cancel', {'reason': 'case-evidence-incomplete'})
                except (ValueError, KeyError, TypeError, OSError):
                    pass
            retained.append(ep.retain(reason))
    result = dict(status=status, reason=reason, retained_workers=retained, epochs=[], **_scope(config))
    if outcome is not None:
        result['outcome'] = outcome
    if evidence is not None:
        result['case_evidence'] = evidence
        result['actions'] = evidence.get('actions', {})
    return result


def _prepare_payload(config, common, role):
    return dict(common, **{k: config[k] for k in ('mode', 'groups', 'first_seq', 'seed', 'observer_object', 'ptx_path')}, gpu_bdf=config['gpu_bdf'][role], nvidia_node=config['nvidia_node'][role], link_token=config['link_token'][role])


def _admission(payload):
    from admission import match_admission
    a = payload.get('admission')
    if type(a) is not dict:
        raise ValueError('actual admission evidence absent')
    keys(a, {'records', 'window', 'expected'})
    if type(a['records']) is not list or len(a['records']) > 100000:
        raise ValueError('admission records capacity')
    # The extracted canonical scalar body must remain independently checkable
    # against the original kmsg bytes, not a caller-created parsed message.
    for record in a['records']:
        keys(record, {'seq', 'monotonic_ns', 'message', 'raw'})
        raw = record['raw']
        if type(raw) is not str or len(raw.encode()) > 65536 or ';' not in raw:
            raise ValueError('admission raw kmsg absent')
        header, body = raw.rstrip('\n').split(';', 1)
        fields = header.split(',')
        if len(fields) < 4 or not fields[1].isdigit() or not fields[2].isdigit() or int(fields[1]) != record['seq'] or int(fields[2]) * 1000 != record['monotonic_ns'] or not body.endswith(record['message']):
            raise ValueError('admission raw kmsg disagrees with parsed record')
    return match_admission(a['records'], a['window'], a['expected'])


def _caps(payload):
    caps = payload.get('stage_caps')
    if type(caps) is not dict or caps.get('session_id') != payload.get('session_id') or payload.get('create_error'):
        raise ValueError('actual successful CREATE/STAGE_CAPS absent')
    return caps


def _safe_stop(ep, session, groups=None):
    r = ep.command('stop', {})
    p = r['payload']
    if r['fate'] != 'SAFE' or not p.get('stop_proved') or p.get('stop_error') or p.get('first_error'):
        raise ValueError('actual STOP failed')
    if groups is not None:
        _settled(r, groups, session)
    else:
        if p.get('stats_valid') is not True or p.get('transport_valid') is not True:
            raise ValueError('STOP terminal facts absent')
        s = p['stats']; tr = p['transport']['v3']['v2']['v1']
        if s['session_id'] != session or any(s[k] for k in ('inflight', 'held', 'sequestered')) or any(tr[k] for k in ('native_controls', 'pending_acks', 'uncertain_controls')):
            raise ValueError('STOP cannot prove release')
    return r


def _native_wait(ep, config, session, action=None, link=None):
    from native_barrier import qualify_native_barrier
    request = ({'until': 'native-action-evidence', 'action': action} if action is not None else {'until': 'accepted-native-inflight', 'max_age_ms': config.get('max_native_age_ms', 1000)})
    try:
        response = ep.command('wait', request)
    except ValueError:
        # A held terminal can still carry facts, but never cleanup authority.
        response = ep.last
        if action is None or response is None or 'native_trace' not in response.get('payload', {}):
            raise
    trace = response['payload']['native_trace']
    expected = trace['expected']
    anchor_identity = action['identity'] if action is not None else response['identity']
    if expected['identity'] != anchor_identity or expected['session_id'] != session or expected['identity']['role'] != ep.role or any(expected['identity'][k] != ep.identity[k] for k in ep.identity if k != 'request_id'):
        raise ValueError('native trace session/run identity mismatch')
    if link is not None and any(expected[k] != link[k] for k in ('local_inc', 'remote_inc')):
        raise ValueError('native trace incarnation mismatch')
    if expected['link_token'] != config['link_token'][ep.role] or expected['group_bytes'] != config['geometry']['group_bytes']:
        raise ValueError('native trace request binding mismatch')
    # This timestamp is supplied by the target owner. Coordinator clocks never
    # substitute for a remote boot's CLOCK_MONOTONIC domain.
    qualified = qualify_native_barrier(trace['raw_trace'], trace['receipt'], expected, now_ns=trace['receipt']['captured_monotonic_ns'], action=action)
    if qualified['status'] != 'ready':
        raise ValueError('native barrier incomplete: ' + qualified['reason'])
    return qualified['barrier'], response


def _provider_action(config, ep, barrier, target, actions):
    from action_provider import execute_action
    challenge = {'version': 1, 'action_id': secrets.token_hex(32), 'identity': barrier['identity'], 'kind': _ACTION_KINDS[config['identity']['case']], 'target': target, 'barrier': barrier,
                 'deadline_monotonic_ns': barrier['observed_monotonic_ns'] + config['action_provider']['timeout_ms'] * 1000000}
    action = execute_action(challenge, config['action_provider'], evidence_dir=config['evidence_dir'])
    recorded = dict(action, challenge=challenge)
    actions[ep.role] = recorded
    if action['status'] != 'complete':
        raise ValueError('physical action incomplete: ' + action['reason'])
    return recorded


def _special_case(config, endpoints, common, links, preflights, platform_facts, evidence):
    case = config['identity']['case']
    role = config.get('action_role', 'rx' if case == 'peer-reboot' else 'tx')
    if role not in endpoints:
        raise ValueError('action role')
    if case.startswith('idle-'):
        # No prepare/CREATE/GPU allocation is allowed on either endpoint.
        facts = preflights[role]['payload']['raw_evidence']
        owner_idle = {'scope': 'this-owner', 'prepared': False, 'session_id': 0, 'native_payload_owners': 0}
        from action_provider import _same
        for idle_role in ('tx', 'rx'):
            idle_proof = preflights[idle_role]['payload']['raw_evidence'].get('idle')
            if not _same(idle_proof, owner_idle) or endpoints[idle_role].prepared or endpoints[idle_role].phase != 'NEW':
                raise ValueError('both actual scoped idle proofs required before action')
        idle = facts['idle']
        target = {k: facts[k] for k in ('boot_id', 'nhi_bdf', 'clock_domain')}
        target.update(link_token=config['link_token'][role], **links[role])
        observed = integer(facts['observed_monotonic_ns'])
        barrier = {'identity': preflights[role]['identity'], 'observed_monotonic_ns': observed, 'idle': idle}
        action = _provider_action(config, endpoints[role], barrier, target, evidence['actions'])
        evidence['actions'][role] = action
        for other in ('tx', 'rx'):
            payload = dict(common, gpu_bdf=config['gpu_bdf'][other], nvidia_node=config['nvidia_node'][other], link_token=config['link_token'][other])
            post = endpoints[other].command('preflight', payload)
            evidence.setdefault('post_preflights', {})[other] = post
            if post['payload'].get('available') is not True and case != 'idle-module-unload':
                raise ValueError('idle PM service did not return')
        # Idle outcomes require raw post-action service/relogin facts. Keep them
        # visible instead of treating a provider receipt as physical proof.
        if idle != owner_idle:
            raise ValueError('final idle outcome needs actual this-owner idle proof')
        after = evidence['post_preflights'][role]['payload']['raw_evidence']
        if case == 'idle-suspend-resume':
            post_link = evidence['post_preflights'][role]['payload']['link_identity']
            if post_link.get('local_inc') in (None, links[role]['local_inc']) or after.get('replugged') is not False:
                raise ValueError('idle PM new incarnation/no-replug evidence absent')
        elif after.get('module_absent') is not True:
            raise ValueError('actual post-unload module absence missing')
        return _finish_special(config, endpoints, 'idle action and actual post-action facts recorded', status='pass', outcome='PASSED', evidence=evidence)
    sessions = {}
    roles = (role,) if case in _STRICT_CASES else ('rx', 'tx')
    for current in roles:
        ep = endpoints[current]
        p = _prepare_payload(config, common, current)
        if case in _STRICT_CASES:
            p['flags'] = 0
        elif case == 'explicit-unverified-override':
            integer(config['flags'], maximum=1)
            p['flags'] = 1
            evidence['override_requested_by_case_selection'] = True
        ep.prepared = True
        try:
            response = ep.command('prepare', p)
        except ValueError:
            if case not in _STRICT_CASES or ep.last is None:
                raise
            response = ep.last
            q = response['payload']
            if response['phase'] != 'HELD' or response['fate'] != 'HELD' or response['error'] != -18 or q.get('create_error') != -18 or q.get('session_id') != 0 or q.get('stage_caps', 'missing') is not None:
                raise ValueError('strict CREATE lacks actual retained refusal')
            admission = _admission(q)
            if admission['status'] != 'matched' or not admission['matched']['refused'] & _STRICT_CASES[case]:
                raise ValueError('strict CREATE lacks uniquely associated refusal bit')
            evidence['prepare'][current] = response
            evidence['admission'] = admission
            return _finish_special(config, endpoints, 'strict CREATE refused; owner remains retained', outcome='REFUSED', evidence=evidence)
        q = response['payload']
        evidence['prepare'][current] = response
        if q['registration_bytes'] != config['geometry']['allocation_bytes'] or not q['session_id'] or q['create_error'] or q['stop_proved'] is not False:
            raise ValueError('special prepare registration/CREATE not proved')
        sessions[current] = q['session_id']
        caps = _caps(q) if case in ('bringup', 'explicit-unverified-override') else None
        if case == 'explicit-unverified-override' and (caps['reachability'] != 3 or caps['refused'] & ~1):
            raise ValueError('override did not prove UNVERIFIED_FORCED only')
        if case in _STRICT_CASES:
            evidence['stops'][current] = _safe_stop(ep, sessions[current])
            # The untouched peer has no CREATE but remains under explicit owner
            # retention; never manufacture a pair close acknowledgement.
            return _finish_special(config, endpoints, 'strict CREATE unexpectedly succeeded', status='failed', evidence=evidence)
    if case in ('bringup', 'explicit-unverified-override'):
        for current in ('tx', 'rx'):
            evidence['stops'][current] = _safe_stop(endpoints[current], sessions[current], groups=0)
        return _finish_special(config, endpoints, 'CREATE/STAGE_CAPS and paired STOP proved without START', status='pass', outcome='UNVERIFIED_FORCED' if case == 'explicit-unverified-override' else 'PASSED', evidence=evidence, close=True)
    for current in ('rx', 'tx'):
        r = endpoints[current].command('start', {k: config[k] for k in ('groups', 'first_seq')})
        if r['payload'] != {'start_accepted': True, 'arm_error': 0, 'start_error': 0}:
            raise ValueError('START not accepted')
    barriers = {}
    evidence['pending'] = {}
    # Both cable/removal endpoints must be observed pending before action, so
    # each later terminal request follows its own real pending WAIT (request4).
    pending_roles = (role,) if case == 'peer-reboot' else ('tx', 'rx')
    for current in pending_roles:
        barriers[current], pending = _native_wait(endpoints[current], config, sessions[current], link=links[current])
        evidence['pending'][current] = pending
    if case == 'stop-inflight':
        for current in ('tx', 'rx'):
            b = barriers[current]
            stop = _safe_stop(endpoints[current], sessions[current])
            evidence['stops'][current] = stop
            timing = stop['evidence'].get('stop_action')
            if type(timing) is not dict:
                raise ValueError('target-local STOP invocation timing absent')
            target = {k: timing[k] for k in ('boot_id', 'clock_domain')}
            target.update(nhi_bdf=preflights[current]['payload']['raw_evidence']['nhi_bdf'], link_token=config['link_token'][current], **links[current])
            a = {'version': 1, 'action_id': secrets.token_hex(32), 'identity': b['identity'], 'kind': 'stop', 'target': target, 'barrier': b, 'attempted': True, 'completed': True, 'error': 0, 'started_monotonic_ns': timing['started_monotonic_ns'], 'finished_monotonic_ns': timing['finished_monotonic_ns'], 'evidence': {'stop_response': stop}}
            evidence['actions'][current] = a
            _, continued = _native_wait(endpoints[current], config, sessions[current], a, link=links[current])
            evidence['continued'][current] = continued
            trace = continued['payload']['native_trace']
            if 'phase=native_complete ' not in trace['raw_trace']:
                raise ValueError('STOP lacks later actual native completion')
            terminal = continued['payload']['terminal']
            validate_terminal(terminal, sessions[current], settled=True)
            if continued['evidence'].get('link_up') is not True:
                raise ValueError('STOP link preservation unproved')
        return _finish_special(config, endpoints, 'native STOP action window and pair release proved', status='pass', outcome='PASSED', evidence=evidence, close=True)
    b = barriers[role]
    raw = preflights[role]['payload']['raw_evidence']
    target = {k: raw[k] for k in ('nhi_bdf',)}
    target.update(boot_id=b['boot_id'], clock_domain=b['clock_domain'], link_token=config['link_token'][role], **links[role])
    action = _provider_action(config, endpoints[role], b, target, evidence['actions'])
    evidence['actions'][role] = action
    _, continued = _native_wait(endpoints[role], config, sessions[role], action['receipt'], link=links[role])
    evidence['continued'][role] = continued
    # The survivor's actual response is required too, even when its owner has
    # latched HELD. Payload verification/close is forbidden on fault paths.
    other = 'rx' if role == 'tx' else 'tx'
    if case == 'peer-reboot':
        affected = action['receipt']['evidence'].get('affected_peer', {})
        old_boot = preflights[other]['payload']['raw_evidence'].get('boot_id')
        if affected.get('role') != other or affected.get('old_boot_id') != old_boot or not old_boot or not affected.get('new_boot_id') or affected['new_boot_id'] == old_boot:
            raise ValueError('reboot victim boot/role binding absent')
        # The old victim owner cannot respond after reboot. Preserve its handle
        # and use the surviving native owner for continued trace/ENOLINK facts.
        terminal = continued
        evidence['affected_peer'] = affected
    else:
        try:
            terminal = endpoints[other].command('wait', {})
        except ValueError:
            terminal = endpoints[other].last
            if terminal is None:
                raise
    evidence['survivor_terminal'] = terminal
    terminal_facts = continued['payload']['terminal']
    stage = b['stage']
    validate_terminal(terminal_facts, sessions[role], fault=True, stage=stage)
    if not continued['held'] or continued['error'] >= 0:
        raise ValueError('affected endpoint actual retained error absent')
    if not terminal['held'] or terminal['error'] >= 0:
        raise ValueError('survivor actual retained error absent')
    if case != 'peer-reboot':
        validate_terminal(terminal['payload'], sessions[other], fault=True, stage=stage)
    if case == 'peer-reboot' and terminal['error'] != -67:
        raise ValueError('reboot survivor lacks ENOLINK')
    return _finish_special(config, endpoints, 'expected fault observed; native resources retained', outcome='EXPECTED_RETAINED', evidence=evidence)


def run(config, agent_argv=None):
    endpoints = {}
    epochs = []
    actions = {}
    case_evidence = None
    try:
        case_id = config["identity"]["case"]
        from case_registry import CASES
        if case_id not in CASES:
            raise ValueError("unknown case")
        if case_id not in ("functional-epochs", "bulk-static") and "execution_mode" not in config:
            return dict(status="incomplete", reason="explicit case execution mode and prerequisites required before prepare", retained_workers=[], epochs=[], **_scope(config))
        execution_mode = config.get("execution_mode", "contract")
        if execution_mode not in ("contract", "physical"):
            raise ValueError("execution_mode")
        if case_id in _ACTION_KINDS:
            if not config.get("action_provider"):
                return dict(status="incomplete", reason="action provider required before prepare", retained_workers=[], epochs=[], **_scope(config))
            from action_provider import validate_provider
            validate_provider(config["action_provider"])
        physical_facts = {}
        platform = config.get("platform_evidence")
        if execution_mode == "physical":
            if type(platform) is not dict or set(platform) != {"tx", "rx"}:
                return dict(status="incomplete", reason="current C1 physical evidence required before prepare", retained_workers=[], epochs=[], **_scope(config))
            for role in ("tx", "rx"):
                proof = platform[role]
                keys(proof, {"log_path", "receipt_path", "expected"})
                for path_key in ("log_path", "receipt_path"):
                    value = proof[path_key]
                    if type(value) is not str or not value.startswith("/") or "\0" in value or len(value) > 4096:
                        raise ValueError("target C1 evidence path")
                expected = proof["expected"]
                keys(expected, {"identity", "nhi_bdf", "domain", "link_token", "channel", "max_log_age_ms"})
                _identity(expected["identity"])
                if expected["identity"] != dict(config["identity"], role=role, request_id=1):
                    raise ValueError("C1 descriptor identity mismatch")
                for key in ("domain", "channel"):
                    integer(expected[key], maximum=(1 << 32) - 1)
                integer(expected["link_token"])
                integer(expected["max_log_age_ms"], minimum=1, maximum=120000)
                if expected["link_token"] != config["link_token"][role] or expected["channel"] != config["channel"]:
                    raise ValueError("C1 descriptor link/channel mismatch")
                if type(expected["nhi_bdf"]) is not str or not expected["nhi_bdf"] or len(expected["nhi_bdf"]) > 32:
                    raise ValueError("C1 descriptor NHI")
        _geometry(config)
        integer(config["flags"], maximum=1)
        if config["flags"] and case_id != "explicit-unverified-override":
            raise ValueError("allow-unverified requires explicit override case selection")
        Path(config["evidence_dir"]).mkdir(mode=0o700, parents=True, exist_ok=True)
        argv = agent_argv if agent_argv is not None else config.get("agent_argv")
        if not isinstance(argv, dict) or set(argv) != {"tx", "rx"}:
            raise ValueError("both agent argv required")
        for role in ("tx", "rx"):
            command_argv = list(argv[role])
            if config.get("kernel_receipt"):
                command_argv += ["--kernel-receipt", config["kernel_receipt"][role]]
            if execution_mode == "physical":
                command_argv += ["--thunderbolt-log", platform[role]["log_path"],
                                 "--thunderbolt-receipt", platform[role]["receipt_path"]]
            if config.get("helpers_dir"):
                helpers = config["helpers_dir"]
                helpers = helpers[role] if type(helpers) is dict else helpers
                if type(helpers) is not str or not helpers.startswith("/") or "\0" in helpers or len(helpers) > 4096:
                    raise ValueError("helpers directory")
                command_argv += ["--helpers-dir", helpers]
            endpoints[role] = Endpoint(role, command_argv, config)
        common = {k: config[k] for k in ("geometry", "flags", "channel")}
        links = {}
        preflights = {}
        for role in ("tx", "rx"):
            p = dict(
                common,
                gpu_bdf=config["gpu_bdf"][role],
                nvidia_node=config["nvidia_node"][role],
                link_token=config["link_token"][role],
            )
            preflights[role] = endpoints[role].command("preflight", p)
            links[role] = _preflight(preflights[role], config, role)
            if execution_mode == "physical":
                facts = preflights[role]["payload"]["raw_evidence"].get("platform_facts")
                if type(facts) is not dict or facts.get("status") != "complete":
                    raise ValueError("target actual C1 collection incomplete")
                observed = facts["identity"]
                expected = platform[role]["expected"]
                if observed["run"] != preflights[role]["identity"] or any(observed[k] != expected[k] for k in ("nhi_bdf", "link_token", "channel", "domain")):
                    raise ValueError("target actual C1 role/link/kernel identity mismatch")
                raw = preflights[role]["payload"]["raw_evidence"]
                if raw.get("boot_id") != observed["boot_id"] or raw.get("nhi_bdf") != observed["nhi_bdf"] or raw.get("clock_domain") != observed["boot_id"] + ":CLOCK_MONOTONIC":
                    raise ValueError("target C1 current boot/NHI clock binding absent")
                physical_facts[role] = facts
        if (
            links["tx"]["local_inc"] != links["rx"]["remote_inc"]
            or links["rx"]["local_inc"] != links["tx"]["remote_inc"]
        ):
            raise ValueError("cross-host incarnation mismatch")
        case_evidence = {"platform_facts": physical_facts, "preflights": preflights,
                         "prepare": {}, "stops": {}, "actions": actions, "continued": {},
                         "verify": {}, "verify_launch_cookies": {}, "close": {}}
        if case_id not in ("functional-epochs", "bulk-static"):
            return _special_case(config, endpoints, common, links, preflights, physical_facts, case_evidence)
        sessions = {}
        for role in ("rx", "tx"):
            p = dict(
                common,
                **{
                    k: config[k]
                    for k in (
                        "mode",
                        "groups",
                        "first_seq",
                        "seed",
                        "observer_object",
                        "ptx_path",
                    )
                },
                gpu_bdf=config["gpu_bdf"][role],
                nvidia_node=config["nvidia_node"][role],
                link_token=config["link_token"][role]
            )
            # From this point even an unknown response retains that process.
            endpoints[role].prepared = True
            r = endpoints[role].command("prepare", p)
            case_evidence["prepare"][role] = r
            q = r["payload"]
            if (
                q["create_error"]
                or q["registration_bytes"] != config["geometry"]["allocation_bytes"]
                or not q["session_id"]
                or q.get("stop_proved") is not False
            ):
                raise ValueError("prepare did not prove registration/CREATE")
            if not q["guard_sync_proved" if role == "rx" else "producer_sync_proved"]:
                raise ValueError("prepare GPU synchronization absent")
            sessions[role] = q["session_id"]
        for role in ("rx", "tx"):
            p = {k: config[k] for k in ("groups", "first_seq")}
            r = endpoints[role].command("start", p)
            if r["payload"] != {
                "start_accepted": True,
                "arm_error": 0,
                "start_error": 0,
            }:
                raise ValueError("START not accepted")
        for role in ("tx", "rx"):
            _settled(
                endpoints[role].command("wait", {}), config["groups"], sessions[role]
            )
        stops = []
        for role in ("tx", "rx"):
            r = endpoints[role].command("stop", {})
            if (
                r["fate"] != "SAFE"
                or not r["payload"]["stop_proved"]
                or r["payload"]["stop_error"]
                or r["payload"]["first_error"]
            ):
                raise ValueError("STOP proof failed")
            _settled(r, config["groups"], sessions[role])
            stops.append(r)
            case_evidence["stops"][role] = r
        records = {}
        for role in ("tx", "rx"):
            records[role] = []
            ordinal = 0
            while ordinal < config["groups"]:
                limit = min(32, config["groups"] - ordinal)
                p = endpoints[role].command(
                    "observe", {"first_ordinal": ordinal, "limit": limit}
                )["payload"]
                keys(p, {"records", "next_ordinal", "total", "error_bits"})
                if (
                    p["total"] != config["groups"]
                    or p["error_bits"]
                    or len(p["records"]) != limit
                ):
                    raise ValueError("observer page count/error")
                for i, item in enumerate(p["records"]):
                    keys(item, {"ordinal", "record"})
                    if item["ordinal"] != ordinal + i:
                        raise ValueError("observer duplicate/gap")
                    records[role].append(item["record"])
                ordinal += limit
                if p["next_ordinal"] != (
                    ordinal if ordinal < config["groups"] else None
                ):
                    raise ValueError("observer next ordinal")
        oc = dict(
            config["geometry"],
            **{
                k: config[k]
                for k in ("groups", "first_seq", "epoch", "seed")
                if k in config
            }
        )
        oc["epoch"] = config["identity"]["epoch"]
        oc["link_token"] = config["link_token"]
        oc["channel"] = config["channel"]
        for role in ("tx", "rx"):
            oc[role + "_session_id"] = sessions[role]
            oc[role + "_local_inc"] = links[role]["local_inc"]
        extents = build_expectations(records["tx"], records["rx"], oc)
        case_evidence["records"] = records
        case_evidence["oracle_config"] = oc
        verification = None
        for role, expected_extents in (
            ("rx", extents),
            (
                "tx",
                [
                    {
                        "dst_off": 0,
                        "src_off": 0,
                        "len": config["geometry"]["allocation_bytes"],
                        "seed": config["seed"],
                        "kind": 1,
                        "reserved": 0,
                    }
                ],
            ),
        ):
            cookie = secrets.randbits(64) or 1
            parts = [
                {
                    "kind": "begin",
                    "launch_cookie": cookie,
                    "extent_count": len(expected_extents),
                    "stop_receipts": stops,
                }
            ]
            for i in range(0, len(expected_extents), 1024):
                parts.append(
                    {
                        "kind": "extents",
                        "first_extent": i,
                        "extents": expected_extents[i : i + 1024],
                    }
                )
            parts.append({"kind": "end", "extent_count": len(expected_extents)})
            verify_response = endpoints[role].command("verify", {}, parts)
            case_evidence["verify"][role] = verify_response
            case_evidence["verify_launch_cookies"][role] = cookie
            summary = verify_response["payload"]
            if summary["visibility_error"]:
                raise ValueError("receive visibility failed")
            validate_summary(summary, expected_extents, cookie)
            if role == "rx":
                verification = summary
        for role in ("tx", "rx"):
            r = endpoints[role].command("close", {})
            case_evidence["close"][role] = r
            if r["payload"].get("closed") is not True or r["payload"].get(
                "retained_resources"
            ):
                raise ValueError("resources not closed")
        epochs.append(
            {
                "epoch": config["identity"]["epoch"],
                "stop_receipts": stops,
                "verification": verification,
                "groups": config["groups"],
            }
        )
        # CLOSED is an explicit safe acknowledgement, so pipe closure is now safe.
        for ep in endpoints.values():
            os.close(ep.infd)
            os.close(ep.outfd)
            try:
                ep.process.wait(timeout=config["deadline_ms"] / 1000)
            except subprocess.TimeoutExpired:
                # CLOSED acknowledged resource release; process may finish later.
                ep.process.retained = True
                _RETAINED.append(ep)
        return {
            "status": "pass",
            "reason": "both endpoints stopped and complete allocation verified",
            "case_evidence": case_evidence,
            "retained_workers": [],
            "epochs": epochs,
            **_scope(config),
        }
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as error:
        retained = []
        for ep in endpoints.values():
            if ep.phase != "HELD":
                try:
                    ep.command("cancel", {"reason": "coordinator-failure"})
                except (ValueError, KeyError, TypeError, OSError):
                    pass
            retained.append(ep.retain(str(error)))
        return {
            "status": "incomplete" if config.get("execution_mode") == "physical" or config.get("identity", {}).get("case") not in ("functional-epochs", "bulk-static") else "failed",
            "reason": str(error),
            "actions": actions,
            "case_evidence": case_evidence,
            "retained_workers": retained,
            "epochs": epochs,
            **_scope(config),
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--tx-argv", required=True)
    ap.add_argument("--rx-argv", required=True)
    ap.add_argument("--evidence-dir", required=True)
    a = ap.parse_args()
    with open(a.config, encoding="utf-8") as f:
        config = json.load(f)
    argv = {}
    for role, path in (("tx", a.tx_argv), ("rx", a.rx_argv)):
        with open(path, encoding="utf-8") as f:
            argv[role] = json.load(f)
    config["evidence_dir"] = a.evidence_dir
    result = run(config, argv)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
