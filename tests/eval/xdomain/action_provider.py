# SPDX-License-Identifier: GPL-2.0
"""Bounded, one-shot real action helper. Unknown helpers remain retained."""

import json
import os
from pathlib import Path
import re
import select
import stat
import struct
import subprocess
import time

from check_protocol import MAX_JSON, _identity, _pairs, _tree, integer, keys

_CHALLENGE = set('version action_id identity kind target barrier deadline_monotonic_ns'.split())
_RECEIPT = (_CHALLENGE - {'deadline_monotonic_ns'}) | set('attempted completed error started_monotonic_ns finished_monotonic_ns evidence'.split())
_TARGET = set('boot_id nhi_bdf link_token local_inc remote_inc clock_domain'.split())
_KINDS = {'stop', 'cable-loss', 'remove-on-resume', 'reboot', 'suspend-resume', 'unload'}
_USED = set()
_RETAINED = []
_STREAM_LIMIT = 2 * 1024 * 1024


class _Process(subprocess.Popen):
    retained = True

    def __del__(self):
        if not self.retained:
            super().__del__()


def _argv(argv):
    if type(argv) is not list or not argv or len(argv) > 1024 or any(type(v) is not str or not v or '\0' in v or len(v.encode()) > 65536 for v in argv):
        raise ValueError('action argv must be explicit strings')


def validate_provider(provider):
    keys(provider, {'argv', 'timeout_ms'})
    _argv(provider['argv'])
    integer(provider['timeout_ms'], minimum=1, maximum=120000)


def validate_action_binding(challenge):
    """Validate the typed action identity shared by provider and builtin proof."""
    keys(challenge, _CHALLENGE - {'deadline_monotonic_ns'})
    _tree(challenge)
    _identity(challenge['identity'])
    if type(challenge['version']) is not int or challenge['version'] != 1:
        raise ValueError('action version')
    if type(challenge['action_id']) is not str or re.fullmatch('[0-9a-f]{64}', challenge['action_id']) is None:
        raise ValueError('fresh 32-byte action nonce required')
    if type(challenge['kind']) is not str or challenge['kind'] not in _KINDS:
        raise ValueError('action kind')
    keys(challenge['target'], _TARGET)
    t = challenge['target']
    for k in ('boot_id', 'nhi_bdf', 'clock_domain'):
        if type(t[k]) is not str or not t[k] or len(t[k]) > 256 or '\0' in t[k]:
            raise ValueError('action target')
    for k in ('link_token', 'local_inc', 'remote_inc'):
        integer(t[k])
    if type(challenge['barrier']) is not dict:
        raise ValueError('action barrier')


def _challenge(challenge):
    keys(challenge, _CHALLENGE)
    validate_action_binding({k: challenge[k] for k in _CHALLENGE - {'deadline_monotonic_ns'}})
    integer(challenge['deadline_monotonic_ns'], minimum=1)


def _raw_primitive(evidence):
    if type(evidence) is not dict:
        raise ValueError('actual primitive evidence absent')
    _argv(evidence.get('argv'))
    integer(evidence.get('returncode'), minimum=-(1 << 31), maximum=(1 << 31) - 1)
    if evidence['returncode'] != 0:
        raise ValueError('primitive failed')
    for k in ('stdout_path', 'stderr_path'):
        p = evidence.get(k)
        if type(p) is not str or not os.path.isabs(p):
            raise ValueError('primitive raw stream path')
        info = os.stat(p)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _STREAM_LIMIT:
            raise ValueError('primitive stream missing or oversized')


def _same(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(_same(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return left == right


def validate_action_receipt(receipt, challenge):
    _challenge(challenge)
    keys(receipt, _RECEIPT)
    _tree(receipt)
    for k in _CHALLENGE - {'deadline_monotonic_ns'}:
        if not _same(receipt[k], challenge[k]):
            raise ValueError('action receipt challenge mismatch: ' + k)
    if type(receipt['attempted']) is not bool or type(receipt['completed']) is not bool:
        raise ValueError('action receipt boolean')
    integer(receipt['error'], minimum=-(1 << 31), maximum=(1 << 31) - 1)
    start = integer(receipt['started_monotonic_ns'])
    finish = integer(receipt['finished_monotonic_ns'])
    if not start < finish <= challenge['deadline_monotonic_ns']:
        raise ValueError('action target deadline')
    barrier = challenge['barrier']
    if 'observed_monotonic_ns' in barrier and start < integer(barrier['observed_monotonic_ns']):
        raise ValueError('action before native observation')
    if not receipt['attempted'] or not receipt['completed'] or receipt['error']:
        raise ValueError('action was not completed')
    e = receipt['evidence']
    _raw_primitive(e)
    kind = challenge['kind']
    if kind == 'cable-loss' and not (e.get('operator_event') or e.get('cable_event')):
        raise ValueError('cable action requires operator or device event')
    if kind == 'reboot':
        peer = e.get('affected_peer')
        other = 'rx' if challenge['identity']['role'] == 'tx' else 'tx'
        if type(peer) is not dict or peer.get('role') != other or type(peer.get('old_boot_id')) is not str or not peer['old_boot_id'] or type(peer.get('new_boot_id')) is not str or not peer['new_boot_id'] or peer['new_boot_id'] == peer['old_boot_id']:
            raise ValueError('reboot affected peer boot/role evidence absent')
        integer(peer.get('new_incarnation'), minimum=1)
        if peer['new_incarnation'] in (challenge['target']['local_inc'], challenge['target']['remote_inc']):
            raise ValueError('reboot needs a fresh peer incarnation')
    if kind == 'remove-on-resume' and not all(e.get(k) is True for k in ('suspended', 'resumed', 'nhi_removed', 'going_away', 'upstream_still_running_warning')):
        raise ValueError('remove/resume primitive evidence absent')
    if kind == 'suspend-resume' and not all(e.get(k) is True for k in ('suspended', 'resumed')):
        raise ValueError('suspend/resume evidence absent')
    if kind == 'unload' and not all(e.get(k) is True for k in ('module_absent', 'logout', 'link_down')):
        raise ValueError('module unload evidence absent')
    return receipt


def execute_action(challenge, provider, *, evidence_dir):
    """Execute one challenge over real framed pipes, retaining on any uncertainty."""
    _challenge(challenge)
    validate_provider(provider)
    if challenge['action_id'] in _USED:
        raise ValueError('action nonce replay')
    body = json.dumps(challenge, separators=(',', ':'), allow_nan=False).encode()
    if not 1 <= len(body) <= MAX_JSON:
        raise ValueError('action challenge frame capacity')
    _USED.add(challenge['action_id'])
    root = Path(evidence_dir)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    outpath = root / (challenge['action_id'] + '-stdout.raw')
    errpath = root / (challenge['action_id'] + '-stderr.raw')
    execution = {'argv': list(provider['argv']), 'returncode': None, 'stdout_path': str(outpath.resolve()), 'stderr_path': str(errpath.resolve()), 'timed_out': False, 'ack_count': 0}
    result = {'status': 'incomplete', 'reason': '', 'receipt': None, 'execution': execution}
    process = None
    retained_fds = []
    try:
        deadline = time.monotonic() + provider['timeout_ms'] / 1000
        child_input, input_fd = os.pipe()
        output_fd, child_output = os.pipe()
        error_fd, child_error = os.pipe()
        retained_fds = [input_fd, output_fd, error_fd]
        try:
            process = _Process(provider['argv'], stdin=child_input, stdout=child_output, stderr=child_error, shell=False, bufsize=0, start_new_session=True)
        finally:
            for fd in (child_input, child_output, child_error):
                os.close(fd)
        execution['pid'] = process.pid
        for fd in retained_fds:
            os.set_blocking(fd, False)
        frame = struct.pack('!I', len(body)) + body
        offset = 0
        outputs = {output_fd: bytearray(), error_fd: bytearray()}
        openfds = set(outputs)
        with outpath.open('xb') as stdout, errpath.open('xb') as stderr:
            logs = {output_fd: stdout, error_fd: stderr}
            while openfds or offset < len(frame):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    execution['timed_out'] = True
                    raise ValueError('action provider full I/O deadline')
                readable, writable, _ = select.select(list(openfds), [input_fd] if offset < len(frame) else [], [], remaining)
                if writable:
                    try:
                        offset += os.write(input_fd, frame[offset:])
                    except BlockingIOError:
                        pass
                    if offset == len(frame):
                        os.close(input_fd)
                        retained_fds.remove(input_fd)
                for fd in readable:
                    try:
                        data = os.read(fd, 65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        openfds.remove(fd)
                        continue
                    logs[fd].write(data)
                    logs[fd].flush()
                    outputs[fd].extend(data)
                    if len(outputs[fd]) > _STREAM_LIMIT:
                        raise ValueError('action provider stream capacity')
                    if fd == output_fd and len(outputs[fd]) >= 4:
                        n = struct.unpack('!I', outputs[fd][:4])[0]
                        if not 1 <= n <= MAX_JSON:
                            raise ValueError('action acknowledgement frame capacity')
                        if len(outputs[fd]) >= n + 4:
                            execution['ack_count'] = 1
                            if len(outputs[fd]) > n + 4:
                                execution['ack_count'] = 2
                                raise ValueError('multiple acknowledgements or trailing bytes')
        raw = bytes(outputs[output_fd])
        if len(raw) < 4 or len(raw) != struct.unpack('!I', raw[:4])[0] + 4:
            raise ValueError('missing or truncated action acknowledgement')
        receipt = json.loads(raw[4:].decode('utf-8'), object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
        validate_action_receipt(receipt, challenge)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            execution['timed_out'] = True
            raise ValueError('action provider completion deadline')
        try:
            execution['returncode'] = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            execution['timed_out'] = True
            raise ValueError('action provider completion deadline')
        process.retained = False
        for fd in retained_fds:
            os.close(fd)
        retained_fds.clear()
        if execution['returncode'] != 0:
            raise ValueError('action provider failed')
        result.update(status='complete', reason='one exact action acknowledged with primitive evidence', receipt=receipt)
    except (ValueError, OSError, UnicodeError, TypeError, RecursionError) as error:
        result['reason'] = str(error)
        if process is not None and process.retained:
            _RETAINED.append({'process': process, 'fds': retained_fds})
        elif process is None:
            for fd in retained_fds:
                os.close(fd)
    return result
