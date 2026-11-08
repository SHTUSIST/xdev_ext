#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""One unchanged HTTP request to one owned fresh service. Dry-run by default.

Linux /proc ownership evidence is mandatory. No cached PID state is read.
The interval is full HTTP response time; startup/health/shutdown are excluded.
"""
import argparse
from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import time
import urllib.error
import urllib.request

LOCK_ROOT = Path('/tmp') / f'xdev-ext-cold-request-{os.getuid()}'


class ColdError(RuntimeError):
    pass


class OwnershipError(ColdError):
    pass


def listener_inodes(port):
    found = set()
    try:
        for name in ('tcp', 'tcp6'):
            lines = (Path('/proc/net') / name).read_text().splitlines()[1:]
            for line in lines:
                fields = line.split()
                if fields[3] == '0A' and int(fields[1].rsplit(':', 1)[1], 16) == port:
                    found.add(fields[9])
    except (OSError, ValueError, IndexError) as exc:
        raise OwnershipError('cannot prove listener ownership from /proc') from exc
    return found


def group_members(pgid):
    members = {}
    try:
        paths = list(Path('/proc').iterdir())
    except OSError as exc:
        raise OwnershipError('cannot inspect owned process group') from exc
    for path in paths:
        if not path.name.isdigit():
            continue
        try:
            fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == pgid and int(fields[3]) == pgid:
                members[int(path.name)] = fields[0]
        except (OSError, ValueError, IndexError):
            continue
    if pgid not in members:
        raise OwnershipError('the unreaped owned group leader is not visible in /proc')
    return members


def assert_owned_listener(child, port):
    inodes = listener_inodes(port)
    owned = set()
    for pid in group_members(child.pid):
        try:
            for fd in (Path('/proc') / str(pid) / 'fd').iterdir():
                try:
                    target = os.readlink(fd)
                    if target.startswith('socket:[') and target.endswith(']'):
                        owned.add(target[8:-1])
                except OSError:
                    continue
        except OSError:
            continue
    if not inodes or not inodes <= owned:
        raise OwnershipError('listener is not proven to belong to this fresh child group')


@contextmanager
def port_lock(port):
    LOCK_ROOT.mkdir(mode=0o700, exist_ok=True)
    info = LOCK_ROOT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
        raise OwnershipError('unsafe project cold-request lock directory')
    fd = os.open(LOCK_ROOT / f'{port}.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def child_exited(child):
    # Keep the direct child unreaped so its PID/session/group cannot be reused
    # before finally signals the group. Popen.poll() would reap too early.
    return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def cleanup(child, timeout):
    def send(sig):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
    send(signal.SIGTERM)
    deadline = time.monotonic() + timeout
    killed = False
    try:
        while any(state != 'Z' for state in group_members(child.pid).values()):
            if time.monotonic() >= deadline:
                if killed:
                    raise ColdError('owned group did not stop after SIGKILL')
                send(signal.SIGKILL)
                killed = True
                deadline = time.monotonic() + timeout
            time.sleep(0.01)
    except OwnershipError:
        send(signal.SIGKILL)
        raise
    finally:
        child.wait(timeout=timeout)
    return True


def cached_tokens(value):
    values = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'cached_tokens':
                values.append(item)
            else:
                values.extend(cached_tokens(item))
    elif isinstance(value, list):
        for item in value:
            values.extend(cached_tokens(item))
    return values


def run_request(server_argv, body, port, startup_timeout=1800, request_timeout=300,
                cleanup_timeout=10):
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError('an explicit port in 1..65535 is required')
    if (not isinstance(server_argv, (list, tuple)) or not server_argv
            or not all(isinstance(arg, str) for arg in server_argv)
            or not isinstance(body, bytes) or not isinstance(json.loads(body), dict)):
        raise ValueError('server argv and an unchanged JSON object request are required')
    if any(not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0
           for value in (startup_timeout, request_timeout, cleanup_timeout)):
        raise ValueError('timeouts must be finite positive numbers')
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL or not hasattr(os, 'WNOWAIT'):
        raise OwnershipError('owned-child observation requires default SIGCHLD and WNOWAIT')
    with port_lock(port):
        if listener_inodes(port):
            raise OwnershipError('port has an existing listener; it will not be stopped')
        child = subprocess.Popen(server_argv, start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        result = None
        try:
            http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            deadline = time.monotonic() + startup_timeout
            while True:
                if child_exited(child):
                    raise ColdError('owned service exited before health readiness')
                if listener_inodes(port):
                    assert_owned_listener(child, port)
                    try:
                        with http.open(f'http://127.0.0.1:{port}/health', timeout=1) as reply:
                            if reply.status == 200:
                                break
                    except (OSError, urllib.error.URLError):
                        pass
                if time.monotonic() >= deadline:
                    raise ColdError('owned service health timeout')
                time.sleep(0.02)
            assert_owned_listener(child, port)
            if child_exited(child):
                raise ColdError('owned service exited before request')
            request = urllib.request.Request(f'http://127.0.0.1:{port}/v1/completions',
                                             data=body, headers={'Content-Type': 'application/json'})
            started = time.perf_counter_ns()
            with http.open(request, timeout=request_timeout) as reply:
                response = reply.read()
            elapsed = time.perf_counter_ns() - started
            parsed = json.loads(response)
            hits = cached_tokens(parsed)
            if any(isinstance(hit, bool) or not isinstance(hit, (int, float)) or hit != 0 for hit in hits):
                raise ColdError('response reports cached_tokens other than numeric zero')
            result = dict(fresh_process=True, owned_pid=child.pid, elapsed_ns=elapsed,
                          timing_scope='http-full-response', reported_cached_tokens=hits,
                          cache_counter='zero' if hits else 'not-reported', response=parsed,
                          scope='one-request-fresh-process', performance_claim='none')
        finally:
            cleaned = cleanup(child, cleanup_timeout)
        result['owned_group_cleaned'] = cleaned
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-argv-json', required=True)
    parser.add_argument('--request-file', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--startup-timeout', type=float, default=1800)
    args = parser.parse_args(argv)
    command = json.loads(args.server_argv_json)
    body = Path(args.request_file).read_bytes()
    if not args.execute:
        print(json.dumps(dict(dry_run=True, server_argv=command, request_file=args.request_file,
                              port=args.port, scope='one-request-fresh-process',
                              timing_scope='http-full-response', performance_claim='none')))
        return 0
    print(json.dumps(run_request(command, body, args.port, startup_timeout=args.startup_timeout)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
