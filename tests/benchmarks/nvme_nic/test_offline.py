#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Offline contract tests: CLI, independent oracle, record validator and refusals.

No device, network peer or timing is involved; fixtures exercise the
validator and refusal logic only and cannot unlock a measured run.
"""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gate      # noqa: E402
import results   # noqa: E402
import run       # noqa: E402

BUILD = Path(os.environ.get('NNB_BUILD_DIR', HERE / '.build'))


def usage_error(argv):
    with contextlib.redirect_stderr(io.StringIO()), unittest.TestCase().assertRaises(SystemExit) as caught:
        run.parse(argv)
    return caught.exception.code


class Oracle(unittest.TestCase):
    def test_generator_matches_c(self):
        out = subprocess.run([str(BUILD / 'test_wire'), '--vectors'], text=True, capture_output=True, check=True)
        rows = [tuple(map(int, line.split())) for line in out.stdout.splitlines()]
        self.assertEqual(len(rows), 7)
        for off, byte in rows:
            self.assertEqual(results.generator_byte(0x5eed, off), byte, off)

    def test_geometry_matches_c(self):
        for mtu in (1500, 4200, 9000):
            for size in (4096, 65536, 1 << 20, 4 << 20):
                out = subprocess.run([str(BUILD / 'test_wire'), '--geometry', str(mtu), str(size), str(64 << 20)],
                                     text=True, capture_output=True, check=True)
                self.assertEqual(json.loads(out.stdout), results.geometry(mtu, size, 64 << 20), (mtu, size))

    def test_geometry_refusals(self):
        for mtu, size, window in ((1500, 3 << 12, 8 << 20), (1500, 8 << 20, 8 << 20), (1500, 4096, 6 << 20), (190, 4096, 8 << 20)):
            with self.assertRaises(results.Invalid):
                results.geometry(mtu, size, window)


class Cli(unittest.TestCase):
    def test_lists(self):
        args = run.parse(['--sizes', '4096..65536', '--qd', '1,8,32,128'])
        self.assertEqual(args.sizes, [4096, 8192, 16384, 32768, 65536])
        self.assertEqual(args.qd, [1, 8, 32, 128])
        self.assertEqual(run.parse([]).sizes[-1], 4 << 20)
        self.assertEqual(run.parse([]).arms, ['posix', 'uring', 'splice', 'session'])
        rev = run.parse(['--direction', 'rev', '--allow-window-write'])
        self.assertEqual(rev.arms, ['posix', 'uring', 'session'])

    def test_usage_refusals(self):
        for argv in (['--sizes', '3000'], ['--sizes', '8388608'], ['--sizes', '4096..2048'], ['--qd', '256'],
                     ['--qd', '3'], ['--sizes', '4096,4096'], ['--arms', 'posix,dpdk'], ['--arms', 'posix,posix'],
                     ['--direction', 'rev', '--allow-window-write', '--arms', 'posix,splice'],
                     ['--loopback'], ['--correctness-only', '--loopback', '--arms', 'session'],
                     ['--fault', 'skip-write'], ['--direction', 'rev'], ['--prepare-window'],
                     ['--pairs', '1', '--pairs', '2'], ['--peer', '10.0.0.1'], ['--window-mib', '6'],
                     ['--local-mac', 'zz:00:00:00:00:00']):
            self.assertEqual(usage_error(argv), 2, argv)

    def test_units_rule(self):
        args = run.parse(['--direction', 'rev', '--allow-window-write', '--units', '5'])
        self.assertEqual(run.units_for(args, 4096, 4), 8)    # whole bursts
        args = run.parse([])
        self.assertEqual(run.units_for(args, 4 << 20, 128), 128)
        self.assertEqual(run.units_for(args, 4096, 1), 16384)

    def test_producer_cli(self):
        exe = str(BUILD / 'nnb_producer')
        features = json.loads(subprocess.run([exe, '--features'], text=True, capture_output=True, check=True).stdout)
        self.assertEqual(set(features), {'uring', 'session'})
        base = [exe, '--direction', 'fwd', '--size', '4096', '--qd', '1', '--source', '/dev/null',
                '--nlb', '8192', '--lba', '512', '--local-ip', '127.0.0.1', '--peer-ip', '127.0.0.1',
                '--local-port', '4000', '--peer-port', '4001', '--control', '127.0.0.1:4002']
        for extra in (['--arms', 'dpdk'], ['--arms', 'posix', '--fault', 'skip-write'], ['--arms', 'posix,posix'],
                      ['--arms', 'posix', '--qd', '1'], ['--arms', 'posix', '--bogus']):
            out = subprocess.run(base + extra, text=True, capture_output=True)
            self.assertEqual(out.returncode, 2, extra)
            self.assertEqual(out.stdout, '')
        rev = [a if a != 'fwd' else 'rev' for a in base] + ['--arms', 'posix,splice']
        self.assertEqual(subprocess.run(rev, capture_output=True).returncode, 2)
        bad = [a if a != '4096' else '12288' for a in base] + ['--arms', 'posix']
        self.assertEqual(subprocess.run(bad, capture_output=True).returncode, 2)
        # No peer listening: refused before any trial, exit 4, no records.
        with tempfile.NamedTemporaryFile(dir=BUILD) as window:
            window.truncate(4 << 20)
            refused = [a if a != '/dev/null' else window.name for a in base] + ['--arms', 'posix']
            out = subprocess.run(refused, text=True, capture_output=True)
        self.assertEqual(out.returncode, 4)
        self.assertEqual(out.stdout, '')


class Admission(unittest.TestCase):
    def fixture(self, root, vendor='Dell Inc.', driver='mlx5_core', hypervisor=False, cpu='fpu sse'):
        root = Path(root)
        (root / 'proc').mkdir()
        (root / 'proc/cpuinfo').write_text('flags : ' + cpu + '\n')
        dmi = root / 'sys/class/dmi/id'
        dmi.mkdir(parents=True)
        for name, value in (('sys_vendor', vendor), ('product_name', 'PowerEdge R760'), ('board_vendor', vendor)):
            (dmi / name).write_text(value + '\n')
        if hypervisor:
            (root / 'sys/hypervisor').mkdir()
            (root / 'sys/hypervisor/type').write_text('xen\n')
        pci = root / 'sys/devices/pci0000:00/0000:00:01.0'
        (pci / 'drivers' / driver).mkdir(parents=True)
        (pci / 'driver').symlink_to(pci / 'drivers' / driver)
        net = root / 'sys/class/net/eth9'
        net.mkdir(parents=True)
        (net / 'device').symlink_to(pci)
        (net / 'mtu').write_text('9000\n')
        (net / 'address').write_text('02:00:00:00:00:09\n')
        return str(root / 'sys'), str(root / 'proc')

    def test_physical_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            sysfs, proc = self.fixture(tmp)
            seen = gate.physical('eth9', sysfs, proc)
            self.assertEqual((seen['mtu'], seen['nic_driver']), (9000, 'mlx5_core'))
        for kwargs, why in ((dict(vendor='QEMU'), 'virtual DMI'), (dict(vendor='Acme'), 'unknown physical'),
                            (dict(driver='virtio_net'), 'virtual NIC'), (dict(hypervisor=True), 'hypervisor'),
                            (dict(cpu='fpu hypervisor'), 'hypervisor')):
            with tempfile.TemporaryDirectory() as tmp:
                sysfs, proc = self.fixture(tmp, **kwargs)
                with self.assertRaises(gate.Refused) as caught:
                    gate.physical('eth9', sysfs, proc)
                self.assertIn(why, caught.exception.message)
                self.assertEqual(caught.exception.status, 'not_run_hardware')

    def test_measured_run_refuses_without_hardware(self):
        out = subprocess.run([sys.executable, str(HERE / 'run.py'), '--build-dir', str(BUILD), '--arms', 'posix',
                              '--sizes', '4096', '--qd', '1'], text=True, capture_output=True, timeout=60)
        self.assertEqual(out.returncode, 4)
        self.assertEqual(out.stdout, '')
        self.assertEqual(json.loads(out.stderr)['completed_configurations'], 0)

    def test_session_needs_backend(self):
        args = run.parse(['--arms', 'session', '--ifname', 'eth9', '--source', '/dev/null', '--nlb', '8',
                          '--local-ip', '10.0.0.1', '--peer-ip', '10.0.0.2', '--peer', '10.0.0.2:9',
                          '--peer-port', '10'])
        with self.assertRaises(gate.Refused) as caught:
            gate.admit(args, dict(uring=True, session=False))
        self.assertEqual(caught.exception.status, 'not_run_capability')
        args.arms = ['uring']
        with self.assertRaises(gate.Refused):
            gate.admit(args, dict(uring=False, session=True))


def fixture_records(direction='fwd', arms=('posix', 'uring'), pairs=2, warmup=1, measured=True, size=65536, qd=2):
    """Records shaped exactly as nnb_producer prints them, for validator mutation tests."""
    geo = results.geometry(1500, size, 8 << 20)
    units = qd if direction == 'rev' else 4
    out, gen, trial = [], {a: 1 for a in arms}, 0
    for a in arms:
        out.append(dict(record='setup', arm=a, status='ok', registrations=1, effective_qd=qd, session_depth=0,
                        xsk_zerocopy=-1, port=1, inflight_bytes=results.inflight_bytes(a, direction, size, qd, geo, 0),
                        diagnostic=''))

    def rec(kind, arm, pair, position):
        nonlocal trial
        trial += 1
        n = geo['window_units'] if kind == 'integrity' else units
        groups = n * geo['groups_per_unit']
        dgrams = groups * geo['dgrams']
        r = dict(record=kind, arm=arm, direction=direction, size=size, qd=qd, effective_qd=qd, session_depth=0,
                 xsk_zerocopy=-1, pair=pair, position=position, trial=trial, units=n, groups=groups,
                 group_bytes=geo['group'], seg=geo['seg'], dgrams_per_group=geo['dgrams'], payload_bytes=n * size,
                 bursts=-(-n // qd) if direction == 'rev' else 0, wire_session=7, first_gen=gen[arm],
                 inflight_bytes=results.inflight_bytes(arm, direction, size, qd, geo, 0),
                 window_passes=-(-n // geo['window_units']), lat_samples=0 if arm == 'session' else n)
        gen[arm] += groups
        for k in results.COUNTERS:
            r[k] = 0
        r['datagrams'] = dgrams
        if direction == 'fwd':
            r.update(read_ops=n, read_bytes=n * size, send_calls=groups, send_bytes=n * size + 40 * dgrams,
                     peer_datagrams=dgrams, peer_bytes=n * size + 40 * dgrams, peer_foreign=0,
                     peer_buffers=max(1, dgrams // 4), peer_compare=1 if kind == 'integrity' else 0)
            if arm == 'uring':
                r.update(notifs=groups, zc_copied=1)
        else:
            r.update(write_ops=n, write_bytes=n * size, readback_compare=1 if kind == 'integrity' else 0)
        if measured and kind != 'integrity':
            if direction == 'fwd':
                r.update(local_release_ns=1000 + 10 * trial, receipt_ns=2000 + 10 * trial)
            else:
                r.update(durable_ns=1000 + 10 * trial)
            r.update(cpu_user_us=1, cpu_sys_us=2)
            if arm != 'session':
                r.update(lat_min_ns=100, lat_p50_ns=200 + trial, lat_p90_ns=300, lat_p99_ns=400,
                         lat_p999_ns=500, lat_max_ns=600)
        return r
    for i, a in enumerate(arms):
        for _ in range(warmup):
            out.append(rec('warmup', a, -1, i))
    for p in range(pairs):
        order = list(arms) if p % 2 == 0 else list(reversed(arms))
        for i, a in enumerate(order):
            out.append(rec('trial', a, p, i))
    for i, a in enumerate(arms):
        out.append(rec('integrity', a, -1, i))
    expect = dict(direction=direction, size=size, qd=qd, units=units, pairs=pairs, warmup=warmup,
                  arms=list(arms), geometry=geo)
    return out, expect


class Validator(unittest.TestCase):
    def lines(self, records):
        return [json.dumps(r) for r in records]

    def test_valid_fixtures(self):
        for direction in ('fwd', 'rev'):
            for measured in (True, False):
                records, expect = fixture_records(direction, measured=measured)
                trials, integrity = results.validate(self.lines(records), expect, measured)
                self.assertEqual(len(trials), 4)
                self.assertEqual(len(integrity), 2)

    def test_mutations_rejected(self):
        records, expect = fixture_records()

        def broken(index, change):
            mutated = copy.deepcopy(records)
            change(mutated[index])
            return mutated
        trial = next(i for i, r in enumerate(records) if r['record'] == 'trial')
        integ = next(i for i, r in enumerate(records) if r['record'] == 'integrity')
        cases = [
            broken(trial, lambda r: r.update(datagrams=r['datagrams'] - 1)),
            broken(trial, lambda r: r.update(peer_datagrams=r['peer_datagrams'] - 1)),
            broken(trial, lambda r: r.update(peer_bytes=r['peer_bytes'] + 1)),
            broken(trial, lambda r: r.pop('local_release_ns')),
            broken(trial, lambda r: r.update(local_release_ns=0)),
            broken(trial, lambda r: r.update(seg=r['seg'] + 8)),
            broken(trial, lambda r: r.update(first_gen=r['first_gen'] + 1)),
            broken(trial, lambda r: r.update(pair=1)),
            broken(trial, lambda r: r.update(extra_field=1)),
            broken(integ, lambda r: r.update(peer_compare=0)),
            broken(integ, lambda r: r.update(local_release_ns=5)),   # integrity carries no timing
            broken(0, lambda r: r.update(status='refused')),
        ]
        cases += [
            # Per-unit latency distribution: one sample per unit, ordered percentiles, all present.
            broken(trial, lambda r: r.update(lat_samples=r['units'] - 1)),
            broken(trial, lambda r: r.update(lat_p99_ns=r['lat_p50_ns'] - 1)),
            broken(trial, lambda r: r.update(lat_min_ns=0)),
            broken(trial, lambda r: r.pop('lat_p999_ns')),
            broken(integ, lambda r: r.update(lat_p50_ns=5)),            # integrity carries no timing
            broken(integ, lambda r: r.update(lat_samples=0)),
            # Bytes in flight and window passes are stated independently.
            broken(trial, lambda r: r.update(inflight_bytes=r['inflight_bytes'] * 2)),
            broken(trial, lambda r: r.update(window_passes=r['window_passes'] + 1)),
            broken(0, lambda r: r.update(inflight_bytes=1)),
            # Peer receive buffers (UDP GRO): at least one, at most one per datagram.
            broken(trial, lambda r: r.update(peer_buffers=0)),
            broken(trial, lambda r: r.update(peer_buffers=r['peer_datagrams'] + 1)),
        ]
        uring = next(i for i, r in enumerate(records) if r['record'] == 'trial' and r['arm'] == 'uring')
        cases.append(broken(uring, lambda r: r.update(zc_copied=r['notifs'] + 1)))
        cases.append(records[:-1])
        for case in cases:
            with self.assertRaises(results.Invalid):
                results.validate(self.lines(case), expect, True)
        # Timing fields are refused in a correctness run.
        with self.assertRaises(results.Invalid):
            results.validate(self.lines(records), expect, False)
        rev, rexpect = fixture_records('rev')
        rev_trial = next(i for i, r in enumerate(rev) if r['record'] == 'trial')
        rev[rev_trial]['bursts'] += 1
        with self.assertRaises(results.Invalid):
            results.validate(self.lines(rev), rexpect, True)

    def test_session_fields(self):
        records, expect = fixture_records(arms=('posix', 'session'))
        with self.assertRaises(results.Invalid):     # session needs batches, zero copy and a teardown STOP
            results.validate(self.lines(records), expect, True)
        geo = expect['geometry']
        for r in records:
            if r.get('arm') == 'session':
                r.update(inflight_bytes=8 * geo['group'], session_depth=8)
            if r.get('arm') == 'session' and r['record'] != 'setup':
                r.update(batches=r['groups'], xsk_zerocopy=1, session_depth=8)
        with self.assertRaises(results.Invalid):
            results.validate(self.lines(records), expect, True)
        records.append(dict(record='teardown', arm='session', stop_ret=0))
        results.validate(self.lines(records), expect, True)
        # The session arm has no per-unit completion times: no samples, no percentiles.
        session_trial = next(r for r in records if r.get('arm') == 'session' and r['record'] == 'trial')
        session_trial.update(lat_p50_ns=1)
        with self.assertRaises(results.Invalid):
            results.validate(self.lines(records), expect, True)
        del session_trial['lat_p50_ns']
        session_trial['lat_samples'] = session_trial['units']
        with self.assertRaises(results.Invalid):
            results.validate(self.lines(records), expect, True)
        session_trial['lat_samples'] = 0
        session_trial['inflight_bytes'] = 9 * geo['group']     # must be session_depth x group
        with self.assertRaises(results.Invalid):
            results.validate(self.lines(records), expect, True)
        session_trial['inflight_bytes'] = 8 * geo['group']
        records[-1]['stop_ret'] = -11
        with self.assertRaises(results.Invalid):
            results.validate(self.lines(records), expect, True)

    def test_summary_keeps_every_sample(self):
        records, expect = fixture_records()
        trials, _ = results.validate(self.lines(records), expect, True)
        summary = results.summarize(trials, 'fwd')
        self.assertEqual(summary['metric'], 'local_release_ns')
        self.assertEqual(len(summary['arms']['uring']['samples_ns']), 2)
        ratios = summary['paired_ratio_vs_posix']['uring']
        self.assertEqual(len(ratios), 2)
        self.assertTrue(any(r > 1 for r in ratios))   # slower results are retained, not filtered
        self.assertEqual(summary['arms']['uring']['zc_copied_fraction'], [1 / t['notifs'] for t in trials if t['arm'] == 'uring'])
        lat = summary['arms']['posix']['unit_latency_ns']
        self.assertEqual(sorted(lat), ['max', 'min', 'p50', 'p90', 'p99', 'p999'])
        self.assertEqual(len(lat['p50']), 2)
        self.assertEqual(summary['arms']['posix']['inflight_bytes'], 2 * 65536)

    def test_producer_latency_record(self):
        # The real run_trial() prints a measured forward record for a fake posix arm whose
        # unit stamps are fixed numbers (unit u: 1000 * (u + 1) ns); no clock data is checked.
        out = subprocess.run([str(BUILD / 'test_latency'), '--record'], text=True, capture_output=True,
                             timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        record = json.loads(out.stdout)
        expect = dict(direction='fwd', size=65536, qd=2, units=4, geometry=results.geometry(1500, 65536, 8 << 20))
        results.check_trial(record, expect, True)
        self.assertEqual([record[k] for k in results.LATENCY], [1000, 2000, 4000, 4000, 4000, 4000])
        self.assertEqual((record['lat_samples'], record['local_release_ns']), (4, 10000))
        self.assertEqual(record['peer_buffers'], record['groups'])

    def test_inflight_statement(self):
        geo = results.geometry(1500, 4 << 20, 8 << 20)
        self.assertEqual(results.inflight_bytes('posix', 'fwd', 4 << 20, 8, geo, 0), 8 * (4 << 20))
        self.assertEqual(results.inflight_bytes('posix', 'rev', 4 << 20, 8, geo, 0), 4 << 20)
        self.assertEqual(results.inflight_bytes('uring', 'rev', 4 << 20, 8, geo, 0), 8 * (4 << 20))
        self.assertEqual(results.inflight_bytes('splice', 'fwd', 4 << 20, 8, geo, 0), 8 * geo['seg'])
        # 4 MiB at qd 1 with a 1500 MTU: 32 KiB groups, depth 64, so 2 MiB in flight, not 4 MiB.
        self.assertEqual(geo['group'], 32768)
        self.assertEqual(results.inflight_bytes('session', 'fwd', 4 << 20, 1, geo, 64), 2 << 20)


if __name__ == '__main__':
    unittest.main()
