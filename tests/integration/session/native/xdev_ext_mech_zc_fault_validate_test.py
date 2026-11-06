#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host-only tests of the fault campaign validator; no KVM, network or device access.

fault_fixtures/<campaign>.log are synthetic passing consoles (4 groups, depth
2) in the guest console protocol of xdev_ext_mech_zc_fault_validate.py, never
evidence that a guest was actually run.  Disk images are generated in a
temporary directory.  Every failing fixture changes exactly one invariant of a
passing one and must fail for that stated reason.
The ctl lines of the fixtures follow what xdev_ext_mech_ctl actually prints: a
chain a/d session is laid out like an AF_XDP one (six 4 KiB frames per 8 KiB
group at MTU 1500), and a ce-chain run whose session latched an error prints
its final STATS, XDEV_EXT_MECH_SOURCE_DRAIN and 'xdev_ext_mech_ctl: chain X:'
instead of an XDEV_EXT_MECH_CE_* verdict.
Run directly with python3 xdev_ext_mech_zc_fault_validate_test.py -v.
"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'fault_fixtures'
CTL_SOURCES = (HERE.parents[2] / 'xdev_ext_mech' / 'xdev_ext_mech_ctl.c',
               HERE.parents[2] / 'xdev_ext_mech' / 'xdev_ext_mech_ctl_core.h')
VERIFIER = HERE / 'verifier'
GUEST = HERE / 'xdev_ext_mech_zc_fault_guest.sh'
G, D = 4, 2


def _load():
    spec = importlib.util.spec_from_file_location(
        'xdev_ext_mech_zc_fault_validate', HERE / 'xdev_ext_mech_zc_fault_validate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fv = _load()

# Source groups written into each declared window by the passing fixture;
# the remaining groups of a window stay zero.  AFTER windows are always exact.
IMAGE_SPEC = {
    'ring-exit-rx': dict(rx=2), 'exit-rx': dict(rx=1), 'exit-source': dict(ce=1),
    'detach-afxdp-mid-run': dict(rx=2), 'detach-nvme-under-load': dict(rx=2),
    'netdev-remove-tx': {}, 'netdev-remove-rx': dict(rx=1), 'window-reject': {},
    'fq-dup': dict(rx=G), 'afxdp-copy': dict(rx=G), 'afxdp-drv-copy': {},
    'ce-presubmit': {}, 'ce-ambiguous-multi': {}, 'nvme-readonly-dest': {},
    'nvme-reset-mid-run': dict(ce=G), 'concurrent-ce-disjoint': dict(ce=G, alt=G),
    'concurrent-ce-overlap': dict(ce=G, alt=G),
    'cross-session-isolation': dict(ce=fv.LONG_GROUPS, rx=G),
}
SOURCE_KEY = dict(rx='source', ce='source', after='source', alt='alt_source')


def replace(text, old, new):
    """Exactly one occurrence changes; a fixture mutation is never a no-op."""
    if text.count(old) != 1:
        raise AssertionError(f'{old!r} occurs {text.count(old)} times')
    return text.replace(old, new)


def section_replace(text, role, old, new):
    begin = text.index(f'XDEV_EXT_ZC_FAULT_LOG_BEGIN role={role} ')
    end = text.index(f'XDEV_EXT_ZC_FAULT_LOG_END role={role}\n', begin)
    return text[:begin] + replace(text[begin:end], old, new) + text[end:]


def final_stats_replace(text, role, old, new):
    """Edit the last STATS line of @role, the snapshot the validator reads."""
    begin = text.index(f'XDEV_EXT_ZC_FAULT_LOG_BEGIN role={role} ')
    end = text.index(f'XDEV_EXT_ZC_FAULT_LOG_END role={role}\n', begin)
    start = text.rindex('\nXDEV_EXT_MECH_STATS ', begin, end) + 1
    stop = text.index('\n', start)
    return text[:start] + replace(text[start:stop], old, new) + text[stop:]


def edit(text, role, old, new):
    """role None: whole console; 'R': section R; 'R:final': last STATS line of R."""
    if role is None:
        return replace(text, old, new)
    if role.endswith(':final'):
        return final_stats_replace(text, role[:-len(':final')], old, new)
    return section_replace(text, role, old, new)


def section_set(text, role, exit_code, body):
    """Replace the whole ctl log of @role (exit status and lines)."""
    begin = text.index(f'XDEV_EXT_ZC_FAULT_LOG_BEGIN role={role} ')
    end = text.index(f'XDEV_EXT_ZC_FAULT_LOG_END role={role}\n', begin)
    return (text[:begin] + f'XDEV_EXT_ZC_FAULT_LOG_BEGIN role={role} exit={exit_code}\n' +
            body.rstrip('\n') + '\n' + text[end:])


class FaultValidator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdev-ext-fault-validate-')
        cls.layout = fv.make_images(cls.tmp.name, G)
        directory = Path(cls.tmp.name)
        cls.source = (directory / 'source.raw').read_bytes()
        cls.zero = (directory / 'destination.raw').read_bytes()
        cls.passing = {}
        assert (directory / 'source-before.raw').read_bytes() == cls.source
        assert (directory / 'destination-before.raw').read_bytes() == cls.zero

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def console(self, name):
        return (FIXTURES / (name + '.log')).read_text()

    def group(self, window, index):
        offset = self.layout[SOURCE_KEY[window] + '_slba'] * fv.SECTOR + index * fv.GROUP_BYTES
        return self.source[offset:offset + fv.GROUP_BYTES]

    def put(self, destination, window, index, data):
        offset = self.layout[window + '_slba'] * fv.SECTOR + index * fv.GROUP_BYTES
        destination[offset:offset + len(data)] = data

    def destination(self, name):
        spec = dict(IMAGE_SPEC[name])
        if fv.CAMPAIGNS[name]['after']:
            spec['after'] = G
        destination = bytearray(self.zero)
        for window, count in spec.items():
            for index in range(count):
                self.put(destination, window, index, self.group(window, index))
        return destination

    def images(self, destination=None, *, name=None):
        if destination is None:
            if name not in self.passing:
                self.passing[name] = bytes(self.destination(name))
            return self.source, self.source, self.zero, self.passing[name]
        return self.source, self.source, self.zero, bytes(destination)

    def verdict(self, name, text=None, destination=None):
        text = self.console(name) if text is None else text
        try:
            result = fv.validate_campaign(name, text, self.images(destination, name=name),
                                          groups=G, depth=D)
        except fv.Inconclusive as exc:
            return 'INCONCLUSIVE', str(exc)
        except fv.FaultCheckError as exc:
            return 'FAIL', str(exc)
        return 'PASS', result

    def assertVerdict(self, expected, pattern, name, text=None, destination=None):
        verdict, detail = self.verdict(name, text, destination)
        self.assertEqual(verdict, expected, f'{name}: {detail}')
        self.assertRegex(detail, pattern)

    # --- campaign table ---------------------------------------------------

    def test_campaign_names_are_neutral_and_complete(self):
        self.assertEqual(len(fv.CAMPAIGNS), 18)
        for old, new in (('kill9-rx', 'exit-rx'), ('kill9-source', 'exit-source'),
                         ('adversarial-tenant', 'cross-session-isolation')):
            self.assertNotIn(old, fv.CAMPAIGNS)
            self.assertIn(new, fv.CAMPAIGNS)
        self.assertEqual({p.stem for p in FIXTURES.glob('*.log')}, set(fv.CAMPAIGNS))
        self.assertEqual(set(IMAGE_SPEC), set(fv.CAMPAIGNS))

    def test_matrix_interface_is_stable(self):
        line = fv.expectation_line('ce-ambiguous-multi')
        self.assertEqual(line, 'XDEV_EXT_ZC_FAULT_EXPECT campaign=ce-ambiguous-multi findings=E2E-05 '
                               'outcome=multi-group-quarantine-retained retention=required '
                               'ce_fail_mode=ambiguous ce_delay_us=10000 destination=writable')
        self.assertEqual(fv.host_settings('nvme-readonly-dest'),
                         dict(destination_readonly=1, ce_fail_mode='none', ce_delay_us=10000, nvme_mode=0))
        self.assertEqual(fv.host_settings('window-reject')['nvme_mode'], 1)
        layout = fv.fault_layout(G)
        self.assertEqual(self.layout, layout)
        self.assertEqual(layout['image_bytes'] % (1 << 20), 0)
        self.assertGreaterEqual(layout['ce_slba'] - layout['rx_slba'], (fv.LONG_GROUPS + 1) * fv.GROUP_SECTORS)
        for groups in (1, 257):
            with self.assertRaises(fv.FaultCheckError):
                fv.fault_layout(groups)

    def test_fixtures_print_only_ctl_markers_and_fields(self):
        """Every ctl line the validator parses is printed by xdev_ext_mech_ctl."""
        ctl = '\n'.join(path.read_text() for path in CTL_SOURCES)
        stats_format = re.search(r'"(XDEV_EXT_MECH_STATS [^"]*)"((?:\s*"[^"]*")*)', ctl)
        fmt = stats_format.group(1) + ''.join(re.findall(r'"([^"]*)"', stats_format.group(2)))
        stats_keys = re.findall(r'([a-z_]+)=%', fmt)
        for marker in ('XDEV_EXT_MECH_READY mode=nic-nvme session=', 'XDEV_EXT_MECH_READY mode=source session=',
                       'XDEV_EXT_MECH_RING_EXIT_CLOSE inflight=', 'XDEV_EXT_MECH_RING_EXIT=%s inflight=',
                       'XDEV_EXT_MECH_PROG_DETACH=%s last_err=', 'XDEV_EXT_MECH_FQ_DUP_REJECT=%s pushed=',
                       'XDEV_EXT_MECH_NATIVE_COPY=%s held=', 'XDEV_EXT_MECH_CE_%s=%s chain=%c',
                       'XDEV_EXT_MECH_NIC_NVME_E2E=%s groups=', 'XDEV_EXT_MECH_NIC_CE_NVME_E2E=%s groups=',
                       'XDEV_EXT_MECH_NVME_NIC_E2E=%s groups=', 'XDEV_EXT_MECH_DETACH=PASS pin=',
                       'XDEV_EXT_MECH_NOTIFY mode=terminal', '"STATS %llu: %s\\n"',
                       '"chain %c: %s\\n"',
                       'XDEV_EXT_MECH_SOURCE_DRAIN session=%llu result=%s wait_err=%d drain_err=%d '
                       'stats_reads=%u'):
            self.assertIn(marker, ctl)
        verifier = '\n'.join(p.read_text() for p in VERIFIER.glob('run*.sh'))
        for marker in ('XDEV_EXT_MECH_VERIFIER_NEGATIVES=PASS', 'XDEV_EXT_MECH_VERIFIER_STATES=PASS',
                       'XDEV_EXT_MECH_CE_ABI=PASS'):
            self.assertIn(marker, verifier)
        for name in fv.CAMPAIGNS:
            for line in self.console(name).splitlines():
                if line.startswith('XDEV_EXT_MECH_STATS '):
                    self.assertEqual(re.findall(r'([a-z_]+)=', line), stats_keys, name)
                if line.startswith('XDEV_EXT_MECH_SOURCE_DRAIN '):
                    self.assertEqual(re.findall(r'([a-z_]+)=', line),
                                     ['session', 'result', 'wait_err', 'drain_err', 'stats_reads'], name)

    def test_ce_chain_error_path_prints_no_verdict(self):
        """cmd_ce_chain reports a latched session error only by errno, never by verdict."""
        ctl = CTL_SOURCES[0].read_text()
        body = ctl[ctl.index('static int cmd_ce_chain('):]
        body = body[:body.index('\n}\n')]
        error = body[body.index('ret = ctl_run_source(&src, &s, &frames_ok);'):]
        error = error[:error.index('goto out;')]
        self.assertIn('ctl_err("chain %c: %s\\n", o->chain, strerror(-ret));', error)
        self.assertIn('verdict = src.started ? CTL_FAIL : CTL_SETUP;', error)
        self.assertNotIn('report', error)
        # A failed source wait goes through the drain record that names wait_err.
        wait = ctl[ctl.index('static int ctl_wait_coarse('):]
        wait = wait[:wait.index('\n}\n')]
        self.assertIn('return ctl_source_error_drain(r, groups, s, ret);', wait)
        self.assertIn('.source_error_drain = !o->expect_unbind', ctl)
        # The only CE verdict is the core report, printed once the wait succeeded.
        self.assertEqual(ctl.count('xdev_ext_mech_ctl_report_ce_chain('), 1)

    def test_ctl_layout_model_matches_the_ctl(self):
        """Frames per group come from the layout xdev_ext_mech_ctl registers, at MTU 1500."""
        core = CTL_SOURCES[1].read_text()
        ctl = CTL_SOURCES[0].read_text()
        self.assertIn('#define XDEV_EXT_MECH_CTL_FRAME_SIZE\t\t4096U', core)
        self.assertIn('#define XDEV_EXT_MECH_CTL_XDP_HEADROOM\t256U', core)
        self.assertIn('(XDEV_EXT_MECH_CTL_XDP_HEADROOM + 22U + \\\n\t\t\t\t\t XDEV_EXT_MP_PKT_HDR_LEN)', core)
        self.assertIn('o->mtu = 1500;', ctl)
        # Without a NIC the layout uses --mtu; the guest never passes one.
        self.assertIn('/* The NXP layout on @ifname, or on --mtu (default 1500) without a NIC. */', ctl)
        self.assertNotIn('--mtu', GUEST.read_text())
        self.assertEqual(fv.ctl_frames_per_group(1500), 6)
        self.assertEqual(fv.ctl_frames_per_group(9000), 3)
        self.assertEqual(fv.IOU_FRAMES_PER_GROUP, 6)
        self.assertEqual(fv.AFXDP_FRAMES_PER_GROUP, 6)
        for name in fv.CAMPAIGNS:
            for line in self.console(name).splitlines():
                if line.startswith('XDEV_EXT_MECH_READY mode=source ') and 'xsk=none' in line:
                    self.assertIn(' frames=6 seg_len=1432 ', line, name)

    # --- passing fixtures -------------------------------------------------

    def test_every_campaign_passes_its_fixture(self):
        for name in fv.CAMPAIGNS:
            with self.subTest(name=name):
                verdict, result = self.verdict(name)
                self.assertEqual(verdict, 'PASS', f'{name}: {result}')
                self.assertEqual(result['campaign'], name)
                self.assertEqual(result['scope'], 'KVM software devices; correctness only')

    def test_quarantine_fixture_reports_retained_session(self):
        _, result = self.verdict('ce-ambiguous-multi')
        # Two groups were accepted, each of six frames: 12 frames stay pinned.
        self.assertEqual((result['retained'], result['pin_delta']), (['SRC'], 12))

    def test_detach_accepts_a_tx_source_cancelled_by_the_same_retraction(self):
        tx = ('XDEV_EXT_MECH_STATS session=21 state=STOPPED last_err=-ECANCELED batches_done=2 '
              'batches_abort=1 rejects=0 recycled=0 held=0 sequestered=0 timeouts=0 inflight=0 '
              'native_publish=0 protocol_err=0 published=0 submitted=3,15,0,0 completed=3,15,0,0')
        for name in ('detach-afxdp-mid-run', 'detach-nvme-under-load', 'fq-dup'):
            text = self.console(name)
            text = section_replace(text, 'TX', 'XDEV_EXT_MECH_NVME_NIC_E2E=PASS', 'XDEV_EXT_MECH_NVME_NIC_E2E=FAIL')
            text = section_replace(text, 'TX', re.search(r'XDEV_EXT_MECH_STATS session=21 [^\n]*', text).group(0), tx)
            text = replace(text, 'LOG_BEGIN role=TX exit=0', 'LOG_BEGIN role=TX exit=1')
            with self.subTest(name=name):
                if name == 'fq-dup':
                    self.assertVerdict('FAIL', 'TX ctl failed', name, text)
                else:
                    self.assertEqual(self.verdict(name, text)[0], 'PASS')

    def test_netdev_remove_tx_accepts_the_device_down_window(self):
        """Unregistering closes the device before NETDEV_UNREGISTER unbinds the
        socket; a TX submit in between latches -ENETDOWN first. Only a run whose
        AF_XDP TX stage accepted a submission can carry it."""
        down = self.console('netdev-remove-tx')
        for old, new in (('last_err=-ENXIO', 'last_err=-ENETDOWN'), ('wait_err=-6', 'wait_err=-100'),
                         ('chain b: No such device or address', 'chain b: Network is down')):
            down = down.replace(old, new)
        self.assertEqual(self.verdict('netdev-remove-tx', down)[0], 'PASS')
        never = down.replace('submitted=2,2,2,6 completed=2,2,2,6', 'submitted=2,2,2,0 completed=2,2,2,0')
        self.assertNotEqual(never, down)
        self.assertVerdict('FAIL', r'SRC latched -ENETDOWN without a submission at its AF_XDP TX stage',
                           'netdev-remove-tx', never)

    # --- failing fixtures: one invariant each -----------------------------

    def test_invariant_failures(self):
        stats_ce_ambiguous = 'sequestered=12 timeouts=0 inflight=0 native_publish=0 protocol_err=0 published=0 submitted=2,0,0,0'
        cases = [
            # early reuse: a destination group carries another group's bytes
            ('ring-exit-rx', 'early reuse of a destination group', None, ('rx', 1, ('rx', 3)),
             'FAIL', r'rx window holds bytes of no source group \(early reuse'),
            ('nvme-reset-mid-run', 'early reuse of a destination group', None, ('ce', 2, ('ce', 0)),
             'FAIL', r'ce window holds bytes of no source group'),
            ('concurrent-ce-overlap', 'cross-session bytes in the other window', None, ('alt', 0, ('ce', 0)),
             'FAIL', r'alt window holds bytes of no source group'),
            ('fq-dup', 'torn group in an exact window', None, ('rx', 2, 'torn'),
             'FAIL', r'rx window not exact'),
            ('window-reject', 'refused group written anyway', None, ('ce', 0, ('ce', 0)),
             'FAIL', r'write outside every declared window'),
            ('afxdp-drv-copy', 'native copy reached the namespace', None, ('rx', 0, ('rx', 0)),
             'FAIL', r'write outside every declared window'),
            ('nvme-readonly-dest', 'read-only destination changed', None, ('ce', 0, ('ce', 0)),
             'FAIL', r'write outside every declared window'),
            ('detach-nvme-under-load', 'fewer groups than batches done', None, ('rx', 1, 'zero'),
             'FAIL', r'fewer source groups than batches reported done'),
            # completed > submitted (stale completion match)
            ('detach-afxdp-mid-run', 'completed > submitted',
             ('RX', 'submitted=0,2,0,0', 'submitted=0,1,0,0'), None,
             'FAIL', r'RX stage 1 completed more than accepted \(stale completion\)'),
            ('netdev-remove-tx', 'completed > submitted',
             ('SRC:final', 'submitted=2,2,2,6', 'submitted=2,1,2,6'), None,
             'FAIL', r'SRC stage 1 completed more than accepted'),
            ('concurrent-ce-disjoint', 'completed > submitted',
             ('A', 'submitted=4,4,4,4', 'submitted=4,4,3,4'), None,
             'FAIL', r'A stage 2 completed more than accepted'),
            ('nvme-readonly-dest', 'accepted NVMe write reissued',
             ('SRC:final', 'submitted=2,2,2,2 completed=2,2,2,2', 'submitted=2,2,2,5 completed=2,2,2,5'), None,
             'FAIL', r'NVMe stage 3 reissued an accepted command'),
            ('window-reject', 'out-of-window command reached NVMe',
             ('SRC:final', 'submitted=0,0,0,0 completed=0,0,0,0', 'submitted=1,0,0,0 completed=1,0,0,0'), None,
             'FAIL', r'out-of-window plan reached NVMe or CE'),
            # leaked pins
            ('exit-rx', 'leaked pin count',
             (None, 'PINS phase=after acquired=9000', 'PINS phase=after acquired=9006'), None,
             'FAIL', r'6 FOLL_PIN pins leaked after every session was freed'),
            ('ce-ambiguous-multi', 'sequestered frames unpinned early',
             (None, 'PINS phase=after acquired=9012', 'PINS phase=after acquired=9000'), None,
             'FAIL', r'sequestered frames were unpinned early'),
            ('ce-ambiguous-multi', 'parked session holds more pins than its pool',
             (None, 'PINS phase=after acquired=9012', 'PINS phase=after acquired=9013'), None,
             'FAIL', r'parked sessions hold 13 pins, pool bound 12'),
            # sequestered count above the pool
            ('exit-source', 'parked quarantine above the pool',
             (None, 'role=SRC session=31 state=FREED', 'role=SRC session=31 state=ZOMBIE inflight=0 sequestered=13'), None,
             'FAIL', r'SRC parked quarantine exceeds its pool'),
            ('ce-ambiguous-multi', 'sequestered count above the pool',
             ('SRC:final', stats_ce_ambiguous, stats_ce_ambiguous.replace('sequestered=12', 'sequestered=13')), None,
             'FAIL', r'SRC quarantine exceeds its pool'),
            ('nvme-reset-mid-run', 'parked session still in flight',
             (None, 'role=SRC session=31 state=FREED', 'role=SRC session=31 state=ZOMBIE inflight=1 sequestered=0'), None,
             'FAIL', r'SRC parked session still in flight \(lost completion\)'),
            # missing quarantine
            ('ce-ambiguous-multi', 'missing quarantine',
             ('SRC:final', stats_ce_ambiguous, stats_ce_ambiguous.replace('sequestered=12', 'sequestered=0')), None,
             'FAIL', r'ambiguous copies left no quarantine'),
            ('ce-ambiguous-multi', 'quarantined session freed',
             (None, 'state=ZOMBIE inflight=0 sequestered=12', 'state=FREED'), None,
             'FAIL', r'ambiguous quarantine not parked as ZOMBIE'),
            ('ce-ambiguous-multi', 'quarantined session lost its CE module reference',
             (None, 'CE_UNLOAD result=refused', 'CE_UNLOAD result=unloaded'), None,
             'FAIL', r'CE module removable under quarantine'),
            ('ce-presubmit', 'pre-submit refusal sequestered frames',
             ('SRC:final', 'sequestered=0 timeouts=0 inflight=0 native_publish=0 protocol_err=0 published=0 submitted=2,2,0,0',
              'sequestered=2 timeouts=0 inflight=0 native_publish=0 protocol_err=0 published=0 submitted=2,2,0,0'), None,
             'FAIL', r'pre-submit sequestered'),
            ('ce-presubmit', 'CE module reference leaked',
             (None, 'CE_REFS refcnt=0 settled=1', 'CE_REFS refcnt=1 settled=0'), None,
             'FAIL', r'CE module reference leaked'),
            ('ce-presubmit', 'a later stage ran after the refused copy',
             ('SRC:final', 'submitted=2,2,0,0 completed=2,2,0,0', 'submitted=2,2,1,0 completed=2,2,1,0'), None,
             'FAIL', r'a stage after the refused copy ran'),
            # wrong terminal outcome
            ('netdev-remove-rx', 'receiver claims success after its NIC went away',
             ('RX', 'XDEV_EXT_MECH_NOTIFY mode=terminal', f'XDEV_EXT_MECH_NIC_CE_NVME_E2E=PASS groups={G}\nXDEV_EXT_MECH_NOTIFY mode=terminal'),
             None, 'FAIL', r'receiver falsely succeeded'),
            ('netdev-remove-tx', 'still in flight after the removal',
             ('SRC:final', 'inflight=0', 'inflight=1'), None, 'FAIL', r'SRC still in flight'),
            ('exit-rx', 'killed run claims a verdict',
             ('RX', 'xsk=zc', 'xsk=zc\nXDEV_EXT_MECH_NIC_CE_NVME_E2E=PASS groups=4'), None,
             'FAIL', r'RX exited run claims a verdict'),
            ('detach-nvme-under-load', 'detach left the pin',
             (None, 'PIN_GONE pin=zc-nvme gone=1', 'PIN_GONE pin=zc-nvme gone=0'), None,
             'FAIL', r'expected exactly one PIN_GONE'),
            ('nvme-reset-mid-run', 'controller not live after reset',
             (None, 'state=live', 'state=resetting'), None, 'FAIL', r'did not return to live'),
            ('afxdp-copy', 'copy path never traced',
             (None, 'TRACE copy_calls=48', 'TRACE copy_calls=0'), None,
             'FAIL', r'never traced the copy path'),
            ('afxdp-drv-copy', 'native copy frames held',
             ('RX', 'NATIVE_COPY=PASS held=0', 'NATIVE_COPY=PASS held=6'), None,
             'FAIL', r'native copy frames were held'),
            ('concurrent-ce-disjoint', 'both runs shared one session',
             ('B', 'XDEV_EXT_MECH_STATS session=42', 'XDEV_EXT_MECH_STATS session=41'), None,
             'FAIL', r'concurrent runs shared one session'),
            ('cross-session-isolation', 'out-of-device CE window admitted',
             (None, 'LOG_BEGIN role=AGG_CEVA exit=3\nxdev_ext_mech_ctl: chain a: Invalid argument',
              'LOG_BEGIN role=AGG_CEVA exit=0\nXDEV_EXT_MECH_READY mode=source session=60 frames=2 seg_len=4096 xsk=none'),
             None, 'FAIL', r'AGG_CEVA attempt was admitted'),
            ('cross-session-isolation', 'another uid read the victim STATS',
             ('AGG_STATS', 'xdev_ext_mech_ctl: STATS 51: No such file or directory',
              'XDEV_EXT_MECH_STATS session=51 state=ACTIVE'), None,
             'FAIL', r'another uid could read the victim session'),
            ('window-reject', 'out-of-window chain claims success',
             ('SRC', 'xdev_ext_mech_ctl: chain a: Numerical result out of range',
              'XDEV_EXT_MECH_CE_SIM=PASS chain=a\nxdev_ext_mech_ctl: chain a: Numerical result out of range'), None,
             'FAIL', r'out-of-window chain falsely succeeded'),
            ('ring-exit-rx', 'ring exit left a batch in flight',
             ('RX', 'RING_EXIT=PASS inflight=0', 'RING_EXIT=PASS inflight=1'), None,
             'FAIL', r'ring exit not drained'),
            ('nvme-reset-mid-run', 'AFTER run with the failure still injected',
             (None, 'CE_CONFIG phase=after fail_mode=none', 'CE_CONFIG phase=after fail_mode=ambiguous'), None,
             'FAIL', r'AFTER run with a CE failure still injected'),
        ]
        for name, reason, console_edit, image_edit, expected, pattern in cases:
            with self.subTest(name=name, reason=reason):
                text = self.console(name)
                if console_edit:
                    text = edit(text, *console_edit)
                destination = None
                if image_edit:
                    destination = self.destination(name)
                    window, index, what = image_edit
                    if what == 'zero':
                        data = bytes(fv.GROUP_BYTES)
                    elif what == 'torn':
                        data = self.group(window, index)[:fv.SECTOR] + bytes(fv.GROUP_BYTES - fv.SECTOR)
                    else:
                        data = self.group(*what)
                    self.put(destination, window, index, data)
                self.assertEqual(self.verdict(name)[0], 'PASS')
                self.assertVerdict(expected, pattern, name, text, destination)
        self.assertGreaterEqual(len({case[0] for case in cases}), 18)

    # --- ce-chain runs that end with a latched session error ------------------

    WR_ERR = 'xdev_ext_mech_ctl: chain a: Numerical result out of range'
    WR_DRAIN = 'XDEV_EXT_MECH_SOURCE_DRAIN session=31 result=settled wait_err=-34 drain_err=0 stats_reads=1'
    AMB_DRAIN = 'XDEV_EXT_MECH_SOURCE_DRAIN session=31 result=quarantine wait_err=-5 drain_err=0 stats_reads=1'

    def test_ce_chain_failure_records(self):
        """The terminal-error record must match the latched error, the chain and the session."""
        done = ('XDEV_EXT_MECH_READY mode=source session=31 frames=6 seg_len=1432 xsk=none\n'
                'XDEV_EXT_MECH_NOTIFY mode=terminal eventfd_reads=1 stats_reads=1\n'
                'XDEV_EXT_MECH_CE_SIM=PASS chain=a\n'
                'XDEV_EXT_MECH_STATS session=31 state=ACTIVE last_err=0 batches_done=4 batches_abort=0 '
                'rejects=0 recycled=12 held=0 sequestered=0 timeouts=0 inflight=0 native_publish=0 '
                'protocol_err=0 published=12 submitted=4,4,4,4 completed=4,4,4,4')
        cases = [
            # out-of-window chain that actually completed, exactly as ctl reports success
            ('window-reject', 'chain completed and reported PASS',
             [lambda x: section_set(x, 'SRC', 0, done)], 'FAIL', r'out-of-window chain must fail the run'),
            ('window-reject', 'every group completed behind an error record',
             [('SRC:final', 'batches_done=0 batches_abort=1', 'batches_done=4 batches_abort=0'),
              ('SRC:final', 'submitted=0,0,0,0 completed=0,0,0,0', 'submitted=4,4,4,4 completed=4,4,4,4')],
             'FAIL', r'an out-of-window group completed'),
            ('window-reject', 'FAIL verdict naming another chain',
             [('SRC', self.WR_ERR, 'XDEV_EXT_MECH_CE_SIM=FAIL chain=b\n' + self.WR_ERR)],
             'FAIL', r'SRC verdict names chain b, ran chain a'),
            # wrong error code
            ('window-reject', 'refused for another reason than the window',
             [('SRC:final', 'last_err=-ERANGE', 'last_err=-EINVAL'),
              ('SRC', 'wait_err=-34', 'wait_err=-22')],
             'FAIL', r'SRC expected -ERANGE, latched -EINVAL'),
            ('window-reject', 'run error is a timeout, not the latched refusal',
             [('SRC', 'wait_err=-34', 'wait_err=-110')],
             'FAIL', r'SRC run error -110 differs from the latched -ERANGE'),
            ('window-reject', 'failed run with no latched error',
             [('SRC:final', 'last_err=-ERANGE', 'last_err=0')],
             'FAIL', r'SRC failed run without a latched error'),
            ('ce-ambiguous-multi', 'ambiguous copy latched a timeout',
             [('SRC:final', 'last_err=-EIO', 'last_err=-ETIMEDOUT'), ('SRC', 'wait_err=-5', 'wait_err=-110')],
             'FAIL', r'SRC expected -EIO, latched -ETIMEDOUT'),
            # the record itself
            ('window-reject', 'error line of another chain',
             [('SRC', 'chain a: Numerical', 'chain d: Numerical')], 'FAIL', r'SRC chain a failure not reported'),
            ('window-reject', 'error line missing',
             [('SRC', self.WR_ERR + '\n', '')], 'FAIL', r'SRC chain a failure not reported'),
            ('window-reject', 'drain record missing',
             [('SRC', self.WR_DRAIN + '\n', '')], 'FAIL', r'SRC failed without exactly one source drain record'),
            ('window-reject', 'drain record repeated',
             [('SRC', self.WR_DRAIN, self.WR_DRAIN + '\n' + self.WR_DRAIN)],
             'FAIL', r'SRC failed without exactly one source drain record'),
            ('window-reject', 'drain of another session',
             [('SRC', 'SOURCE_DRAIN session=31', 'SOURCE_DRAIN session=32')],
             'FAIL', r'SRC source drain record names another session'),
            ('window-reject', 'final snapshot unreadable',
             [('SRC', 'drain_err=0', 'drain_err=-2')], 'FAIL', r'SRC final STATS of the failed run could not be read'),
            ('window-reject', 'drain claims quarantine of a stopped session',
             [('SRC', 'result=settled', 'result=quarantine')],
             'FAIL', r'SRC source drain result quarantine differs from the final state STOPPED'),
            ('ce-ambiguous-multi', 'drain claims a parked session settled',
             [('SRC', 'result=quarantine', 'result=settled')],
             'FAIL', r'SRC source drain result settled differs from the final state ZOMBIE'),
            ('ce-ambiguous-multi', 'drain never settled',
             [('SRC', 'result=quarantine', 'result=timeout')],
             'FAIL', r'SRC source drain result timeout differs'),
            # quarantine count off by one, below (the pool bound covers above)
            ('ce-ambiguous-multi', 'one sequestered frame short',
             [('SRC:final', 'sequestered=12', 'sequestered=11'),
              (None, 'state=ZOMBIE inflight=0 sequestered=12', 'state=ZOMBIE inflight=0 sequestered=11'),
              (None, 'PINS phase=after acquired=9012', 'PINS phase=after acquired=9011')],
             'FAIL', r'not every ambiguous group was sequestered'),
            ('ce-ambiguous-multi', 'parked count differs from the final snapshot',
             [(None, 'state=ZOMBIE inflight=0 sequestered=12', 'state=ZOMBIE inflight=0 sequestered=11')],
             'FAIL', r'parked quarantine differs from the final snapshot'),
            # pool layout: frames per group must be the ctl layout
            ('ce-ambiguous-multi', 'quarantined pool registered with another layout',
             [('SRC', 'session=31 frames=6 seg_len=1432', 'session=31 frames=2 seg_len=4096')],
             'FAIL', r'SRC pool layout frames=2 differs from the ctl layout \(6\)'),
            ('nvme-reset-mid-run', 'AFTER pool registered with another layout',
             [('AFTER', 'frames=6 seg_len=1432', 'frames=7 seg_len=1232')],
             'FAIL', r'AFTER pool layout frames=7 differs from the ctl layout \(6\)'),
            # the other chains with the same error path
            ('ce-presubmit', 'pre-submit run claims success',
             [('SRC', 'xdev_ext_mech_ctl: chain b:', 'XDEV_EXT_MECH_CE_SIM=PASS chain=b\nxdev_ext_mech_ctl: chain b:')],
             'FAIL', r'pre-submit failure falsely succeeded'),
            ('ce-presubmit', 'pre-submit run error differs from the latched one',
             [('SRC', 'wait_err=-16', 'wait_err=-5')],
             'FAIL', r'SRC run error -5 differs from the latched -EBUSY'),
            ('netdev-remove-tx', 'stopped chain b claims success',
             [('SRC', 'xdev_ext_mech_ctl: chain b:', 'XDEV_EXT_MECH_CE_SIM=PASS chain=b\nxdev_ext_mech_ctl: chain b:')],
             'FAIL', r'chain b falsely succeeded after its NIC went away'),
            ('netdev-remove-tx', 'stopped run reported as another chain',
             [('SRC', 'chain b: No such', 'chain a: No such')], 'FAIL', r'SRC chain b failure not reported'),
            ('netdev-remove-tx', 'stopped with another error than the removal',
             [('SRC:final', 'last_err=-ENXIO', 'last_err=-ECANCELED'), ('SRC', 'wait_err=-6', 'wait_err=-125')],
             'FAIL', r'SRC expected STOPPED with -ENXIO'),
            ('netdev-remove-tx', 'removal error reported as a timeout',
             [('SRC', 'wait_err=-6', 'wait_err=-110')],
             'FAIL', r'SRC run error -110 differs from the latched -ENXIO'),
        ]
        for name, reason, edits, expected, pattern in cases:
            with self.subTest(name=name, reason=reason):
                text = self.console(name)
                for change in edits:
                    text = change(text) if callable(change) else edit(text, *change)
                self.assertNotEqual(text, self.console(name))
                self.assertVerdict(expected, pattern, name, text)

    def test_ce_chain_failure_may_also_print_a_fail_verdict(self):
        """A FAIL verdict for the same chain beside the record is consistent; PASS never is."""
        text = edit(self.console('window-reject'), 'SRC', self.WR_ERR,
                    'XDEV_EXT_MECH_CE_SIM=FAIL chain=a\n' + self.WR_ERR)
        self.assertEqual(self.verdict('window-reject', text)[0], 'PASS')

    def test_refused_and_quarantined_victim_bytes(self):
        """Victim bytes: no window may receive bytes of another group, the AFTER run stays exact."""
        for name in ('window-reject', 'ce-ambiguous-multi'):
            for reason, (window, index, data), pattern in (
                    ('AFTER group carries another group', ('after', 1, ('after', 2)),
                     r'after window holds bytes of no source group'),
                    ('one AFTER sector flipped', ('after', 0, 'flip'), r'after window holds bytes of no source group'),
                    ('refused group reached the CE window', ('ce', 0, ('ce', 0)), r'write outside every declared window')):
                with self.subTest(name=name, reason=reason):
                    destination = self.destination(name)
                    if data == 'flip':
                        payload = bytearray(self.group(window, index))
                        payload[100] ^= 0xff
                        data = bytes(payload)
                    else:
                        data = self.group(*data)
                    self.put(destination, window, index, data)
                    self.assertVerdict('FAIL', pattern, name, None, destination)

    def reset_failure(self):
        """nvme-reset-mid-run where the reset failed the run: ctl's terminal-error record."""
        stats = ('XDEV_EXT_MECH_STATS session=31 state=STOPPED last_err=-EIO batches_done=1 batches_abort=1 '
                 'rejects=0 recycled=0 held=0 sequestered=0 timeouts=0 inflight=0 native_publish=0 '
                 'protocol_err=0 published=12 submitted=2,2,2,2 completed=2,2,2,2')
        body = '\n'.join(('XDEV_EXT_MECH_READY mode=source session=31 frames=6 seg_len=1432 xsk=none',
                          'XDEV_EXT_MECH_NOTIFY mode=terminal eventfd_reads=1 stats_reads=1', stats, stats,
                          'XDEV_EXT_MECH_SOURCE_DRAIN session=31 result=settled wait_err=-5 drain_err=0 stats_reads=1',
                          'xdev_ext_mech_ctl: chain a: Input/output error'))
        destination = self.destination('nvme-reset-mid-run')
        for index in range(1, G):
            self.put(destination, 'ce', index, bytes(fv.GROUP_BYTES))
        return section_set(self.console('nvme-reset-mid-run'), 'SRC', 1, body), destination

    def test_reset_failure_branch(self):
        text, destination = self.reset_failure()
        verdict, result = self.verdict('nvme-reset-mid-run', text, destination)
        self.assertEqual(verdict, 'PASS', result)
        self.assertEqual(result['observed'], 'native-failure')
        for reason, change, pattern in (
                ('no error record', lambda x: replace(replace(x, 'xdev_ext_mech_ctl: chain a: Input/output error\n', ''),
                                                     'XDEV_EXT_MECH_SOURCE_DRAIN session=31 result=settled wait_err=-5 '
                                                     'drain_err=0 stats_reads=1\n', ''),
                 r'SRC failed without exactly one source drain record'),
                ('claims success', lambda x: replace(x, 'xdev_ext_mech_ctl: chain a:',
                                                    'XDEV_EXT_MECH_CE_SIM=PASS chain=a\nxdev_ext_mech_ctl: chain a:'),
                 r'reset failure not reported'),
                ('run error differs', lambda x: replace(x, 'wait_err=-5', 'wait_err=-110'),
                 r'SRC run error -110 differs from the latched -EIO'),
                ('setup exit, not a run failure', lambda x: replace(x, 'LOG_BEGIN role=SRC exit=1', 'LOG_BEGIN role=SRC exit=3'),
                 r'reset failure not reported'),
                ('fewer source groups than done', None, r'fewer source groups than batches reported done')):
            with self.subTest(reason=reason):
                if change is None:
                    bad = bytearray(destination)
                    self.put(bad, 'ce', 0, bytes(fv.GROUP_BYTES))
                    self.assertVerdict('FAIL', pattern, 'nvme-reset-mid-run', text, bad)
                else:
                    self.assertVerdict('FAIL', pattern, 'nvme-reset-mid-run', change(text), destination)

    def test_console_failures_apply_to_every_campaign(self):
        for name in fv.CAMPAIGNS:
            text = self.console(name)
            with self.subTest(name=name, reason='WARNING line'):
                dirty = replace(text, 'XDEV_EXT_ZC_FAULT_CAMPAIGN_DONE',
                                '[   20.000000] WARNING: CPU: 0 PID: 1 at io_uring/xdev_ext_mech.c:1 x+0x1/0x2\n'
                                'XDEV_EXT_ZC_FAULT_CAMPAIGN_DONE')
                self.assertVerdict('FAIL', r'kernel debug diagnostic: .*"diagnostic": 1', name, dirty)
            with self.subTest(name=name, reason='lockdep report'):
                dirty = replace(text, 'XDEV_EXT_ZC_FAULT_CAMPAIGN_DONE',
                                'WARNING: possible circular locking dependency detected\n'
                                'XDEV_EXT_ZC_FAULT_CAMPAIGN_DONE')
                self.assertVerdict('FAIL', r'"lockdep": 1', name, dirty)
            with self.subTest(name=name, reason='expectation differs'):
                other = replace(text, ' ce_delay_us=', ' ce_delay_us=1')
                self.assertVerdict('FAIL', r'guest expectation differs', name, other)
            with self.subTest(name=name, reason='guest exit'):
                bad = replace(text, 'XDEV_EXT_ZC_FAULT_GUEST_EXIT=0', 'XDEV_EXT_ZC_FAULT_GUEST_EXIT=1')
                self.assertVerdict('FAIL', r'guest did not exit cleanly', name, bad)
            with self.subTest(name=name, reason='expectation after start'):
                lines = text.splitlines()
                expect = lines.pop(1)
                lines.insert(3, expect)
                self.assertVerdict('FAIL', r'expectation stated after the campaign started',
                                   name, '\n'.join(lines) + '\n')
            with self.subTest(name=name, reason='CE stand-in not drained'):
                bad = re.sub(r'(CE_SIM_STATS accepted=\d+ completed=\d+) pending=0', r'\1 pending=1', text)
                self.assertNotEqual(bad, text)
                self.assertVerdict('FAIL', r'CE stand-in not drained', name, bad)
            with self.subTest(name=name, reason='session never settled'):
                bad = re.sub(r'(SESSION role=\w+ session=\d+) state=FREED', r'\1 state=STOPPED', text, count=1)
                self.assertNotEqual(bad, text)
                self.assertVerdict('FAIL', r'neither freed nor parked', name, bad)
            if not fv.CAMPAIGNS[name]['retention'] == 'required':
                with self.subTest(name=name, reason='leaked pin'):
                    leak = replace(text, 'PINS phase=after acquired=9000', 'PINS phase=after acquired=9001')
                    self.assertVerdict('FAIL', r'1 FOLL_PIN pins leaked', name, leak)
            if fv.CAMPAIGNS[name]['after']:
                with self.subTest(name=name, reason='AFTER window not exact'):
                    destination = self.destination(name)
                    self.put(destination, 'after', G - 1, bytes(fv.GROUP_BYTES))
                    self.assertVerdict('FAIL', r'after window not exact', name, None, destination)

    # --- INCONCLUSIVE: precondition not met -------------------------------

    def test_unmet_preconditions_are_inconclusive(self):
        cases = [
            ('ring-exit-rx', (None, 'RING_EXIT_CLOSE inflight=1 held=12', 'RING_EXIT_CLOSE inflight=0 held=6'),
             r'ring closed while the session held nothing'),
            ('exit-rx', (None, 'INFLIGHT_SEEN role=RX seen=1', 'INFLIGHT_SEEN role=RX seen=0'),
             r'RX: nothing observed in flight'),
            ('exit-source', (None, 'LOG_BEGIN role=SRC exit=137', 'LOG_BEGIN role=SRC exit=0'),
             r'SRC finished before the signal was delivered'),
            ('netdev-remove-rx', (None, 'INFLIGHT_SEEN role=RX seen=1', 'INFLIGHT_SEEN role=RX seen=0'),
             r'nothing observed in flight'),
            ('nvme-reset-mid-run', (None, 'INFLIGHT_SEEN role=SRC seen=1', 'INFLIGHT_SEEN role=SRC seen=0'),
             r'nothing observed in flight'),
            ('window-reject', ('SRC:final', 'batches_abort=1', 'batches_abort=0'), r'no group was offered'),
            ('fq-dup', ('RX', 'FQ_DUP_REJECT=PASS pushed=1', 'FQ_DUP_REJECT=FAIL pushed=0'),
             r'fill ring had no room'),
            ('concurrent-ce-overlap', (None, 'CONCURRENT both_ready=1', 'CONCURRENT both_ready=0'),
             r'second session was created after the first ended'),
            ('cross-session-isolation', (None, 'VICTIM_ALIVE alive=1', 'VICTIM_ALIVE alive=0'),
             r'victim finished before every attempt ran'),
        ]
        single = ('SRC:final', 'sequestered=12 timeouts=0 inflight=0 native_publish=0 protocol_err=0 published=0 '
                               'submitted=2,0,0,0 completed=2,0,0,0',
                  'sequestered=6 timeouts=0 inflight=0 native_publish=0 protocol_err=0 published=0 '
                  'submitted=1,0,0,0 completed=1,0,0,0')
        for name, console_edit, pattern in cases + [('ce-ambiguous-multi', single, r'only one group')]:
            with self.subTest(name=name):
                text = edit(self.console(name), *console_edit)
                if name == 'ce-ambiguous-multi':
                    text = replace(text, 'state=ZOMBIE inflight=0 sequestered=12', 'state=ZOMBIE inflight=0 sequestered=6')
                    text = replace(text, 'acquired=9012', 'acquired=9006')
                self.assertVerdict('INCONCLUSIVE', pattern, name, text)

    def late_netdev_remove_tx(self, *, marker):
        """chain b finished before its NIC went away: ctl printed its verdict, no error record."""
        body = ('XDEV_EXT_MECH_READY mode=source session=31 frames=6 seg_len=1448 xsk=zc\n'
                'XDEV_EXT_MECH_NOTIFY mode=terminal eventfd_reads=1 stats_reads=1\n' +
                ('XDEV_EXT_MECH_CE_SIM=PASS chain=b\n' if marker else '') +
                'XDEV_EXT_MECH_STATS session=31 state=ACTIVE last_err=0 batches_done=4 batches_abort=0 '
                'rejects=0 recycled=24 held=0 sequestered=0 timeouts=0 inflight=0 native_publish=0 '
                'protocol_err=0 published=0 submitted=4,4,4,24 completed=4,4,4,24')
        return section_set(self.console('netdev-remove-tx'), 'SRC', 0, body)

    def test_netdev_removal_after_the_last_group_is_inconclusive(self):
        self.assertVerdict('INCONCLUSIVE', r'SRC: the fault arrived after every group ended',
                           'netdev-remove-tx', self.late_netdev_remove_tx(marker=True))
        # A finished chain b still states its verdict; without it the run proves nothing.
        self.assertVerdict('FAIL', r'chain b verdict missing', 'netdev-remove-tx',
                           self.late_netdev_remove_tx(marker=False))

    def test_detach_after_the_last_group_is_inconclusive(self):
        text = self.console('detach-afxdp-mid-run')
        text = section_replace(text, 'RX', 'batches_done=2 batches_abort=0 rejects=0 recycled=12 held=12',
                               'batches_done=4 batches_abort=0 rejects=0 recycled=24 held=24')
        text = section_replace(text, 'RX', 'submitted=0,2,0,0 completed=2,2,0,0',
                               'submitted=0,4,0,0 completed=4,4,0,0')
        destination = self.destination('detach-afxdp-mid-run')
        for index in range(G):
            self.put(destination, 'rx', index, self.group('rx', index))
        self.assertVerdict('INCONCLUSIVE', r'detach after every group ended', 'detach-afxdp-mid-run',
                           text, destination)

    def test_violated_invariant_wins_over_missed_precondition(self):
        text = replace(self.console('exit-rx'), 'INFLIGHT_SEEN role=RX seen=1', 'INFLIGHT_SEEN role=RX seen=0')
        self.assertEqual(self.verdict('exit-rx', text)[0], 'INCONCLUSIVE')
        leak = replace(text, 'PINS phase=after acquired=9000', 'PINS phase=after acquired=9001')
        self.assertVerdict('FAIL', r'pins leaked', 'exit-rx', leak)
        dirty = replace(text, 'XDEV_EXT_ZC_FAULT_GUEST_EXIT=0', '[ 9.0] BUG: KASAN: use-after-free\nXDEV_EXT_ZC_FAULT_GUEST_EXIT=0')
        self.assertVerdict('FAIL', r'"kasan": 1', 'exit-rx', dirty)
        destination = self.destination('exit-rx')
        self.put(destination, 'rx', 0, self.group('rx', 2))
        self.assertVerdict('FAIL', r'early reuse', 'exit-rx', text, destination)

    # --- command line -----------------------------------------------------

    def run_main(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = fv.main(argv)
        return code, out.getvalue()

    def evidence(self, directory, name, text, destination=None):
        directory = Path(directory)
        (directory / 'guest.log').write_text(text)
        (directory / 'qemu.exit').write_text('0\n')
        snapshot = '4242 17 ' + 'a' * 64 + ' ' + 'b' * 64 + '\n'
        (directory / 'other-qemu-before.txt').write_text(snapshot)
        (directory / 'other-qemu-after.txt').write_text(snapshot)
        for filename, data in zip(('source-before.raw', 'source.raw', 'destination-before.raw', 'destination.raw'),
                                  self.images(destination, name=name)):
            (directory / filename).write_bytes(data)

    def test_command_line_exit_codes(self):
        argv = lambda d, n: ['check', '--campaign', n, '--dir', d, '--groups', str(G), '--depth', str(D)]
        with tempfile.TemporaryDirectory(prefix='xdev-ext-fault-cli-') as directory:
            self.evidence(directory, 'ce-ambiguous-multi', self.console('ce-ambiguous-multi'))
            code, out = self.run_main(argv(directory, 'ce-ambiguous-multi'))
            self.assertEqual((code, out.strip()), (0, 'XDEV_EXT_ZC_FAULT=PASS campaign=ce-ambiguous-multi '
                                                       'outcome=multi-group-quarantine-retained '
                                                       'observed=as-expected retained=SRC'))
            result = json.loads((Path(directory) / 'validation.json').read_text())
            self.assertEqual(result['retained'], ['SRC'])
            (Path(directory) / 'validation.json').unlink()

            text = replace(self.console('ce-ambiguous-multi'), 'acquired=9012', 'acquired=9000')
            self.evidence(directory, 'ce-ambiguous-multi', text)
            code, out = self.run_main(argv(directory, 'ce-ambiguous-multi'))
            self.assertEqual(code, fv.EXIT_FAIL)
            self.assertIn('XDEV_EXT_ZC_FAULT=FAIL', out)
            self.assertFalse((Path(directory) / 'validation.json').exists())

            text = replace(self.console('exit-source'), 'seen=1', 'seen=0')
            self.evidence(directory, 'exit-source', text)
            code, out = self.run_main(argv(directory, 'exit-source'))
            self.assertEqual(code, fv.EXIT_INCONCLUSIVE)
            self.assertIn('XDEV_EXT_ZC_FAULT=INCONCLUSIVE campaign=exit-source', out)
            self.assertNotIn('=PASS', out)
            self.assertFalse((Path(directory) / 'validation.json').exists())

            (Path(directory) / 'other-qemu-after.txt').write_text('not a snapshot\n')
            self.assertEqual(self.run_main(argv(directory, 'exit-source'))[0], fv.EXIT_FAIL)
            self.assertEqual(self.run_main(argv(directory, 'kill9-rx'))[0], fv.EXIT_USAGE)
            self.assertEqual(self.run_main(['expect', 'adversarial-tenant'])[0], fv.EXIT_USAGE)
            self.assertEqual(self.run_main(['bogus'])[0], fv.EXIT_USAGE)

    def test_command_line_matrix_actions(self):
        code, out = self.run_main(['list'])
        self.assertEqual(code, 0)
        self.assertEqual([line.split()[1] for line in out.splitlines()],
                         ['campaign=' + name for name in fv.CAMPAIGNS])
        self.assertEqual(self.run_main(['expect', 'exit-rx']), (0, fv.expectation_line('exit-rx') + '\n'))
        self.assertEqual(self.run_main(['host', 'window-reject']),
                         (0, 'destination_readonly=0\nce_fail_mode=none\nce_delay_us=10000\nnvme_mode=1\n'))
        code, out = self.run_main(['layout', '--groups', str(G)])
        self.assertEqual(code, 0)
        self.assertIn(f'image_bytes={self.layout["image_bytes"]}', out.splitlines())
        with tempfile.TemporaryDirectory(prefix='xdev-ext-fault-images-') as directory:
            self.assertEqual(self.run_main(['images', '--groups', str(G), '--dir', directory])[0], 0)
            self.assertEqual((Path(directory) / 'source.raw').read_bytes(), self.source)
        self.assertEqual(self.run_main(['layout', '--groups', '1'])[0], fv.EXIT_FAIL)


if __name__ == '__main__':
    unittest.main()
