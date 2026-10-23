#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fault-injection campaigns on the KVM software devices: expectations and checks.

Each campaign of xdev_ext_mech_zc_fault_matrix.sh boots its own guest on the
QEMU NVMe, virtio-net AF_XDP and xdev_ext_ce_sim (CPU-memcpy stand-in) devices.
This module is the single table of what every campaign expects; the matrix
prints that expectation before the guest boots, the guest echoes it, and after
QEMU exits ``check`` compares the console and the whole disk images with it.
Correctness only: no timing field of any campaign is a performance result.

Invariants asserted, campaign by campaign:
  * no early reuse: every destination group is the source group, untouched,
    or (only where an outcome is declared uncertain) a sector mix of the two;
    no byte outside a declared window changes; the source never changes;
  * no stale-completion match: per stage completed <= submitted, and once
    nothing is in flight they are equal; NVMe stages never exceed one
    accepted command per group (no reissue of an accepted command);
  * no leaked pins: FOLL_PIN acquired-released returns to its baseline once
    every session was freed; a parked (ZOMBIE) session with sequestered
    frames still holds pins, never more than its pool; Mlocked is unchanged;
  * bounded quarantine: sequestered frames never exceed the session pool, a
    quarantined session is parked as ZOMBIE, keeps its CE module reference
    (rmmod refused) and a later session on a disjoint window still runs exact;
  * clean console: no lockdep, KASAN, atomic-sleep, hung-task or other
    BUG/WARNING/Oops report (xdev_ext_mech_zc_debug.check_console).

On the software devices every accepted NVMe and CE command completes, so a
session still in flight at the end of a campaign is a lost completion.

One struct_ops program serves each device class, and every session captures
it at CREATE.  Detaching a program therefore stops every session using it
with -ECANCELED (xdev_ext_mech_generation_gone), and nvme_mode=1 moves the
SLBA of every NVMe command, reads included.  Hence the TX source of a detach
campaign may itself end STOPPED with -ECANCELED, and window-reject runs a
source chain (no network sender could read its source under nvme_mode=1).

Guest console protocol (one line each, fields in this order; <R> is a role
of the campaign table, AFTER, or an aggressor role of cross-session-isolation):
  XDEV_EXT_ZC_FAULT_EXPECT <expectation_line(name) after the prefix>
      first XDEV_EXT_ZC_FAULT_ line of the console
  XDEV_EXT_ZC_FAULT_ENV campaign=<name> groups=<g> depth=<d>
  XDEV_EXT_ZC_FAULT_PINS phase=before|after acquired=<n> released=<n> mlocked_kb=<n>
      nr_foll_pin_acquired/nr_foll_pin_released of /proc/vmstat, Mlocked of
      /proc/meminfo; before every ctl run, after every session settled
  XDEV_EXT_ZC_FAULT_CE_CONFIG phase=campaign|after fail_mode=<s> delay_us=<n>
      /sys/module/xdev_ext_ce_sim/parameters/{fail_mode,delay_us} when the
      campaign roles start, and again before the AFTER run
  XDEV_EXT_ZC_FAULT_LOG_BEGIN role=<R> exit=<exit status>
  <the unchanged stdout and stderr of that ctl or helper run>
  XDEV_EXT_ZC_FAULT_LOG_END role=<R>
  XDEV_EXT_ZC_FAULT_INFLIGHT_SEEN role=<R> seen=0|1 inflight=<n>
      ctl stats of the session polled until inflight >= 1, before the fault
  XDEV_EXT_ZC_FAULT_KILL role=<R> signal=9
  XDEV_EXT_ZC_FAULT_NETDEV_REMOVED ifname=<eth0|eth1> present=0
  XDEV_EXT_ZC_FAULT_RESET controller=<nvmeN> state=<state after the reset>
  XDEV_EXT_ZC_FAULT_PIN_GONE pin=<zc-afxdp|zc-nvme> gone=1
  XDEV_EXT_ZC_FAULT_CONCURRENT both_ready=0|1
  XDEV_EXT_ZC_FAULT_VICTIM_ALIVE alive=0|1
  XDEV_EXT_ZC_FAULT_SESSION role=<R> session=<id|0> state=FREED|ZOMBIE|NOT_CREATED
      [inflight=<n> sequestered=<n>, from ctl stats, for a ZOMBIE]
  XDEV_EXT_ZC_FAULT_CE_SIM_STATS accepted=<n> completed=<n> pending=<n>
      peak_pending=<n> submit_before_first_complete=<n>
  XDEV_EXT_ZC_FAULT_CE_REFS refcnt=<n> settled=0|1
      /sys/module/xdev_ext_ce_sim/refcnt after a bounded wait for 0
  XDEV_EXT_ZC_FAULT_CE_UNLOAD result=unloaded|refused
  XDEV_EXT_ZC_FAULT_TRACE copy_calls=<n> zc_calls=<n>
      the counts xdev_ext_mech_zc_kvm.sh greps from the function trace
  XDEV_EXT_ZC_FAULT_CAMPAIGN_DONE campaign=<name>
  XDEV_EXT_ZC_FAULT_GUEST_EXIT=0

Provenance of the ported legacy cases (read, never executed):
archive/release-excluded/retained-legacy/kernel/tools/testing/selftests/
xdev_ext_integration/xdev_ext_final_kvm.sh, git blob
93737322ad3fbc3ce121856412890f592debef4d, sha256
49f98e0a4c268019db63ac2b94d14a504f1b2b408ecfbf00f6ee557c97862241:
mech_arm_s1_fq_dup -> campaign fq-dup; mech_ce_refcnt_zero -> the guest's
bounded CE refcnt wait (CE_REFS marker); mech_arm_s3_presubmit -> campaign
ce-presubmit; snapshot_other_qemu -> the matrix's host QEMU snapshots,
checked by check_other_qemu().  nvme_sgl_field is not ported: its producer
(nvme_xdev_ext_passthru/nvme_sgl_gap_runtime) needs a dedicated SGL
controller and a host recompute of the regions it writes.

Exit status of the command line: 0 PASS, 1 FAIL, 2 usage, 5 INCONCLUSIVE
(every invariant held but the fault never met its precondition, e.g.
nothing was in flight when the exit or removal was due; never reported as
PASS).  A violated invariant is FAIL even when the precondition was missed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from xdev_ext_mech_zc_debug import check_console  # noqa: E402

SECTOR = 512
GROUP_BYTES = 8192
GROUP_SECTORS = GROUP_BYTES // SECTOR
FRAME_BYTES = 4096
# xdev_ext_mech_ctl at MTU 1500: six AF_XDP frames carry one 8 KiB group;
# the ring's XDEV_EXT UMEM (chains a and d) uses two 4 KiB frames.
AFXDP_FRAMES_PER_GROUP = 6
IOU_FRAMES_PER_GROUP = GROUP_BYTES // FRAME_BYTES
# CTL_NUM_FRAMES 4096-byte frames: the UMEM of every ctl AF_XDP socket.
AFXDP_POOL_PAGES = 4096
LONG_GROUPS = 512
CE_LEN = 65536
CE_SIM_WINDOW = 4 << 20
CE_VA = dict(primary=0, secondary=2 << 20, rx=1 << 20, after=3 << 20)
EXIT_PASS, EXIT_FAIL, EXIT_USAGE, EXIT_INCONCLUSIVE = 0, 1, 2, 5
KILLED_EXIT = 128 + 9
CTL_FAIL, CTL_SETUP = 1, 3
TRACE_MODES = ('zc', 'nocopy', 'copy', 'mixed', 'idle')


class FaultCheckError(ValueError):
    """The evidence contradicts the campaign's stated expectation."""


class Inconclusive(Exception):
    """The fault precondition was not met; the run proves nothing either way."""


def _require(condition, message):
    if not condition:
        raise FaultCheckError(message)


# --- campaign table ------------------------------------------------------

def _campaign(findings, outcome, detail, *, retention='never', trace='idle',
              readonly_destination=False, delay_us=10000, nvme_mode=0,
              fail_mode='none', roles=None, windows=(), after=True):
    # Every guest loads xdev_ext_ce_sim: the campaign itself or the AFTER run
    # (chain a on a disjoint window and CE range) needs it.
    assert trace in TRACE_MODES and retention in ('never', 'allowed', 'required')
    return dict(findings=findings, outcome=outcome, detail=detail,
                retention=retention, trace=trace,
                readonly_destination=readonly_destination, delay_us=delay_us,
                nvme_mode=nvme_mode, fail_mode=fail_mode, roles=roles or {},
                windows=tuple(windows), after=after)


# Role pool kinds: 'afxdp' sessions own a 16 MiB XSK UMEM, 'iou' sessions the
# ring's XDEV_EXT UMEM of min(groups, depth) groups; uses_ce marks a session
# that binds xdev_ext_ce_sim regions (and so pins the module while parked).
ROLE_AFXDP, ROLE_AFXDP_CE, ROLE_IOU_CE = ('afxdp', False), ('afxdp', True), ('iou', True)

# Window policies: 'exact' every group is the source group; 'whole' every
# group is the source group or untouched; 'torn' sector mixes also allowed.
CAMPAIGNS = {
    'ring-exit-rx': _campaign(
        ('E2E-01',), 'rx-ring-exit-drained',
        'RX->CE->CE->NVMe receiver closes its ring while holding frames; the '
        'session drains or parks, nothing stays in flight, the TX source '
        'succeeds, RX window groups are source or untouched',
        retention='allowed', trace='zc',
        roles=dict(RX=ROLE_AFXDP_CE, TX=ROLE_AFXDP),
        windows=(('rx', 'source', 'groups', 'whole'),)),
    'exit-rx': _campaign(
        ('E2E-01', 'E8'), 'rx-exited-session-freed',
        'the RX->CE->CE->NVMe receiver process exits on SIGKILL with batches '
        'in flight; ring exit frees or parks the session, no pin or CE '
        'reference leaks, the TX source succeeds',
        retention='allowed', trace='zc',
        roles=dict(RX=ROLE_AFXDP_CE, TX=ROLE_AFXDP),
        windows=(('rx', 'source', 'groups', 'whole'),)),
    'exit-source': _campaign(
        ('E8',), 'source-exited-session-freed',
        'a chain a source process (NVMe->CE->CE->NVMe) exits on SIGKILL with '
        'batches in flight; destination groups are source or untouched',
        retention='allowed', roles=dict(SRC=ROLE_IOU_CE),
        windows=(('ce', 'source', 'groups', 'whole'),)),
    'detach-afxdp-mid-run': _campaign(
        ('E2E-03',), 'rx-stopped-ECANCELED',
        'AF_XDP struct_ops link detached after half the groups: the receiver '
        'stops with -ECANCELED and settles; the pin is gone; the TX source '
        'succeeds or, still running, stops with -ECANCELED too',
        trace='zc', roles=dict(RX=ROLE_AFXDP, TX=ROLE_AFXDP),
        windows=(('rx', 'source', 'groups', 'whole'),)),
    'detach-nvme-under-load': _campaign(
        ('E2E-03', 'E8'), 'rx-stopped-ECANCELED',
        'NVMe struct_ops link detached under full RX->CE->CE->NVMe load: the '
        'session stops with -ECANCELED and settles (generation retraction '
        'as STOP under load); the TX source succeeds or stops the same way',
        trace='zc', roles=dict(RX=ROLE_AFXDP_CE, TX=ROLE_AFXDP),
        windows=(('rx', 'source', 'groups', 'whole'),)),
    'netdev-remove-tx': _campaign(
        ('E2E-03',), 'tx-stopped-ENXIO',
        'virtio-net of the chain b TX stage unbound with batches in flight: '
        'the source stops with -ENXIO, nothing in flight, accepted NVMe and '
        'CE commands each completed once',
        retention='allowed', trace='nocopy', roles=dict(SRC=ROLE_AFXDP_CE)),
    'netdev-remove-rx': _campaign(
        ('E2E-03',), 'rx-stopped-ENXIO',
        'virtio-net of the RX->CE->CE->NVMe receiver unbound with batches in '
        'flight: the receiver stops with -ENXIO, nothing in flight',
        retention='allowed', trace='zc',
        roles=dict(RX=ROLE_AFXDP_CE, TX=ROLE_AFXDP),
        windows=(('rx', 'source', 'groups', 'whole'),)),
    'window-reject': _campaign(
        ('E2E-02',), 'every-group-refused-before-nvme',
        'chain a under an NVMe program built with nvme_mode=1 (every SLBA '
        'outside the bound window): no group reaches NVMe or CE, the '
        'destination image is unchanged',
        nvme_mode=1, roles=dict(SRC=ROLE_IOU_CE)),
    'fq-dup': _campaign(
        ('legacy:mech_arm_s1_fq_dup',), 'duplicate-fill-refused-run-exact',
        'receiver pushes an owned frame address into the fill ring again: '
        'the duplicate changes nothing, the whole run stays exact',
        trace='zc', roles=dict(RX=ROLE_AFXDP, TX=ROLE_AFXDP),
        windows=(('rx', 'source', 'groups', 'exact'),)),
    'afxdp-copy': _campaign(
        ('E2E-04',), 'copy-mode-exact',
        'XDP_COPY sockets on both ends (SKB-mode redirect): exact transfer, '
        'the copy path is actually traced',
        trace='copy', roles=dict(RX=ROLE_AFXDP, TX=ROLE_AFXDP),
        windows=(('rx', 'source', 'groups', 'exact'),)),
    'afxdp-drv-copy': _campaign(
        ('E2E-04',), 'native-copy-published-not-held',
        'DRV-mode XDP with an XDP_COPY receiver: frames are published to user '
        'space, never held, and nothing reaches the namespace',
        trace='mixed', roles=dict(RX=ROLE_AFXDP, TX=ROLE_AFXDP)),
    'ce-presubmit': _campaign(
        ('legacy:mech_arm_s3_presubmit', 'E8'),
        'every-group-aborted-nothing-sequestered',
        'xdev_ext_ce_sim fail_mode=pre_submit on chain b: every group aborts '
        'at CE H2D, nothing is sequestered, later stages never run, the '
        'module unloads',
        fail_mode='pre_submit', delay_us=0, roles=dict(SRC=ROLE_AFXDP_CE)),
    'ce-ambiguous-multi': _campaign(
        ('E2E-05',), 'multi-group-quarantine-retained',
        'xdev_ext_ce_sim fail_mode=ambiguous on chain d with depth in flight: '
        'every accepted group is sequestered, more than one, the session '
        'parks as ZOMBIE, keeps its CE reference and pins, a disjoint later '
        'session is exact',
        retention='required', fail_mode='ambiguous',
        roles=dict(SRC=ROLE_IOU_CE)),
    'nvme-readonly-dest': _campaign(
        ('E2E-05',), 'native-write-error-no-reissue',
        'chain a into a read-only QEMU NVMe namespace: CREATE is refused or '
        'every accepted write completes once with a native error; no write is '
        'reissued, the destination is unchanged',
        retention='allowed', readonly_destination=True, after=False,
        roles=dict(SRC=ROLE_IOU_CE)),
    'nvme-reset-mid-run': _campaign(
        ('E2E-05',), 'success-or-native-failure-bounded',
        'destination controller reset during a delayed chain a: either an '
        'exact image, or a native failure with every accepted command '
        'completed once and bounded quarantine; no misdirected write',
        retention='allowed', roles=dict(SRC=ROLE_IOU_CE),
        windows=(('ce', 'source', 'groups', 'torn'),)),
    'concurrent-ce-disjoint': _campaign(
        ('E2E-14',), 'both-sessions-exact',
        'two chain a sessions at once on the same NVMe and CE devices, '
        'disjoint LBA and CE windows, different source patterns: both exact',
        roles=dict(A=ROLE_IOU_CE, B=ROLE_IOU_CE), after=False,
        windows=(('ce', 'source', 'groups', 'exact'),
                 ('alt', 'alt_source', 'groups', 'exact'))),
    'concurrent-ce-overlap': _campaign(
        ('E2E-14',), 'both-sessions-exact-serialized',
        'two chain a sessions bound to the same CE window: the CE lease '
        'serializes them, both images exact, no cross-session bytes',
        roles=dict(A=ROLE_IOU_CE, B=ROLE_IOU_CE), after=False,
        windows=(('ce', 'source', 'groups', 'exact'),
                 ('alt', 'alt_source', 'groups', 'exact'))),
    'cross-session-isolation': _campaign(
        ('E13',), 'aggressor-refused-victim-exact',
        'victim chain a runs while another session binds a CE window past the '
        'device, names an LBA window past capacity, loads malformed plans, '
        'reads victim STATS as another uid and re-fills an owned frame; every '
        'attempt is refused and the victim image is exact',
        trace='zc', delay_us=50000,
        roles=dict(VICTIM=ROLE_IOU_CE, AGG_FQDUP_RX=ROLE_AFXDP,
                   AGG_FQDUP_TX=ROLE_AFXDP),
        windows=(('ce', 'source', 'long', 'exact'),
                 ('rx', 'source', 'groups', 'exact'))),
}


def expectation_line(name):
    c = CAMPAIGNS[name]
    return ('XDEV_EXT_ZC_FAULT_EXPECT campaign={} findings={} outcome={} retention={} '
            'ce_fail_mode={} ce_delay_us={} destination={}').format(
                name, ','.join(c['findings']), c['outcome'], c['retention'],
                c['fail_mode'], c['delay_us'],
                'readonly' if c['readonly_destination'] else 'writable')


def host_settings(name):
    """Shell assignments the matrix needs before the guest boots."""
    c = CAMPAIGNS[name]
    return dict(destination_readonly=int(c['readonly_destination']),
                ce_fail_mode=c['fail_mode'], ce_delay_us=c['delay_us'],
                nvme_mode=c['nvme_mode'])


# --- geometry and images -------------------------------------------------

def fault_layout(groups):
    """Windows in 512-byte sectors, each sized for LONG_GROUPS plus a guard group."""
    _require(2 <= groups <= 256, 'fault matrix campaign length must be 2..256 groups')
    span = (LONG_GROUPS + 1) * GROUP_SECTORS
    base = 2048
    layout = dict(groups=groups, long_groups=LONG_GROUPS,
                  source_slba=base, alt_source_slba=base + span,
                  rx_slba=base, ce_slba=base + span, after_slba=base + 2 * span,
                  alt_slba=base + 3 * span)
    end = (base + 4 * span) * SECTOR
    layout['image_bytes'] = max(16 << 20, -(-end // (1 << 20)) * (1 << 20))
    layout['image_sectors'] = layout['image_bytes'] // SECTOR
    return layout


def _pattern(label, groups):
    return hashlib.shake_256(b'XDEV_EXT fault matrix 20261022 ' + label).digest(groups * GROUP_BYTES)


def make_images(directory, groups):
    """Source: primary pattern at source_slba, secondary at alt_source_slba."""
    layout = fault_layout(groups)
    directory = Path(directory)
    source = bytearray(layout['image_bytes'])
    for key, label in (('source_slba', b'primary'), ('alt_source_slba', b'secondary')):
        offset = layout[key] * SECTOR
        data = _pattern(label, LONG_GROUPS)
        source[offset:offset + len(data)] = data
    zero = bytes(layout['image_bytes'])
    for name, data in (('source.raw', source), ('source-before.raw', source),
                       ('destination.raw', zero), ('destination-before.raw', zero)):
        (directory / name).write_bytes(data)
    return layout


def classify_group(destination, source):
    if destination == source:
        return 'source'
    if not any(destination):
        return 'zero'
    zero = bytes(SECTOR)
    for i in range(0, len(destination), SECTOR):
        piece = destination[i:i + SECTOR]
        if piece != zero and piece != source[i:i + SECTOR]:
            return 'foreign'
    return 'partial'


def check_images(name, layout, source_before, source_after, destination_before,
                 destination_after, *, prefix_minimum=None):
    """Return {window: {state: count}}; raise on any write outside the windows."""
    c = CAMPAIGNS[name]
    _require(source_before == source_after, 'source image changed')
    _require(len(destination_before) == len(destination_after), 'destination size changed')
    _require(len(destination_before) == layout['image_bytes'], 'destination size differs from the layout')
    expected = bytearray(destination_before)
    counts = {}
    windows = list(c['windows'])
    if c['after']:
        windows.append(('after', 'source', 'groups', 'exact'))
    for window, source_key, length, policy in windows:
        groups = layout['long_groups'] if length == 'long' else layout['groups']
        doff = layout[window + '_slba'] * SECTOR
        soff = layout[source_key + '_slba'] * SECTOR
        states = dict(source=0, zero=0, partial=0, foreign=0)
        for g in range(groups):
            dpart = destination_after[doff + g * GROUP_BYTES:doff + (g + 1) * GROUP_BYTES]
            spart = source_before[soff + g * GROUP_BYTES:soff + (g + 1) * GROUP_BYTES]
            states[classify_group(dpart, spart)] += 1
        expected[doff:doff + groups * GROUP_BYTES] = \
            destination_after[doff:doff + groups * GROUP_BYTES]
        _require(not states['foreign'], window + ' window holds bytes of no source group '
                 '(early reuse or misdirected write)')
        if policy == 'exact':
            _require(states['source'] == groups, window + ' window not exact: ' + json.dumps(states))
        elif policy == 'whole':
            _require(not states['partial'], window + ' window has a torn group')
        else:
            _require(policy == 'torn', 'bad window policy')
        minimum = (prefix_minimum or {}).get(window)
        if minimum is not None:
            _require(states['source'] >= minimum,
                     window + ' window has fewer source groups than batches reported done')
        counts[window] = states
    _require(bytes(expected) == destination_after, 'write outside every declared window')
    return counts


# --- console parsing -----------------------------------------------------

_PAIR = re.compile(r'(?:^|(?<=\s))([a-z_][a-z0-9_]*)=(\S+)')


def _pairs(line):
    pairs = _PAIR.findall(line)
    _require(len({k for k, _ in pairs}) == len(pairs), 'duplicate field: ' + line)
    return dict(pairs)


def _int(fields, key):
    try:
        return int(fields[key], 0)
    except (KeyError, ValueError) as exc:
        raise FaultCheckError('missing/invalid ' + key) from exc


def _vector(fields, key):
    try:
        vector = [int(v) for v in fields[key].split(',')]
    except (KeyError, ValueError) as exc:
        raise FaultCheckError('invalid ' + key) from exc
    _require(len(vector) == 4 and min(vector) >= 0, 'bad stage vector ' + key)
    return vector


class Section:
    """The raw log of one ctl (or helper script) run, as the guest printed it."""

    def __init__(self, role, exit_code, lines):
        self.role, self.exit, self.lines = role, exit_code, lines

    def starting(self, prefix):
        return [line for line in self.lines if line.startswith(prefix)]

    def stats(self):
        """The final STATS snapshot (error paths may print an earlier one)."""
        lines = self.starting('XDEV_EXT_MECH_STATS ')
        return _pairs(lines[-1]) if lines else None

    def marker(self, name):
        """(verdict, fields) of the only '<name>=PASS|FAIL' line, or None."""
        lines = [line for line in self.lines if line.startswith(name + '=')]
        _require(len(lines) <= 1, self.role + ' duplicate ' + name)
        if not lines:
            return None
        verdict = lines[0][len(name) + 1:].split(' ', 1)[0]
        _require(verdict in ('PASS', 'FAIL'), self.role + ' bad verdict ' + name)
        return verdict, _pairs(lines[0].split(' ', 1)[1] if ' ' in lines[0] else '')

    def ready(self):
        lines = self.starting('XDEV_EXT_MECH_READY ')
        _require(len(lines) <= 1, self.role + ' duplicate READY')
        return _pairs(lines[0]) if lines else None

    def verdicts(self):
        return [line for line in self.lines if re.match(r'XDEV_EXT_MECH_[A-Z0-9_]+=(PASS|FAIL)', line)]


class Console:
    BEGIN = re.compile(r'^XDEV_EXT_ZC_FAULT_LOG_BEGIN role=([A-Z0-9_]+) exit=(-?[0-9]+)$')

    def __init__(self, text):
        self.text = text
        self.lines = text.splitlines()
        self.sections = {}
        self.first_section = None
        self.missed = []
        current = None
        for index, line in enumerate(self.lines):
            match = self.BEGIN.match(line)
            if match:
                _require(current is None, 'nested ctl log section')
                role = match.group(1)
                _require(role not in self.sections, 'duplicate ctl log section ' + role)
                current = Section(role, int(match.group(2)), [])
                self.sections[role] = current
                if self.first_section is None:
                    self.first_section = index
                continue
            if current is not None:
                if line == 'XDEV_EXT_ZC_FAULT_LOG_END role=' + current.role:
                    current = None
                else:
                    current.lines.append(line)
        _require(current is None, 'unterminated ctl log section')

    def section(self, role):
        _require(role in self.sections, 'missing ctl log of ' + role)
        return self.sections[role]

    def markers(self, kind):
        prefix = 'XDEV_EXT_ZC_FAULT_' + kind + ' '
        return [_pairs(line[len(prefix):]) for line in self.lines if line.startswith(prefix)]

    def one(self, kind, **match):
        found = [m for m in self.markers(kind) if all(m.get(k) == v for k, v in match.items())]
        _require(len(found) == 1, 'expected exactly one ' + kind + ' ' + json.dumps(match))
        return found[0]

    def index(self, kind):
        prefix = 'XDEV_EXT_ZC_FAULT_' + kind + ' '
        found = [i for i, line in enumerate(self.lines) if line.startswith(prefix)]
        _require(len(found) == 1, 'expected exactly one ' + kind)
        return found[0]

    def miss(self, reason):
        """Record an unmet precondition; the remaining invariants still run."""
        self.missed.append(reason)


# --- shared role checks --------------------------------------------------

def _stage_balance(stats, role, *, rx, groups, nvme_stages=(), ce_bound=True, ce_stages=()):
    """completed <= submitted; equal once nothing is in flight; no NVMe reissue."""
    submitted, completed = _vector(stats, 'submitted'), _vector(stats, 'completed')
    settled = _int(stats, 'inflight') == 0
    for i in range(1 if rx else 0, 4):
        _require(completed[i] <= submitted[i], f'{role} stage {i} completed more than accepted (stale completion)')
        if settled:
            _require(completed[i] == submitted[i], f'{role} stage {i} accepted command never completed')
    for i in nvme_stages:
        _require(submitted[i] <= groups, f'{role} NVMe stage {i} reissued an accepted command')
    if ce_bound:
        for i in ce_stages:
            _require(submitted[i] <= groups, f'{role} CE stage {i} reissued an accepted copy')
    return submitted, completed


def _bounded_quarantine(stats, role, pool_frames):
    sequestered = _int(stats, 'sequestered')
    _require(0 <= sequestered <= pool_frames, role + ' quarantine exceeds its pool')
    return sequestered


def _pool_frames(pool, groups, depth):
    return AFXDP_POOL_PAGES if pool == 'afxdp' else min(groups, depth) * IOU_FRAMES_PER_GROUP


def _success(con, role, marker, groups, *, kind):
    sec = con.section(role)
    _require(sec.exit == 0, role + ' ctl failed')
    verdict = sec.marker(marker)
    _require(verdict is not None and verdict[0] == 'PASS', role + ' missing ' + marker + '=PASS')
    stats = sec.stats()
    _require(stats is not None, role + ' missing STATS')
    _require(stats.get('last_err') == '0', role + ' last_err')
    for key in ('batches_abort', 'inflight', 'sequestered', 'protocol_err'):
        _require(_int(stats, key) == 0, role + ' ' + key)
    _require(_int(stats, 'batches_done') == groups, role + ' incomplete')
    submitted, completed = _vector(stats, 'submitted'), _vector(stats, 'completed')
    for i in range(4):
        _require(completed[i] <= submitted[i] or (kind.startswith('nic') and i == 0),
                 f'{role} stage {i} completed more than accepted (stale completion)')
    if kind == 'nic-nvme':
        _require(submitted == [0, groups, 0, 0] and completed == [groups, groups, 0, 0],
                 role + ' RX->NVMe stage counts')
        _require(_int(stats, 'held') == groups * AFXDP_FRAMES_PER_GROUP, role + ' held frames')
    elif kind == 'nic-ce-nvme':
        _require(submitted == [0, groups, groups, groups] and completed == [groups] * 4,
                 role + ' RX->CE->CE->NVMe stage counts')
    elif kind == 'nvme-nic':
        _require(submitted[0] == completed[0] == groups and submitted[1] >= groups and
                 completed[1] == submitted[1] and submitted[2:] == [0, 0],
                 role + ' NVMe->TX stage counts')
    elif kind == 'chain-a':
        _require(submitted == completed == [groups] * 4, role + ' chain a stage counts')
    else:
        raise FaultCheckError('bad success kind')
    return stats


def _inflight_seen(con, role):
    seen = con.one('INFLIGHT_SEEN', role=role)
    if seen.get('seen') != '1':
        con.miss(role + ': nothing observed in flight before the fault was due')
        return False
    _require(_int(seen, 'inflight') >= 1, role + ' INFLIGHT_SEEN without inflight')
    return True


def _session_fates(con, name, groups, depth):
    """Every READY session ends FREED or parked (ZOMBIE); return the parked ones."""
    c = CAMPAIGNS[name]
    retained = {}
    roles = dict(c['roles'])
    if c['after']:
        roles['AFTER'] = ROLE_IOU_CE
    for role, (pool, uses_ce) in roles.items():
        fate = con.one('SESSION', role=role)
        state = fate.get('state')
        ready = con.section(role).ready()
        if ready is None:
            _require(state == 'NOT_CREATED', role + ' session without READY')
            continue
        _require(fate.get('session') == ready.get('session'), role + ' session id mismatch')
        if state == 'FREED':
            continue
        _require(state == 'ZOMBIE', role + ' session neither freed nor parked: ' + str(state))
        _require(role != 'AFTER', 'the clean AFTER session was parked')
        _require(_int(fate, 'inflight') == 0, role + ' parked session still in flight (lost completion)')
        pool_frames = _pool_frames(pool, groups, depth)
        sequestered = _int(fate, 'sequestered')
        _require(sequestered <= pool_frames, role + ' parked quarantine exceeds its pool')
        retained[role] = dict(pool=pool, uses_ce=uses_ce, sequestered=sequestered,
                              pool_pages=pool_frames)
    if c['retention'] == 'never':
        _require(not retained, 'session parked in a campaign that must release everything')
    if c['retention'] == 'required':
        _require(any(r['sequestered'] for r in retained.values()), 'expected quarantine absent')
    return retained


def _pins(con, retained):
    before, after = con.one('PINS', phase='before'), con.one('PINS', phase='after')
    held_before = _int(before, 'acquired') - _int(before, 'released')
    held_after = _int(after, 'acquired') - _int(after, 'released')
    leak = held_after - held_before
    _require(_int(before, 'mlocked_kb') == _int(after, 'mlocked_kb'), 'Mlocked changed')
    _require(leak >= 0, f'{-leak} more FOLL_PIN pins released than acquired')
    if not retained:
        _require(leak == 0, f'{leak} FOLL_PIN pins leaked after every session was freed')
        return leak
    bound = sum(r['pool_pages'] for r in retained.values())
    _require(leak <= bound, f'parked sessions hold {leak} pins, pool bound {bound}')
    if any(r['sequestered'] for r in retained.values()):
        _require(leak > 0, 'sequestered frames were unpinned early')
    return leak


def _ce_module(con, name, retained):
    c = CAMPAIGNS[name]
    config = con.one('CE_CONFIG', phase='campaign')
    _require(config.get('fail_mode') == c['fail_mode'] and _int(config, 'delay_us') == c['delay_us'],
             'CE stand-in configuration differs from the expectation')
    if c['after']:
        _require(con.one('CE_CONFIG', phase='after').get('fail_mode') == 'none',
                 'AFTER run with a CE failure still injected')
    else:
        _require(not [m for m in con.markers('CE_CONFIG') if m.get('phase') == 'after'],
                 'AFTER CE configuration in a campaign without AFTER')
    refs = con.one('CE_REFS')
    unload = con.one('CE_UNLOAD')
    stats = con.one('CE_SIM_STATS')
    _require(con.index('CE_SIM_STATS') < con.index('CE_UNLOAD'), 'CE stand-in counters read after unload')
    _require(_int(stats, 'completed') <= _int(stats, 'accepted'),
             'CE stand-in completed more copies than it accepted')
    _require(_int(stats, 'accepted') == _int(stats, 'completed') and _int(stats, 'pending') == 0,
             'CE stand-in not drained')
    if any(r['uses_ce'] for r in retained.values()):
        _require(_int(refs, 'refcnt') >= 1 and refs.get('settled') == '0',
                 'parked CE session lost its module reference')
        _require(unload.get('result') == 'refused', 'CE module removable under quarantine')
    else:
        _require(_int(refs, 'refcnt') == 0 and refs.get('settled') == '1', 'CE module reference leaked')
        _require(unload.get('result') == 'unloaded', 'CE module not unloaded')


def _trace(con, name):
    mode = CAMPAIGNS[name]['trace']
    trace = con.one('TRACE')
    copy, zc = _int(trace, 'copy_calls'), _int(trace, 'zc_calls')
    if mode == 'zc':
        _require(copy == 0 and zc > 0, 'copy fallback in a zero-copy campaign')
    elif mode == 'nocopy':
        _require(copy == 0, 'copy fallback in a zero-copy campaign')
    elif mode == 'copy':
        _require(copy > 0, 'copy-mode campaign never traced the copy path')
    elif mode == 'mixed':
        _require(copy > 0 and zc > 0, 'mixed campaign must trace both paths')
    else:
        _require(copy == 0 and zc == 0, 'AF_XDP activity in a campaign without a network stage')


def _after(con, name, groups):
    if CAMPAIGNS[name]['after']:
        _success(con, 'AFTER', 'XDEV_EXT_MECH_CE_SIM', groups, kind='chain-a')
    else:
        _require('AFTER' not in con.sections, 'AFTER run in a campaign without AFTER')


def _stopped(con, role, err, *, rx, groups, depth, pool, exits, nvme_stages, ce_stages=()):
    """The fault stopped the session with @err; or it came after the last group."""
    sec = con.section(role)
    stats = sec.stats()
    _require(stats is not None, role + ' missing STATS')
    _require(_int(stats, 'inflight') == 0, role + ' still in flight')
    _stage_balance(stats, role, rx=rx, groups=groups, nvme_stages=nvme_stages, ce_stages=ce_stages)
    _bounded_quarantine(stats, role, pool)
    if (stats.get('state') == 'ACTIVE' and stats.get('last_err') == '0' and
            _int(stats, 'batches_done') == groups):
        con.miss(role + ': the fault arrived after every group ended')
        return stats
    _require(sec.exit in exits, f'{role} unexpected exit {sec.exit}')
    _require(stats.get('state') == 'STOPPED' and stats.get('last_err') == err,
             f'{role} expected STOPPED with {err}')
    _require(_int(stats, 'batches_done') < groups, role + ' stopped yet reports every group done')
    return stats


def _tx_outcome(con, g, *, cancel_allowed=False):
    """TX succeeded; a detach may also have stopped it with -ECANCELED."""
    sec = con.section('TX')
    stats = sec.stats()
    if cancel_allowed and stats is not None and stats.get('last_err') == '-ECANCELED':
        _require(sec.exit == CTL_FAIL and stats.get('state') == 'STOPPED' and
                 _int(stats, 'inflight') == 0 and _int(stats, 'sequestered') == 0,
                 'cancelled TX source not settled')
        _stage_balance(stats, 'TX', rx=False, groups=g, nvme_stages=(0,))
        return 'cancelled'
    _success(con, 'TX', 'XDEV_EXT_MECH_NVME_NIC_E2E', g, kind='nvme-nic')
    return 'success'


# --- per-campaign checks -------------------------------------------------

def check_ring_exit_rx(con, g, d):
    sec = con.section('RX')
    _require(sec.exit == 0, 'RX ring-exit verdict failed')
    close = [_pairs(line) for line in sec.starting('XDEV_EXT_MECH_RING_EXIT_CLOSE ')]
    _require(len(close) == 1, 'missing ring close record')
    verdict = sec.marker('XDEV_EXT_MECH_RING_EXIT')
    _require(verdict and verdict[0] == 'PASS' and verdict[1].get('inflight') == '0' and
             verdict[1].get('state') in ('STOPPED', 'FREED', 'ZOMBIE'), 'ring exit not drained')
    _tx_outcome(con, g)
    if not (_int(close[0], 'inflight') > 0 or _int(close[0], 'held') > _int(close[0], 'recycled')):
        con.miss('ring closed while the session held nothing')
    return {}


def check_exit(con, g, d, role):
    _inflight_seen(con, role)
    con.one('KILL', role=role, signal='9')
    sec = con.section(role)
    if role == 'RX':
        _tx_outcome(con, g)
    if sec.exit == 0:
        con.miss(role + ' finished before the signal was delivered')
        return {}
    _require(sec.exit == KILLED_EXIT, role + ' did not exit on SIGKILL')
    _require(not [line for line in sec.verdicts() if '=PASS' in line.split(' ', 1)[0]],
             role + ' exited run claims a verdict')
    return {}


def check_detach(con, g, d, pin):
    sec = con.section('RX')
    _require(sec.exit == 0, 'RX detach verdict failed')
    verdict = sec.marker('XDEV_EXT_MECH_PROG_DETACH')
    _require(verdict and verdict[0] == 'PASS' and verdict[1].get('last_err') == '-ECANCELED' and
             verdict[1].get('state') == 'STOPPED', 'detach did not stop the session with -ECANCELED')
    stats = sec.stats()
    _require(stats is not None and _int(stats, 'inflight') == 0 and _int(stats, 'sequestered') == 0,
             'detached session not settled')
    _require(_int(stats, 'batches_done') >= (g + 1) // 2, 'detach before half the groups')
    _stage_balance(stats, 'RX', rx=True, groups=g, nvme_stages=(1, 2, 3))
    con.one('PIN_GONE', pin=pin, gone='1')
    _tx_outcome(con, g, cancel_allowed=True)
    if _int(stats, 'batches_done') >= g:
        con.miss('detach after every group ended; nothing was cut')
    return dict(rx=_int(stats, 'batches_done'))


def check_netdev_remove_tx(con, g, d):
    _inflight_seen(con, 'SRC')
    con.one('NETDEV_REMOVED', ifname='eth0', present='0')
    stats = _stopped(con, 'SRC', '-ENXIO', rx=False, groups=g, depth=d,
                     pool=AFXDP_POOL_PAGES, exits=(CTL_FAIL,), nvme_stages=(0,), ce_stages=(1, 2))
    verdict = con.section('SRC').marker('XDEV_EXT_MECH_CE_SIM')
    _require(verdict and verdict[1].get('chain') == 'b', 'chain b verdict missing')
    if stats.get('state') == 'STOPPED':
        _require(verdict[0] == 'FAIL', 'chain b falsely succeeded after its NIC went away')
    return {}


def check_netdev_remove_rx(con, g, d):
    _inflight_seen(con, 'RX')
    con.one('NETDEV_REMOVED', ifname='eth1', present='0')
    stats = _stopped(con, 'RX', '-ENXIO', rx=True, groups=g, depth=d,
                     pool=AFXDP_POOL_PAGES, exits=(CTL_FAIL,), nvme_stages=(3,), ce_stages=(1, 2))
    verdict = con.section('RX').marker('XDEV_EXT_MECH_NIC_CE_NVME_E2E')
    if stats.get('state') == 'STOPPED':
        _require(verdict is None or verdict[0] == 'FAIL',
                 'receiver falsely succeeded after its NIC went away')
    _tx_outcome(con, g)
    return dict(rx=_int(stats, 'batches_done'))


def check_window_reject(con, g, d):
    sec = con.section('SRC')
    _require(sec.exit == CTL_FAIL, 'out-of-window chain must fail the run')
    verdict = sec.marker('XDEV_EXT_MECH_CE_SIM')
    _require(verdict and verdict[0] == 'FAIL' and verdict[1].get('chain') == 'a',
             'out-of-window chain falsely succeeded')
    stats = sec.stats()
    _require(stats is not None, 'SRC missing STATS')
    _require(_int(stats, 'inflight') == 0 and _int(stats, 'sequestered') == 0,
             'refused groups left something in flight or sequestered')
    _require(_int(stats, 'batches_done') == 0, 'an out-of-window group completed')
    _require(_vector(stats, 'submitted') == [0, 0, 0, 0] and
             _vector(stats, 'completed') == [0, 0, 0, 0],
             'out-of-window plan reached NVMe or CE')
    _require(_int(stats, 'batches_abort') <= g, 'more refusals than groups')
    if _int(stats, 'batches_abort') == 0:
        con.miss('no group was offered for admission')
    return {}


def check_fq_dup(con, g, d):
    sec = con.section('RX')
    verdict = sec.marker('XDEV_EXT_MECH_FQ_DUP_REJECT')
    _require(verdict is not None, 'missing fill-ring duplicate verdict')
    _tx_outcome(con, g)
    if verdict[1].get('pushed') == '0':
        _require(_int(verdict[1], 'batches_done') == g and _int(verdict[1], 'errors') == 0,
                 'run not exact without the duplicate')
        con.miss('the fill ring had no room for the duplicate entry')
        return {}
    _require(sec.exit == 0 and verdict[0] == 'PASS' and verdict[1].get('pushed') == '1' and
             _int(verdict[1], 'batches_done') == g and _int(verdict[1], 'errors') == 0,
             'duplicate fill entry changed the run')
    return {}


def check_afxdp_copy(con, g, d):
    for role in ('RX', 'TX'):
        ready = con.section(role).ready()
        _require(ready is not None and ready.get('xsk') == 'copy', role + ' did not bind XDP_COPY')
    _success(con, 'RX', 'XDEV_EXT_MECH_NIC_NVME_E2E', g, kind='nic-nvme')
    _tx_outcome(con, g)
    return {}


def check_afxdp_drv_copy(con, g, d):
    sec = con.section('RX')
    _require(sec.exit == 0, 'native copy verdict failed')
    ready = sec.ready()
    _require(ready is not None and ready.get('xsk') == 'copy', 'RX did not bind XDP_COPY')
    verdict = sec.marker('XDEV_EXT_MECH_NATIVE_COPY')
    _require(verdict and verdict[0] == 'PASS' and _int(verdict[1], 'held') == 0 and
             _int(verdict[1], 'native_publish') > 0, 'native copy frames were held')
    stats = sec.stats()
    _require(stats is not None and _vector(stats, 'submitted')[1] == 0,
             'native copy frames reached NVMe')
    _tx_outcome(con, g)
    return {}


def check_ce_presubmit(con, g, d):
    sec = con.section('SRC')
    _require(sec.exit == CTL_FAIL, 'pre-submit failures must fail the run')
    verdict = sec.marker('XDEV_EXT_MECH_CE_SIM')
    _require(verdict and verdict[0] == 'FAIL' and verdict[1].get('chain') == 'b',
             'pre-submit failure falsely succeeded')
    stats = sec.stats()
    _require(stats is not None, 'SRC missing STATS')
    for key in ('batches_done', 'sequestered', 'inflight'):
        _require(_int(stats, key) == 0, 'pre-submit ' + key)
    _require(1 <= _int(stats, 'batches_abort') <= g, 'pre-submit abort count')
    submitted, completed = _stage_balance(stats, 'SRC', rx=False, groups=g,
                                          nvme_stages=(0,), ce_bound=False)
    _require(submitted[1] >= 1 and submitted[2] == submitted[3] == 0,
             'a stage after the refused copy ran')
    return {}


def check_ce_ambiguous(con, g, d):
    sec = con.section('SRC')
    _require(sec.exit == CTL_FAIL, 'ambiguous copies must fail the run')
    verdict = sec.marker('XDEV_EXT_MECH_CE_SIM')
    _require(verdict and verdict[0] == 'FAIL' and verdict[1].get('chain') == 'd',
             'ambiguous copy falsely succeeded')
    stats = sec.stats()
    _require(stats is not None and _int(stats, 'batches_done') == 0 and
             _int(stats, 'inflight') == 0, 'ambiguous run not settled')
    submitted, _ = _stage_balance(stats, 'SRC', rx=False, groups=g, ce_stages=(0, 1))
    _require(submitted[1] == 0, 'a group passed its ambiguous H2D copy')
    pool = min(g, d) * IOU_FRAMES_PER_GROUP
    sequestered = _bounded_quarantine(stats, 'SRC', pool)
    _require(sequestered > 0, 'ambiguous copies left no quarantine (frames released early)')
    # Every accepted copy whose outcome was lost keeps its group's frames.
    _require(sequestered == submitted[0] * IOU_FRAMES_PER_GROUP,
             'not every ambiguous group was sequestered')
    fate = con.one('SESSION', role='SRC')
    _require(fate.get('state') == 'ZOMBIE', 'ambiguous quarantine not parked as ZOMBIE')
    _require(fate.get('sequestered') == str(sequestered),
             'parked quarantine differs from the final snapshot')
    if submitted[0] < 2:
        con.miss('only one group was in flight; multi-group quarantine not exercised')
    return {}


def check_nvme_readonly(con, g, d):
    sec = con.section('SRC')
    _require(sec.exit in (CTL_FAIL, CTL_SETUP), 'write into a read-only namespace did not fail')
    verdict = sec.marker('XDEV_EXT_MECH_CE_SIM')
    _require(verdict is None or verdict[0] == 'FAIL', 'read-only destination falsely succeeded')
    if sec.ready() is None:
        _require(sec.exit == CTL_SETUP, 'refusal without CREATE must be a setup error')
        return dict(outcome='refused-at-create')
    stats = sec.stats()
    _require(stats is not None and stats.get('last_err') not in ('0', None), 'native error not latched')
    _require(_int(stats, 'batches_done') == 0 and _int(stats, 'inflight') == 0,
             'read-only run reported progress or kept commands in flight')
    _stage_balance(stats, 'SRC', rx=False, groups=g, nvme_stages=(0, 3), ce_stages=(1, 2))
    _require(_vector(stats, 'submitted')[3] >= 1, 'no write reached the read-only namespace')
    _bounded_quarantine(stats, 'SRC', min(g, d) * IOU_FRAMES_PER_GROUP)
    return dict(outcome='native-error')


def check_nvme_reset(con, g, d):
    _inflight_seen(con, 'SRC')
    reset = con.one('RESET')
    _require(reset.get('state') == 'live', 'controller did not return to live after reset')
    sec = con.section('SRC')
    stats = sec.stats()
    _require(stats is not None and _int(stats, 'inflight') == 0, 'reset left commands in flight')
    verdict = sec.marker('XDEV_EXT_MECH_CE_SIM')
    if sec.exit == 0:
        _success(con, 'SRC', 'XDEV_EXT_MECH_CE_SIM', g, kind='chain-a')
        return dict(outcome='success', exact=True)
    _require(sec.exit == CTL_FAIL and verdict and verdict[0] == 'FAIL', 'reset failure not reported')
    _require(stats.get('last_err') != '0', 'failure without a latched error')
    _stage_balance(stats, 'SRC', rx=False, groups=g, nvme_stages=(0, 3), ce_stages=(1, 2))
    _bounded_quarantine(stats, 'SRC', min(g, d) * IOU_FRAMES_PER_GROUP)
    return dict(outcome='native-failure', ce=_int(stats, 'batches_done'))


def check_concurrent(con, g, d):
    sessions = set()
    for role in ('A', 'B'):
        stats = _success(con, role, 'XDEV_EXT_MECH_CE_SIM', g, kind='chain-a')
        sessions.add(stats.get('session'))
    _require(len(sessions) == 2, 'concurrent runs shared one session')
    if con.one('CONCURRENT').get('both_ready') != '1':
        con.miss('the second session was created after the first ended')
    return {}


def check_cross_session(con, g, d):
    victim = _success(con, 'VICTIM', 'XDEV_EXT_MECH_CE_SIM', LONG_GROUPS, kind='chain-a')
    _require(_int(victim, 'rejects') == 0, 'victim saw rejections')
    for role in ('AGG_CEVA', 'AGG_LBA'):
        sec = con.section(role)
        _require(sec.exit == CTL_SETUP and sec.ready() is None, role + ' attempt was admitted')
    stats_probe = con.section('AGG_STATS')
    _require(stats_probe.exit == CTL_SETUP and not stats_probe.starting('XDEV_EXT_MECH_STATS ') and
             any('No such file or directory' in line for line in stats_probe.lines),
             'another uid could read the victim session')
    for role, marker in (('AGG_VERIFIER_NEG', 'XDEV_EXT_MECH_VERIFIER_NEGATIVES=PASS'),
                         ('AGG_VERIFIER_STATE', 'XDEV_EXT_MECH_VERIFIER_STATES=PASS'),
                         ('AGG_VERIFIER_ABI', 'XDEV_EXT_MECH_CE_ABI=PASS')):
        sec = con.section(role)
        _require(sec.exit == 0 and any(line.startswith(marker) for line in sec.lines) and
                 not [line for line in sec.verdicts() if '=FAIL' in line.split(' ', 1)[0]],
                 role + ' malformed plan not refused')
    sec = con.section('AGG_FQDUP_RX')
    verdict = sec.marker('XDEV_EXT_MECH_FQ_DUP_REJECT')
    _require(sec.exit == 0 and verdict and verdict[0] == 'PASS', 'duplicate fill changed its run')
    _success(con, 'AGG_FQDUP_TX', 'XDEV_EXT_MECH_NVME_NIC_E2E', g, kind='nvme-nic')
    if con.one('VICTIM_ALIVE').get('alive') != '1':
        con.miss('victim finished before every attempt ran')
    return {}


CHECKS = {
    'ring-exit-rx': check_ring_exit_rx,
    'exit-rx': lambda con, g, d: check_exit(con, g, d, 'RX'),
    'exit-source': lambda con, g, d: check_exit(con, g, d, 'SRC'),
    'detach-afxdp-mid-run': lambda con, g, d: check_detach(con, g, d, 'zc-afxdp'),
    'detach-nvme-under-load': lambda con, g, d: check_detach(con, g, d, 'zc-nvme'),
    'netdev-remove-tx': check_netdev_remove_tx,
    'netdev-remove-rx': check_netdev_remove_rx,
    'window-reject': check_window_reject,
    'fq-dup': check_fq_dup,
    'afxdp-copy': check_afxdp_copy,
    'afxdp-drv-copy': check_afxdp_drv_copy,
    'ce-presubmit': check_ce_presubmit,
    'ce-ambiguous-multi': check_ce_ambiguous,
    'nvme-readonly-dest': check_nvme_readonly,
    'nvme-reset-mid-run': check_nvme_reset,
    'concurrent-ce-disjoint': check_concurrent,
    'concurrent-ce-overlap': check_concurrent,
    'cross-session-isolation': check_cross_session,
}
assert set(CHECKS) == set(CAMPAIGNS)


def check_other_qemu(text):
    """Port of snapshot_other_qemu: 'pid start exe_sha256 cmd_sha256' lines."""
    for line in text.splitlines():
        _require(re.fullmatch(r'[0-9]+ [0-9]+ [0-9a-f]{64} [0-9a-f]{64}', line) is not None,
                 'malformed foreign QEMU snapshot line')


def validate_campaign(name, text, images, *, groups, depth, qemu_exit=0):
    """Raise FaultCheckError or Inconclusive; return a JSON-ready result."""
    _require(name in CAMPAIGNS, 'unknown campaign ' + name)
    _require(1 <= depth <= 8 and depth <= groups, 'bad depth')
    layout = fault_layout(groups)
    _require(qemu_exit == 0, 'QEMU did not exit cleanly')
    try:
        counts = check_console(text)
    except ValueError as exc:
        raise FaultCheckError(str(exc)) from exc
    con = Console(text)
    _require(con.lines.count('XDEV_EXT_ZC_FAULT_GUEST_EXIT=0') == 1 and
             not [line for line in con.lines if line.startswith('XDEV_EXT_ZC_FAULT_GUEST_EXIT=')
                  and line != 'XDEV_EXT_ZC_FAULT_GUEST_EXIT=0'], 'guest did not exit cleanly')
    fault_lines = [i for i, line in enumerate(con.lines) if line.startswith('XDEV_EXT_ZC_FAULT_')]
    expect = [i for i in fault_lines if con.lines[i].startswith('XDEV_EXT_ZC_FAULT_EXPECT ')]
    _require(len(expect) == 1 and con.lines[expect[0]] == expectation_line(name),
             'guest expectation differs from the campaign table')
    _require(expect[0] == fault_lines[0], 'expectation stated after the campaign started')
    con.one('CAMPAIGN_DONE', campaign=name)
    env = con.one('ENV', campaign=name)
    _require(_int(env, 'groups') == groups and _int(env, 'depth') == depth, 'guest geometry differs')
    detail = CHECKS[name](con, groups, depth)
    retained = _session_fates(con, name, groups, depth)
    leak = _pins(con, retained)
    _ce_module(con, name, retained)
    _trace(con, name)
    _after(con, name, groups)
    minimum = {window: value for window, value in detail.items()
               if window in ('rx', 'ce') and type(value) is int}
    windows = check_images(name, layout, *images, prefix_minimum=minimum)
    if detail.get('exact'):
        _require(windows['ce']['source'] == groups, 'successful reset run not exact')
    if con.missed:
        raise Inconclusive('; '.join(con.missed))
    return dict(campaign=name, findings=list(CAMPAIGNS[name]['findings']),
                outcome=CAMPAIGNS[name]['outcome'], observed=detail.get('outcome', 'as-expected'),
                retained=sorted(retained), pin_delta=leak, windows=windows,
                console_reports=counts, scope='KVM software devices; correctness only')


# --- command line --------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('list')
    expect = sub.add_parser('expect')
    expect.add_argument('campaign', choices=list(CAMPAIGNS))
    host = sub.add_parser('host')
    host.add_argument('campaign', choices=list(CAMPAIGNS))
    layout = sub.add_parser('layout')
    layout.add_argument('--groups', type=int, required=True)
    images = sub.add_parser('images')
    images.add_argument('--groups', type=int, required=True)
    images.add_argument('--dir', required=True)
    check = sub.add_parser('check')
    check.add_argument('--campaign', required=True, choices=list(CAMPAIGNS))
    check.add_argument('--dir', required=True)
    check.add_argument('--groups', type=int, required=True)
    check.add_argument('--depth', type=int, required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_PASS if exc.code == 0 else EXIT_USAGE
    try:
        if args.action == 'list':
            for name, c in CAMPAIGNS.items():
                print(expectation_line(name) + ' detail="' + c['detail'] + '"')
        elif args.action == 'expect':
            print(expectation_line(args.campaign))
        elif args.action == 'host':
            for key, value in host_settings(args.campaign).items():
                print(f'{key}={value}')
        elif args.action == 'layout':
            for key, value in fault_layout(args.groups).items():
                print(f'{key}={value}')
        elif args.action == 'images':
            make_images(args.dir, args.groups)
        else:
            directory = Path(args.dir)
            check_other_qemu((directory / 'other-qemu-before.txt').read_text())
            check_other_qemu((directory / 'other-qemu-after.txt').read_text())
            result = validate_campaign(
                args.campaign, (directory / 'guest.log').read_text(),
                tuple((directory / n).read_bytes() for n in
                      ('source-before.raw', 'source.raw', 'destination-before.raw', 'destination.raw')),
                groups=args.groups, depth=args.depth,
                qemu_exit=int((directory / 'qemu.exit').read_text()))
            (directory / 'validation.json').write_text(json.dumps(result, sort_keys=True) + '\n')
            print(f'XDEV_EXT_ZC_FAULT=PASS campaign={args.campaign} outcome={result["outcome"]} '
                  f'observed={result["observed"]} retained={",".join(result["retained"]) or "none"}')
    except Inconclusive as exc:
        print(f'XDEV_EXT_ZC_FAULT=INCONCLUSIVE campaign={getattr(args, "campaign", "")} reason={exc}')
        return EXIT_INCONCLUSIVE
    except (FaultCheckError, ValueError, KeyError, OSError) as exc:
        print(f'XDEV_EXT_ZC_FAULT=FAIL campaign={getattr(args, "campaign", "")} reason={exc}')
        return EXIT_FAIL
    return EXIT_PASS


if __name__ == '__main__':
    sys.exit(main())
