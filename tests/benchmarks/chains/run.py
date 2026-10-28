#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Multi-stage pipeline campaigns (reviewer E1), ablations (E7), sweeps (E10).

  run.py --rig RIG.json --chain nvme-gpu-nic --sizes 4096..4194304 \\
         --arms staged,userspace-shared,session --pairs 5

Every named chain runs as one kernel session (arm "session"), as the best
per-pair Linux composition with registered/pinned buffers ("staged",
chain_bench), and as one user process over one shared region
("userspace-shared", ../userspace_orchestrator/uo_bench).  A chain that
leaves the host over the NIC is paired with its complement on the receiving
NIC, and the receiver's destination window is compared byte for byte with
the expected bytes after the campaign; a chain that ends in GPU memory is
checked by reading the GPU window back.

--load picks how records are offered: "sustained" admits the whole campaign
at once and keeps up to --depth batches in flight in every arm (throughput is
the campaign's bytes over its wall time, latency the gaps between record
completions); "closed" offers one record at a time and times each one.
Timed runs default to sustained, correctness runs exercise both.

--correctness-only is the mode for the KVM guest with the CE simulator and
deflate-generic: no timing is produced at all.  Without it every case first
passes hardware_gate.admit() (physical devices observed in sysfs) or the run
exits 4.  Exit: 0 every case passed, 1 a case failed, 2 invalid arguments,
4 nothing was admitted.
"""
import argparse
import itertools
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
M64 = (1 << 64) - 1
CHAINS = ('nvme-gpu-nic', 'nic-gpu-nvme', 'nvme-iaa-gpu', 'nic-iaa-gpu', 'nvme-crc-nic',
          'nvme-nic', 'nic-nvme')
ARMS = ('staged', 'userspace-shared', 'session')
# Stage lists: (class, direction, role); role names the rig entry it uses.
STAGES = {
    'nvme-nic': [('nvme', 'from', 'src'), ('afxdp', 'to', 'tx')],
    'nic-nvme': [('afxdp', 'from', 'rx'), ('nvme', 'to', 'dst')],
    'nvme-gpu-nic': [('nvme', 'from', 'src'), ('ce', 'to', 'tx'), ('ce', 'from', 'tx'),
                     ('afxdp', 'to', 'tx')],
    'nic-gpu-nvme': [('afxdp', 'from', 'rx'), ('ce', 'to', 'rx'), ('ce', 'from', 'rx'),
                     ('nvme', 'to', 'dst')],
    'nvme-iaa-gpu': [('nvme', 'from', 'src'), ('iaa', 'from', 'src'), ('ce', 'to', 'src')],
}
COMPLEMENT = {'nvme-nic': 'nic-nvme', 'nic-nvme': 'nvme-nic',
              'nvme-gpu-nic': 'nic-gpu-nvme', 'nic-gpu-nvme': 'nvme-gpu-nic'}
REFUSED = {
    'nvme-crc-nic': 'unsupported: in-frame transform not implemented (no mechanism class '
                    'claims a frame, rewrites it in place and republishes it; the BPF frame '
                    'view is read-only)',
    'nic-iaa-gpu': 'unsupported: one session cannot hold AF_XDP RX and an IAA transform: '
                   'AF_XDP stages need the socket UMEM pool and IAA destination leases need '
                   'the io_uring UMEM pool',
}
MAX_DEPTH = 64          # XDEV_EXT_MECH_MAX_DEPTH
MAX_FRAMES = 32         # XDEV_EXT_MECH_MAX_FRAMES
IAA_MAX = 131072        # CRYPTO_ACOMP_DST_MAX: deflate source and destination per batch
XSK_FRAME = 4096
XSK_POOL = 4096 * XSK_FRAME
NXP_HDR_ROOM = 256 + 22 + 82
NXP_FIXED = 20 + 8 + 40
EXIT_PASS, EXIT_FAIL, EXIT_USAGE, EXIT_NOT_RUN = 0, 1, 2, 4


class Usage(Exception):
    pass


# --- expected bytes: an independent transcription of chain_oracle.h -------------

def mix(x):
    x ^= x >> 33
    x = (x * 0xff51afd7ed558ccd) & M64
    x ^= x >> 33
    x = (x * 0xc4ceb9fe1a85ec53) & M64
    x ^= x >> 33
    return x


def group_bytes(seed, g, length, text=False):
    """Bytes [0, length) of group g, as chain_fill() writes them."""
    out = bytearray()
    if text:
        for block in range((length + 63) // 64):
            letter = 0x61 + (mix(seed ^ ((g * 0x9e3779b97f4a7c15) & M64) ^ block) & 15)
            out += bytes([letter]) * 64
    else:
        for word in range((length + 7) // 8):
            x = mix(seed ^ ((g * 0x9e3779b97f4a7c15) & M64) ^
                    ((word * 0xc2b2ae3d27d4eb4f) & M64))
            out += x.to_bytes(8, 'little')
    out[0:8] = (g & M64).to_bytes(8, 'little')
    return bytes(out[:length])


def compressed_record(seed, g, payload, slot):
    """Raw DEFLATE of group g's text bytes with a 2 KiB window (the kernel's
    deflate-generic inflates with -DEFLATE_DEF_WINBITS = -11), zero-padded to
    the slot; inflate stops at the end of the stream."""
    c = zlib.compressobj(9, zlib.DEFLATED, -11)
    data = c.compress(group_bytes(seed, g, payload, text=True)) + c.flush()
    if len(data) > slot:
        raise Usage('group %d compresses to %d bytes, above its %d-byte slot' % (g, len(data), slot))
    return data + bytes(slot - len(data))


# --- argument parsing ----------------------------------------------------------

UNITS = {'': 1, 'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30}


def size(text):
    m = re.fullmatch(r'([0-9]+)([KMG]?)', text)
    if not m:
        raise Usage('bad size %r' % text)
    return int(m.group(1)) * UNITS[m.group(2)]


def powers(text):
    """'4096', '4K,64K' or a power-of-two range '4K..2M'."""
    values = []
    for part in text.split(','):
        if '..' in part:
            lo, hi = (size(x) for x in part.split('..', 1))
            if lo <= 0 or lo & (lo - 1) or hi < lo:
                raise Usage('range %r needs a power-of-two start below its end' % part)
            while lo <= hi:
                values.append(lo)
                lo *= 2
        else:
            values.append(size(part))
    if not values or len(set(values)) != len(values):
        raise Usage('empty or duplicate list %r' % text)
    return values


def sweep(text):
    axes = {}
    for item in re.split(r',(?=[a-z]+=)', text):
        key, sep, value = item.partition('=')
        if not sep or key not in ('frame', 'pool', 'qd', 'sessions') or key in axes:
            raise Usage('sweep axis %r: use frame=, pool=, qd=, sessions= once each' % key)
        axes[key] = powers(value)
    return axes


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0], allow_abbrev=False)
    p.add_argument('--rig', required=True, help='host devices (see README.md)')
    p.add_argument('--chain', required=True)
    p.add_argument('--sizes', default='4096')
    p.add_argument('--arms', default='session')
    p.add_argument('--pairs', type=int, default=1)
    p.add_argument('--records', type=int, default=32)
    p.add_argument('--warmup-records', type=int, default=4)
    p.add_argument('--depth', type=int, default=8)
    p.add_argument('--correctness-only', action='store_true')
    p.add_argument('--afxdp-mode', choices=('zc', 'copy'), default='zc')
    p.add_argument('--start-per', choices=('batch', 'run'), default='batch')
    p.add_argument('--plan', choices=('bpf', 'default'), default='bpf')
    p.add_argument('--ablate', default='')
    p.add_argument('--sweep', default='')
    p.add_argument('--wait', default='eventfd')
    p.add_argument('--load', help='closed, sustained or both (default: sustained for timed '
                                  'runs, both for --correctness-only)')
    p.add_argument('--seed', type=int)
    p.add_argument('--prepare-source', action='store_true',
                   help='write the expected bytes into the source NVMe window first')
    p.add_argument('--out-dir', default=str(HERE / '.results'))
    p.add_argument('--chain-bench', default=str(HERE / '.build/chain_bench'))
    p.add_argument('--uo-bench', default=str(ROOT / 'tests/eval/userspace_orchestrator/.build/uo_bench'))
    p.add_argument('--role', choices=('both', 'sender', 'receiver'), default='both',
                   help='paired chains: run both ends here, or one end (the other host '
                        'runs the other role with the same --seed)')
    p.add_argument('--dry-run', action='store_true', help='write the specs, run nothing')
    a = p.parse_args(argv)
    a.chains = a.chain.split(',')
    a.size_list = powers(a.sizes)
    a.arm_list = a.arms.split(',')
    a.waits = a.wait.split(',')
    a.loads = (a.load.split(',') if a.load else
               ['closed', 'sustained'] if a.correctness_only else ['sustained'])
    a.ablations = [x for x in a.ablate.split(',') if x]
    a.axes = sweep(a.sweep) if a.sweep else {}
    if set(a.chains) - set(CHAINS) or len(set(a.chains)) != len(a.chains):
        raise Usage('chains: %s' % ', '.join(CHAINS))
    if set(a.arm_list) - set(ARMS) or len(set(a.arm_list)) != len(a.arm_list):
        raise Usage('arms: %s' % ', '.join(ARMS))
    if set(a.waits) - {'poll', 'eventfd'}:
        raise Usage('wait: poll, eventfd')
    if set(a.loads) - {'closed', 'sustained'} or len(set(a.loads)) != len(a.loads):
        raise Usage('load: closed, sustained')
    if set(a.ablations) - {'afxdp-mode', 'start-per', 'plan'}:
        raise Usage('ablate: afxdp-mode, start-per, plan')
    if not (1 <= a.pairs <= 100 and 1 <= a.records <= 1 << 16 and
            0 <= a.warmup_records <= 1 << 12 and 1 <= a.depth):
        raise Usage('pairs, records, warmup-records or depth out of range')
    if any(s < 4096 or s & (s - 1) for s in a.size_list):
        raise Usage('sizes are powers of two from 4096')
    if a.correctness_only and a.pairs != 1:
        raise Usage('--pairs repeats timed runs; correctness-only runs once')
    if a.role != 'both' and a.seed is None:
        raise Usage('--role sender/receiver needs the --seed both hosts share')
    return a


# --- planning --------------------------------------------------------------------

def seg_len(mtu):
    """xdev_ext_mp_seg_limit() for 4 KiB AF_XDP chunks with the NXP header room."""
    return min(mtu - NXP_FIXED, XSK_FRAME - NXP_HDR_ROOM) & ~7


def record_shape(chain, size_bytes, rig):
    """(group_bytes, batches per record, frame_size) of one record."""
    if chain == 'nvme-iaa-gpu':
        # deflate takes at most CRYPTO_ACOMP_DST_MAX bytes per batch; a larger
        # record is a burst of such groups.  One frame per group keeps the
        # source one contiguous span (deflate-iaa needs a single-entry list).
        group = min(size_bytes, IAA_MAX)
        return group, size_bytes // group, group
    mtus = [rig[side]['mtu'] for side in ('tx', 'rx') if side in rig]
    limit = MAX_FRAMES * seg_len(min(mtus) if mtus else 1500)
    group = 1 << (min(size_bytes, limit).bit_length() - 1)
    return group, size_bytes // group, XSK_FRAME


def variants(a):
    """The base configuration, then one change per ablation and sweep value."""
    base = dict(afxdp_mode=a.afxdp_mode, start_per=a.start_per, plan=a.plan,
                depth=a.depth, frame=None, pool=None, sessions=1, label='base')
    out = [base]
    flips = {'afxdp-mode': ('afxdp_mode', {'zc': 'copy', 'copy': 'zc'}),
             'start-per': ('start_per', {'batch': 'run', 'run': 'batch'}),
             'plan': ('plan', {'bpf': 'default', 'default': 'bpf'})}
    for name in a.ablations:
        key, other = flips[name]
        out.append(dict(base, **{key: other[base[key]]}, label='ablate-%s=%s' % (name, other[base[key]])))
    keys = {'frame': 'frame', 'pool': 'pool', 'qd': 'depth', 'sessions': 'sessions'}
    for axis, values in a.axes.items():
        for v in values:
            if v != base.get(keys[axis]):
                out.append(dict(base, **{keys[axis]: v}, label='sweep-%s=%d' % (axis, v)))
    return out


def refusal(chain, arm, var, rig, corr, size_bytes=4096, load='closed', role='both'):
    """A reason this case cannot run, or None.  Mirrors chain_validate()."""
    if chain in REFUSED:
        return REFUSED[chain]
    xsk = 'afxdp' in [c for c, _, _ in STAGES[chain]]
    if load == 'sustained' and var['start_per'] == 'run':
        return ('invalid: start_per run is a closed-load option; the sustained load already '
                'issues one START for the campaign (compare --load closed with sustained)')
    if arm == 'session' and var['plan'] == 'default':
        return ('unsupported: no mechanism class registers default_build, so a build '
                'returning XDEV_EXT_MECH_BUILD_DEFAULT aborts with -EOPNOTSUPP')
    if arm != 'session' and (var['plan'] != 'bpf' or var['start_per'] != 'batch'):
        return 'unsupported: plan and START-granularity ablations exist only for the session arm'
    if arm == 'userspace-shared' and chain == 'nvme-iaa-gpu':
        return 'unsupported: the user-space orchestrator has no IAA stage'
    if arm == 'staged' and chain == 'nvme-iaa-gpu' and not corr:
        return ('unsupported: staged nvme-iaa-gpu has no device decompressor (user-space IAA '
                'via QPL/accel-config is not implemented)')
    if chain.startswith('nic-') and var['start_per'] == 'run':
        return 'invalid: a chain fed by AF_XDP RX has no START; measure the sender with start-per run'
    if var['depth'] > MAX_DEPTH:
        return 'invalid: depth %d above XDEV_EXT_MECH_MAX_DEPTH=%d' % (var['depth'], MAX_DEPTH)
    if xsk and var['frame'] not in (None, XSK_FRAME):
        return 'unsupported: AF_XDP UMEM chunks are fixed at 4 KiB in this harness'
    if xsk and var['pool'] not in (None, XSK_POOL):
        return 'unsupported: the AF_XDP pool is fixed at 4096 x 4 KiB chunks in this harness'
    if var['sessions'] > 1 and xsk:
        return ('unsupported: one XDP redirect program per interface; concurrent '
                'NIC sessions need a shared multi-queue redirect')
    if var['sessions'] > 1 and arm != 'session':
        return 'unsupported: concurrent sessions are a session-arm sweep'
    ce = rig.get('ce', {})
    # Both ends on this host share one CE device; the staged CUDA leg and the
    # user-space arm allocate their own GPU memory instead.
    windows = arm == 'session' or (arm == 'staged' and 'xdev_ext_ce_sim' in ce.get('dev', ''))
    if chain in COMPLEMENT and role == 'both' and windows and \
            'ce' in [c for c, _, _ in STAGES[chain]]:
        tx, rx, length = ce.get('tx_va', 0), ce.get('rx_va', 0), ce.get('len', 0)
        if tx < rx + length and rx < tx + length:
            return ('invalid: the two ends\' GPU windows overlap: [tx_va, tx_va + len) = '
                    '[%d, %d) and [rx_va, rx_va + len) = [%d, %d)' % (tx, tx + length,
                                                                     rx, rx + length))
    group = record_shape(chain, size_bytes, rig)[0]
    if 'ce' in [c for c, _, _ in STAGES[chain]] and arm != 'userspace-shared' and \
            var['depth'] * group > rig.get('ce', {}).get('len', 0) // var['sessions']:
        return ('invalid: the GPU window (rig ce.len %d per end, over %d sessions) is below '
                'depth x group_bytes = %d' % (rig.get('ce', {}).get('len', 0), var['sessions'],
                                             var['depth'] * group))
    if arm == 'session':
        missing = [m for m, _, _ in needed_plans(chain, rig, var)
                   if m not in rig.get('attached', [])]
        if chain in COMPLEMENT and missing:
            return ('invalid: paired chains share one struct_ops plan per class; attach %s '
                    'once (rig "attached") before the campaign' % ', '.join(missing))
        if var['sessions'] > 1 and missing:
            return ('invalid: %d concurrent sessions share one struct_ops plan per class; '
                    'attach %s once (rig "attached") before the campaign'
                    % (var['sessions'], ', '.join(missing)))
        unknown = [key for m, key, _ in needed_plans(chain, rig, var)
                   if m in missing and key not in rig.get('plans', {})]
        if unknown:
            return 'invalid: rig "plans" lacks the %s object' % ', '.join(sorted(set(unknown)))
    return None


def cases(a, rig):
    out = []
    reps = range(1 if a.correctness_only else a.pairs)
    for chain, size_bytes, load, var in itertools.product(a.chains, a.size_list, a.loads,
                                                          variants(a)):
        for rep in reps:
            arms = a.arm_list if rep % 2 == 0 else list(reversed(a.arm_list))
            for arm in arms:
                for wait in (a.waits if arm == 'userspace-shared' else [None]):
                    out.append(dict(chain=chain, size=size_bytes, arm=arm, rep=rep, wait=wait,
                                    load=load, var=var,
                                    refused=refusal(chain, arm, var, rig, a.correctness_only,
                                                    size_bytes, load, a.role)))
    return out


# --- specs -------------------------------------------------------------------------

def peer(rig, role):
    me, other = (rig['tx'], rig['rx']) if role == 'tx' else (rig['rx'], rig['tx'])
    return dict(local_mac=me['mac'], peer_mac=other['mac'], local_ip=me['ip'],
                peer_ip=other['ip'], local_port=me['port'], peer_port=other['port'],
                session=rig.get('nxp_session', 270019))


def needed_plans(chain, rig, var):
    """(struct_ops map, rig "plans" object key, globals) of every stage class."""
    classes = {c for c, _, _ in STAGES.get(chain, [])}
    out = []
    if 'nvme' in classes:
        out.append(('nxp_nvme_ops', 'nxp', dict(nvme_mode=0, key_base=1)))
    if 'afxdp' in classes:
        out.append(('nxp_afxdp_ops', 'nxp', dict(nxp_session=rig.get('nxp_session', 270019))))
    if 'ce' in classes:
        out.append(('ce_plan_ops', 'ce', {}))
    if 'iaa' in classes:
        out.append(('chain_iaa_ops', 'iaa', dict(expect_out=var.get('group', 0))))
    return out


def plans(rig, chain, var):
    """The plans chain_bench loads itself: those not attached system-wide.
    One struct_ops per class is live at a time, so an attached class is reused."""
    attached = rig.get('attached', [])
    return [dict(obj=rig['plans'][key], map=name, **(dict(set=sets) if sets else {}))
            for name, key, sets in needed_plans(chain, rig, var) if name not in attached]


def chain_spec(case, chain, rig, a, shape, seed, out_dir, index=0):
    """The chain_bench spec of @chain (the measured one or its complement)."""
    var = case['var']
    group, burst, frame = shape
    arm = case['arm']
    corr = a.correctness_only
    stages, role_tx = [], None
    nvme_role = None
    for cls, direction, role in STAGES[chain]:
        st = dict(**{'class': cls, 'dir': direction})
        if cls == 'nvme':
            side = rig['nvme_src' if role == 'src' else 'nvme_dst']
            share = side['nlb'] // var['sessions']
            st.update(dev=side['ng'], block=side['block'],
                      slba=side['slba'] + index * share, nlb=share)
            nvme_role = role
        elif cls == 'afxdp':
            side = rig['tx' if role == 'tx' else 'rx']
            st.update(ifname=side['ifname'], queue=side.get('queue', 0))
            role_tx = role
        elif cls == 'iaa':
            st.update(software=rig.get('iaa_software', True), capacity=group, expect=group)
        stages.append(st)
    records = a.records
    spec = dict(schema='xdev-chain-spec-v1', chain=chain, arm=arm,
                mode='correctness' if corr else 'timing', group_bytes=group,
                batches=records * burst, warmup=a.warmup_records * burst,
                burst=burst, depth=var['depth'],
                start_per='batch' if chain.startswith('nic-') else var['start_per'],
                plan=var['plan'],
                afxdp_mode=var['afxdp_mode'], timeout_ms=rig.get('timeout_ms', 60000),
                seed=seed, load=case.get('load', 'closed'), stages=stages)
    if role_tx:
        spec['peer'] = peer(rig, role_tx)
    ce = rig.get('ce')
    if ce and any(c == 'ce' for c, _, _ in STAGES[chain]):
        va = ce.get('rx_va' if role_tx == 'rx' else 'tx_va', 0)
        share = ce['len'] // var['sessions']
        spec['ce'] = dict(dev=ce['dev'], va=va + index * share, len=share,
                          alloc=ce.get('alloc', 'given'))
        if ce.get('bdf'):
            spec['ce']['bdf'] = ce['bdf']
        if arm == 'staged':
            spec['staged_gpu'] = 'ce-sim' if 'xdev_ext_ce_sim' in ce['dev'] else 'cuda'
    if chain == 'nvme-iaa-gpu':
        spec['pool'] = dict(frame_size=var['frame'] or frame)
        if var['pool']:
            spec['pool']['frames'] = var['pool'] // spec['pool']['frame_size']
        spec['oracle'] = dict(kind='ce-window', reference=str(out_dir / ('reference-%d.bin' % index)),
                              every_window=corr and burst == 1 and spec['load'] == 'closed')
        if 'chain_iaa_ops' in rig.get('attached', []) and rig.get('iaa_counts_pin'):
            spec['iaa_counts_pin'] = rig['iaa_counts_pin']
    elif nvme_role == 'dst':
        side = rig['nvme_dst']
        spec['oracle'] = dict(kind='file', path=side['block'],
                              offset=(side['slba'] + index * (side['nlb'] // var['sessions'])) *
                              side['lba_bytes'],
                              reference=str(out_dir / ('reference-%d.bin' % index)))
    spec['plans'] = plans(rig, chain, dict(var, group=group))
    if not spec['plans']:
        del spec['plans']
    return spec


def uo_spec(case, chain, rig, a, shape, seed, out_dir):
    group, burst, _ = shape
    rx = chain.startswith('nic-')
    side = rig['nvme_dst' if rx else 'nvme_src']
    nic = rig['rx' if rx else 'tx']
    spec = dict(schema='xdev-uo-spec-v1', chain=chain,
                mode='correctness' if a.correctness_only else 'timing',
                wait=case['wait'] or 'eventfd', afxdp_mode=case['var']['afxdp_mode'],
                load=case.get('load', 'closed'), seed=seed,
                group_bytes=group, batches=a.records * burst, warmup=a.warmup_records * burst,
                burst=burst, depth=case['var']['depth'], timeout_ms=rig.get('timeout_ms', 60000),
                hugepage=rig.get('hugepage', True),
                nvme=dict(ng=side['ng'], block=side['block'], slba=side['slba'], nlb=side['nlb'],
                          lba_bytes=side['lba_bytes']),
                nic=dict(ifname=nic['ifname'], queue=nic.get('queue', 0)),
                peer=peer(rig, 'rx' if rx else 'tx'))
    if '-gpu-' in chain:
        spec['gpu'] = dict(bdf=rig.get('ce', {}).get('bdf', ''))
    if rx:
        spec['oracle'] = dict(kind='file', path=side['block'], offset=side['slba'] * side['lba_bytes'],
                              reference=str(out_dir / 'reference-0.bin'))
    return spec


# --- execution ---------------------------------------------------------------------

def write_source(rig, chain, shape, seed, total, sessions):
    """Expected bytes into the source NVMe window, before any timing."""
    group, _, _ = shape
    side = rig['nvme_src']
    share = side['nlb'] // sessions
    fd = os.open(side['block'], os.O_WRONLY)
    try:
        for index in range(sessions):
            base = (side['slba'] + index * share) * side['lba_bytes']
            for g in range(total):
                data = (compressed_record(seed + index, g, group, group) if chain == 'nvme-iaa-gpu'
                        else group_bytes(seed + index, g, group))
                os.pwrite(fd, data, base + g * group)
        os.fsync(fd)
    finally:
        os.close(fd)


def write_reference(path, chain, shape, seed, total):
    group, _, _ = shape
    with open(path, 'xb') as f:
        for g in range(total):
            f.write(group_bytes(seed, g, group, text=chain == 'nvme-iaa-gpu'))


def start(argv, spec_path, netns=None):
    prefix = ['ip', 'netns', 'exec', netns] if netns else []
    return subprocess.Popen([*prefix, *argv, '--spec', str(spec_path)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


def wait_ready(proc, timeout):
    """Read the receiver's stderr until CHAIN_READY; the rest is kept."""
    deadline = time.monotonic() + timeout
    lines = []
    while time.monotonic() < deadline:
        line = proc.stderr.readline()
        if not line:
            break
        lines.append(line)
        if line.startswith('CHAIN_READY'):
            return True, lines
    return False, lines


def finish(proc, timeout):
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return dict(status='fail', failure='timed out'), err
    try:
        result = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except ValueError:
        result = {}
    if not result:
        result = dict(status='fail', failure='no result line, exit %d' % proc.returncode)
    result['exit'] = proc.returncode
    return result, err


def binary(case, a):
    return [a.uo_bench] if case['arm'] == 'userspace-shared' else [a.chain_bench]


def run_case(case, rig, a, out_dir, seed):
    chain, var = case['chain'], case['var']
    shape = record_shape(chain, case['size'], rig)
    total = (a.records + a.warmup_records) * shape[1]
    out_dir.mkdir(parents=True, exist_ok=True)
    measured, peer_chain = chain, COMPLEMENT.get(chain)
    sender = chain if chain.startswith('nvme-') else peer_chain
    receiver = peer_chain if chain.startswith('nvme-') else chain
    make = uo_spec if case['arm'] == 'userspace-shared' else chain_spec
    specs = {}
    if peer_chain:
        for name in (sender, receiver):
            specs[name] = make(case, name, rig, a, shape, seed, out_dir)
    else:
        for index in range(var['sessions']):
            specs['%s#%d' % (chain, index)] = chain_spec(case, chain, rig, a, shape, seed + index,
                                                         out_dir, index)
    for name, spec in specs.items():
        (out_dir / (name.replace('#', '-') + '.spec.json')).write_text(json.dumps(spec, indent=1))
    if a.dry_run:
        return dict(status='planned', specs=sorted(specs))
    if a.prepare_source:
        write_source(rig, chain, shape, seed, total, var['sessions'])
    for index in range(var['sessions'] if not peer_chain else 1):
        write_reference(out_dir / ('reference-%d.bin' % index), chain, shape, seed + index, total)
    timeout = rig.get('timeout_ms', 60000) / 1000 * (total + 4) + 30
    if peer_chain and a.role != 'both':
        name = sender if a.role == 'sender' else receiver
        proc = start(binary(case, a), out_dir / (name + '.spec.json'),
                     rig.get('rx_netns') if a.role == 'receiver' else None)
        result, err = finish(proc, timeout)
        ok = result.get('status') == 'pass' and (a.role == 'sender' or
                                                  result.get('oracle', {}).get('verdict') == 'pass')
        return dict(measured=measured, status='pass' if ok else 'fail', role=a.role,
                    **{a.role: result}, stderr=err[-2000:])
    if peer_chain:
        rx = start(binary(case, a), out_dir / (receiver + '.spec.json'), rig.get('rx_netns'))
        ready, early = wait_ready(rx, 60)
        if not ready:
            rx.kill()
            result, err = finish(rx, 10)
            return dict(status='fail', failure='receiver not ready: ' + ''.join(early) + err)
        tx = start(binary(case, a), out_dir / (sender + '.spec.json'))
        tx_result, tx_err = finish(tx, timeout)
        rx_result, rx_err = finish(rx, timeout)
        result = dict(measured=measured, sender=tx_result, receiver=rx_result,
                      stderr=dict(sender=tx_err[-2000:], receiver=(''.join(early) + rx_err)[-2000:]))
        ok = tx_result.get('status') == 'pass' and rx_result.get('status') == 'pass' and \
            rx_result.get('oracle', {}).get('verdict') == 'pass'
        result['status'] = 'pass' if ok else 'fail'
        return result
    procs = [start(binary(case, a), out_dir / (name.replace('#', '-') + '.spec.json'))
             for name in specs]
    results = [finish(p, timeout) for p in procs]
    ok = all(r.get('status') == 'pass' and r.get('oracle', {}).get('verdict') == 'pass'
             for r, _ in results)
    return dict(measured=measured, status='pass' if ok else 'fail',
                sessions=[r for r, _ in results], stderr=[e[-2000:] for _, e in results])


# --- summary -------------------------------------------------------------------------

def quantile(values, q):
    values = sorted(values)
    if not values:
        return None
    return values[min(len(values) - 1, int(q * len(values)))]


def gaps(completions):
    """Inter-completion intervals of one sustained run (the first from t0)."""
    out, prev = [], 0
    for c in completions:
        out.append(c - prev)
        prev = c
    return out


def sustained_rate(timings):
    """GB/s (bytes per ns) of concurrent sustained runs on the one system clock:
    every run's measured bytes over the span from the earliest t0 to the last
    completion of any run."""
    timings = [t for t in timings if t.get('completions')]
    if not timings:
        return None
    total = sum(t['record_bytes'] * len(t['completions']) for t in timings)
    begin = min(t['t0_ns'] for t in timings)
    end = max(t['t0_ns'] + t['completions'][-1] for t in timings)
    return total / (end - begin) if end > begin else None


def summarize(rows):
    groups = {}
    for row in rows:
        result = row.get('result', {})
        side = result.get('receiver') if row['chain'].startswith('nic-') else result.get('sender')
        records = [side] if side else result.get('sessions', [])
        timings = [rec['timing'] for rec in records if rec and rec.get('timing')]
        if not timings:
            continue
        load = row.get('load', 'closed')
        key = (row['chain'], row['size'], row['arm'], row['wait'] or '', row['var']['label'], load)
        g = groups.setdefault(key, dict(samples=[], rates=[], bytes=None, costs=[]))
        g['costs'] += [rec.get('cost', {}) for rec in records if rec]
        if load == 'sustained':
            for t in timings:
                g['samples'] += gaps(t['completions'])
            g['rates'].append(sustained_rate(timings))
        else:
            for t in timings:
                g['samples'] += t['samples']
                g['bytes'] = t['window_bytes']
    out = []
    for (chain, size_bytes, arm, wait, label, load), g in sorted(groups.items()):
        p50 = quantile(g['samples'], 0.5)
        entry = dict(chain=chain, record_bytes=size_bytes, arm=arm, wait=wait or None,
                     variant=label, load=load, records=len(g['samples']), p50_ns=p50,
                     p99_ns=quantile(g['samples'], 0.99), p999_ns=quantile(g['samples'], 0.999),
                     mean_ns=statistics.fmean(g['samples']) if g['samples'] else None,
                     syscalls=sum(c.get('syscalls', 0) for c in g['costs']),
                     observer_syscalls=sum(c.get('observer_syscalls', 0) for c in g['costs']),
                     voluntary_ctxsw=sum(c.get('voluntary_ctxsw', 0) for c in g['costs']))
        if load == 'sustained':
            rates = [r for r in g['rates'] if r]
            entry.update(latency='gap between record completions, depth in flight',
                         gbytes_per_s=statistics.median(rates) if rates else None,
                         gbytes_per_s_runs=rates)
        else:
            entry.update(latency='one record at a time, start to completion',
                         gbytes_per_s_closed_loop_at_p50=g['bytes'] / p50 if p50 else None)
        out.append(entry)
    return out


def gate_stages(chain, a):
    """The stages this host runs for @chain: itself and, paired, its complement."""
    names = [chain] + ([COMPLEMENT[chain]] if chain in COMPLEMENT else [])
    if a.role != 'both':
        names = [n for n in names if n.startswith('nvme-') == (a.role == 'sender')]
    return [s for name in names for s in STAGES[name]]


def main(argv):
    try:
        a = parse(argv)
        rig = json.loads(Path(a.rig).read_text())
    except (Usage, OSError, ValueError) as error:
        print('run.py: %s' % error, file=sys.stderr)
        return EXIT_USAGE
    plan = cases(a, rig)
    runnable = [c for c in plan if not c['refused']]
    if not a.correctness_only and not a.dry_run and runnable:
        import hardware_gate
        try:
            evidence = {chain: hardware_gate.admit(rig, gate_stages(chain, a), a.arm_list)
                        for chain in sorted({c['chain'] for c in runnable})}
        except (hardware_gate.Refusal, KeyError, OSError) as error:
            print(json.dumps(dict(status='not_run_hardware', failure=str(error))))
            return EXIT_NOT_RUN
    else:
        evidence = {}
    stamp = time.strftime('%Y%m%dT%H%M%S')
    root = Path(a.out_dir) / ('%s-%s' % ('correctness' if a.correctness_only else 'timing', stamp))
    rows = []
    for i, case in enumerate(plan):
        row = dict(case, index=i)
        if case['refused']:
            row['result'] = dict(status='not_run', failure=case['refused'])
        else:
            seed = a.seed if a.seed is not None else int.from_bytes(os.urandom(6), 'little')
            out_dir = root / ('%03d-%s-%d-%s-%s-%s%s' % (i, case['chain'], case['size'], case['arm'],
                                                       case['load'], case['var']['label'],
                                                       '-' + case['wait'] if case['wait'] else ''))
            try:
                row['result'] = run_case(case, rig, a, out_dir, seed)
            except (Usage, OSError, KeyError) as error:
                row['result'] = dict(status='fail', failure=str(error))
            row['seed'] = seed
        rows.append(row)
        print(json.dumps(dict(index=i, chain=case['chain'], size=case['size'], arm=case['arm'],
                              load=case['load'], variant=case['var']['label'], wait=case['wait'],
                              status=row['result']['status'],
                              failure=row['result'].get('failure', ''))), flush=True)
    summary = dict(schema='xdev-chain-campaign-v1', correctness_only=a.correctness_only,
                   evidence=evidence, rows=rows,
                   summary=[] if a.correctness_only else summarize(rows))
    if not a.dry_run:
        root.mkdir(parents=True, exist_ok=True)
        (root / 'campaign.json').write_text(json.dumps(summary, indent=1))
    statuses = {r['result']['status'] for r in rows}
    if 'fail' in statuses:
        return EXIT_FAIL
    if not runnable:
        return EXIT_NOT_RUN
    return EXIT_PASS


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
