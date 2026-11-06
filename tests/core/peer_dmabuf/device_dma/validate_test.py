#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Mutation checks for the host oracle of the dma-buf device-DMA guest test.

Each case builds the console text and disk images a correct guest run would
produce, written here independently of validate.py, then changes one thing
and requires the oracle to reject it. Nothing boots or touches a device.
"""
import hashlib
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
LBA = 512
IMAGE = 32 << 20
GUARD = 0x6b
EXPORT = 65536
PAGE = 4096
NVME = ('0000:00:04.0', '0000:00:05.0')


def load():
    spec = importlib.util.spec_from_file_location('dmabuf_dma_validate', HERE / 'validate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_image():
    out = bytearray()
    for sector in range(IMAGE // LBA):
        out += hashlib.sha256(b'xdev-dmabuf-dma' + sector.to_bytes(8, 'little')).digest() * 16
    return bytes(out)


def fnv64(data):
    value = 0xcbf29ce484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    return value


PLANS = [
    'PLAN case=batch-read src_slba=2048 pages=16 order=reverse',
    'PLAN case=batch-write dst_slba=2048 pages=16 pattern=xor5a',
    'PLAN case=chain frame=4096 seg=4096 group=8192 depth=4 groups=96 src_slba=4096 dst_slba=4096 copies=ALL',
    'PLAN case=exporter-close frame=4096 seg=4096 group=8192 depth=4 groups=1024 src_slba=8192 dst_slba=8192 copies=ALL',
    'PLAN case=kill frame=4096 seg=4096 group=8192 depth=4 groups=512 src_slba=32768 dst_slba=32768 copies=PART',
    'PLAN case=victim frame=4096 seg=4096 group=8192 depth=4 groups=1536 src_slba=40960 dst_slba=40960 copies=ALL',
]


# Stage caps a correct run prints, per exporter (written independently of the
# oracle): STORAGE, HOST_DMA_MAPPED or UNKNOWN, ESTABLISHED, backing, refused.
CAPS = {'system-heap': 'family=2 reachability=7 requester_mapping=1 backing=0x22 refused=0x0',
        'udmabuf': 'family=2 reachability=0 requester_mapping=1 backing=0x40 refused=0x0'}


def good_run(source, copied_kill=(0, 1, 5, 300), viommu=False, exporter='system-heap'):
    dest = bytearray([GUARD]) * IMAGE
    pattern = bytes((((o * 131) + 7) & 0xff) ^ 0x5a for o in range(EXPORT))
    dest[2048 * LBA:2048 * LBA + EXPORT] = pattern
    for slba, groups in ((4096, 96), (8192, 1024), (40960, 1536)):
        dest[slba * LBA:slba * LBA + groups * 8192] = source[slba * LBA:slba * LBA + groups * 8192]
    for g in copied_kill:
        off = 32768 * LBA + g * 8192
        dest[off:off + 8192] = source[off:off + 8192]
    read_view = b''.join(source[(2048 + (15 - i) * 8) * LBA:(2048 + (15 - i) * 8) * LBA + PAGE]
                         for i in range(16))
    lines = ['[    0.000000] Linux version 6.16.0-rc7-xdev_ext-mech-zc',
             '[    3.021560] pci %s: [1b36:0010] type 00 class 0x010802 PCIe Root Complex Integrated Endpoint' % NVME[0],
             '[    3.045528] pci %s: [1b36:0010] type 00 class 0x010802 PCIe Root Complex Integrated Endpoint' % NVME[1],
             '[    5.635887] nvme nvme0: pci function %s' % NVME[0],
             '[    5.635888] nvme nvme1: pci function %s' % NVME[1]]
    if viommu:
        lines[1:1] = ['[    0.010000] DMAR: IOMMU enabled',
                      '[    3.354681] iommu: Default domain type: Translated',
                      '[    3.354687] iommu: DMA domain TLB invalidation policy: strict mode',
                      '[    3.400000] DMAR: Intel(R) Virtualization Technology for Directed I/O',
                      '[    3.400300] pci %s: Adding to iommu group 3' % NVME[0],
                      '[    3.400400] pci %s: Adding to iommu group 4' % NVME[1]]
    lines += ['XDEV_EXT_DMABUF_GUEST_BEGIN', 'TAP version 13', '# dma-buf device DMA guest test']
    lines += PLANS
    checks = 0

    def ok(text):
        nonlocal checks
        checks += 1
        lines.append('ok %d - %s' % (checks, text))

    for i in range(5):
        ok('setup %d' % i)
    lines.append('OBSERVE case=batch-read fnv64=%016x' % fnv64(read_view))
    if exporter == 'udmabuf':
        plans = PLANS[:3] + ['PLAN case=fenced-chain frame=4096 seg=4096 group=8192 depth=4 groups=64 '
                             'src_slba=24576 dst_slba=24576 copies=NONE'] + PLANS[3:]
        lines[lines.index(PLANS[0]):lines.index(PLANS[-1]) + 1] = plans
        lines.append('OBSERVE case=fenced-chain last_err=-16 batches_done=0 batches_abort=64 submitted=0,0')
    cases = ('batch', 'chain') + (('fenced-chain',) if exporter == 'udmabuf' else ()) + ('exporter-close', 'victim')
    for case in cases:
        ok(case + ' register')
        lines.append('OBSERVE case=%s vmpin_baseline=4096 vmpin_registered=%d vmpin_closed=4096' % (case, 4096 + EXPORT))
        lines.append('OBSERVE case=%s bufinfo attached=%s' % (case, ','.join(NVME)))
        lines.append('OBSERVE case=%s bufinfo_after_close=absent' % case)
    for stage in (0, 1):
        lines.append('OBSERVE case=chain stage=%d %s' % (stage, CAPS[exporter]))
    lines.append('OBSERVE case=exporter-close exporter_fd_closed_inflight=1 done_at_close=3 groups=1024')
    lines.append('OBSERVE case=kill quota_while_owner_alive=ENOMEM quota_after_owner_exit=ok copied_groups=%d'
                 % len(copied_kill))
    lines.append('OBSERVE case=kill bufinfo_after_owner_exit=absent')
    lines.append('OBSERVE case=victim running_at_kill=1 done_at_kill=40 groups=1536')
    ok('final')
    lines.append('1..%d' % checks)
    lines.append('XDEV_EXT_DMABUF_DMA=PASS cases=batch-read,batch-write,chain,%sexporter-close,kill,victim '
                 'exporter=%s requesters=2 timing=none' % ('fenced-chain,' if exporter == 'udmabuf' else '', exporter))
    lines.append('XDEV_EXT_DMABUF_GUEST_EXIT=0')
    return '\n'.join(lines) + '\n', bytes(dest)


class Oracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = load()
        cls.source = source_image()
        cls.log, cls.dest = good_run(cls.source)
        cls.vlog, _ = good_run(cls.source, viommu=True)
        cls.ulog, _ = good_run(cls.source, exporter='udmabuf')

    def check(self, log=None, dest=None, source=None, viommu=False, exporter='system-heap'):
        return self.v.validate(self.source if source is None else source,
                               self.dest if dest is None else dest,
                               self.log if log is None else log, viommu=viommu, exporter=exporter)

    def rejects(self, fragment, **kwargs):
        with self.assertRaises(ValueError) as caught:
            self.check(**kwargs)
        self.assertIn(fragment, str(caught.exception))

    def test_undescribed_exporter_run(self):
        result = self.check(log=self.ulog, exporter='udmabuf')
        self.assertEqual(result['exporter'], 'udmabuf')
        # An undescribed import must never be reported as host-mapped RAM.
        self.rejects('stage caps', log=self.ulog.replace('reachability=0', 'reachability=7'),
                     exporter='udmabuf')
        self.rejects('stage caps', log=self.ulog.replace('backing=0x40', 'backing=0x22'),
                     exporter='udmabuf')
        # Neither exporter's run certifies the other.
        self.rejects('final PASS line', log=self.log, exporter='udmabuf')
        self.rejects('final PASS line', log=self.ulog)
        with self.assertRaises(ValueError):
            self.check(exporter='dma-heap')

    def test_fenced_chain(self):
        fenced = 'OBSERVE case=fenced-chain last_err=-16 batches_done=0 batches_abort=64 submitted=0,0'
        self.assertIn(fenced, self.ulog)
        # A fenced batch that reached the device, completed, or failed otherwise.
        for bad in (fenced.replace('submitted=0,0', 'submitted=1,0'),
                    fenced.replace('batches_done=0 batches_abort=64', 'batches_done=64 batches_abort=0'),
                    fenced.replace('last_err=-16', 'last_err=-5'),
                    fenced.replace('batches_abort=64', 'batches_abort=63')):
            with self.subTest(bad=bad):
                self.rejects('fenced-chain', log=self.ulog.replace(fenced, bad), exporter='udmabuf')
        # Its accounting and release follow the same rules as the other cases.
        self.rejects('VmPin accounting for fenced-chain',
                     log=self.ulog.replace('case=fenced-chain vmpin_baseline=4096 vmpin_registered=69632 '
                                           'vmpin_closed=4096',
                                           'case=fenced-chain vmpin_baseline=4096 vmpin_registered=69632 '
                                           'vmpin_closed=69632'), exporter='udmabuf')
        self.rejects('fenced-chain', log=self.ulog.replace('case=fenced-chain bufinfo_after_close=absent',
                                                           'case=fenced-chain bufinfo_after_close=present'),
                     exporter='udmabuf')
        # The fenced plan line is required in udmabuf runs and refused otherwise.
        self.rejects('plan mismatch', log=self.ulog.replace('copies=NONE', 'copies=ALL'), exporter='udmabuf')
        self.rejects('final PASS line', log=self.log.replace('chain,exporter-close', 'chain,fenced-chain,exporter-close'))

    def test_source_generator_matches_independent_definition(self):
        self.assertEqual(self.v.make_source(), self.source)

    def test_good_run_passes(self):
        result = self.check()
        self.assertEqual(result['kill_copied_groups'], 4)
        self.assertEqual(result['requesters'], list(NVME))
        self.assertEqual(result['checks'], 10)

    def test_good_viommu_run_passes(self):
        result = self.check(log=self.vlog, viommu=True)
        self.assertEqual(result['viommu']['groups'], {NVME[0]: 3, NVME[1]: 4})

    def flip(self, image, offset):
        mutated = bytearray(image)
        mutated[offset] ^= 0x01
        return bytes(mutated)

    def test_chain_byte(self):
        self.rejects('destination', dest=self.flip(self.dest, 4096 * LBA + 8191))

    def test_exporter_close_last_byte(self):
        self.rejects('destination', dest=self.flip(self.dest, 8192 * LBA + 1024 * 8192 - 1))

    def test_batch_write_pattern_byte(self):
        self.rejects('destination', dest=self.flip(self.dest, 2048 * LBA + 12345))

    def test_guard_byte(self):
        self.rejects('destination', dest=self.flip(self.dest, IMAGE - 1))

    def test_kill_partial_group(self):
        mutated = bytearray(self.dest)
        off = 32768 * LBA + 7 * 8192
        mutated[off:off + 4096] = self.source[off:off + 4096]
        self.rejects('kill', dest=bytes(mutated))

    def test_victim_byte(self):
        self.rejects('destination', dest=self.flip(self.dest, 40960 * LBA + 1536 * 8192 - 1))

    def test_victim_finished_before_kill(self):
        self.rejects('victim', log=self.log.replace('running_at_kill=1 done_at_kill=40', 'running_at_kill=1 done_at_kill=1536'))

    def test_victim_not_running_at_kill(self):
        self.rejects('victim', log=self.log.replace('running_at_kill=1', 'running_at_kill=0'))

    def test_victim_vmpin(self):
        self.rejects('VmPin', log=self.log.replace('case=victim vmpin_baseline=4096 vmpin_registered=69632 vmpin_closed=4096',
                                                   'case=victim vmpin_baseline=4096 vmpin_registered=69632 vmpin_closed=69632'))

    def test_kill_copied_count(self):
        self.rejects('copied', log=self.log.replace('copied_groups=4', 'copied_groups=5'))

    def test_source_changed(self):
        self.rejects('source', source=self.flip(self.source, 100))

    def test_read_hash(self):
        line = [l for l in self.log.splitlines() if 'fnv64=' in l][0]
        bad = line[:-1] + ('0' if line[-1] != '0' else '1')
        self.rejects('batch-read', log=self.log.replace(line, bad))

    def test_not_ok(self):
        self.rejects('TAP', log=self.log.replace('ok 3 - setup 2', 'not ok 3 - setup 2'))

    def test_tap_count(self):
        plan = [line for line in self.log.splitlines() if line.startswith('1..')]
        self.assertEqual(len(plan), 1)
        self.rejects('TAP', log=self.log.replace(plan[0], '1..%d' % (int(plan[0][3:]) + 1)))

    def test_duplicated_check_line(self):
        # A check printed by both parent and child after fork.
        self.rejects('TAP', log=self.log.replace('ok 4 - setup 3\n', 'ok 4 - setup 3\nok 4 - setup 3\n'))

    def test_skip(self):
        self.rejects('TAP', log=self.log.replace('ok 2 - setup 1', 'ok 2 - setup 1 # SKIP'))

    def test_missing_pass(self):
        self.rejects('PASS', log=self.log.replace('XDEV_EXT_DMABUF_DMA=PASS', 'XDEV_EXT_DMABUF_DMA=FAIL'))

    def test_guest_exit(self):
        self.rejects('exit', log=self.log.replace('XDEV_EXT_DMABUF_GUEST_EXIT=0', 'XDEV_EXT_DMABUF_GUEST_EXIT=1'))

    def test_plan_changed(self):
        self.rejects('plan', log=self.log.replace('groups=96', 'groups=95'))

    def test_vmpin_not_returned(self):
        self.rejects('VmPin', log=self.log.replace('case=chain vmpin_baseline=4096 vmpin_registered=69632 vmpin_closed=4096',
                                                   'case=chain vmpin_baseline=4096 vmpin_registered=69632 vmpin_closed=69632'))

    def test_vmpin_not_charged(self):
        self.rejects('VmPin', log=self.log.replace('case=batch vmpin_baseline=4096 vmpin_registered=69632',
                                                   'case=batch vmpin_baseline=4096 vmpin_registered=4096'))

    def test_single_requester_attached(self):
        self.rejects('attached', log=self.log.replace('case=chain bufinfo attached=%s' % ','.join(NVME),
                                                      'case=chain bufinfo attached=%s' % NVME[0]))

    def test_buffer_not_freed(self):
        self.rejects('bufinfo', log=self.log.replace('case=exporter-close bufinfo_after_close=absent',
                                                     'case=exporter-close bufinfo_after_close=present'))

    def test_stage_caps(self):
        self.rejects('caps', log=self.log.replace('stage=1 family=2 reachability=7', 'stage=1 family=2 reachability=2'))

    def test_quota_not_enforced(self):
        self.rejects('quota', log=self.log.replace('quota_while_owner_alive=ENOMEM', 'quota_while_owner_alive=ok'))

    def test_exporter_close_not_inflight(self):
        self.rejects('exporter', log=self.log.replace('exporter_fd_closed_inflight=1', 'exporter_fd_closed_inflight=0'))

    def test_kernel_warning(self):
        self.rejects('diagnostic', log=self.log + '[   9.0] WARNING: CPU: 1 PID: 77 at mm/foo.c:1\n')

    def test_viommu_requested_but_absent(self):
        self.rejects('IOMMU enabled', viommu=True)

    def test_viommu_off_but_enabled(self):
        self.rejects('off', log=self.vlog, viommu=False)

    def test_viommu_fault(self):
        fault = '[   10.0] DMAR: [DMA Write NO_PASID] Request device [00:05.0] fault addr 0x1000 [fault reason 0x05]\n'
        self.rejects('fault', log=self.vlog + fault, viommu=True)

    def test_viommu_shared_group(self):
        self.rejects('group', log=self.vlog.replace('Adding to iommu group 4', 'Adding to iommu group 3'), viommu=True)


if __name__ == '__main__':
    unittest.main()
