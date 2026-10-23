#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise strict ordinary-fork evidence parsing; fixtures are not guest runs."""
import unittest
import xdev_ext_preload_mech_validate as validator


def fixture(alias=False):
    maps = 4 if alias else 6
    text = (f'XDEV_EXT_ORDINARY_FORK_LIVE workers=2 rings=2 maps={maps} baseline_fds=3 allowed=baseline+2-rings\n'
        'XDEV_EXT_ORDINARY_FORK_ALLOWED fd=0 dev=1 ino=10 flags=0 target=/dev/null\n'
        'XDEV_EXT_ORDINARY_FORK_ALLOWED fd=1 dev=1 ino=11 flags=0 target=pipe:[11]\n'
        'XDEV_EXT_ORDINARY_FORK_ALLOWED fd=2 dev=1 ino=12 flags=0 target=pipe:[12]\n'
        'XDEV_EXT_ORDINARY_FORK_RING fd=3 ino=77 target=anon_inode:[io_uring] fdinfo=SqMask:0x1,CqMask\n'
        'XDEV_EXT_ORDINARY_FORK_RING fd=4 ino=77 target=anon_inode:[io_uring] fdinfo=SqMask:0x1,CqMask\n')
    offsets = [0, 0x10000000] if alias else [0, 0x8000000, 0x10000000]
    for index, offset in enumerate(offsets * 2):
        address = 0x10000 + index * 0x2000
        text += f'XDEV_EXT_ORDINARY_FORK_MAP range={address:x}-{address+0x1000:x} ino=77 offset={offset:x}\n'
    for round in range(3):
        text += (f'XDEV_EXT_ORDINARY_FORK_CHILD round={round} before_rings=0 after_rings=1 '
                 f'inherited_maps_removed={maps} allowed=exact-baseline\n')
    for pid, tid, reads, writes in [(100, 101, 8, 4), (100, 102, 8, 4),
                                   (201, 201, 2, 1), (202, 202, 2, 1), (203, 203, 2, 1)]:
        text += (f'XDEV_EXT_PRELOAD_REPORT pid={pid} tid={tid} read_count={reads} read_bytes={reads*4096} '
                 f'read_errors=0 write_count={writes} write_bytes={writes*4096} write_errors=0 '
                 'custom_send_count=0 custom_send_bytes=0 custom_send_errors=0\n')
    return text + ('XDEV_EXT_ORDINARY_FORK=PASS workers=2 forks=3 main_eligible=0 parent_reads=16 '
        'parent_writes=8 child_reads=6 child_writes=3 bytes=49152 source=unchanged '
        'received=complete guards=complete first_child_call=observed-real-proc exit=normal\n')


class OrdinaryForkEvidence(unittest.TestCase):
    def validate(self, text):
        validator.validate_ordinary_fork(text)

    def test_real_proc_layout_shapes_and_shared_inode_accepted(self):
        self.validate(fixture())
        self.validate(fixture(alias=True))

    def test_each_record_required_and_duplicates_rejected(self):
        text = fixture()
        for line in text.splitlines():
            with self.subTest(missing=line), self.assertRaises((AssertionError, ValueError, KeyError)):
                self.validate(text.replace(line+'\n', '', 1))
            with self.subTest(duplicate=line), self.assertRaises((AssertionError, ValueError, KeyError)):
                self.validate(text+line+'\n')

    def test_failures_fallback_and_resource_or_byte_lies_rejected(self):
        text = fixture()
        mutations = [('', 'XDEV_EXT_ORDINARY_FORK=FAIL stage=child\n'),
            ('', 'XDEV_EXT_ORDINARY_FORK_CHILD_ERROR round=0 error=1\n'),
            ('read_count=8', 'read_count=0'), ('read_bytes=32768', 'read_bytes=0'),
            ('write_count=4', 'write_count=0'), ('read_errors=0', 'read_errors=1'),
            ('write_errors=0', 'write_errors=1'), ('custom_send_count=0', 'custom_send_count=1'),
            ('pid=202 tid=202', 'pid=201 tid=201'), ('pid=100 tid=102', 'pid=100 tid=101'),
            ('pid=100 tid=102', 'pid=101 tid=102'), ('before_rings=0', 'before_rings=2'),
            ('after_rings=1', 'after_rings=0'), ('inherited_maps_removed=6', 'inherited_maps_removed=0'),
            ('source=unchanged', 'source=changed'), ('received=complete', 'received=wrong'),
            ('guards=complete', 'guards=wrong'), ('main_eligible=0', 'main_eligible=1'),
            ('exit=normal', 'exit=aborted'), ('target=anon_inode:[io_uring]', 'target=anon_inode:[eventfd]'),
            ('fd=3 ino=77', 'fd=0 ino=77'), ('range=10000-11000', 'range=10000-10000'),
            ('range=12000-13000', 'range=10000-11000'), ('offset=10000000', 'offset=20000000')]
        for old, new in mutations:
            bad = text.replace(old, new, 1) if old else text+new
            with self.subTest(mutation=(old, new)), self.assertRaises((AssertionError, ValueError, KeyError)):
                self.validate(bad)
        for bad in ('', 'XDEV_EXT_ORDINARY_FORK_SELFTEST=PASS guest_coverage=none\n'):
            with self.subTest(text=bad), self.assertRaises((AssertionError, ValueError, KeyError)):
                self.validate(bad)


class OrdinaryForkGuestOutput(unittest.TestCase):
    def test_each_fork_follows_a_stdio_flush(self):
        """A child's exit() flushes inherited stdio; unflushed CHILD lines would repeat."""
        from pathlib import Path
        import re
        source = (Path(__file__).resolve().parent / 'xdev_ext_preload_ordinary_fork_guest.c').read_text()
        loop = source[source.index('for (round = 0; round < FORKS; round++) {'):]
        before_fork = loop[:loop.index('fork()')]
        self.assertRegex(before_fork, r'fflush\(NULL\);',
                         'stdout must be flushed inside the loop before every fork')
        self.assertEqual(len(re.findall(r'\bfork\(\)', source)), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
