#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the real demo reader with host OS shims under AddressSanitizer.

No demo files, network or custom kernel calls are made.  read() returning its
entire requested length must remain safe, including zero/error handling.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

KERNEL = Path(__file__).resolve().parents[4]
SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
static unsigned requested, closes, unlinks;
static int mode;
static int shim_open(const char *path, int flags, ...)
{
 (void)path; (void)flags; return 42;
}
static ssize_t shim_write(int fd, const void *data, size_t size)
{
 (void)data; assert(fd == 42); return size;
}
static off_t shim_lseek(int fd, off_t offset, int whence)
{
 assert(fd == 42 && offset == 0 && whence == SEEK_SET); return 0;
}
static ssize_t shim_read(int fd, void *data, size_t size)
{
 assert(fd == 42 && size > 0 && size <= 1024);
 requested = size;
 if (mode == 2) { errno = EIO; return -1; }
 if (mode == 1) return 0;
 memset(data, 'R', size); return size;
}
static int shim_close(int fd) { assert(fd == 42); ++closes; return 0; }
static int shim_unlink(const char *path) { (void)path; ++unlinks; return 0; }
#define open shim_open
#define write shim_write
#define lseek shim_lseek
#define read shim_read
#define close shim_close
#define unlink shim_unlink
'''
MAIN = r'''
int main(int argc, char **argv)
{
 assert(argc == 2);
 mode = atoi(argv[1]);
 process_a_read();
 assert(closes == 1 && unlinks == 1);
 printf("SHIM_REQUESTED=%u\n", requested);
 return 0;
}
'''


class UnifiedDemoRead(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = (KERNEL / 'tools/test_unified_ops.c').read_text()
        start = text.index('void process_a_read(void)')
        end = text.index('/* Process B:', start)
        cls.tmp = tempfile.TemporaryDirectory(prefix='unified-demo-read-')
        source = Path(cls.tmp.name) / 'reader.c'
        cls.exe = Path(cls.tmp.name) / 'reader'
        source.write_text(SHIM + text[start:end] + MAIN)
        build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11',
                                '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                                '-fsanitize=address', '-fno-omit-frame-pointer',
                                str(source), '-o', str(cls.exe)],
                               capture_output=True, text=True)
        if build.returncode:
            raise AssertionError(build.stdout + build.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_case(self, mode):
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1')
        run = subprocess.run([str(self.exe), str(mode)], capture_output=True,
                             text=True, env=env, timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertNotIn('AddressSanitizer', run.stderr)
        return run

    def test_read_fills_entire_requested_buffer(self):
        run = self.run_case(0)
        requested = int(re.search(r'SHIM_REQUESTED=(\d+)', run.stdout)[1])
        self.assertGreater(requested, 0)
        self.assertIn("Read %d bytes: '%s'" % (requested, 'R' * requested), run.stdout)

    def test_zero_length_result(self):
        run = self.run_case(1)
        self.assertIn("Read 0 bytes: ''", run.stdout)

    def test_read_error(self):
        run = self.run_case(2)
        self.assertIn('read:', run.stderr)
        self.assertNotIn('Read ', run.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
