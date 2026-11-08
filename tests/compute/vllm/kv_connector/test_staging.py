#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Importing the restore worker's CUDA VMM staging allocation into the vLLM process.

kv_restore --dst ce-vmm exports its VMM allocation as a POSIX file descriptor
(cuMemExportToShareableHandle) and reports the descriptor number and size in
KV_READY. The connector duplicates that descriptor out of the worker process
(pidfd_getfd), imports it with cuMemImportFromShareableHandle and maps it on
the same GPU, so the scatter kernel reads the bytes the copy engine wrote.
The descriptor transfer runs anywhere on Linux >= 5.6; the import needs CUDA.
"""
import ctypes
import os
import subprocess
import sys
import unittest

import _paths  # noqa: F401
from xdev_kv_vllm import staging as ks

try:
    import torch
except ImportError:
    torch = None
CUDA = torch is not None and torch.cuda.is_available()


@unittest.skipUnless(sys.platform == 'linux', 'needs Linux pidfd_getfd')
class DescriptorTransfer(unittest.TestCase):
    def test_duplicates_a_descriptor_of_another_process(self):
        child = subprocess.Popen([sys.executable, '-c',
                                  'import os,sys,time; r,w=os.pipe(); print(w, flush=True); '
                                  'os.write(w, b"from-child"); time.sleep(30)'],
                                 stdout=subprocess.PIPE, text=True)
        self.addCleanup(child.kill)
        number = int(child.stdout.readline())
        try:
            fd = ks.pidfd_getfd(child.pid, number)
        except PermissionError:
            self.skipTest('ptrace access to the child is not permitted here')
        try:
            self.assertNotEqual(os.fstat(fd).st_ino, 0)
            # Same open pipe: writing through the duplicate is visible to the child's pipe.
            os.write(fd, b'!')
            self.assertEqual(os.fstat(fd).st_ino, int(subprocess.check_output(
                ['stat', '-L', '-c', '%i', f'/proc/{child.pid}/fd/{number}'])))
        finally:
            os.close(fd)

    def test_missing_descriptor(self):
        with self.assertRaises(OSError):
            ks.pidfd_getfd(os.getpid(), 987654)


class ReadyChecks(unittest.TestCase):
    def test_refuses_a_worker_without_an_export(self):
        for ready in ({'vmm_export_fd': -1, 'vmm_bytes': 1 << 21}, {'vmm_bytes': 1 << 21},
                      {'vmm_export_fd': 5, 'vmm_bytes': 0}):
            with self.subTest(ready=ready), self.assertRaises(ks.StagingError):
                ks.import_from_worker(ready, os.getpid(), device_index=0)

    def test_bus_id_comparison(self):
        self.assertTrue(ks.same_bus_id('0000:01:00.0', '00000000:01:00.0'))
        self.assertTrue(ks.same_bus_id('0000:0A:00.0', '0000:0a:00.0'))
        self.assertFalse(ks.same_bus_id('0000:01:00.0', '0000:02:00.0'))


@unittest.skipUnless(CUDA, 'needs torch with a CUDA device')
class CudaImport(unittest.TestCase):
    def export_allocation(self, nbytes):
        """A VMM allocation of this process exported as a POSIX fd (what kv_restore does)."""
        drv = ks.CudaDriver()
        torch.cuda.init()
        dev = ctypes.c_int()
        drv.check('cuCtxGetDevice', ctypes.byref(dev))

        class Prop(ctypes.Structure):
            _fields_ = [('type', ctypes.c_int), ('requestedHandleTypes', ctypes.c_int),
                        ('location', ks.CUmemLocation), ('win32HandleMetaData', ctypes.c_void_p),
                        ('compressionType', ctypes.c_ubyte), ('gpuDirectRDMACapable', ctypes.c_ubyte),
                        ('usage', ctypes.c_ushort), ('reserved', ctypes.c_ubyte * 4)]
        prop = Prop(type=1, requestedHandleTypes=1, location=ks.CUmemLocation(1, dev.value))
        gran = ctypes.c_size_t()
        drv.check('cuMemGetAllocationGranularity', ctypes.byref(gran), ctypes.byref(prop), 0)
        size = -(-nbytes // gran.value) * gran.value
        handle = ctypes.c_ulonglong()
        drv.check('cuMemCreate', ctypes.byref(handle), ctypes.c_size_t(size), ctypes.byref(prop),
                  ctypes.c_ulonglong(0))
        fd = ctypes.c_int(-1)
        drv.check('cuMemExportToShareableHandle', ctypes.byref(fd), handle, 1, ctypes.c_ulonglong(0))
        self.addCleanup(drv.check, 'cuMemRelease', handle)
        return fd.value, size

    def test_two_mappings_share_the_bytes(self):
        torch.cuda.set_device(0)
        fd, size = self.export_allocation(4 << 20)
        a = ks.import_from_worker({'vmm_export_fd': fd, 'vmm_bytes': size}, os.getpid(), 0)
        b = ks.import_from_worker({'vmm_export_fd': fd, 'vmm_bytes': size}, os.getpid(), 0)
        try:
            self.assertEqual(a.tensor.numel(), size)
            self.assertNotEqual(a.tensor.data_ptr(), b.tensor.data_ptr())
            a.tensor[:4096] = torch.arange(4096, device='cuda').to(torch.uint8)
            torch.cuda.synchronize()
            self.assertTrue(torch.equal(b.tensor[:4096].cpu(),
                                        torch.arange(4096).to(torch.uint8)))
        finally:
            a.release()
            b.release()
            os.close(fd)

    def test_wrong_gpu_is_refused(self):
        torch.cuda.set_device(0)
        fd, size = self.export_allocation(2 << 20)
        try:
            with self.assertRaises(ks.StagingError):
                ks.import_from_worker({'vmm_export_fd': fd, 'vmm_bytes': size}, os.getpid(), 0,
                                      expect_bdf='0000:ff:1f.7')
        finally:
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
