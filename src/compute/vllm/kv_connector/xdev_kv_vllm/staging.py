# SPDX-License-Identifier: GPL-2.0
"""Map the restore worker's CUDA VMM staging allocation into this process.

kv_restore --dst ce-vmm creates its staging allocation with cuMemCreate,
exports it as a POSIX file descriptor (CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR,
src/cli/xdev_ext_mech_cuda.h) and reports vmm_export_fd and vmm_bytes in
KV_READY. Here the descriptor is duplicated out of the worker (pidfd_getfd,
Linux >= 5.6, same ptrace rule as the worker's owner), imported with
cuMemImportFromShareableHandle and mapped read-write on this process's current
CUDA device, which must be the worker's GPU (cuDeviceGetPCIBusId). The mapping
is exposed as a 1-D uint8 torch tensor without a copy. Release it only when no
GPU work still reads it.
"""
import ctypes
import os

SYS_PIDFD_OPEN = 434           # same numbers on every Linux architecture
SYS_PIDFD_GETFD = 438
CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR = 1
CU_MEM_LOCATION_TYPE_DEVICE = 1
CU_MEM_ACCESS_FLAGS_PROT_READWRITE = 3


class StagingError(RuntimeError):
    pass


class CUmemLocation(ctypes.Structure):
    _fields_ = [('type', ctypes.c_int), ('id', ctypes.c_int)]


class CUmemAccessDesc(ctypes.Structure):
    _fields_ = [('location', CUmemLocation), ('flags', ctypes.c_int)]


def pidfd_getfd(pid, fd):
    """A duplicate of descriptor fd of process pid (close-on-exec)."""
    libc = ctypes.CDLL(None, use_errno=True)
    if hasattr(os, 'pidfd_open'):
        pidfd = os.pidfd_open(pid)
    else:
        pidfd = libc.syscall(ctypes.c_long(SYS_PIDFD_OPEN), ctypes.c_int(pid), ctypes.c_uint(0))
        if pidfd < 0:
            err = ctypes.get_errno()
            raise OSError(err, f'pidfd_open({pid}): {os.strerror(err)}')
    try:
        dup = libc.syscall(ctypes.c_long(SYS_PIDFD_GETFD), ctypes.c_int(pidfd), ctypes.c_int(fd),
                           ctypes.c_uint(0))
        if dup < 0:
            err = ctypes.get_errno()
            raise OSError(err, f'pidfd_getfd({pid}, {fd}): {os.strerror(err)}')
        return dup
    finally:
        os.close(pidfd)


def same_bus_id(a, b):
    def parts(text):
        try:
            domain, bus, rest = text.strip().lower().split(':')
            device, function = rest.split('.')
            return tuple(int(x, 16) for x in (domain, bus, device, function))
        except ValueError:
            raise StagingError(f'not a PCI bus id: {text!r}') from None
    return parts(a) == parts(b)


class CudaDriver:
    """The few libcuda entry points the import needs."""

    def __init__(self):
        try:
            self.lib = ctypes.CDLL('libcuda.so.1')
        except OSError as error:
            raise StagingError(f'libcuda.so.1: {error}') from None

    def check(self, name, *args):
        result = getattr(self.lib, name)(*args)
        if result != 0:
            raise StagingError(f'{name} failed with CUDA error {result}')


class VmmStaging:
    def __init__(self, fd, nbytes, device_index, expect_bdf=None, driver=None):
        import torch
        self.driver = driver or CudaDriver()
        self.nbytes, self.ptr, self.handle, self.tensor = nbytes, 0, None, None
        torch.cuda.set_device(device_index)
        torch.cuda.current_stream(device_index)     # the primary context is current now
        d = self.driver
        ctx, dev = ctypes.c_void_p(), ctypes.c_int()
        d.check('cuCtxGetCurrent', ctypes.byref(ctx))
        if not ctx.value:
            raise StagingError('no current CUDA context')
        d.check('cuCtxGetDevice', ctypes.byref(dev))
        if expect_bdf:
            buf = ctypes.create_string_buffer(64)
            d.check('cuDeviceGetPCIBusId', buf, 64, dev)
            if not same_bus_id(buf.value.decode(), expect_bdf):
                raise StagingError(f'CUDA device {buf.value.decode()} is not the restore GPU '
                                   f'{expect_bdf}')
        handle, ptr = ctypes.c_ulonglong(), ctypes.c_ulonglong()
        size = ctypes.c_size_t(nbytes)
        d.check('cuMemImportFromShareableHandle', ctypes.byref(handle), ctypes.c_void_p(fd),
                CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR)
        self.handle = handle
        try:
            d.check('cuMemAddressReserve', ctypes.byref(ptr), size, ctypes.c_size_t(0),
                    ctypes.c_ulonglong(0), ctypes.c_ulonglong(0))
            self.ptr = ptr.value
            d.check('cuMemMap', ptr, size, ctypes.c_size_t(0), handle, ctypes.c_ulonglong(0))
            self.mapped = True
            access = CUmemAccessDesc(CUmemLocation(CU_MEM_LOCATION_TYPE_DEVICE, dev.value),
                                     CU_MEM_ACCESS_FLAGS_PROT_READWRITE)
            d.check('cuMemSetAccess', ptr, size, ctypes.byref(access), ctypes.c_size_t(1))
        except BaseException:
            self.release()
            raise

        class _Cai:
            __cuda_array_interface__ = {'shape': (nbytes,), 'typestr': '|u1',
                                        'data': (self.ptr, False), 'version': 2}
        self._cai = _Cai()
        self.tensor = torch.as_tensor(self._cai, device=torch.device('cuda', device_index))
        if self.tensor.data_ptr() != self.ptr:
            raise StagingError('torch copied the staging mapping')

    def release(self):
        d, size = self.driver, ctypes.c_size_t(self.nbytes)
        self.tensor = None
        if self.ptr:
            if getattr(self, 'mapped', False):
                d.check('cuMemUnmap', ctypes.c_ulonglong(self.ptr), size)
                self.mapped = False
            d.check('cuMemAddressFree', ctypes.c_ulonglong(self.ptr), size)
            self.ptr = 0
        if self.handle is not None:
            d.check('cuMemRelease', self.handle)
            self.handle = None


def import_from_worker(ready, pid, device_index, expect_bdf=None):
    """Map the staging allocation a ce-vmm worker reported in KV_READY."""
    fd_number, nbytes = ready.get('vmm_export_fd'), ready.get('vmm_bytes')
    if type(fd_number) is not int or fd_number < 0 or type(nbytes) is not int or nbytes < 1:
        raise StagingError(f'worker reports no VMM export: fd {fd_number!r}, {nbytes!r} bytes')
    fd = pidfd_getfd(pid, fd_number)
    try:
        return VmmStaging(fd, nbytes, device_index, expect_bdf)
    finally:
        os.close(fd)
