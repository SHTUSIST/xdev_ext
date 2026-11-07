#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""K-KV Mooncake Store baseline: SSD offload on host 1, TCP over thunderbolt0.

host1-load     on host 1, the real client with SSD offload (Mooncake's
               factory defaults otherwise): put the KV objects (fixed-size
               chunks of the kv_layout pattern), push the last ones out of
               DRAM with filler objects, require every KV key to be on the
               local SSD only, then stay alive as the owner of that SSD data.
host2-restore  on host 2, a client that contributes no DRAM segment
               (global_segment_size 0, so no replica can land in host 2's
               DRAM), restores a prefix with one batch_get_into() into a
               registered CUDA buffer and synchronizes before the clock stops.
Both talk the worker protocol of kv_protocol.py. Before every GO the
restore role checks that each key has a COMPLETE local-disk replica and no
COMPLETE memory replica, and refuses the run otherwise; after every run it
records whether a memory replica appeared. Pinned facts (Mooncake
d01447808d10af78011e9203d53796a15a032a03): setup(dict) keys and defaults,
ReplicaDescriptor.is_memory_replica/is_disk_replica/is_local_disk_replica
and ReplicaStatus (mooncake-integration/store/store_py.cpp); TCP transport
stages device memory through cudaMemcpy (tcp_transport_session_impl.h).
"""
import argparse
import ctypes
import importlib.util
import json
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kl = _load('kv_layout')
kp = _load('kv_protocol')

DEFAULT_OBJECT_BYTES = 4 << 20
FILLER_SEED = 0xF111F111F111F111


class MooncakeError(RuntimeError):
    pass


def object_keys(namespace, name, total_bytes, object_bytes):
    """(key, offset, size) of each chunk of the first total_bytes of an object."""
    if object_bytes <= 0 or total_bytes <= 0:
        raise MooncakeError('object and total sizes must be positive')
    return [(f'{namespace}/{name}/{i}', off, min(object_bytes, total_bytes - off))
            for i, off in enumerate(range(0, total_bytes, object_bytes))]


def residency(store, keys):
    """Per key: complete local-disk replica present, complete memory replica present."""
    descs = store.batch_get_replica_desc(list(keys))
    out = {}
    for key in keys:
        disk = mem = False
        for d in descs.get(key, []):
            complete = 'COMPLETE' in str(d.status)
            disk |= complete and (d.is_local_disk_replica() or d.is_disk_replica())
            mem |= complete and d.is_memory_replica()
        out[key] = dict(disk=disk, memory=mem)
    return out


def gate(store, keys):
    r = residency(store, keys)
    not_disk = [k for k, v in r.items() if not v['disk']]
    in_memory = [k for k, v in r.items() if v['memory']]
    return dict(ok=not not_disk and not in_memory, keys=len(keys), not_on_disk=len(not_disk),
                in_memory=len(in_memory), first_problem=(not_disk + in_memory)[:1])


class Cuda:
    """CUDA driver API through ctypes; --test-host-destination uses host memory."""

    def __init__(self, bdf, nbytes, test_host=False):
        self.test_host, self.nbytes = test_host, nbytes
        if test_host:
            self.host = ctypes.create_string_buffer(nbytes)
            self.ptr = ctypes.addressof(self.host)
            return
        self.lib = ctypes.CDLL('libcuda.so.1')
        self._call('cuInit', ctypes.c_uint(0))
        count = ctypes.c_int()
        self._call('cuDeviceGetCount', ctypes.byref(count))
        self.dev = None
        for i in range(count.value):
            dev, name = ctypes.c_int(), ctypes.create_string_buffer(32)
            self._call('cuDeviceGet', ctypes.byref(dev), i)
            self._call('cuDeviceGetPCIBusId', name, 32, dev)
            if name.value.decode().lower() == bdf.lower():
                self.dev = dev
        if self.dev is None:
            raise MooncakeError(f'no CUDA device at {bdf}')
        self.ctx = ctypes.c_void_p()
        self._call('cuDevicePrimaryCtxRetain', ctypes.byref(self.ctx), self.dev)
        self._call('cuCtxSetCurrent', self.ctx)
        ptr = ctypes.c_uint64()
        self._call('cuMemAlloc_v2', ctypes.byref(ptr), ctypes.c_size_t(nbytes))
        self.ptr = ptr.value

    def _call(self, name, *args):
        ret = getattr(self.lib, name)(*args)
        if ret:
            raise MooncakeError(f'{name} returned CUDA error {ret}')

    def sync(self):
        if not self.test_host:
            self._call('cuCtxSynchronize')

    def read(self, offset, size):
        if self.test_host:
            return self.host.raw[offset:offset + size]
        out = ctypes.create_string_buffer(size)
        self._call('cuMemcpyDtoH_v2', out, ctypes.c_uint64(self.ptr + offset), ctypes.c_size_t(size))
        return out.raw

    def close(self):
        if not self.test_host:
            self._call('cuMemFree_v2', ctypes.c_uint64(self.ptr))
            self._call('cuDevicePrimaryCtxRelease_v2', self.dev)


def open_store(store_module, config):
    store = store_module.MooncakeDistributedStore()
    ret = store.setup(config)
    if ret:
        raise MooncakeError(f'setup returned {ret}')
    return store


def put_with_retry(store, key, data, deadline_s):
    """put() until accepted: with a small DRAM segment a put waits for offload."""
    end = time.monotonic() + deadline_s
    delay = 0.05
    while True:
        ret = store.put(key, data)
        if not ret:
            return
        if time.monotonic() > end:
            raise MooncakeError(f'put({key}) still failing ({ret}) after {deadline_s} s')
        time.sleep(delay)
        delay = min(delay * 2, 2.0)


def load(store, manifest, namespace, object_bytes, put_deadline_s, settle_s, filler_max):
    keys = []
    for o in manifest.objects:
        for key, off, size in object_keys(namespace, o.name, o.bytes, object_bytes):
            put_with_retry(store, key, kl.pattern_bytes(o.seed, off, size), put_deadline_s)
            keys.append(key)
    fillers = []
    end = time.monotonic() + settle_s
    while True:
        g = gate(store, keys)
        if g['ok'] or time.monotonic() > end:
            break
        if g['in_memory'] and len(fillers) < filler_max:
            key = f'{namespace}/filler/{len(fillers)}'
            put_with_retry(store, key, kl.pattern_bytes(FILLER_SEED, 0, object_bytes), put_deadline_s)
            fillers.append(key)
        else:
            time.sleep(0.5)
    for key in fillers:
        store.remove(key)
    return keys, fillers, gate(store, keys)


def emit(kind, body):
    print(f'{kind} {json.dumps(body, sort_keys=True)}', flush=True)


def host1(args, store_module):
    m = kl.load_manifest(args.manifest)
    config = dict(local_hostname=args.local_hostname, metadata_server=args.metadata_server,
                  master_server_addr=args.master, protocol='tcp', enable_ssd_offload=True,
                  ssd_offload_path=args.ssd_offload_path)
    store = open_store(store_module, config)
    keys, fillers, g = load(store, m, args.namespace, args.object_bytes, args.put_deadline_s,
                            args.settle_s, args.filler_max)
    if not g['ok']:
        emit('KV_ERROR', dict(where='residency after load', error=-5, strerror=json.dumps(g)))
        store.close()
        return 1
    emit('KV_READY', dict(role='mooncake-host1', keys=len(keys), fillers=len(fillers),
                          object_bytes=args.object_bytes, residency=g, config=config))
    for line in sys.stdin:
        if line.startswith('QUIT'):
            break
    emit('KV_BYE', dict(error=store.close(), retained=False, restores=0))
    return 0


def parse_go(line):
    words = line.split()
    if not words or words[0] != 'GO':
        raise kp.ProtocolError('expected GO')
    f = dict(w.split('=', 1) for w in words[1:] if '=' in w)
    try:
        return dict(run=f['run'], ordinal=int(f['ordinal']), object_slba=int(f['object_slba']),
                    bytes=int(f['bytes']), dst_frame0=int(f['dst_frame0']),
                    seed=int(f.get('seed', '0')), verify=f.get('verify') == '1')
    except (KeyError, ValueError) as error:
        raise kp.ProtocolError(f'bad GO line: {error}') from None


def host2(args, store_module):
    m = kl.load_manifest(args.manifest)
    by_slba = {o.slba: o for o in m.objects}
    config = dict(local_hostname=args.local_hostname, metadata_server=args.metadata_server,
                  master_server_addr=args.master, protocol='tcp', global_segment_size=0)
    store = open_store(store_module, config)
    gpu = Cuda(args.gpu_bdf, args.pool_bytes, test_host=args.test_host_destination)
    if store.register_buffer(gpu.ptr, args.pool_bytes):
        raise MooncakeError('register_buffer failed')
    emit('KV_READY', dict(role='mooncake-host2', config=config, object_bytes=args.object_bytes,
                          pool_bytes=args.pool_bytes,
                          test_host_destination=args.test_host_destination))
    restores = 0
    for line in sys.stdin:
        if line.startswith('QUIT'):
            break
        try:
            go = parse_go(line)
        except kp.ProtocolError as error:
            emit('KV_ERROR', dict(where='GO arguments', error=-22, strerror=str(error)))
            continue
        restores += 1
        emit('KV_RESULT', restore(store, gpu, by_slba, go, args))
    store.unregister_buffer(gpu.ptr)
    gpu.close()
    emit('KV_BYE', dict(error=store.close(), retained=False, restores=restores))
    return 0


def restore(store, gpu, by_slba, go, args):
    result = dict(run=go['run'], role='mooncake', ok=False, error=0, bytes=0, started=False,
                  t0_ns=0, t1_ns=0, latency_ns=0, verified=None)
    obj = by_slba.get(go['object_slba'])
    dst = go['dst_frame0'] * args.frame_bytes
    if obj is None or go['bytes'] > obj.bytes or dst + go['bytes'] > args.pool_bytes:
        result['error'] = -22 if obj is None or go['bytes'] > obj.bytes else -28
        return result
    chunks = object_keys(args.namespace, obj.name, go['bytes'], args.object_bytes)
    keys = [k for k, _, _ in chunks]
    before = gate(store, keys)
    result['residency_before'] = before
    if not before['ok']:
        result['error'] = -5
        result['reason'] = 'KV not resident on host 1 SSD only'
        return result
    ptrs = [gpu.ptr + dst + off for _, off, _ in chunks]
    sizes = [size for _, _, size in chunks]
    result['started'] = True
    t0 = time.monotonic_ns()
    got = store.batch_get_into(keys, ptrs, sizes)
    gpu.sync()
    t1 = time.monotonic_ns()
    result['residency_after'] = gate(store, keys)
    bad = [i for i, (g, s) in enumerate(zip(got, sizes)) if g != s]
    if bad:
        result.update(error=-5, failed_keys=len(bad), first_failed=keys[bad[0]], first_ret=got[bad[0]])
        return result
    result.update(ok=True, bytes=go['bytes'], t0_ns=t0, t1_ns=t1, latency_ns=t1 - t0,
                  objects=len(keys))
    if go['verify']:
        data = gpu.read(dst, go['bytes'])
        want = kl.pattern_bytes(obj.seed, 0, go['bytes'])
        result['verified'] = data == want
        if data != want:
            result['ok'] = False
            result['first_bad'] = next(i for i, (a, b) in enumerate(zip(data, want)) if a != b)
    return result


def main(argv=None, store_module=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('role', choices=('host1-load', 'host2-restore'))
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--local-hostname', required=True, help='this host\'s thunderbolt0 address')
    parser.add_argument('--master', required=True, help='host 1 thunderbolt0 address:50051')
    parser.add_argument('--metadata-server', default='P2PHANDSHAKE')
    parser.add_argument('--namespace', default='kv')
    parser.add_argument('--object-bytes', type=int, default=DEFAULT_OBJECT_BYTES)
    parser.add_argument('--ssd-offload-path')
    parser.add_argument('--put-deadline-s', type=float, default=600.0)
    parser.add_argument('--settle-s', type=float, default=600.0)
    parser.add_argument('--filler-max', type=int, default=64)
    parser.add_argument('--gpu-bdf')
    parser.add_argument('--pool-bytes', type=int)
    parser.add_argument('--frame-bytes', type=int, default=131072)
    parser.add_argument('--test-host-destination', action='store_true')
    args = parser.parse_args(argv)
    if store_module is None:
        import mooncake.store as store_module  # the build from the pinned source
    try:
        if args.role == 'host1-load':
            if not args.ssd_offload_path:
                parser.error('host1-load needs --ssd-offload-path')
            return host1(args, store_module)
        if not args.pool_bytes or (not args.gpu_bdf and not args.test_host_destination):
            parser.error('host2-restore needs --pool-bytes and --gpu-bdf')
        return host2(args, store_module)
    except (MooncakeError, kl.LayoutError, OSError) as error:
        emit('KV_ERROR', dict(where='setup', error=-5, strerror=str(error)))
        return 1


if __name__ == '__main__':
    sys.exit(main())
