# SPDX-License-Identifier: GPL-2.0
"""Strict two-rank Tensor adapter for an already admitted native endpoint pair.

The owner keeps endpoint/authority/context resources alive. close() must succeed
before the owner releases them. Native graph lifetime and GPU completion gate
storage release; dropping this Python object never proves either fact.
"""
import importlib
from .policy import qualify

__version__ = '0.1.0'


class TorchCommunicator:
    backend = 'xdev_tp'

    def _initialize(self, config, owner):
        import torch
        if torch.__version__.split('+')[0] != '2.8.0':
            raise RuntimeError('xdev TP bridge requires torch 2.8.0')
        self.config = dict(config)
        self.rank = int(config['rank'])
        self.world_size = int(config['world_size'])
        if self.world_size != 2 or self.rank not in (0, 1):
            raise ValueError('xdev TP requires two ranks')
        self.mode = int(config['mode'])
        if self.mode not in (1, 2):
            raise ValueError('unsupported native mode')
        self._owner = owner
        self._closed = False
        self._api_attempts = 0
        self._preflight_rejected = 0
        self._comm_stream = None
        self._bound_stream = None
    def __init__(self, config, owner):
        import torch
        if owner is None:
            raise ValueError('an endpoint/context owner reference is required')
        self._initialize(config, owner)
        with torch.cuda.device(self.config['device_index']):
            self._native = importlib.import_module('xdev_tp_torch._native').Communicator(config, owner)

    @classmethod
    def from_options(cls, options, stream=None):
        import torch
        from .config import validate_options
        config = validate_options(options, rank=options['rank'], device_index=options['device_index'])
        result = cls.__new__(cls)
        result._initialize(config, None)
        with torch.cuda.device(config['device_index']):
            if torch.cuda.current_device() != config['device_index']:
                raise ValueError('actual CUDA device does not match admission options')
            caller = torch.cuda.current_stream(config['device_index'])
            owned_stream = stream if stream is not None else torch.cuda.Stream(device=config['device_index'])
            if caller != owned_stream:
                owned_stream.wait_stream(caller)
            with torch.cuda.stream(owned_stream):
                if torch.cuda.is_current_stream_capturing():
                    raise RuntimeError('endpoint bootstrap must run before graph capture')
                actual = torch.cuda.current_stream(config['device_index'])
                native = importlib.import_module('xdev_tp_torch._native').Communicator
                result._native = native.from_options(config, actual.cuda_stream, owned_stream)
            if caller != owned_stream:
                caller.wait_stream(owned_stream)
        result._comm_stream = owned_stream
        result._bound_stream = owned_stream
        return result

    @property
    def execution_stream(self):
        return self._comm_stream if self._comm_stream is not None else self._bound_stream

    @staticmethod
    def _is_shape_only(tensor):
        if tensor.is_meta:
            return True
        # FakeTensor has a CUDA device but no runtime CUDA storage.
        try:
            from torch._subclasses.fake_tensor import FakeTensor
        except ImportError:
            return False
        return isinstance(tensor, FakeTensor)

    def _call(self, tensor, operation, *, dim=-1, dst=0):
        import torch
        if self._closed:
            raise RuntimeError('xdev TP communicator is closed')
        shape_only = self._is_shape_only(tensor)
        if not shape_only:
            self._api_attempts += 1
        dtype = {torch.float16: 'float16', torch.bfloat16: 'bfloat16',
                 torch.float32: 'float32'}.get(tensor.dtype, 'unsupported')
        try:
            q = qualify(tensor.shape, dtype=dtype, device_type=tensor.device.type,
                        contiguous=tensor.is_contiguous(), world_size=self.world_size,
                        rank=self.rank, operation=operation, dim=dim, dst=dst,
                        max_payload_bytes=self.config['max_payload_bytes'])
        except (ValueError, OverflowError):
            if not shape_only:
                self._preflight_rejected += 1
            raise
        if shape_only:
            return tensor.new_empty(q.output_shape) if q.output_shape is not None else None
        if tensor.device.index != self.config['device_index']:
            self._preflight_rejected += 1
            raise ValueError('tensor device differs from admitted communicator device')
        with torch.cuda.device(tensor.device):
            caller = torch.cuda.current_stream(tensor.device)
            capturing = torch.cuda.is_current_stream_capturing()
            if self.mode == 1 and capturing:
                self._preflight_rejected += 1
                raise RuntimeError('d1 does not support CUDA graph capture')
            target = self._comm_stream
            def submit():
                actual = torch.cuda.current_stream(tensor.device)
                if self._bound_stream is None:
                    self._bound_stream = actual
                # No catch/fallback: accepted errors retain native work/storage.
                if operation == 'all_reduce':
                    return self._native.all_reduce(tensor, actual.cuda_stream)
                return self._native.gather(tensor, actual.cuda_stream, dst, operation == 'all_gather')
            if target is None or caller == target:
                return submit()
            if capturing:
                self._preflight_rejected += 1
                raise RuntimeError('capture on a different communicator stream is unsupported')
            target.wait_stream(caller)
            try:
                with torch.cuda.stream(target):
                    if torch.cuda.is_current_stream_capturing():
                        self._preflight_rejected += 1
                        raise RuntimeError('unknown cross-stream capture is unsupported')
                    return submit()
            finally:
                # This event dependency also protects accepted input use when
                # an asynchronous native error makes the Python call raise.
                caller.wait_stream(target)

    def all_reduce(self, tensor):
        return self._call(tensor, 'all_reduce')

    def all_gather(self, tensor, dim=-1):
        return self._call(tensor, 'all_gather', dim=dim)

    def gather(self, tensor, dst=0, dim=-1):
        return self._call(tensor, 'gather', dim=dim, dst=dst)

    def synchronize(self, timeout_ns=None):
        """Wait for actual native/CUDA completion; timeout never revokes work.

        A completed captured template still retains storage until CUDA releases
        the graph/exec references. No collective is repeated by this method.
        """
        import torch
        if self._closed:
            raise RuntimeError('xdev TP communicator is closed')
        timeout = self.config['timeout_ns'] if timeout_ns is None else timeout_ns
        if not isinstance(timeout, int) or timeout < 0:
            raise ValueError('timeout_ns must be a nonnegative integer')
        with torch.cuda.device(self.config['device_index']):
            self._native.wait(timeout)
        return self.stats()

    def stats(self):
        import torch
        with torch.cuda.device(self.config['device_index']):
            native = self._native.stats()
        return dict(backend=self.backend, plugin_version=__version__, rank=self.rank,
                    world_size=self.world_size, mode=self.mode,
                    device_index=self.config['device_index'], native=native,
                    framework=dict(api_attempts=self._api_attempts,
                                   preflight_rejected=self._preflight_rejected,
                                   fallback_by_reason={}))

    def close(self):
        import torch
        if not self._closed:
            with torch.cuda.device(self.config['device_index']):
                self._native.close()
            self._closed = True
            self._owner = None
