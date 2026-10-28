# SPDX-License-Identifier: GPL-2.0
"""Version-limited vLLM general plugin. Opt in with XDEV_TP_BACKEND=strict.

XDEV_TP_CONFIG selects rank-local JSON for the shipped native endpoint owner.
XDEV_TP_FACTORY=package.module:callable is an optional admitted-backend override.
Before a strict run assert_backend_selected() on every TP instance; before
resource teardown collect_backend_evidence() for every expected rank/group.
"""
from contextlib import contextmanager
import functools
import importlib
import inspect
import os
import re

__version__ = '0.1.0'
_SIGNATURES = {
    '__init__': (('self', 'cpu_group', 'device', 'device_group', 'unique_name'),
                 (inspect.Parameter.empty, inspect.Parameter.empty, None, None, '')),
    'all_reduce': (('self', 'input_'), (inspect.Parameter.empty,) * 2),
    'all_gather': (('self', 'input_', 'dim'), (inspect.Parameter.empty,) * 2 + (-1,)),
    'gather': (('self', 'input_', 'dst', 'dim'), (inspect.Parameter.empty,) * 2 + (0, -1)),
    'destroy': (('self',), (inspect.Parameter.empty,)),
}


def _check_signatures(cls):
    originals = {}
    for name, (names, defaults) in _SIGNATURES.items():
        method = getattr(cls, name, None)
        if method is None:
            raise RuntimeError(f'vLLM 0.10.2 method missing: {name}')
        params = tuple(inspect.signature(method, follow_wrapped=False).parameters.values())
        if (tuple(p.name for p in params) != names or
                tuple(p.default for p in params) != defaults or
                any(p.kind != inspect.Parameter.POSITIONAL_OR_KEYWORD for p in params)):
            raise RuntimeError(f'unsupported vLLM 0.10.2 signature: {name}')
        originals[name] = method
    return originals


def _target(instance):
    return re.fullmatch(r'tp:[0-9]+', instance.unique_name) is not None


def _install_on_class(cls, *, version, factory):
    if version != '0.10.2':
        raise RuntimeError('xdev TP plugin requires exactly vLLM 0.10.2')
    # Inherited markers must not make a changed subclass pass the signature gate.
    if cls.__dict__.get('_xdev_tp_plugin_version') == __version__:
        return
    originals = _check_signatures(cls)

    @functools.wraps(originals['__init__'])
    def init(self, cpu_group, device=None, device_group=None, unique_name=''):
        originals['__init__'](self, cpu_group, device, device_group, unique_name)
        if not _target(self):
            return
        if self.world_size != 2:
            self._xdev_tp_selection_error = 'strict xdev TP requires world_size=2'
            return
        backend = factory(self)
        if (getattr(backend, 'backend', None) != 'xdev_tp' or
                backend.world_size != 2 or backend.rank != self.rank_in_group):
            raise RuntimeError('endpoint factory selected an incompatible TP backend')
        self._xdev_tp_backend = backend
        self._xdev_tp_selection = dict(plugin_version=__version__, vllm_version=version,
                                       group=self.unique_name, rank=self.rank_in_group,
                                       world_size=self.world_size, backend='xdev_tp')

    def selected(self):
        if _target(self):
            assert_backend_selected(self)
            return self._xdev_tp_backend
        return None

    @functools.wraps(originals['all_reduce'])
    def all_reduce(self, input_):
        backend = selected(self)
        return backend.all_reduce(input_) if backend else originals['all_reduce'](self, input_)

    @functools.wraps(originals['all_gather'])
    def all_gather(self, input_, dim=-1):
        backend = selected(self)
        return (backend.all_gather(input_, dim=dim) if backend else
                originals['all_gather'](self, input_, dim=dim))

    @functools.wraps(originals['gather'])
    def gather(self, input_, dst=0, dim=-1):
        backend = selected(self)
        return (backend.gather(input_, dst=dst, dim=dim) if backend else
                originals['gather'](self, input_, dst=dst, dim=dim))

    @functools.wraps(originals['destroy'])
    def destroy(self):
        backend = getattr(self, '_xdev_tp_backend', None)
        if backend is not None:
            # A retained native graph/work blocks original resource destruction.
            backend.close()
            self._xdev_tp_final_stats = backend.stats()
        originals['destroy'](self)

    for name, method in [('__init__', init), ('all_reduce', all_reduce),
                         ('all_gather', all_gather), ('gather', gather), ('destroy', destroy)]:
        setattr(cls, name, method)
    cls._xdev_tp_plugin_version = __version__


def _install_coordinator(cls, graph_context_class):
    """Gate real upstream capture and teardown before their resource actions."""
    if cls.__dict__.get('_xdev_tp_lifecycle_version') == __version__:
        return
    original_capture = cls.graph_capture
    original_destroy = cls.destroy
    capture_params = tuple(inspect.signature(original_capture).parameters.values())
    destroy_params = tuple(inspect.signature(original_destroy).parameters.values())
    if (tuple(p.name for p in capture_params) != ('self', 'graph_capture_context') or
            capture_params[-1].default is not None or
            tuple(p.name for p in destroy_params) != ('self',)):
        raise RuntimeError('unsupported vLLM 0.10.2 GroupCoordinator lifecycle signature')

    @contextmanager
    @functools.wraps(original_capture)
    def graph_capture(self, graph_capture_context=None):
        comm = self.device_communicator
        backend = getattr(comm, '_xdev_tp_backend', None)
        if backend is not None:
            import torch
            assert_backend_selected(comm)
            if getattr(backend, 'mode', 2) != 2:
                raise RuntimeError('d1 backend cannot capture CUDA graphs')
            stream = backend.execution_stream
            if stream is None or not stream.cuda_stream:
                raise RuntimeError('graph capture requires an admitted nondefault communicator stream')
            if torch.cuda.is_current_stream_capturing():
                raise RuntimeError('nested or unknown cross-stream graph capture is unsupported')
            if graph_capture_context is None:
                graph_capture_context = graph_context_class(stream)
            elif graph_capture_context.stream != stream:
                # The module-level upstream graph_capture shares this exact
                # context with TP then PP. Preserve its dependencies before
                # updating it so both original context managers use one stream.
                stream.wait_stream(graph_capture_context.stream)
                graph_capture_context.stream = stream
        with original_capture(self, graph_capture_context) as context:
            yield context

    @functools.wraps(original_destroy)
    def destroy(self):
        comm = self.device_communicator
        backend = getattr(comm, '_xdev_tp_backend', None)
        if backend is not None and not getattr(self, '_xdev_tp_preclosed', False):
            assert_backend_selected(comm)
            backend.synchronize()
            evidence = collect_backend_evidence([comm], expected_ranks={comm.rank_in_group},
                                                require_completed=False)
            backend.close()
            self._xdev_tp_final_evidence = evidence
            self._xdev_tp_preclosed = True
        # The fixed original destroys device/cpu ProcessGroups first. It is safe
        # only after the preceding native drain and graph-lifetime guard pass.
        original_destroy(self)

    cls.graph_capture = graph_capture
    cls.destroy = destroy
    cls._xdev_tp_lifecycle_version = __version__


def assert_backend_selected(communicator):
    if (getattr(communicator, '_xdev_tp_backend', None) is None or
            getattr(communicator, '_xdev_tp_selection', {}).get('backend') != 'xdev_tp'):
        raise RuntimeError(getattr(communicator, '_xdev_tp_selection_error',
                                   'strict xdev TP backend was not selected'))
    return dict(communicator._xdev_tp_selection)


def collect_backend_evidence(communicators, *, expected_ranks, require_completed=True):
    """Collect before close; callers merge per-process records for both ranks.

    expected_ranks is explicit: worker-local collection normally expects only its
    local rank; the run coordinator must check rank 0 and rank 1 per TP group.
    """
    records = []
    observed = set()
    groups = set()
    ranks_by_group = {}
    for comm in communicators:
        selection = assert_backend_selected(comm)
        key = (selection['group'], selection['rank'])
        if key in groups:
            raise RuntimeError('duplicate TP group/rank evidence')
        groups.add(key)
        observed.add(selection['rank'])
        ranks_by_group.setdefault(selection['group'], set()).add(selection['rank'])
        stats = comm._xdev_tp_backend.stats()
        native = stats['native']
        required = {'submitted', 'completed', 'failed', 'error', 'retained',
                    'fallback_calls', 'logical_inflight', 'tx_done',
                    'rx_delivered', 'last_use_released'}
        if not required.issubset(native):
            raise RuntimeError('native strict statistics are incomplete')
        if (stats['backend'] != 'xdev_tp' or stats['rank'] != selection['rank'] or
                stats['world_size'] != 2 or native.get('failed', 0) or
                native.get('error', 0) or native.get('retained', 0) or
                native.get('fallback_calls', 0) or native['logical_inflight']):
            raise RuntimeError('strict TP backend has failed/retained/fallback work')
        if require_completed and (native.get('submitted', 0) <= 0 or
                                  native.get('completed', 0) != native['submitted'] or
                                  any(native[key] != native['completed'] for key in
                                      ('tx_done', 'rx_delivered', 'last_use_released'))):
            raise RuntimeError('native TP activity/completion evidence is missing')
        records.append(dict(selection=selection, **stats))
    if (observed != set(expected_ranks) or not ranks_by_group or
            any(ranks != set(expected_ranks) for ranks in ranks_by_group.values())):
        raise RuntimeError('TP evidence does not cover expected ranks')
    return records


def install():
    choice = os.environ.get('XDEV_TP_BACKEND', '')
    if not choice:
        return
    if choice != 'strict':
        raise RuntimeError('XDEV_TP_BACKEND supports strict only')
    import vllm
    from vllm.distributed.device_communicators.cuda_communicator import CudaCommunicator
    from xdev_tp_torch import TorchCommunicator
    value = os.environ.get('XDEV_TP_FACTORY', '')
    if value:
        if value.count(':') != 1:
            raise RuntimeError('XDEV_TP_FACTORY requires module:callable')
        module, name = value.split(':')
        factory = getattr(importlib.import_module(module), name)
        if not callable(factory):
            raise RuntimeError('XDEV_TP_FACTORY is not callable')
    else:
        if not os.environ.get('XDEV_TP_CONFIG'):
            raise RuntimeError('strict TP requires XDEV_TP_CONFIG rank-local JSON')
        from .bootstrap import create_backend
        factory = create_backend
    def checked_factory(comm):
        result = factory(comm)
        if not isinstance(result, TorchCommunicator):
            raise RuntimeError('factory must return the real TorchCommunicator')
        return result
    from vllm.distributed.parallel_state import GroupCoordinator, GraphCaptureContext
    _install_on_class(CudaCommunicator, version=vllm.__version__, factory=checked_factory)
    _install_coordinator(GroupCoordinator, GraphCaptureContext)
