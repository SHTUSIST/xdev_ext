# SPDX-License-Identifier: GPL-2.0
"""Fixed V1 worker shutdown: stop dispatch, finish use, release owned caches.

Only wrappers actually dispatched with a selected backend are recorded. Clearing
that wrapper's cache never resets a graph held by another caller; native graph
user-object custody still refuses close while any such future use remains.
"""
import functools
import inspect
import threading
import weakref
from . import __version__


def install_worker_shutdown(worker_class, graph_wrapper_class, get_tp_group):
    if worker_class.__dict__.get('_xdev_tp_shutdown_version') == __version__:
        return
    original_execute = worker_class.execute_model
    original_shutdown = worker_class.shutdown
    original_call = graph_wrapper_class.__call__
    pos = inspect.Parameter.POSITIONAL_OR_KEYWORD
    expected = [(original_execute, ('self', 'scheduler_output'), (pos, pos)),
                (original_shutdown, ('self',), (pos,)),
                (original_call, ('self', 'args', 'kwargs'),
                 (pos, inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD))]
    for method, names, kinds in expected:
        params = tuple(inspect.signature(method).parameters.values())
        if (tuple(p.name for p in params) != names or tuple(p.kind for p in params) != kinds or
                any(p.default is not inspect.Parameter.empty for p in params)):
            raise RuntimeError('unsupported vLLM 0.10.2 V1 shutdown/dispatch signature')
    lock = threading.RLock()
    wrappers = weakref.WeakKeyDictionary()

    def selected_backend():
        try:
            group = get_tp_group()
        except AssertionError:
            return None
        comm = getattr(group, 'device_communicator', None)
        backend = getattr(comm, '_xdev_tp_backend', None)
        return backend if backend is not None and backend.mode == 2 else None

    @functools.wraps(original_execute)
    def execute_model(self, scheduler_output):
        with lock:
            if getattr(self, '_xdev_tp_shutdown_started', False):
                raise RuntimeError('TP worker dispatch has stopped for shutdown')
            backend = selected_backend()
            if backend is not None and getattr(backend, '_xdev_tp_stopping', False):
                raise RuntimeError('TP backend dispatch has stopped for shutdown')
            return original_execute(self, scheduler_output)

    @functools.wraps(original_call)
    def call(self, *args, **kwargs):
        with lock:
            backend = wrappers.get(self)
            if backend is None:
                backend = selected_backend()
            if backend is not None:
                if getattr(backend, '_xdev_tp_stopping', False):
                    raise RuntimeError('TP graph replay has stopped for shutdown')
                wrappers[self] = backend
            return original_call(self, *args, **kwargs)

    @functools.wraps(original_shutdown)
    def shutdown(self):
        with lock:
            backend = selected_backend()
            if backend is None:
                return original_shutdown(self)
            if getattr(self, '_xdev_tp_shutdown_finished', False):
                return
            # This also gates direct shutdown calls, beyond WorkerProc's normal
            # finally-after-busy-loop entry. Existing CPU dispatch has left lock.
            self._xdev_tp_shutdown_started = True
            backend._xdev_tp_stopping = True
            original_shutdown(self)  # actual upstream KV transfer shutdown
            import torch
            with torch.cuda.device(backend.config['device_index']):
                # Do not wait on never-replayed native templates first. Complete
                # real GPU last use, then release only framework-owned refs.
                torch.cuda.synchronize(backend.config['device_index'])
                for wrapper, owner in list(wrappers.items()):
                    if owner is backend:
                        wrapper.concrete_cudagraph_entries.clear()
                # Native work_destroy can now reap a truly released unused
                # template without fabricating runtime completion. External
                # graph/exec refs and UNKNOWN work remain native-owned.
                backend.synchronize()
            self._xdev_tp_shutdown_finished = True

    worker_class.execute_model = execute_model
    worker_class.shutdown = shutdown
    graph_wrapper_class.__call__ = call
    worker_class._xdev_tp_shutdown_version = __version__
