# SPDX-License-Identifier: GPL-2.0
"""XdevExtConnector: vLLM 0.33.0 KV connector that restores prefixes with xdev_ext (K-KV).

    --kv-transfer-config '{"kv_connector": "XdevExtConnector",
      "kv_connector_module_path": "xdev_kv_vllm.connector",
      "kv_role": "kv_consumer", "kv_load_failure_policy": "recompute",
      "kv_connector_extra_config": {"xdev_ext.index": "/path/kv.index",
        "xdev_ext.model_key": "qwen3-8b-bf16", "xdev_ext.pool_bytes": 5368709120,
        "xdev_ext.worker_argv": ["kv_restore", "restore", "--dst", "ce-vmm", ...]}}'

Scheduler process: a prompt's longest stored prefix (xdev_ext.index) beyond
vLLM's own prefix-cache hit becomes external tokens. Worker process: the
connector starts one restore worker (xdev_ext.worker_argv, normally
`kv_restore restore --dst ce-vmm` with host 1 serving over Thunderbolt, or
`kv_restore local-verify --dst ce-vmm` on one host), maps its CUDA VMM staging
allocation, and for each load sends one GO; the copy engine writes the prefix
into staging and a GPU kernel scatters it into vLLM's paged blocks
(scatter.py). Rules and fallback: core.py. Only full-attention models with one
KV cache group, without tensor or pipeline parallelism, are accepted.
"""
import re
from typing import Any

from vllm.distributed.kv_transfer.kv_connector.v1.base import (
    KVConnectorBase_V1,
    KVConnectorMetadata,
    KVConnectorRole,
    KVConnectorTransferResults,
    SupportsHMA,
)
from vllm.logger import init_logger
from vllm.v1.metrics.cache_hit_source import CacheHitSource

from . import core
from .index import PrefixIndex
from .layout import LayoutError, StagingLayout, canonical_dtype, resolved_dtype
from .restore import RestoreError, RestoreService
from .scatter import layer_target

logger = init_logger(__name__)
_LAYER = re.compile(r'(?:^|\.)layers\.(\d+)\.')


def layer_order(names):
    """Attention layers in model order (the staged order); unnumbered names keep vLLM's order."""
    numbers = [_LAYER.search(n) for n in names]
    if all(numbers):
        return [n for _, n in sorted(zip((int(m.group(1)) for m in numbers), names))]
    return list(names)


def staging_from_spec(spec, num_layers):
    """The staged layout a vLLM full-attention KV cache spec implies."""
    if type(spec).__name__ != 'FullAttentionSpec':
        raise ValueError(f'XdevExtConnector needs full attention, got {type(spec).__name__}')
    if getattr(spec, 'state_content_bytes', None) is not None:
        raise ValueError('XdevExtConnector needs dense K/V cells (state_content_bytes is set)')
    itemsize = spec.dtype.itemsize
    cell = spec.state_content_size_bytes
    if cell % itemsize:
        raise ValueError(f'{cell}-byte cells are not whole {itemsize}-byte elements')
    return StagingLayout(spec.block_size, num_layers, spec.num_heads, cell // itemsize, itemsize,
                         canonical_dtype(spec.dtype))


def make_device(views, staging, device_index, scatter):
    from .scatter import TorchDevice
    return TorchDevice(views, staging, device_index, scatter)


def make_service(restore_cfg, staging_factory):
    return RestoreService(restore_cfg, staging_factory)


class XdevExtConnectorMetadata(KVConnectorMetadata):
    def __init__(self, loads=()):
        self.loads = list(loads)

    def __repr__(self):
        return f'XdevExtConnectorMetadata({[(s.req_id, s.end_token) for s in self.loads]})'


class XdevExtConnector(KVConnectorBase_V1, SupportsHMA):
    _cache_hit_source = CacheHitSource.DISK

    def __init__(self, vllm_config, role, kv_cache_config):
        super().__init__(vllm_config=vllm_config, role=role, kv_cache_config=kv_cache_config)
        ktc = self._kv_transfer_config
        if ktc.kv_load_failure_policy != 'recompute':
            raise ValueError('XdevExtConnector needs kv_load_failure_policy="recompute": a failed '
                             'restore must be recomputed')
        pc = vllm_config.parallel_config
        if pc.tensor_parallel_size != 1 or pc.pipeline_parallel_size != 1:
            raise ValueError('XdevExtConnector supports one GPU (no tensor or pipeline parallelism)')
        groups = kv_cache_config.kv_cache_groups
        if len(groups) != 1:
            raise ValueError(f'XdevExtConnector supports one KV cache group, got {len(groups)}')
        self.layer_names = layer_order(groups[0].layer_names)
        self.staging_layout = staging_from_spec(groups[0].kv_cache_spec, len(self.layer_names))
        self.block_size = self.staging_layout.block_size
        try:
            self.cfg = core.ConnectorConfig.from_extra(ktc.kv_connector_extra_config,
                                                       worker=role == KVConnectorRole.WORKER)
        except core.ConfigError as error:
            raise ValueError(f'XdevExtConnector: {error}') from None
        if resolved_dtype(vllm_config, self.cfg.kv_dtype) != self.staging_layout.dtype:
            raise ValueError('resolved KV dtype disagrees with the actual cache spec dtype')
        self._scheduler = self._worker = None
        if role == KVConnectorRole.SCHEDULER:
            index = PrefixIndex.load(self.cfg.index_path, self.cfg.model_key, self.staging_layout,
                                     self.cfg.lba_bytes)
            logger.info('XdevExtConnector: %d stored prefixes, %s loads', len(index),
                        self.cfg.load_mode)
            self._scheduler = core.SchedulerSide(self.cfg, index, self.staging_layout,
                                                 self.block_size)

    # ---- worker side -----------------------------------------------------------
    def register_kv_caches(self, kv_caches):
        views = [kv_caches[name] for name in self.layer_names]
        device_index = views[0].device.index
        try:
            for view in views:
                if canonical_dtype(view.dtype) != self.staging_layout.dtype:
                    raise LayoutError('registered cache tensor dtype disagrees with the cache spec')
                layer_target(view, self.staging_layout)
            device = make_device(views, self.staging_layout, device_index, self.cfg.scatter)
        except LayoutError as error:
            raise ValueError(f'XdevExtConnector: vLLM KV cache does not hold the staged layout: '
                             f'{error}') from None

        def staging_factory(ready, pid):
            from .staging import import_from_worker
            return import_from_worker(ready, pid, device_index, self.cfg.gpu_bdf)
        service = make_service(self.cfg.restore, staging_factory)
        try:
            service.start()
        except RestoreError as error:
            logger.error('XdevExtConnector: restore worker did not start (%s); every stored '
                         'prefix will be recomputed', error)
            service.disabled = True
        try:
            self._worker = core.WorkerSide(self.cfg, service, device,
                                           {n: i for i, n in enumerate(self.layer_names)},
                                           self.staging_layout)
        except BaseException:
            service.close()
            raise

    def start_load_kv(self, forward_context, **kwargs: Any) -> None:
        meta = self._get_connector_metadata()
        assert isinstance(meta, XdevExtConnectorMetadata)
        self._worker.start_loads(meta.loads)

    def wait_for_layer_load(self, layer_name):
        if self._worker is not None:
            self._worker.wait_layer(layer_name)

    def save_kv_layer(self, layer_name, kv_layer, attn_metadata, **kwargs: Any) -> None:
        return

    def wait_for_save(self):
        return

    def get_transfer_results(self, finished_req_ids):
        if self._worker is None:
            return KVConnectorTransferResults()
        finished, failed = self._worker.transfer_results(finished_req_ids)
        for req_id in failed:
            logger.warning('XdevExtConnector: restore of %s failed; vLLM recomputes it', req_id)
        return KVConnectorTransferResults(finished_recving=finished, failed_recving=failed)

    def get_block_ids_with_load_errors(self):
        return self._worker.load_error_blocks() if self._worker is not None else set()

    def shutdown(self):
        if self._worker is not None:
            if self._worker.shutdown():
                self._worker = None

    @classmethod
    def requires_piecewise_for_cudagraph(cls, extra_config):
        # Sync loads scatter inside wait_for_layer_load, which graph replay skips.
        return extra_config.get(core.PREFIX + 'load_mode', 'async') == 'sync'

    # ---- scheduler side --------------------------------------------------------
    def get_num_new_matched_tokens(self, request, num_computed_tokens):
        if getattr(request.status, 'name', '') == 'PREEMPTED':
            return 0, False
        return self._scheduler.lookup(request.request_id, list(request.prompt_token_ids or ()),
                                      num_computed_tokens)

    def update_state_after_alloc(self, request, blocks, num_external_tokens):
        block_ids = blocks.get_block_ids()[0] if num_external_tokens > 0 else []
        self._scheduler.after_alloc(request.request_id, list(block_ids), num_external_tokens)

    def build_connector_meta(self, scheduler_output):
        return XdevExtConnectorMetadata(self._scheduler.build())

    def request_finished(self, request, block_ids):
        self._scheduler.finished(request.request_id)
        return False, None

    def request_finished_all_groups(self, request, block_ids):
        return self.request_finished(request, block_ids[0] if block_ids else [])
