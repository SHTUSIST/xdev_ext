# SPDX-License-Identifier: GPL-2.0
"""The part of vLLM 0.33.0's KV connector API the connector imports, for host tests.

Copied in shape (names, abstract methods, signatures, defaults) from
vllm/distributed/kv_transfer/kv_connector/v1/base.py at the v0.33.0 tag
(commit 4ba787ec9959e566d3b587a796dff07673324da5) and
vllm/v1/metrics/cache_hit_source.py. Behaviour is reduced to what the
connector uses; this is not vLLM.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import enum
import logging
import sys
import types


class CacheHitSource(str, enum.Enum):
    DEVICE = 'device'
    HOST = 'host'
    P2P = 'p2p'
    DISK = 'disk'
    EXTERNAL_UNSPECIFIED = 'external_unspecified'


@dataclass
class KVConnectorTransferResults:
    finished_sending: set = field(default_factory=set)
    finished_recving: set = field(default_factory=set)
    failed_recving: set = field(default_factory=set)


class SupportsHMA(ABC):
    @abstractmethod
    def request_finished_all_groups(self, request, block_ids):
        raise NotImplementedError


class KVConnectorRole(enum.Enum):
    SCHEDULER = 0
    WORKER = 1


class KVConnectorMetadata(ABC):  # noqa: B024
    pass


class KVConnectorBase_V1(ABC):
    _cache_hit_source = CacheHitSource.EXTERNAL_UNSPECIFIED

    def __init__(self, vllm_config, role, kv_cache_config):
        self._connector_metadata = None
        self._vllm_config = vllm_config
        if vllm_config.kv_transfer_config is not None:
            self._kv_transfer_config = vllm_config.kv_transfer_config
        else:
            raise ValueError('kv_transfer_config must be set for KVConnectorBase_V1')
        self._kv_cache_config = kv_cache_config
        self._kv_cache_manager = None
        self._role = role

    @property
    def role(self):
        return self._role

    def bind_connector_metadata(self, connector_metadata):
        self._connector_metadata = connector_metadata

    def clear_connector_metadata(self):
        self._connector_metadata = None

    def _get_connector_metadata(self):
        assert self._connector_metadata is not None
        return self._connector_metadata

    def has_connector_metadata(self):
        return self._connector_metadata is not None

    def register_kv_caches(self, kv_caches):
        return

    @abstractmethod
    def start_load_kv(self, forward_context, **kwargs):
        pass

    @abstractmethod
    def wait_for_layer_load(self, layer_name):
        pass

    @abstractmethod
    def save_kv_layer(self, layer_name, kv_layer, attn_metadata, **kwargs):
        pass

    @abstractmethod
    def wait_for_save(self):
        pass

    def get_finished(self, finished_req_ids):
        return None, None

    def get_transfer_results(self, finished_req_ids):
        finished_sending, finished_recving = self.get_finished(finished_req_ids)
        return KVConnectorTransferResults(finished_sending=set(finished_sending or ()),
                                          finished_recving=set(finished_recving or ()))

    def get_block_ids_with_load_errors(self):
        return set()

    def shutdown(self):
        return None

    @abstractmethod
    def get_num_new_matched_tokens(self, request, num_computed_tokens):
        pass

    @abstractmethod
    def update_state_after_alloc(self, request, blocks, num_external_tokens):
        pass

    @abstractmethod
    def build_connector_meta(self, scheduler_output):
        pass

    def request_finished(self, request, block_ids):
        return False, None

    @classmethod
    def get_required_kvcache_layout(cls, vllm_config):
        return None

    @classmethod
    def requires_piecewise_for_cudagraph(cls, extra_config):
        return False


def install():
    """Put the stub modules into sys.modules (only where vLLM is absent)."""
    names = ['vllm', 'vllm.distributed', 'vllm.distributed.kv_transfer',
             'vllm.distributed.kv_transfer.kv_connector', 'vllm.distributed.kv_transfer.kv_connector.v1',
             'vllm.distributed.kv_transfer.kv_connector.v1.base', 'vllm.logger', 'vllm.v1',
             'vllm.v1.metrics', 'vllm.v1.metrics.cache_hit_source']
    for name in names:
        sys.modules[name] = types.ModuleType(name)
    base = sys.modules['vllm.distributed.kv_transfer.kv_connector.v1.base']
    for obj in (KVConnectorBase_V1, KVConnectorMetadata, KVConnectorRole, KVConnectorTransferResults,
                SupportsHMA):
        setattr(base, obj.__name__, obj)
    sys.modules['vllm.v1.metrics.cache_hit_source'].CacheHitSource = CacheHitSource
    sys.modules['vllm.logger'].init_logger = logging.getLogger
    sys.modules['vllm'].__version__ = '0.33.0'
