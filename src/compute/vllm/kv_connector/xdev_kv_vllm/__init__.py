# SPDX-License-Identifier: GPL-2.0
"""xdev_ext KV connector for vLLM 0.33.0 (K-KV: restore a KV prefix from a neighbour's SSD).

Load it with ``kv_connector="XdevExtConnector"`` and
``kv_connector_module_path="xdev_kv_vllm.connector"``. Only ``connector``,
``scatter`` and ``staging`` import vLLM, torch or CUDA; the other modules run
anywhere, so the scheduling, restore and fallback rules are host-testable.
"""

__version__ = '0.1.0'
VLLM_VERSION = '0.33.0'
