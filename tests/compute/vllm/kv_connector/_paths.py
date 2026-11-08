# SPDX-License-Identifier: GPL-2.0
"""Import paths for the vLLM KV connector tests (canonical tree or source view)."""
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PACKAGE = ROOT / 'src/compute/vllm/kv_connector'
if str(PACKAGE) not in sys.path:
    sys.path.insert(0, str(PACKAGE))
# The K-KV benchmark sits at tests/benchmarks/kv_restore in the canonical tree
# and at tests/eval/kv_restore in the source view.
KV_RESTORE = next((p for p in (ROOT / 'tests/benchmarks/kv_restore', ROOT / 'tests/eval/kv_restore')
                   if (p / 'kv_protocol.py').is_file()), None)


def load_benchmark_module(name):
    """A module of the K-KV benchmark, or None when it is absent."""
    if KV_RESTORE is None or not (KV_RESTORE / f'{name}.py').is_file():
        return None
    spec = importlib.util.spec_from_file_location(f'kv_restore_{name}', KV_RESTORE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
