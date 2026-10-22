#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract of nv_ce_runtime_test, the real-GPU CE round trip.

It runs only in a user-approved GPU window, so its fail-closed gate and the
order of what it does on the GPU are checked here, where it cannot run.
"""

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "nv_ce_runtime_test.c").read_text()


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        depth += {"{": 1, "}": -1}.get(source[pos], 0)
        if not depth:
            return source[brace:pos + 1]
    raise AssertionError(f"unterminated function: {signature}")


def without_cuda(source: str) -> str:
    """The -host build: drop every #ifdef XDEV_EXT_NV_CE_WITH_CUDA block."""
    out, skip = [], 0
    for line in source.splitlines():
        if line.startswith("#ifdef XDEV_EXT_NV_CE_WITH_CUDA"):
            skip += 1
            continue
        if skip and line.startswith("#else"):
            skip = 0
            continue
        if skip and line.startswith("#endif"):
            skip = 0
            continue
        if not skip:
            out.append(line)
    return "\n".join(out)


code = strip_comments(SOURCE)

# The gate comes first: nothing is opened or called on a device before it.
main = function_body(code, "int main(")
gate = main.index("nv_ce_runtime_gate(")
assert main.index("parse_options(") < gate
for call in ("open(", "ioctl(", "cuInit(", "nv_ce_run("):
    if call in main:
        assert main.index(call) > gate, call
assert "XDEV_EXT_NV_CE_RUNTIME=REFUSED reason=%s" in code

# The -host build touches no device and no CUDA symbol at all.
host = without_cuda(code)
for call in ("open(", "ioctl(", "xdev_ext_nv_p2p_", "cuInit(", "cuMemAlloc("):
    assert call not in host, call
assert "nv_ce_runtime_gate(" in host

# The run: shared ABI helpers and GPU identity, a host region pin, every
# round trip and the batch before any error case, a sanity round trip after
# them, and the double unpin last.
run = function_body(code, "static int nv_ce_run(")
assert "xdev_ext_gpu_identity_from_opened(" in code
for helper in ("xdev_ext_nv_p2p_pin_umem(", "xdev_ext_nv_p2p_dma_xfer(",
               "xdev_ext_nv_p2p_dma_batch(", "xdev_ext_nv_p2p_unpin_umem("):
    assert helper in code, helper
assert re.search(r"\.flags = XDEV_EXT_NV_P2P_PIN_F_HOST_REGION", code)
assert re.search(r"\.xsk_fd = -1", code)
cases = run.index("nv_ce_round_trip(")
batch = run.index("nv_ce_batch_round_trip(")
errors = run.index("nv_ce_error_case(")
sanity = run.rindex("nv_ce_round_trip(")
unpin = run.index("nv_ce_unpin_twice(")
assert cases < batch < errors < sanity < unpin
assert "XDEV_EXT_NV_CE_RUNTIME=%s cases=%u errors=%u" in code

# Placement is proven by CUDA's own copies on the other side of each CE
# copy: host to GPU is read back by CUDA, GPU to host was written by CUDA.
trip = function_body(code, "static int nv_ce_round_trip(")
assert trip.index("nv_ce_h2d_check(") < trip.index("nv_ce_d2h_check(")
h2d = function_body(code, "static int nv_ce_h2d_check(")
assert "XDEV_EXT_NV_P2P_UMEM_TO_GPU" in h2d
assert h2d.index("xdev_ext_nv_p2p_dma_xfer(") < h2d.index("cuMemcpyDtoH(")
d2h = function_body(code, "static int nv_ce_d2h_check(")
assert "XDEV_EXT_NV_P2P_GPU_TO_UMEM" in d2h
assert d2h.index("cuMemcpyHtoD(") < d2h.index("xdev_ext_nv_p2p_dma_xfer(")
for body in (h2d, d2h):
    assert "nv_ce_matches(" in body

print("PASS: nv_ce_runtime source contract")
