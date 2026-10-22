#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contracts that are hard to exercise without a live AF_XDP stack."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SOURCE = (ROOT / "net/xdp/xsk_xdev_ext.c").read_text(encoding="utf-8")
REDIRECT = (ROOT / "tools/xdev_ext_xsk_redirect.c").read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : pos]
    raise AssertionError(f"unterminated function: {signature}")


rx_dispatch = function_body(SOURCE, "xsk_xdev_ext_rx_dispatch(")
after_dispatch = rx_dispatch.split("xdev_ext_binding_dispatch(", 1)[1]
error_path = after_dispatch.split(
    "if (plan.action == XDEV_EXT_BINDING_ACTION_TERMINAL)", 1
)[0]

assert "if (unlikely(ret))" in error_path
assert "return XSK_XDEV_EXT_RX_TERMINAL;" in error_path, (
    "an attempted RX policy dispatch failure must fail closed"
)
assert "return XSK_XDEV_EXT_RX_C_FALLBACK;" not in error_path, (
    "dispatch errors must not bypass the attached RX policy"
)

# The userspace redirect owner is built on both the project's older local
# libbpf and current distributions where the pre-1.0 XDP APIs were removed.
assert "<bpf/libbpf_version.h>" in REDIRECT
assert "LIBBPF_MAJOR_VERSION >= 1" in REDIRECT
for token in (
    "bpf_map_create(",
    "bpf_prog_load(",
    "bpf_xdp_attach(",
    "bpf_xdp_query_id(",
    "bpf_xdp_detach(",
):
    assert token in REDIRECT
for token in (
    "bpf_create_map_name(",
    "bpf_load_program(",
    "bpf_set_link_xdp_fd(",
    "bpf_get_link_xdp_id(",
    "bpf_set_link_xdp_fd_opts(",
):
    assert token in REDIRECT

# A rejected redirect program must say why: the verifier log is the only
# evidence of which bound was lost, and EINVAL alone does not name it.
load_body = REDIRECT[REDIRECT.index("static int production_prog_load("):]
load_body = load_body[:load_body.index("\n}\n")]
assert re.search(r"fprintf\(stderr,[^;]*verifier_log\)", load_body), (
    "production_prog_load must report the verifier log when loading fails"
)

print("PASS: AF_XDP XDEV_EXT source policy contracts")
