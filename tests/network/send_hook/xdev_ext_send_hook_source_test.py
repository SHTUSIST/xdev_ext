#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract for both ordinary-socket unified SEND implementations."""

import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SOURCE = Path(os.environ.get(
    "XDEV_EXT_SEND_HOOK_UNIFIED_OPS",
    ROOT / "io_uring/unified_ops.c",
))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.DOTALL)
    require(match is not None, f"missing function: {name}")

    opening = source.find("{", match.start())
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError(f"unterminated function: {name}")


def require_socket_send_contract(source: str, name: str) -> None:
    body = function_body(source, name)
    flags_pattern = re.compile(
        r"msg\.msg_flags\s*=\s*xdev_ext_send_hook_effective_flags\s*\("
        r"\s*\(__u32\)op->offset\s*,\s*op->file->f_flags\s*&\s*O_NONBLOCK\s*,"
        r"\s*MSG_DONTWAIT\s*\)\s*;",
        re.DOTALL,
    )
    native_pattern = re.compile(
        r"ret\s*=\s*xdev_ext_send_hook_call_native\s*\(\s*native_called\s*,"
        r"\s*sock_sendmsg\s*\(\s*sock\s*,\s*&msg\s*\)\s*\)\s*;",
        re.DOTALL,
    )

    flags = flags_pattern.search(body)
    native = native_pattern.search(body)
    require(flags is not None,
            f"{name} must derive msg_flags through xdev_ext_send_hook_effective_flags")
    require(native is not None,
            f"{name} must wrap sock_sendmsg with xdev_ext_send_hook_call_native")
    require(flags.start() < native.start(),
            f"{name} must set effective flags before crossing the native boundary")
    require(body.count("xdev_ext_send_hook_effective_flags(") == 1,
            f"{name} must derive effective flags exactly once")
    require(body.count("xdev_ext_send_hook_call_native(") == 1,
            f"{name} must cross the tracked native boundary exactly once")
    require(body.count("sock_sendmsg(") == 1,
            f"{name} must call sock_sendmsg exactly once")


def main() -> None:
    source = SOURCE.read_text()
    require_socket_send_contract(source, "io_unified_do_send_umem")
    require_socket_send_contract(source, "io_unified_do_send")
    print("ok 1 - UMEM and non-UMEM socket SEND source contract")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError) as error:
        print(f"not ok 1 - {error}")
        raise SystemExit(1)
