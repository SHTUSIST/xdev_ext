#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract for the opt-in connected-UDP preload front end."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
PRELOAD = ROOT / "tools/io_uring_unified_preload.c"
CORE = ROOT / "tools/xdev_ext_preload_core.h"
CONFIG = ROOT / "tools/xdev_ext_preload_config.h"
MAKEFILE = ROOT / "tools/Makefile.unified_ops"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    preload = PRELOAD.read_text()
    core = CORE.read_text()
    config = CONFIG.read_text()
    makefile = MAKEFILE.read_text()

    # The constructor's configuration snapshot reads the switch.
    require('xdev_ext_cfg_get(env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED")' in config,
            "socket takeover is not independently opt-in")
    require("xdev_ext_preload_config_parse(&env, &xdev_ext_cfg)" in preload,
            "front end does not take the configuration snapshot")
    for symbol in ("send", "sendto", "sendmsg", "getsockopt", "getpeername"):
        require(f'xdev_ext_resolve_symbol(&xdev_ext_real.{symbol}_fn, "{symbol}")' in preload,
                f"missing RTLD_NEXT resolution for {symbol}")
    for signature in ("ssize_t send(", "ssize_t sendto(", "ssize_t sendmsg("):
        require(signature in preload, f"missing exported wrapper: {signature}")

    for token in ("F_DUPFD_CLOEXEC", "SO_TYPE", "SO_DOMAIN", "SO_PROTOCOL",
                  "IPPROTO_UDP", "getpeername_fn"):
        require(token in preload, f"socket identity gate lacks {token}")
    require("xdev_ext_preload_execute_send(" in preload,
            "wrapper bypasses the tested publish/no-replay state machine")
    require("IO_UNIFIED_OP_SEND" in core and "sqe->addr3" in core,
            "pure encoder does not emit unified SEND with registered stats")
    require("nm -D $(PRELOAD_LIB) | grep -q ' T send$$'" in makefile,
            "build test does not require the send export")
    require("XDEV_EXT_PRELOAD_SOCKET_ENABLED=1" in makefile,
            "stock-host enabled fallback smoke is not wired")
    require("custom_send_count=" in preload and "custom_send_bytes=" in preload,
            "report lacks unambiguous completed unified SEND counters")

    print("ok 1 - connected UDP preload source contract")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print(f"not ok 1 - {error}")
        raise SystemExit(1)
