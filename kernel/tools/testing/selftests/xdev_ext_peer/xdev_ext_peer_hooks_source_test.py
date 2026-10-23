#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract of the native peer hooks that host code cannot execute.

Requirements P3 (NIC receive into device memory: netdevice hooks, mlx5 RQ),
P4 (completion-driven NET stage, old synchronous path kept compiled out under
XDEV_EXT_PEER_NET_SYNC_ONE), P5 (ice/E810 peer TX hook) and the PRP fallback of
P2. Each check names the requirement it covers. Hardware behaviour is not
claimed; compile coverage is kcheck.sh's job (see results/P/API.md section G).

XDEV_EXT_PREPARED_TREE=<prepared upstream tree> additionally checks that every
ice overlay file was first committed byte-identical to upstream.
"""
from pathlib import Path
import os
import re
import subprocess
import sys

KERNEL = Path(__file__).resolve().parents[4]
MLX5 = KERNEL / "drivers/net/ethernet/mellanox/mlx5/core"
ICE = KERNEL / "drivers/net/ethernet/intel/ice"
results = []


def check(requirement, ok, text):
    results.append((requirement, bool(ok), text))


def read(path):
    try:
        return path.read_text()
    except OSError:
        return ""


def sources(root):
    if not root.is_dir():
        return {}
    return {p: p.read_text() for p in sorted(root.rglob("*")) if p.suffix in (".c", ".h")}


# API callback parameters contain parentheses; match them without truncating the signature.
def body(text, name):
    """Body of the definition of function @name in @text, or None."""
    m = re.search(r"^[^\n;#]*\b" + re.escape(name) + r"\(((?:[^()]|\([^()]*\))*)\)\s*\{", text, re.M)
    if not m:
        return None, None
    i = m.end()
    depth = 1
    while depth and i < len(text):
        depth += (text[i] == "{") - (text[i] == "}")
        i += 1
    return m.group(1), text[m.end():i]


def find(files, name):
    for path, text in files.items():
        params, code = body(text, name)
        if code is not None:
            return path, params, code
    return None, None, None


def params_match(params, *types):
    parts = [re.sub(r"\s+", " ", p.strip()) for p in (params or "").split(",")]
    if len(parts) != len(types):
        return False
    return all(re.match(re.escape(t) + r"(\s|\*|$)", p) or p.startswith(t) for p, t in zip(parts, types))


def functions_with(files, *needles):
    """(path, name) of every function whose body contains all @needles."""
    found = []
    for path, text in files.items():
        for m in re.finditer(r"^(?:static\s+)?[\w\s\*]+?\b(\w+)\(((?:[^()]|\([^()]*\))*)\)\s*\{", text, re.M):
            i, depth = m.end(), 1
            while depth and i < len(text):
                depth += (text[i] == "{") - (text[i] == "}")
                i += 1
            code = text[m.end():i]
            if all(n in code or n in m.group(2) for n in needles):
                found.append((path, m.group(1), code))
    return found


def split_sync(text, macro="XDEV_EXT_PEER_NET_SYNC_ONE"):
    """(default-build lines, lines only under #ifdef macro)."""
    stack, default, sync = [], [], []
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"#\s*if(n?def)?\b", s):
            pos = re.match(r"#\s*ifdef\s+" + macro + r"\b", s) or re.match(r"#\s*if\s+defined\s*\(?\s*" + macro + r"\b", s)
            neg = re.match(r"#\s*ifndef\s+" + macro + r"\b", s) or re.match(r"#\s*if\s+!\s*defined\s*\(?\s*" + macro + r"\b", s)
            stack.append(["pos" if pos else "neg" if neg else "other", False])
            continue
        if re.match(r"#\s*else\b", s) and stack:
            stack[-1][1] = True
            continue
        if re.match(r"#\s*endif\b", s) and stack:
            stack.pop()
            continue
        in_sync = any((k == "pos" and not e) or (k == "neg" and e) for k, e in stack)
        (sync if in_sync else default).append(line)
    return "\n".join(default), "\n".join(sync)


def netdevice():
    text = re.sub(r"\s+", " ", read(KERNEL / "include/linux/netdevice.h"))
    check("P3", re.search(r"int \(\*ndo_xdev_ext_peer_rx\)\( ?struct net_device \*[^,]*, ?u32[^,]*, ?struct xdev_ext_peer_rx \*[^)]*\);", text),
          "netdevice.h declares ndo_xdev_ext_peer_rx(dev, queue, struct xdev_ext_peer_rx *)")
    check("P3", re.search(r"int \(\*ndo_xdev_ext_peer_rx_flush\)\( ?struct net_device \*[^,]*, ?u32[^)]*\);", text),
          "netdevice.h declares ndo_xdev_ext_peer_rx_flush(dev, queue)")
    check("P3", "struct xdev_ext_peer_rx;" in text, "netdevice.h forward-declares struct xdev_ext_peer_rx")
    check("P5", re.search(r"int \(\*ndo_xdev_ext_peer_tx\)\( ?struct net_device \*[^,]*, ?u32[^,]*, ?struct xdev_ext_peer_tx \*[^)]*\);", text),
          "ndo_xdev_ext_peer_tx keeps its signature for every driver")


def ops_member(text, member):
    m = re.search(r"\." + member + r"\s*=\s*(\w+)\s*,", text)
    return m.group(1) if m else None


def mlx5():
    files = sources(MLX5)
    main = read(MLX5 / "en_main.c")
    rx = ops_member(main, "ndo_xdev_ext_peer_rx")
    flush = ops_member(main, "ndo_xdev_ext_peer_rx_flush")
    tx = ops_member(main, "ndo_xdev_ext_peer_tx")
    check("P3", rx, "mlx5e netdev ops set .ndo_xdev_ext_peer_rx")
    check("P3", flush, "mlx5e netdev ops set .ndo_xdev_ext_peer_rx_flush")
    _, params, code = find(files, rx) if rx else (None, None, None)
    check("P3", code is not None and params_match(params, "struct net_device", "u32", "struct xdev_ext_peer_rx"),
          "mlx5 RX post hook defined with the netdevice signature")
    check("P3", code is not None and "->next" in code, "mlx5 RX post walks the whole element chain")
    check("P3", code is not None and re.search(r"mkey|lkey", code), "mlx5 RX WQE data segment carries the peer MKEY")
    _, params, fcode = find(files, flush) if flush else (None, None, None)
    check("P3", fcode is not None and params_match(params, "struct net_device", "u32"), "mlx5 RX flush defined with the netdevice signature")
    completers = [n for p, n, c in functions_with(files, "xdev_ext_peer_rx", "->complete(") if n not in (rx, flush)]
    check("P3", completers, "an mlx5 RX completion function calls rx->complete() outside the post path")
    poll = [n for p, n, c in functions_with(files) if re.search(r"poll_rx_cq|handle_rx_cqe|rx_cqe", n)
            and any(re.search(r"\b" + re.escape(x) + r"\(", c) for x in completers)]
    check("P3", completers and poll, "mlx5 peer RX completion is reached from the RX CQ poll path")
    _, _, tcode = find(files, tx) if tx else (None, None, None)
    check("P4", tcode is not None and "->next" in tcode, "mlx5 TX hook posts a chain (one doorbell per batch)")


def ice():
    files = sources(ICE)
    main = read(ICE / "ice_main.c")
    check("P5", ICE.is_dir() and main, "ice driver files are in the overlay")
    dev = ops_member(main, "ndo_xdev_ext_peer_device")
    tx = ops_member(main, "ndo_xdev_ext_peer_tx")
    check("P5", dev and tx, "ice netdev ops set .ndo_xdev_ext_peer_device and .ndo_xdev_ext_peer_tx")
    if dev and tx:
        ops = main[main.index("." + "ndo_xdev_ext_peer_device") - 400:main.index("." + "ndo_xdev_ext_peer_device")]
        check("P5", "CONFIG_XDEV_EXT_MECH" in ops, "ice peer ops are under CONFIG_XDEV_EXT_MECH")
    _, params, dcode = find(files, dev) if dev else (None, None, None)
    check("P5", dcode is not None and params_match(params, "struct net_device") and "pdev" in dcode,
          "ice peer device hook returns the PF PCI function")
    _, params, tcode = find(files, tx) if tx else (None, None, None)
    check("P5", tcode is not None and params_match(params, "struct net_device", "u32", "struct xdev_ext_peer_tx"),
          "ice peer TX hook defined with the netdevice signature")
    check("P5", tcode is not None and "->next" in tcode, "ice TX posts the whole chain")
    check("P5", tcode is not None and "ICE_TX_DESC_CMD_EOP" in tcode and "dma_address" in tcode,
          "ice TX writes the peer payload descriptor with EOP")
    check("P5", tcode is not None and re.search(r"xdp_ring", tcode), "ice TX is built on the XDP TX ring")
    completers = [n for p, n, c in functions_with(files, "xdev_ext_peer_tx", "->complete(") if n != tx]
    check("P5", completers, "an ice TX clean function calls tx->complete()")
    prepared = os.environ.get("XDEV_EXT_PREPARED_TREE")
    if prepared and ICE.is_dir():
        for path in sorted(files):
            rel = path.relative_to(KERNEL)
            upstream = Path(prepared) / rel
            if not upstream.exists():
                continue
            first = subprocess.run(["git", "log", "--diff-filter=A", "--format=%H", "--", "kernel/" + str(rel)],
                                   cwd=KERNEL.parent, capture_output=True, text=True).stdout.split()
            same = first and subprocess.run(["git", "show", first[-1] + ":kernel/" + str(rel)], cwd=KERNEL.parent,
                                            capture_output=True).stdout == upstream.read_bytes()
            check("P5", same, "ice overlay %s first committed unmodified from upstream" % rel)


def mech_net():
    text = read(KERNEL / "io_uring/xdev_ext_mech_net.c")
    default, sync = split_sync(text)
    check("P4", re.search(r"#\s*(ifdef|if\s+defined\s*\(?)\s*XDEV_EXT_PEER_NET_SYNC_ONE", text),
          "xdev_ext_mech_net.c keeps the old path under #ifdef XDEV_EXT_PEER_NET_SYNC_ONE")
    check("P4", "xdev_ext_peer_net_send_stoppable(" in sync, "the SYNC_ONE path is the one-at-a-time synchronous send")
    check("P4", "xdev_ext_peer_net_send_stoppable(" not in default and "wait_for_completion" not in default,
          "default NET stage never waits synchronously for a native completion")
    check("P4", '#include "xdev_ext_peer_net_track.h"' in default, "default NET stage uses the in-flight tracker")
    for name in ("xdev_ext_peer_net_track_init(", "xdev_ext_peer_net_track_complete(", "xdev_ext_peer_net_track_abandon(",
                 "xdev_ext_peer_net_track_expired(", "xdev_ext_peer_net_post_tx("):
        check("P4", name in default, "default NET stage calls " + name[:-1])
    for name in ("xdev_ext_peer_net_post_rx(", "xdev_ext_peer_net_rx_flush(", "xdev_ext_peer_net_bind_dir(",
                 "xdev_ext_peer_net_rx_result(", "xdev_ext_peer_net_rx_check("):
        check("P3", name in default, "NET FROM_DEVICE stage calls " + name[:-1])
    check("P3", not re.search(r"st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE\)\s*return -EOPNOTSUPP", default),
          "default NET bind no longer refuses FROM_DEVICE by itself")
    check("P4", re.search(r"\.flags\s*=\s*XDEV_EXT_MECH_CLASS_F_ORDERED", text), "NET stays an ordered class")
    peer = read(KERNEL / "io_uring/xdev_ext_peer_net.c")
    for name in ("xdev_ext_peer_net_bind_dir", "xdev_ext_peer_net_peer", "xdev_ext_peer_net_post_tx",
                 "xdev_ext_peer_net_post_rx", "xdev_ext_peer_net_rx_flush"):
        check("P3" if "rx" in name or "dir" in name else "P4", "EXPORT_SYMBOL_GPL(" + name + ")" in peer,
              "xdev_ext_peer_net.c exports " + name)
    for name in ("xdev_ext_peer_net_post_tx", "xdev_ext_peer_net_post_rx"):
        _, _, code = find({1: peer}, name)
        check("P4", code is not None and "wait_for_completion" not in code, name + " does not wait")
    _, _, code = find({1: peer}, "xdev_ext_peer_net_bind_dir")
    check("P3", code is not None and "ndo_xdev_ext_peer_rx_flush" in code and "real_num_rx_queues" in code,
          "RX bind requires the RX and flush hooks and a valid RX queue")


def nvme():
    text = read(KERNEL / "drivers/nvme/host/xdev_ext_mech_nvme.c")
    check("P2", "xdev_ext_peer_nvme_prp_build(" in text, "mechanism NVMe builds PRP lists over peer pages")
    check("P2", "xdev_ext_peer_nvme_sgl_build(" in text, "mechanism NVMe builds SGL data blocks with the shared rule")
    m = re.search(r"if \(xdev_ext_mech_session_pool\(st->s\)->kind == XDEV_EXT_MECH_POOL_PEER\) \{(.*?)\n \}", text, re.S)
    check("P2", m and "nvme_ctrl_sgl_supported" not in m.group(1),
          "GPU-pool NVMe bind accepts a PCIe controller without SGL (PRP fallback)")


def main():
    netdevice()
    mlx5()
    ice()
    mech_net()
    nvme()
    failed = [r for r in results if not r[1]]
    for requirement, ok, text in results:
        print(("ok - " if ok else "not ok - ") + requirement + ": " + text)
    print("# peer hook source contract: %d passed, %d failed" % (len(results) - len(failed), len(failed)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
