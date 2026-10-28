# SPDX-License-Identifier: GPL-2.0
"""Independent offset mapping oracle. Never reads GPU payload bytes."""

from check_protocol import integer, keys, U64

GUARD_XOR = 0xD6E8FEB86659FD93


def _invalid_value(fn):
    def checked(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (KeyError, TypeError, OverflowError, IndexError) as error:
            raise ValueError("missing or malformed oracle metadata") from error

    return checked


def pattern_byte(seed, off):
    integer(seed)
    integer(off)
    x = seed ^ ((off * 0x9E3779B97F4A7C15) & U64)
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & U64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & U64
    return (x ^ (x >> 31)) & 255


def _records(records, role, c):
    if type(records) is not list or len(records) != c["groups"]:
        raise ValueError("missing observer groups")
    out = {}
    for r in records:
        keys(
            r,
            {
                "session_id",
                "batch_id",
                "key",
                "epoch",
                "generation",
                "local_inc",
                "remote_inc",
                "direction",
                "channel",
                "build_attempts",
                "cqe_seen",
                "error_bits",
                "spans",
                "tag",
                "completion",
            },
        )
        for k in (
            "session_id",
            "batch_id",
            "key",
            "epoch",
            "generation",
            "local_inc",
            "remote_inc",
            "direction",
            "channel",
            "build_attempts",
            "cqe_seen",
            "error_bits",
        ):
            integer(r[k])
        ordinal = r["key"] - c["first_seq"]
        if not 0 <= ordinal < c["groups"] or ordinal in out:
            raise ValueError("observer ordinal")
        other = "rx" if role == "tx" else "tx"
        if (
            r["session_id"] != c[role + "_session_id"]
            or r["epoch"] != c["epoch"]
            or r["local_inc"] != c[role + "_local_inc"]
            or r["remote_inc"] != c[other + "_local_inc"]
        ):
            raise ValueError("observer identity")
        if (
            r["direction"] != (1 if role == "tx" else 2)
            or r["channel"] != c.get("channel", 0)
            or not r["generation"]
            or not r["batch_id"]
            or r["build_attempts"] < 1
            or r["cqe_seen"] != 1
            or r["error_bits"]
        ):
            raise ValueError("observer completion")
        spans = r["spans"]
        if type(spans) is not list or not 1 <= len(spans) <= 64:
            raise ValueError("span count")
        intervals = []
        for s in spans:
            keys(s, {"allocation_off", "data_off", "len"})
            for v in s.values():
                integer(v)
            a = s["allocation_off"] + s["data_off"]
            b = a + s["len"]
            if (
                a > U64
                or b > U64
                or b > c["allocation_bytes"]
                or not s["len"]
                or any(v % 4096 for v in s.values())
            ):
                raise ValueError("span bounds/alignment")
            intervals.append((a, b))
        ordered = sorted(intervals)
        if any(ordered[i][1] > ordered[i + 1][0] for i in range(len(ordered) - 1)):
            raise ValueError("within-group overlap")
        if sum(b - a for a, b in intervals) != c["group_bytes"]:
            raise ValueError("group coverage")
        q = r["completion"]
        keys(
            q,
            {
                "status",
                "outcome",
                "remote",
                "elems_done",
                "group",
                "bytes",
                "crc_errors",
                "rsvd",
                "tag",
            },
        )
        for k in (
            "status",
            "outcome",
            "remote",
            "elems_done",
            "group",
            "bytes",
            "crc_errors",
            "rsvd",
        ):
            integer(q[k])
        tag = r["key"].to_bytes(8, "big").hex() + "00" * 16
        if r["tag"] != (tag if role == "tx" else "00" * 24) or q["tag"] != (
            tag if role == "rx" else "00" * 24
        ):
            raise ValueError("BUILD/CQE tag")
        if (
            q["status"]
            or q["outcome"]
            or q["crc_errors"]
            or q["rsvd"]
            or q["remote"] != (2 if role == "tx" else 0)
            or q["bytes"] != c["group_bytes"]
            or q["elems_done"] != c["group_bytes"] // 4096
        ):
            raise ValueError("native CQE")
        out[ordinal] = (r, intervals)
    return out


@_invalid_value
def build_expectations(tx, rx, config):
    c = config
    for k in (
        "allocation_bytes",
        "group_bytes",
        "groups",
        "first_seq",
        "epoch",
        "seed",
        "tx_session_id",
        "rx_session_id",
        "tx_local_inc",
        "rx_local_inc",
    ):
        integer(c[k])
    if (
        not 0 < c["allocation_bytes"] <= 1024**3
        or c["allocation_bytes"] % 4096
        or not 0 < c["group_bytes"] <= c["allocation_bytes"]
        or c["group_bytes"] % 4096
        or not 1 <= c["groups"] <= 10000
        or c["first_seq"] + c["groups"] - 1 > U64
    ):
        raise ValueError("oracle geometry")
    keys(c["link_token"], {"tx", "rx"})
    for v in c["link_token"].values():
        integer(v, minimum=1)
    ts, rs = _records(tx, "tx", c), _records(rx, "rx", c)
    # One entry per native tile bounds memory independently of descriptor count.
    tiles = [
        (i, c["seed"] ^ GUARD_XOR, 2) for i in range(0, c["allocation_bytes"], 4096)
    ]
    previous = -1
    for ordinal in range(c["groups"]):
        tr, src = ts[ordinal]
        rr, dst = rs[ordinal]
        group = tr["completion"]["group"]
        if group != rr["completion"]["group"] or group <= previous:
            raise ValueError("transport sequence")
        previous = group
        src_tiles = [i for a, b in src for i in range(a, b, 4096)]
        dst_tiles = [i for a, b in dst for i in range(a, b, 4096)]
        for s, d in zip(src_tiles, dst_tiles):
            tiles[d // 4096] = (s, c["seed"], 1)
    result = []
    for i, (src, seed, kind) in enumerate(tiles):
        dst = i * 4096
        if (
            result
            and result[-1]["kind"] == kind
            and result[-1]["seed"] == seed
            and result[-1]["src_off"] + result[-1]["len"] == src
        ):
            result[-1]["len"] += 4096
        else:
            result.append(
                {
                    "dst_off": dst,
                    "src_off": src,
                    "len": 4096,
                    "seed": seed,
                    "kind": kind,
                    "reserved": 0,
                }
            )
    return result


@_invalid_value
def validate_summary(summary, extents, launch_cookie):
    integer(launch_cookie, minimum=1)
    if not extents:
        raise ValueError("empty extents")
    cursor = 0
    for e in extents:
        if e["dst_off"] != cursor or e["len"] <= 0:
            raise ValueError("expectation gap/overlap")
        cursor += e["len"]
    if (
        not isinstance(summary, dict)
        or not {"bytes", "mismatches", "first_bad", "launch_cookie"} <= summary.keys()
    ):
        raise ValueError("summary fields")
    for k in ("bytes", "mismatches", "first_bad", "launch_cookie"):
        integer(summary[k])
    if (
        summary["bytes"] != cursor
        or summary["mismatches"] != 0
        or summary["first_bad"] != U64
        or summary["launch_cookie"] != launch_cookie
    ):
        raise ValueError("GPU summary mismatch or untouched sentinel")
