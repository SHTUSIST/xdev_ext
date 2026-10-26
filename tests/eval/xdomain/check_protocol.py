# SPDX-License-Identifier: GPL-2.0
"""Strict metadata-only wire contract for the two-host checker."""

import json
import re
import struct

MAX_JSON = 1024 * 1024
U64 = (1 << 64) - 1
COMMANDS = {
    "preflight",
    "prepare",
    "start",
    "wait",
    "stop",
    "observe",
    "verify",
    "close",
    "cancel",
}
IDENTITY = {
    "version",
    "run_id",
    "sha",
    "role",
    "case",
    "direction",
    "epoch",
    "request_id",
}
REQUEST = {"identity", "command", "deadline_ms", "part_index", "part_count", "payload"}
RESPONSE = {
    "identity",
    "command",
    "phase",
    "fate",
    "error",
    "held",
    "cleanup_permissions",
    "evidence",
    "payload",
    "part_index",
    "part_count",
}
PHASES = {
    "NEW",
    "GPU_BUSY",
    "GPU_READY",
    "EXTERNAL_READY",
    "CREATE_ATTEMPTED",
    "SESSION_CREATED",
    "START_ACCEPTED",
    "TRANSPORT_DONE",
    "DRAINED_SAFE",
    "VERIFYING",
    "VERIFIED",
    "CLOSED",
    "FAILED_SAFE",
    "HELD",
}
FATES = {"EMPTY", "CREATE_ATTEMPTED", "ACTIVE", "SAFE", "FAILED_SAFE", "HELD"}


def integer(x, maximum=U64, minimum=0):
    if type(x) is not int or not minimum <= x <= maximum:
        raise ValueError("integer outside contract")
    return x


def keys(x, required):
    if type(x) is not dict or set(x) != set(required):
        raise ValueError("unknown or missing fields")


def _identity(i):
    keys(i, IDENTITY)
    if integer(i["version"]) != 1:
        raise ValueError("version")
    for name in ("run_id", "sha", "role", "case", "direction"):
        if type(i[name]) is not str or not 1 <= len(i[name].encode("utf-8")) <= 128:
            raise ValueError("identity string")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", i["sha"]):
        raise ValueError("SHA")
    if i["role"] not in ("tx", "rx") or i["direction"] not in ("a-to-b", "b-to-a"):
        raise ValueError("identity enum")
    integer(i["epoch"])
    integer(i["request_id"])


def _tree(x, depth=0):
    if depth > 32:
        raise ValueError("nesting")
    if type(x) is str and len(x.encode("utf-8")) > MAX_JSON:
        raise ValueError("string bound")
    if type(x) is float:
        raise ValueError("floating point not in protocol")
    if type(x) is int and not -(1 << 63) <= x <= U64:
        raise ValueError("integer overflow")
    if type(x) is list:
        if len(x) > 262144:
            raise ValueError("array bound")
        for v in x:
            _tree(v, depth + 1)
    elif type(x) is dict:
        for k, v in x.items():
            if type(k) is not str:
                raise ValueError("object key")
            _tree(v, depth + 1)


def _geometry(g):
    keys(
        g,
        {
            "allocation_bytes",
            "group_bytes",
            "frame_size",
            "seg_len",
            "depth",
            "native_elems",
        },
    )
    for v in g.values():
        integer(v, minimum=1)


def _request_payload(r):
    p, c = r["payload"], r["command"]
    common = {"gpu_bdf", "nvidia_node", "link_token", "channel", "geometry", "flags"}
    required = {
        "preflight": common,
        "prepare": common
        | {"mode", "groups", "first_seq", "seed", "observer_object", "ptx_path"},
        "start": {"groups", "first_seq"},
        "wait": set(),
        "stop": set(),
        "observe": {"first_ordinal", "limit"},
        "close": set(),
        "cancel": {"reason"},
    }
    if c == "verify":
        if type(p) is not dict:
            raise ValueError("verify payload")
        kind = p.get("kind")
        if kind == "begin":
            keys(p, {"kind", "launch_cookie", "extent_count", "stop_receipts"})
            integer(p["launch_cookie"], minimum=1)
            integer(p["extent_count"], maximum=262144, minimum=1)
            if type(p["stop_receipts"]) is not list or len(p["stop_receipts"]) != 2:
                raise ValueError("pair receipts")
            for receipt in p["stop_receipts"]:
                validate_record(receipt)
                if (
                    receipt["command"] != "stop"
                    or receipt["error"]
                    or not receipt["payload"].get("stop_proved")
                ):
                    raise ValueError("STOP proof")
        elif kind == "extents":
            keys(p, {"kind", "first_extent", "extents"})
            integer(p["first_extent"])
            if type(p["extents"]) is not list or not 1 <= len(p["extents"]) <= 1024:
                raise ValueError("extent count")
            for e in p["extents"]:
                keys(e, {"dst_off", "src_off", "len", "seed", "kind", "reserved"})
                for k in ("dst_off", "src_off", "seed"):
                    integer(e[k])
                integer(e["len"], minimum=1)
                if (
                    e["kind"] not in (1, 2)
                    or type(e["kind"]) is not int
                    or e["reserved"] != 0
                ):
                    raise ValueError("extent kind")
        elif kind == "end":
            keys(p, {"kind", "extent_count"})
            integer(p["extent_count"], maximum=262144, minimum=1)
        else:
            raise ValueError("verify kind")
        return
    keys(p, required[c])
    if c in ("preflight", "prepare"):
        _geometry(p["geometry"])
        for k in ("link_token", "channel", "flags"):
            integer(p[k])
        for k in ("gpu_bdf", "nvidia_node"):
            if type(p[k]) is not str or not 1 <= len(p[k]) <= 256:
                raise ValueError("device string")
    if c in ("prepare", "start"):
        integer(p["groups"], maximum=10000, minimum=1)
        integer(p["first_seq"])
        if p["first_seq"] + p["groups"] - 1 > U64:
            raise ValueError("sequence overflow")
    if c == "prepare":
        integer(p["seed"])
        if p["mode"] not in ("single-group", "bulk-static"):
            raise ValueError("mode")
        for k in ("ptx_path", "observer_object"):
            if type(p[k]) is not str or not 1 <= len(p[k]) <= 4096:
                raise ValueError("artifact path")
    if c == "observe":
        integer(p["first_ordinal"], maximum=9999)
        integer(p["limit"], minimum=1, maximum=32)
    if c == "cancel":
        if type(p["reason"]) is not str or not 1 <= len(p["reason"]) <= 128:
            raise ValueError("cancel reason")


def _stats_payload(p):
    if p["stats_valid"]:
        s = p["stats"]
        keys(
            s,
            {
                "session_id",
                "batches_done",
                "batches_abort",
                "rejects",
                "recycled",
                "held",
                "sequestered",
                "timeouts",
                "inflight",
                "native_publish",
                "protocol_err",
                "published",
                "submitted",
                "completed",
                "last_err",
                "state",
            },
        )
        for k, v in s.items():
            if k in ("submitted", "completed"):
                if type(v) is not list or len(v) != 4:
                    raise ValueError("stage counter array")
                for n in v:
                    integer(n)
            elif k == "last_err":
                integer(v, minimum=-(1 << 31), maximum=0)
            else:
                integer(v)
    if p["transport_valid"]:
        tr = p["transport"]
        keys(tr, {"v3", "rel_policy"})
        v3 = tr["v3"]
        keys(v3, {"v2", "nic_copy_ops", "nic_copy_bytes", "nic_zc_ops", "nic_zc_bytes"})
        v2 = v3["v2"]
        keys(
            v2,
            {
                "v1",
                "retransmits",
                "dup_suppressed",
                "held_acks",
                "held_unacked",
                "rsvd2",
            },
        )
        v1 = v2["v1"]
        keys(
            v1,
            {
                "size",
                "version",
                "session_id",
                "native_controls",
                "pending_acks",
                "uncertain_controls",
                "rsvd",
            },
        )
        for layer in (v1, v2, v3):
            for k, v in layer.items():
                if k not in ("v1", "v2"):
                    integer(v)
        if v1["size"] != 216 or v1["version"] != 4:
            raise ValueError("transport layout")
        rel = tr["rel_policy"]
        keys(
            rel,
            {
                "version",
                "size",
                "window",
                "initial_credit",
                "rto_ns",
                "rto_max_ns",
                "backoff",
                "max_attempts",
                "ack_rule",
                "ack_every",
                "ack_delay_ns",
                "resend_order",
                "flags",
                "bad_field",
                "rsvd0",
                "rsvd",
            },
        )
        for k, v in rel.items():
            if k == "rsvd":
                if type(v) is not list or len(v) != 6:
                    raise ValueError("policy reserved array")
                for n in v:
                    integer(n)
            else:
                integer(v)


def _response_payload(r):
    p, c = r["payload"], r["command"]
    # An asynchronous HELD notification may interrupt any command; no success
    # facts are inferred from an absent interrupted-command payload.
    if r["held"] or r["error"]:
        return
    names = {
        "preflight": {
            "available",
            "reason",
            "device_identity",
            "link_identity",
            "kernel_identity",
            "visibility",
            "raw_evidence",
        },
        "prepare": {
            "session_id",
            "registration_bytes",
            "producer_sync_proved",
            "guard_sync_proved",
            "create_error",
            "stop_proved",
        },
        "start": {"start_accepted", "arm_error", "start_error"},
        "wait": {"stats_valid", "stats", "transport_valid", "transport"},
        "stop": {
            "stop_proved",
            "first_error",
            "stop_error",
            "stats_valid",
            "stats",
            "transport_valid",
            "transport",
        },
        "observe": {"records", "next_ordinal", "total", "error_bits"},
        "verify": {
            "bytes",
            "mismatches",
            "first_bad",
            "launch_cookie",
            "visibility",
            "visibility_error",
        },
        "close": {"closed", "retained_resources"},
        "cancel": {"hold_reasons", "retained_resources"},
    }
    keys(p, names[c])
    if c == "preflight":
        if type(p["available"]) is not bool or type(p["reason"]) is not str:
            raise ValueError("preflight type")
        for k in (
            "device_identity",
            "link_identity",
            "kernel_identity",
            "raw_evidence",
        ):
            if type(p[k]) is not dict:
                raise ValueError("preflight evidence object")
    if c == "prepare":
        integer(p["session_id"], minimum=1)
        integer(p["registration_bytes"], minimum=1)
        for k in ("producer_sync_proved", "guard_sync_proved", "stop_proved"):
            if type(p[k]) is not bool:
                raise ValueError("prepare proof type")
        integer(p["create_error"], minimum=-(1 << 31), maximum=0)
    if c == "start":
        if type(p["start_accepted"]) is not bool:
            raise ValueError("START proof type")
        for k in ("arm_error", "start_error"):
            integer(p[k], minimum=-(1 << 31), maximum=0)
    if c in ("wait", "stop"):
        for k in ("stats_valid", "transport_valid"):
            if type(p[k]) is not bool:
                raise ValueError("stats validity type")
        if type(p["stats"]) is not dict or type(p["transport"]) is not dict:
            raise ValueError("stats objects")
        _stats_payload(p)
        if c == "stop":
            if type(p["stop_proved"]) is not bool:
                raise ValueError("STOP proof type")
            for k in ("first_error", "stop_error"):
                integer(p[k], minimum=-(1 << 31), maximum=0)
    if c == "observe":
        if type(p["records"]) is not list or len(p["records"]) > 32:
            raise ValueError("observer page bound")
        for item in p["records"]:
            keys(item, {"ordinal", "record"})
            integer(item["ordinal"], maximum=9999)
            if type(item["record"]) is not dict:
                raise ValueError("observer record type")
        integer(p["total"], minimum=1, maximum=10000)
        integer(p["error_bits"])
        if p["next_ordinal"] is not None:
            integer(p["next_ordinal"], maximum=9999)
    if c == "verify":
        for k in ("bytes", "mismatches", "first_bad", "launch_cookie"):
            integer(p[k])
        integer(p["visibility_error"], minimum=-(1 << 31), maximum=0)
    if c in ("preflight", "verify") and p["visibility"] not in (
        "NATIVE_OWNER",
        "HOST_FLUSH_OWNER",
    ):
        raise ValueError("visibility enum")
    if c == "close" and (
        type(p["closed"]) is not bool or type(p["retained_resources"]) is not list
    ):
        raise ValueError("close facts")


def validate_record(r, expected=None):
    if type(r) is not dict:
        raise ValueError("record object")
    response = "phase" in r
    keys(r, RESPONSE if response else REQUEST)
    _tree(r)
    _identity(r["identity"])
    if r["command"] not in COMMANDS:
        raise ValueError("command")
    integer(r["part_count"], maximum=262146, minimum=1)
    integer(r["part_index"], maximum=r["part_count"] - 1)
    if r["command"] != "verify" or response:
        if (r["part_index"], r["part_count"]) != (0, 1):
            raise ValueError("single-part command")
    if not response:
        integer(r["deadline_ms"], maximum=120000, minimum=1)
        _request_payload(r)
    else:
        if r["phase"] not in PHASES or r["fate"] not in FATES:
            raise ValueError("state enum")
        integer(r["error"], maximum=0, minimum=-(1 << 31))
        integer(r["cleanup_permissions"], maximum=15)
        if (
            type(r["held"]) is not bool
            or type(r["evidence"]) is not dict
            or type(r["payload"]) is not dict
        ):
            raise ValueError("response type")
        if r["held"] or r["phase"] == "HELD" or r["fate"] == "HELD":
            if (
                not r["held"]
                or r["phase"] != "HELD"
                or r["fate"] != "HELD"
                or r["cleanup_permissions"] != 0
            ):
                raise ValueError("HELD contradiction")
        if r["error"] and r["phase"] in {
            "START_ACCEPTED",
            "TRANSPORT_DONE",
            "DRAINED_SAFE",
            "VERIFIED",
            "CLOSED",
        }:
            raise ValueError("success state with error")
        if not r["error"] and not r["held"]:
            phases = {
                "preflight": {"NEW"},
                "prepare": {"SESSION_CREATED"},
                "start": {"START_ACCEPTED"},
                "wait": {"TRANSPORT_DONE"},
                "stop": {"DRAINED_SAFE"},
                "observe": {"DRAINED_SAFE"},
                "verify": {"VERIFIED"},
                "close": {"CLOSED"},
            }
            if r["command"] in phases and r["phase"] not in phases[r["command"]]:
                raise ValueError("impossible success phase")
            if (
                r["command"] in ("prepare", "start", "wait")
                and r["cleanup_permissions"]
            ):
                raise ValueError("active cleanup")
    if response:
        _response_payload(r)
    if expected:
        ei = expected.get("identity", expected)
        if r["identity"] != ei:
            raise ValueError("response identity")
        if "command" in expected and r["command"] != expected["command"]:
            raise ValueError("response command")
        prior = expected.get("phase", expected.get("prior_phase"))
        legal = {
            "preflight": {"NEW"},
            "prepare": {"NEW", "VERIFIED", "DRAINED_SAFE"},
            "start": {"SESSION_CREATED"},
            "wait": {"START_ACCEPTED"},
            "stop": {"SESSION_CREATED", "START_ACCEPTED", "TRANSPORT_DONE"},
            "observe": {"DRAINED_SAFE"},
            "verify": {"DRAINED_SAFE"},
            "close": {"VERIFIED", "DRAINED_SAFE", "FAILED_SAFE", "GPU_READY"},
        }
        if prior and r["command"] in legal and prior not in legal[r["command"]]:
            raise ValueError("prior phase")


def _pairs(items):
    d = {}
    for k, v in items:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def decode_frame(frame):
    if type(frame) is not bytes or len(frame) < 4:
        raise ValueError("frame prefix")
    n = struct.unpack("!I", frame[:4])[0]
    if not 1 <= n <= MAX_JSON or len(frame) != n + 4:
        raise ValueError("frame size")
    try:
        r = json.loads(
            frame[4:].decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
        validate_record(r)
        return r
    except (UnicodeError, RecursionError, TypeError, json.JSONDecodeError) as e:
        raise ValueError("invalid JSON") from e


def encode_record(record):
    validate_record(record)
    body = json.dumps(
        record, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if not 1 <= len(body) <= MAX_JSON:
        raise ValueError("frame size")
    return struct.pack("!I", len(body)) + body
