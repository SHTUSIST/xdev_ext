#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Check one host's XDOMAIN trace; software timestamps do not certify hardware."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

PHASES = {"stage_bound", "tx_attempt", "rx_reserved", "cts_sent",
          "cts_received", "grant_accepted", "native_accepted", "native_rejected",
          "native_complete", "consumer_release", "ack_sent", "fail_sent"}
FIELDS = ("session_id", "stage", "direction", "early", "local_inc", "remote_inc",
          "tx_bind", "rx_bind", "group", "key", "ticket", "pool_generation",
          "status", "quiesced", "ts_ns")
IDENTITY = ("key", "local_inc", "remote_inc", "tx_bind", "rx_bind",
            "pool_generation", "early", "direction")
NATIVE_FIELDS = ("session_id", "stage", "class_id", "batch_id", "batch_key",
                 "frame_id", "generation", "ticket", "cookie", "ts_ns",
                 "frame_ordinal", "frame_offset", "frame_length", "bytes", "status")
MAX_EVENTS = 250000


def _number(value, signed=False):
    if type(value) is not int:
        if not isinstance(value, str) or not re.fullmatch(r"-?[0-9]+", value):
            raise ValueError("noninteger trace field")
        value = int(value)
    if not (-(1 << 31) <= value < (1 << 31) if signed else 0 <= value < (1 << 64)):
        raise ValueError("trace field out of range")
    return value


def _record(e):
    if e.get("phase") not in PHASES:
        raise ValueError("unknown XDOMAIN phase")
    out = {"phase": e["phase"]}
    for k in FIELDS:
        if k not in e:
            raise ValueError("missing trace field: " + k)
        out[k] = _number(e[k], signed=k == "status")
    if (not out["session_id"] or out["direction"] not in (1, 2) or
            out["early"] not in (0, 1) or out["quiesced"] not in (0, 1)):
        raise ValueError("invalid session/mode/direction/quiescence")
    return out


def parse_trace(lines):
    """Parse the kernel print format, with bounded line and event counts."""
    events, native = [], []
    for line in lines:
        if len(line) > 16384:
            raise ValueError("oversized trace line")
        if "abi=xdev-xdomain-v1 " in line:
            tail = line.split("abi=xdev-xdomain-v1 ", 1)[1]
            target = events
        elif "abi=xdev-native-v1-nvme-xsk-batch " in line:
            tail = line.split("abi=xdev-native-v1-nvme-xsk-batch ", 1)[1]
            target = native
        else:
            continue
        pairs = [word.split("=", 1) for word in tail.split()]
        if any(len(pair) != 2 for pair in pairs):
            raise ValueError("malformed trace fields")
        d = dict(pairs)
        if len(d) != len(pairs):
            raise ValueError("duplicate trace field")
        if target is events:
            target.append(_record(d))
        elif d.get("phase") in ("native_submit", "record_terminal"):
            for k in NATIVE_FIELDS:
                if k not in d:
                    raise ValueError("missing native field: " + k)
                d[k] = _number(d[k], signed=k == "status")
            target.append(d)
        if len(events) + len(native) > MAX_EVENTS:
            raise ValueError("trace event budget exceeded")
    return events, native


def loss_count(text):
    """Require per-CPU ftrace overrun, commit-overrun and dropped counters."""
    cpus, current = {}, None
    names = {"overrun", "commit overrun", "dropped events"}
    for line in text.splitlines():
        line = line.strip()
        if re.fullmatch(r"cpu[0-9]+:", line):
            current = line[:-1]
            if current in cpus:
                raise ValueError("duplicate CPU statistics")
            cpus[current] = {}
        elif ":" in line and line.split(":", 1)[0] in names:
            name, value = line.split(":", 1)
            if current is None or name in cpus[current]:
                raise ValueError("unscoped/duplicate trace loss counter")
            cpus[current][name] = _number(value.strip())
    if not cpus or any(set(v) != names for v in cpus.values()):
        raise ValueError("complete per-CPU trace loss statistics required")
    total = sum(sum(v.values()) for v in cpus.values())
    if total:
        raise ValueError("trace loss invalidates execution evidence")
    return total


def select_sessions(events, native, session_ids):
    """Restrict a capture to explicit local run IDs, never to process names."""
    ids = {_number(s) for s in session_ids}
    if not ids or 0 in ids:
        raise ValueError("nonzero local session IDs required")
    present = {e["session_id"] for e in events if e["phase"] == "stage_bound"}
    if not ids <= present:
        raise ValueError("requested session admission is missing from capture")
    return ([e for e in events if e["session_id"] in ids],
            [e for e in native if e["session_id"] in ids])


def _one(rows, phase):
    found = [e for e in rows if e["phase"] == phase]
    if len(found) > 1:
        raise ValueError("duplicate " + phase)
    return found[0] if found else None


def _before(a, b, label):
    if a is not None and b is not None and a["ts_ns"] > b["ts_ns"]:
        raise ValueError(label)


def _union_ns(intervals):
    total, end = 0, None
    for start, stop in sorted(intervals):
        if end is None or start > end:
            total += stop - start
            end = stop
        elif stop > end:
            total += stop - end
            end = stop
    return total


def analyze(events, stats, native=()):
    """Analyze a complete capture, never infer admission from requested flags.

    'complete' additionally requires native frame and kernel terminal records.
    'protocol_complete' describes only the observed local protocol boundaries.
    Unknown/error paths keep their counts, but cannot qualify as complete.
    """
    loss_count(stats)
    es = sorted((_record(e) for e in events), key=lambda e: e["ts_ns"])
    if not es or len(es) > MAX_EVENTS:
        raise ValueError("no XDOMAIN execution events or excessive capture")
    stages, attempts, groups = {}, defaultdict(list), defaultdict(list)
    counts = Counter(e["phase"] for e in es)
    for e in es:
        scope = (e["session_id"], e["stage"])
        if e["phase"] == "stage_bound":
            if scope in stages:
                raise ValueError("duplicate stage admission")
            stages[scope] = e
        elif scope not in stages:
            raise ValueError("capture started after stage admission")
        bound = stages[scope]
        if (bound["early"], bound["direction"]) != (e["early"], e["direction"]):
            raise ValueError("stage mode/direction changed")
        if any(e[k] != bound[k] for k in ("local_inc", "remote_inc", "pool_generation")):
            raise ValueError("stage incarnation or pool generation changed")
        if e["phase"] == "tx_attempt":
            attempts[scope + (e["pool_generation"], e["key"])].append(e)
        elif e["phase"] != "stage_bound":
            if not e["group"]:
                # A rejected pre-group post has no successful transaction.
                if e["phase"] != "native_rejected":
                    raise ValueError("missing transaction group")
                continue
            groups[scope + (e["group"],)].append(e)

    errors = sum(e["status"] != 0 for e in es)
    complete, tx_groups, rx_groups = bool(groups), 0, 0
    pregrants, prereceipts, leads, reordered = 0, 0, [], 0
    rx, native_groups, resolved_attempts = [], [], set()
    for scope, rows in groups.items():
        # Receipt duplicates are allowed; they cannot create extra authority.
        base = next((e for e in rows if e["phase"] != "cts_received"), rows[0])
        for e in rows:
            if any(e[k] != base[k] for k in IDENTITY):
                raise ValueError("transaction identity changed")
        tickets = {e["ticket"] for e in rows if e["ticket"]}
        if len(tickets) > 1:
            raise ValueError("transaction ticket changed")
        accepted = _one(rows, "native_accepted")
        done = _one(rows, "native_complete")
        rejected = _one(rows, "native_rejected")
        grant = _one(rows, "grant_accepted")
        release = _one(rows, "consumer_release")
        ack = _one(rows, "ack_sent")
        if rejected:
            complete = False
            if accepted or done:
                raise ValueError("native rejection also reported accepted completion")
        if not accepted or not done or done["status"] or not done["quiesced"]:
            complete = False
        if accepted and done and done["ts_ns"] < accepted["ts_ns"]:
            reordered += 1  # A real callback may win before post returns.
        if accepted:
            native_groups.append((scope, base, accepted))
        if base["direction"] == 1:
            tx_groups += 1
            attempt_key = scope[:2] + (base["pool_generation"], base["key"])
            tried = attempts.get(attempt_key, [])
            resolved_attempts.add(attempt_key)
            received = [e for e in rows if e["phase"] == "cts_received"]
            if not tried or not received or not grant:
                complete = False
            else:
                first, receipt = tried[0], received[0]
                _before(receipt, grant, "grant accepted before CTS receipt")
                _before(grant, accepted, "native accepted before grant")
                if base["early"]:
                    lead = first["ts_ns"] - grant["ts_ns"]
                    leads.append(lead)
                    pregrants += lead > 0
                    prereceipts += receipt["ts_ns"] < first["ts_ns"]
        else:
            rx_groups += 1
            reserved = _one(rows, "rx_reserved")
            sent = [e for e in rows if e["phase"] == "cts_sent"]
            first_cts = sent[0] if sent else None
            if not all((reserved, accepted, done, first_cts, release, ack)):
                complete = False
            _before(reserved, accepted, "native accepted before RX reservation")
            _before(accepted, first_cts, "CTS sent before RX native acceptance")
            _before(done, release, "consumer release before native completion")
            _before(release, ack, "ACK before consumer release")
            if ack and (not release or not done or not release["quiesced"] or
                        not done["quiesced"] or release["status"] or done["status"]):
                raise ValueError("successful ACK without quiescent successful release")
            if (all((reserved, accepted, done, release)) and
                    all(e["quiesced"] and not e["status"] for e in (done, release))):
                rx.append((scope, reserved["ts_ns"], accepted["ts_ns"], done["ts_ns"], release["ts_ns"]))
    unmatched_attempts = set(attempts) - resolved_attempts
    idle_stages = set(stages) - {s[:2] for s in groups}
    complete = complete and not errors and not unmatched_attempts and not idle_stages

    frames, frame_rows = defaultdict(set), defaultdict(list)
    terminal, frame_batches = {}, {}
    wanted = {scope: (base, accepted, _one(groups[scope], "native_complete"))
              for scope, base, accepted in native_groups}
    for e in native:
        if e["phase"] == "native_submit" and e["class_id"] == 11:
            k = (e["session_id"], e["stage"], e["cookie"])
            if k not in wanted:
                raise ValueError("native frame has no matching XDOMAIN acceptance")
            base, accepted, _ = wanted[k]
            if (e["batch_key"] != base["key"] or e["ticket"] != accepted["ticket"] or
                    not e["frame_length"] or e["status"]):
                raise ValueError("native frame key/ticket/length/status mismatch")
            ident = (e["frame_id"], e["generation"])
            if any(f[0] == e["frame_id"] for f in frames[k]):
                raise ValueError("duplicate native frame submission")
            _before(accepted, e, "native frame logged before post acceptance")
            frames[k].add(ident)
            frame_rows[k].append(e)
            frame_batches[k, ident] = (e["session_id"], e["batch_id"], e["batch_key"],
                                       e["frame_id"], e["generation"])
        elif e["phase"] == "record_terminal" and not e["status"]:
            identity = (e["session_id"], e["batch_id"], e["batch_key"],
                        e["frame_id"], e["generation"])
            if identity in terminal:
                raise ValueError("duplicate successful frame terminal")
            terminal[identity] = e
    for scope, rows in frame_rows.items():
        if len({(e["batch_id"], e["bytes"]) for e in rows}) != 1:
            raise ValueError("native group batch/byte total changed")
        offset = 0
        for ordinal, e in enumerate(sorted(rows, key=lambda e: e["frame_ordinal"])):
            if e["frame_ordinal"] != ordinal or e["frame_offset"] != offset:
                raise ValueError("incomplete or noncontiguous native frame coverage")
            offset += e["frame_length"]
            final = terminal.get(frame_batches[scope, (e["frame_id"], e["generation"])])
            if final is not None:
                _, accepted, done = wanted[scope]
                _before(accepted, final, "terminal before native post acceptance")
                _before(done, final, "terminal before native completion")
        if not offset or offset != rows[0]["bytes"]:
            raise ValueError("incomplete native group byte coverage")
    frame_checked = bool(native_groups) and all(frames[s] for s, _, _ in native_groups)
    kernel_terminal = frame_checked and all(
        frame_batches[s, identity] in terminal for s, _, _ in native_groups
        for identity in frames[s])
    # Reuse of any frame before release is invalid even if no overlap metric
    # would otherwise be positive. Generation changes cannot excuse live reuse.
    overlap, pairs = [], 0
    if frame_checked:
        for i, (s1, reserve1, start1, done1, release1) in enumerate(rx):
            for s2, reserve2, start2, done2, release2 in rx[i+1:]:
                if s1[:2] != s2[:2]:
                    continue
                old, new = ((s1,reserve1,start1,done1,release1),
                            (s2,reserve2,start2,done2,release2))
                if reserve2 < reserve1:
                    old, new = new, old
                same = {f[0] for f in frames[old[0]]} & {f[0] for f in frames[new[0]]}
                if same and new[1] < old[4]:
                    raise ValueError("frame reused before old consumer release")
                begin, end = max(new[2], old[3]), min(new[3], old[4])
                if begin < end and not same:
                    overlap.append((begin, end))
                    pairs += 1
    return {
        "schema": "xdev-tp-early-observation-v1",
        "counts": dict(sorted(counts.items())),
        "admitted_early_stages": sum(e["early"] for e in stages.values()),
        "tx_groups": tx_groups, "rx_groups": rx_groups, "error_events": errors,
        "unmatched_tx_attempt_keys": len(unmatched_attempts),
        "stages_without_groups": len(idle_stages),
        "completion_scope": "observed groups only; TP workload count requires --tp-summary",
        "grants_before_first_tx_attempt": pregrants,
        "received_before_first_tx_attempt": prereceipts, "grant_lead_ns": leads,
        "completion_before_post_return_groups": reordered,
        "protocol_complete": complete, "frame_identity_checked": frame_checked,
        "kernel_terminal_checked": kernel_terminal,
        "complete": complete and frame_checked and kernel_terminal,
        "rx_native_consumer_overlap_ns": _union_ns(overlap) if frame_checked and complete else None,
        "rx_overlapping_group_pairs": pairs if frame_checked and complete else None,
        "physical_dma_proven": False, "gpu_compute_overlap_proven": False,
        "qualification": "trace observations only; runtime hardware and payload oracle required",
        "time_scope": "one host, kernel CLOCK_MONOTONIC; never combine hosts or GPU globaltimer",
        "native_interval": "accepted API return to final callback; not DMA first-byte or engine occupancy",
    }


def qualify_tp(result, events, native, metadata):
    """Bound observed completeness to this driver's finite ordered START keys."""
    fields = ("tx_session_id", "rx_session_id", "iterations", "requested_depth",
              "completed", "first_sequence", "group_bytes", "frame_size", "frame_count")
    for field in fields:
        if type(metadata[field]) is not int or not _number(metadata[field]):
            raise ValueError("invalid TP " + field)
    tx, rx = metadata["tx_session_id"], metadata["rx_session_id"]
    requested = metadata["early_cts_requested"]
    if (tx == rx or type(requested) is not bool or
            metadata["completion_boundary"] != "kernel-end-prefix"):
        raise ValueError("invalid TP session/request/completion contract")
    if any(e["early"] != int(requested) for e in events):
        raise ValueError("requested EARLY differs from kernel admission")
    expected = metadata["iterations"] * metadata["requested_depth"]
    first = metadata["first_sequence"]
    if metadata["completed"] != expected or first + expected >= 1 << 64:
        raise ValueError("incomplete or overflowing TP operation count")
    per_group = (metadata["group_bytes"] + 4095) // 4096
    if (metadata["frame_size"] != 4096 or
            metadata["frame_count"] != per_group * metadata["requested_depth"]):
        raise ValueError("TP frame geometry mismatch")
    covered = True
    for sid, direction in ((tx, 1), (rx, 2)):
        bound = [e for e in events if e["phase"] == "stage_bound" and e["session_id"] == sid]
        if len(bound) != 1 or bound[0]["direction"] != direction:
            raise ValueError("TP native session direction/admission mismatch")
        accepted = [e for e in events if e["phase"] == "native_accepted" and e["session_id"] == sid]
        keys = sorted(e["key"] for e in accepted)
        covered &= (len(keys) == expected and
                    all(key == first + ordinal for ordinal, key in enumerate(keys)))
        submitted = [e for e in native if e["phase"] == "native_submit" and
                     e["class_id"] == 11 and e["session_id"] == sid]
        if any(e["bytes"] != metadata["group_bytes"] for e in submitted):
            raise ValueError("native group bytes differ from TP geometry")
        frames = Counter((e["stage"], e["cookie"]) for e in submitted)
        covered &= all(frames[e["stage"], e["group"]] == per_group for e in accepted)
    result["early_cts_requested"] = requested
    result["expected_groups_per_session"] = expected
    result["tp_workload_covered"] = bool(covered)
    result["complete"] = result["complete"] and bool(covered)
    result["completion_scope"] = "all requested TP keys on both local sessions; teardown/hardware qualification remains external"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trace", type=Path, required=True)
    p.add_argument("--stats", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    selection = p.add_mutually_exclusive_group(required=True)
    selection.add_argument("--session-id", type=int, nargs="+",
                           help="local sessions belonging to this run")
    selection.add_argument("--tp-summary", type=Path,
                           help="run.py summary carrying TX/RX session IDs")
    args = p.parse_args(argv)
    try:
        if args.stats.stat().st_size > 1024*1024:
            raise ValueError("oversized trace statistics")
        with args.trace.open() as stream:
            events, native = parse_trace(stream)
        metadata = None
        if args.tp_summary:
            if args.tp_summary.stat().st_size > 4*1024*1024:
                raise ValueError("oversized TP summary")
            metadata = json.loads(args.tp_summary.read_text())["metadata"]
            ids = [metadata["tx_session_id"], metadata["rx_session_id"]]
            if ids[0] == ids[1]:
                raise ValueError("TX/RX sessions must be distinct")
        else:
            ids = args.session_id
        events, native = select_sessions(events, native, ids)
        result = analyze(events, args.stats.read_text(), native)
        if metadata is not None:
            qualify_tp(result, events, native, metadata)
        result["session_ids"] = sorted(ids)
        with args.output.open("x") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    except (OSError, ValueError, KeyError, TypeError) as error:
        p.exit(2, "early trace rejected: " + str(error) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
