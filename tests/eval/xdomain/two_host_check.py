#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Two-host metadata coordinator; retained resource owners are never killed."""

import argparse
import json
import os
from pathlib import Path
import secrets
import select
import struct
import subprocess
import time

from check_protocol import (
    encode_record,
    decode_frame,
    validate_record,
    integer,
    keys,
    MAX_JSON,
)
from oracle import build_expectations, validate_summary

_RETAINED = []  # Retain pipe/worker handles for manual recovery, including on failures.


class OwnerProcess(subprocess.Popen):
    retained = False

    def __del__(self):
        # Popen's default destructor polls waitpid. That is forbidden for a
        # retained resource owner, even as an interpreter-shutdown side effect.
        if not self.retained:
            super().__del__()


class Endpoint:
    def __init__(self, role, argv, config):
        if (
            type(argv) is not list
            or not argv
            or any(type(s) is not str or not s for s in argv)
        ):
            raise ValueError("argv must be a nonempty string array")
        self.role = role
        self.config = config
        self.phase = "NEW"
        self.seq = 0
        self.last = None
        self.owner_evidence = {}
        self.prepared = False
        self.identity = dict(config["identity"], role=role)
        child_input, self.infd = os.pipe()
        self.outfd, child_output = os.pipe()
        try:
            self.process = OwnerProcess(
                argv,
                stdin=child_input,
                stdout=child_output,
                stderr=subprocess.DEVNULL,
                shell=False,
                start_new_session=True,
                bufsize=0,
            )
        finally:
            os.close(child_input)
            os.close(child_output)
        os.set_blocking(self.infd, False)
        os.set_blocking(self.outfd, False)
        self.pending = bytearray()
        self.log = Path(config["evidence_dir"]) / (role + "-wire.jsonl")

    def _log(self, direction, record):
        with self.log.open("a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {"direction": direction, "record": record}, separators=(",", ":")
                )
                + "\n"
            )

    def _write(self, frame, deadline):
        off = 0
        while off < len(frame):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("agent write deadline")
            _, w, _ = select.select([], [self.infd], [], remaining)
            if not w:
                raise ValueError("agent write deadline")
            try:
                off += os.write(self.infd, frame[off:])
            except BlockingIOError:
                continue
            except (BrokenPipeError, OSError) as e:
                raise ValueError("agent input disconnected") from e

    def _read(self, deadline):
        while True:
            if len(self.pending) >= 4:
                size = struct.unpack("!I", self.pending[:4])[0]
                if not 1 <= size <= MAX_JSON:
                    raise ValueError("agent frame bound")
                if len(self.pending) >= size + 4:
                    frame = bytes(self.pending[: size + 4])
                    del self.pending[: size + 4]
                    return decode_frame(frame)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("agent response deadline")
            r, _, _ = select.select([self.outfd], [], [], remaining)
            if not r:
                raise ValueError("agent response deadline")
            try:
                data = os.read(self.outfd, 65536)
            except BlockingIOError:
                continue
            if not data:
                raise ValueError("agent output EOF")
            self.pending.extend(data)

    def command(self, command, payload, parts=None):
        self.seq += 1
        identity = dict(self.identity, request_id=self.seq)
        payloads = parts if parts is not None else [payload]
        deadline = time.monotonic() + self.config["deadline_ms"] / 1000
        for i, p in enumerate(payloads):
            request = {
                "identity": identity,
                "command": command,
                "deadline_ms": self.config["deadline_ms"],
                "part_index": i,
                "part_count": len(payloads),
                "payload": p,
            }
            self._log("request", request)
            self._write(encode_record(request), deadline)
        result = self._read(deadline)
        self._log("response", result)
        self.last = result
        validate_record(
            result, {"identity": identity, "command": command, "phase": self.phase}
        )
        evidence = result["evidence"]
        owner_pid = evidence.get("owner_pid")
        durable_path = evidence.get("durable_path")
        if (
            type(owner_pid) is int
            and owner_pid > 0
            and type(durable_path) is str
            and durable_path.startswith("/")
            and len(durable_path) <= 4096
        ):
            self.owner_evidence = dict(evidence)
        elif self.owner_evidence and "hold_reasons" in evidence:
            self.owner_evidence["hold_reasons"] = evidence["hold_reasons"]
        self.phase = result["phase"]
        if result["error"] or result["held"]:
            raise ValueError(role_reason(self.role, result))
        return result

    def retain(self, reason):
        # Do not close any pipes, poll/reap, signal, wait, or join a retained owner.
        self.process.retained = True
        _RETAINED.append(self)
        e = self.owner_evidence
        return {
            "owner_pid": e.get("owner_pid"),
            "durable_path": e.get("durable_path"),
            "transport_pid": self.process.pid,
            "coordinator_log_path": str(self.log),
            "evidence_incomplete": not bool(e) or self.phase != "HELD",
            "held_confirmed": self.phase == "HELD",
            "identity": self.identity,
            "phase": self.phase,
            "hold_reasons": e.get("hold_reasons", [reason]),
        }


def role_reason(role, response):
    return role + " returned " + response["phase"] + " error=" + str(response["error"])


def _geometry(config):
    g = config["geometry"]
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
    b = g["group_bytes"]
    elems = b // 4096
    if (
        b % 4096
        or g["frame_size"] != 65536
        or g["seg_len"] != min(b, 65536)
        or not 1 <= elems <= 64
        or g["native_elems"] != elems
        or g["depth"] * elems > 255
        or g["allocation_bytes"] % 65536
        or not b <= g["allocation_bytes"] <= 1024**3
    ):
        raise ValueError("unsupported geometry; request not clamped")
    integer(config["groups"], maximum=10000, minimum=1)
    integer(config["first_seq"])
    if config["first_seq"] + config["groups"] - 1 > (1 << 64) - 1:
        raise ValueError("sequence overflow")
    if config["mode"] == "single-group" and (config["groups"] != 1 or g["depth"] != 1):
        raise ValueError("single-group geometry")
    if config["mode"] not in ("single-group", "bulk-static"):
        raise ValueError("mode")


def _preflight(response, config, role):
    p = response["payload"]
    keys(
        p,
        {
            "available",
            "reason",
            "device_identity",
            "link_identity",
            "kernel_identity",
            "visibility",
            "raw_evidence",
        },
    )
    if p["available"] is not True:
        raise ValueError("preflight unavailable: " + str(p["reason"]))
    device = p["device_identity"]
    link = p["link_identity"]
    kernel = p["kernel_identity"]
    keys(device, {"gpu_bdf", "nvidia_node", "backing"})
    keys(link, {"link_token", "channel", "local_inc", "remote_inc"})
    keys(kernel, {"sha", "config"})
    if (
        kernel["sha"] != config["identity"]["sha"]
        or type(kernel["config"]) is not str
        or not kernel["config"]
    ):
        raise ValueError("actual kernel SHA/config mismatch")
    if (
        device["gpu_bdf"] != config["gpu_bdf"][role]
        or device["nvidia_node"] != config["nvidia_node"][role]
        or device["backing"] != "gpu"
    ):
        raise ValueError("actual GPU BDF/node/backing mismatch")
    if (
        link["link_token"] != config["link_token"][role]
        or link["channel"] != config["channel"]
    ):
        raise ValueError("link token/channel mismatch")
    for k in ("local_inc", "remote_inc"):
        integer(link[k], minimum=1)
    if not p["raw_evidence"].get("service_listing"):
        raise ValueError("actual service listing absent")
    return {"local_inc": link["local_inc"], "remote_inc": link["remote_inc"]}


def _settled(response, groups, session):
    p = response["payload"]
    if p.get("stats_valid") is not True or p.get("transport_valid") is not True:
        raise ValueError("missing actual terminal stats")
    s = p["stats"]
    tr = p["transport"]
    v1 = tr["v3"]["v2"]["v1"]
    if (
        s["session_id"] != session
        or s["batches_done"] != groups
        or any(
            s[k] != 0
            for k in (
                "batches_abort",
                "rejects",
                "held",
                "sequestered",
                "timeouts",
                "inflight",
                "protocol_err",
                "last_err",
            )
        )
    ):
        raise ValueError("terminal stats not settled")
    if (
        v1["size"] != 216
        or v1["version"] != 4
        or v1["session_id"] != session
        or any(
            v1[k] != 0
            for k in ("native_controls", "pending_acks", "uncertain_controls")
        )
    ):
        raise ValueError("transport not settled")


def run(config, agent_argv=None):
    endpoints = {}
    epochs = []
    try:
        case_id = config["identity"]["case"]
        if case_id not in ("functional-epochs", "bulk-static"):
            return {
                "status": "incomplete",
                "reason": "case execution is not implemented: " + str(case_id),
                "retained_workers": [],
                "epochs": [],
            }
        _geometry(config)
        Path(config["evidence_dir"]).mkdir(mode=0o700, parents=True, exist_ok=True)
        argv = agent_argv if agent_argv is not None else config.get("agent_argv")
        if not isinstance(argv, dict) or set(argv) != {"tx", "rx"}:
            raise ValueError("both agent argv required")
        for role in ("tx", "rx"):
            command_argv = list(argv[role])
            if config.get("kernel_receipt"):
                command_argv += ["--kernel-receipt", config["kernel_receipt"][role]]
            endpoints[role] = Endpoint(role, command_argv, config)
        common = {k: config[k] for k in ("geometry", "flags", "channel")}
        links = {}
        for role in ("tx", "rx"):
            p = dict(
                common,
                gpu_bdf=config["gpu_bdf"][role],
                nvidia_node=config["nvidia_node"][role],
                link_token=config["link_token"][role],
            )
            links[role] = _preflight(
                endpoints[role].command("preflight", p), config, role
            )
        if (
            links["tx"]["local_inc"] != links["rx"]["remote_inc"]
            or links["rx"]["local_inc"] != links["tx"]["remote_inc"]
        ):
            raise ValueError("cross-host incarnation mismatch")
        sessions = {}
        for role in ("rx", "tx"):
            p = dict(
                common,
                **{
                    k: config[k]
                    for k in (
                        "mode",
                        "groups",
                        "first_seq",
                        "seed",
                        "observer_object",
                        "ptx_path",
                    )
                },
                gpu_bdf=config["gpu_bdf"][role],
                nvidia_node=config["nvidia_node"][role],
                link_token=config["link_token"][role]
            )
            # From this point even an unknown response retains that process.
            endpoints[role].prepared = True
            r = endpoints[role].command("prepare", p)
            q = r["payload"]
            if (
                q["create_error"]
                or q["registration_bytes"] != config["geometry"]["allocation_bytes"]
                or not q["session_id"]
                or q.get("stop_proved") is not False
            ):
                raise ValueError("prepare did not prove registration/CREATE")
            if not q["guard_sync_proved" if role == "rx" else "producer_sync_proved"]:
                raise ValueError("prepare GPU synchronization absent")
            sessions[role] = q["session_id"]
        for role in ("rx", "tx"):
            p = {k: config[k] for k in ("groups", "first_seq")}
            r = endpoints[role].command("start", p)
            if r["payload"] != {
                "start_accepted": True,
                "arm_error": 0,
                "start_error": 0,
            }:
                raise ValueError("START not accepted")
        for role in ("tx", "rx"):
            _settled(
                endpoints[role].command("wait", {}), config["groups"], sessions[role]
            )
        stops = []
        for role in ("tx", "rx"):
            r = endpoints[role].command("stop", {})
            if (
                r["fate"] != "SAFE"
                or not r["payload"]["stop_proved"]
                or r["payload"]["stop_error"]
                or r["payload"]["first_error"]
            ):
                raise ValueError("STOP proof failed")
            _settled(r, config["groups"], sessions[role])
            stops.append(r)
        records = {}
        for role in ("tx", "rx"):
            records[role] = []
            ordinal = 0
            while ordinal < config["groups"]:
                limit = min(32, config["groups"] - ordinal)
                p = endpoints[role].command(
                    "observe", {"first_ordinal": ordinal, "limit": limit}
                )["payload"]
                keys(p, {"records", "next_ordinal", "total", "error_bits"})
                if (
                    p["total"] != config["groups"]
                    or p["error_bits"]
                    or len(p["records"]) != limit
                ):
                    raise ValueError("observer page count/error")
                for i, item in enumerate(p["records"]):
                    keys(item, {"ordinal", "record"})
                    if item["ordinal"] != ordinal + i:
                        raise ValueError("observer duplicate/gap")
                    records[role].append(item["record"])
                ordinal += limit
                if p["next_ordinal"] != (
                    ordinal if ordinal < config["groups"] else None
                ):
                    raise ValueError("observer next ordinal")
        oc = dict(
            config["geometry"],
            **{
                k: config[k]
                for k in ("groups", "first_seq", "epoch", "seed")
                if k in config
            }
        )
        oc["epoch"] = config["identity"]["epoch"]
        oc["link_token"] = config["link_token"]
        oc["channel"] = config["channel"]
        for role in ("tx", "rx"):
            oc[role + "_session_id"] = sessions[role]
            oc[role + "_local_inc"] = links[role]["local_inc"]
        extents = build_expectations(records["tx"], records["rx"], oc)
        verification = None
        for role, expected_extents in (
            ("rx", extents),
            (
                "tx",
                [
                    {
                        "dst_off": 0,
                        "src_off": 0,
                        "len": config["geometry"]["allocation_bytes"],
                        "seed": config["seed"],
                        "kind": 1,
                        "reserved": 0,
                    }
                ],
            ),
        ):
            cookie = secrets.randbits(64) or 1
            parts = [
                {
                    "kind": "begin",
                    "launch_cookie": cookie,
                    "extent_count": len(expected_extents),
                    "stop_receipts": stops,
                }
            ]
            for i in range(0, len(expected_extents), 1024):
                parts.append(
                    {
                        "kind": "extents",
                        "first_extent": i,
                        "extents": expected_extents[i : i + 1024],
                    }
                )
            parts.append({"kind": "end", "extent_count": len(expected_extents)})
            summary = endpoints[role].command("verify", {}, parts)["payload"]
            if summary["visibility_error"]:
                raise ValueError("receive visibility failed")
            validate_summary(summary, expected_extents, cookie)
            if role == "rx":
                verification = summary
        for role in ("tx", "rx"):
            r = endpoints[role].command("close", {})
            if r["payload"].get("closed") is not True or r["payload"].get(
                "retained_resources"
            ):
                raise ValueError("resources not closed")
        epochs.append(
            {
                "epoch": config["identity"]["epoch"],
                "stop_receipts": stops,
                "verification": verification,
                "groups": config["groups"],
            }
        )
        # CLOSED is an explicit safe acknowledgement, so pipe closure is now safe.
        for ep in endpoints.values():
            os.close(ep.infd)
            os.close(ep.outfd)
            try:
                ep.process.wait(timeout=config["deadline_ms"] / 1000)
            except subprocess.TimeoutExpired:
                # CLOSED acknowledged resource release; process may finish later.
                ep.process.retained = True
                _RETAINED.append(ep)
        return {
            "status": "pass",
            "reason": "both endpoints stopped and complete allocation verified",
            "retained_workers": [],
            "epochs": epochs,
        }
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as error:
        retained = []
        for ep in endpoints.values():
            if ep.phase != "HELD":
                try:
                    ep.command("cancel", {"reason": "coordinator-failure"})
                except (ValueError, KeyError, TypeError, OSError):
                    pass
            retained.append(ep.retain(str(error)))
        return {
            "status": "failed",
            "reason": str(error),
            "retained_workers": retained,
            "epochs": epochs,
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--tx-argv", required=True)
    ap.add_argument("--rx-argv", required=True)
    ap.add_argument("--evidence-dir", required=True)
    a = ap.parse_args()
    with open(a.config, encoding="utf-8") as f:
        config = json.load(f)
    argv = {}
    for role, path in (("tx", a.tx_argv), ("rx", a.rx_argv)):
        with open(path, encoding="utf-8") as f:
            argv[role] = json.load(f)
    config["evidence_dir"] = a.evidence_dir
    result = run(config, argv)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
