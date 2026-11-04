#!/usr/bin/env python3
"""Plan or execute one qualified fixed-source Mooncake baseline cell."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

REVISION = "d01447808d10af78011e9203d53796a15a032a03"
CONTRACT = "mooncake-baseline-v1"
U64 = (1 << 64) - 1
I32 = (1 << 31) - 1
MAX_CELLS = 100000
MAX_JSON_BYTES = 1 << 20
PROFILES = ("native", "xdev_ext")
ARMS = ("iouring-default", "iouring-pinned", "gds-compat")
SHAPE_KEYS = {
    "schema_version", "experiment", "block_bytes", "batch_requests",
    "worker_threads", "buffer_bytes", "target_bytes", "target_offset",
    "duration_seconds", "repetitions", "op_type", "target_access",
    "pinned_slot_kib", "pinned_slots", "gpu_ordinal",
}
RIG_TEXT = {
    "execution", "kernel_release", "kernel_source_revision",
    "nvidia_driver_version", "cuda_version", "cufile_version", "gpu_uuid",
    "gpu_pci_bdf", "gpu_model", "cpu_budget_description", "source_revision",
    "filesystem", "namespace_identity", "host_id",
}
RECEIPT_KEYS = {
    "build_receipt", "input_validation_receipt", "file_extent_receipt",
    "exclusive_window_receipt", "route_receipt", "usb4_link_receipt",
}
COMMON_REQUIRED = (
    "schema_version", "physical_run_authorized", "execution", "kernel_release",
    "kernel_source_revision", "nvidia_driver_version", "cuda_version",
    "gpu_uuid", "gpu_pci_bdf", "gpu_model", "cpuset", "numa_node",
    "cpu_budget_description", "source_revision", "source_tree_verified",
    "build_receipt",
)
E4_REQUIRED = (
    "input_file", "input_initialized", "input_validation_receipt", "filesystem",
    "mount_options", "namespace_identity", "namespace_capacity_bytes",
    "file_extent_receipt", "exclusive_window_receipt",
)
ENDPOINT_REQUIRED = (
    "host_id", "address", "rpc_port", "interface", "mtu", "cpuset", "numa_node",
    "cpu_budget_description", "kernel_release", "kernel_source_revision",
    "route_receipt", "usb4_link_receipt",
)


class InvalidInput(ValueError):
    """A caller-supplied value violates the frozen serialization contract."""


def text_value(value, label, nonempty=True):
    if not isinstance(value, str) or (nonempty and not value):
        raise InvalidInput(f"{label} must be a nonempty string")
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF
           for c in value):
        raise InvalidInput(f"{label} contains unsupported control characters")
    if len(value.encode("utf-8")) > 4096:
        raise InvalidInput(f"{label} exceeds the 4096 byte text limit")
    return value


def integer(value, label, maximum=I32, minimum=1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise InvalidInput(f"{label} must be an integer in {minimum}..{maximum}")
    return value


def multiply(a, b, label, maximum=U64):
    if b and a > maximum // b:
        raise InvalidInput(f"{label} overflows its integer bound")
    return a * b


def add(a, b, label, maximum=U64):
    if a > maximum - b:
        raise InvalidInput(f"{label} overflows its integer bound")
    return a + b


def absolute_path(value, label):
    value = text_value(value, label)
    path = Path(os.path.abspath(value))
    if any(part == ".." for part in Path(value).parts):
        raise InvalidInput(f"{label} must not contain parent traversal")
    if path == Path("/dev") or Path("/dev") in path.parents:
        raise InvalidInput(f"{label} must not address a device path")
    if any(len(part.encode("utf-8")) > 255 for part in path.parts):
        raise InvalidInput(f"{label} has an overlong path component")
    return path


def resolved_path(path):
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise InvalidInput(f"cannot resolve protected path {path}: {error}") from error


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidInput(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_object(filename, label):
    path = absolute_path(filename, label)
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
                raise InvalidInput(f"{label} must be a regular JSON file <= {MAX_JSON_BYTES} bytes")
            payload = stream.read(MAX_JSON_BYTES + 1)
        if len(payload) > MAX_JSON_BYTES:
            raise InvalidInput(f"{label} exceeds the JSON byte limit")
        def bad_constant(value):
            raise InvalidInput(f"{label} contains nonfinite JSON number: {value}")
        result = json.loads(payload, object_pairs_hook=unique_object,
                            parse_constant=bad_constant)
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        raise InvalidInput(f"cannot read {label}: {error}") from error
    if not isinstance(result, dict):
        raise InvalidInput(f"{label} must be a JSON object")
    return result


def validate_shape(shape, experiment):
    allowed = SHAPE_KEYS if experiment == "e4" else SHAPE_KEYS - {
        "pinned_slot_kib", "pinned_slots"}
    unknown, missing = set(shape) - allowed, allowed - set(shape)
    if unknown or missing:
        raise InvalidInput(f"shape unknown keys={sorted(unknown)}, missing keys={sorted(missing)}")
    if integer(shape["schema_version"], "shape.schema_version") != 1:
        raise InvalidInput("shape.schema_version must equal 1")
    if shape["experiment"] != experiment:
        raise InvalidInput("shape.experiment must match --experiment")
    expected = ("read", "random") if experiment == "e4" else ("write", "fixed")
    if (shape["op_type"], shape["target_access"]) != expected:
        raise InvalidInput(f"{experiment} requires op_type={expected[0]}, target_access={expected[1]}")
    for key in ("block_bytes", "batch_requests"):
        values = shape[key]
        if not isinstance(values, list) or not values:
            raise InvalidInput(f"shape.{key} must be a nonempty array")
        # Upstream doubles the induction variable even when start == max.
        maximum = U64 // 2 if key == "block_bytes" else I32
        for value in values:
            integer(value, f"shape.{key} entry", maximum)
            if key == "block_bytes" and value % 4096:
                raise InvalidInput("block_bytes entries must be multiples of 4096")
        if len(values) != len(set(values)):
            raise InvalidInput(f"shape.{key} must contain unique values")
    for key in ("worker_threads", "duration_seconds", "repetitions"):
        integer(shape[key], "shape." + key)
    if shape["worker_threads"] > I32 // 2:
        raise InvalidInput("worker_threads must permit upstream signed32 post-case doubling")
    integer(shape["gpu_ordinal"], "shape.gpu_ordinal", minimum=0)
    for key in ("buffer_bytes", "target_bytes"):
        integer(shape[key], "shape." + key, U64)
    integer(shape["target_offset"], "shape.target_offset", U64, 0)
    if shape["target_offset"] > U64 - shape["target_bytes"]:
        raise InvalidInput("target_offset + target_bytes overflows uint64")
    arms = 3 if experiment == "e4" else 1
    count = len(PROFILES) * arms
    for n in (len(shape["block_bytes"]), len(shape["batch_requests"]),
              shape["repetitions"]):
        count = multiply(count, n, "cell count", MAX_CELLS)
    op_bytes = multiply(max(shape["block_bytes"]), max(shape["batch_requests"]),
                        "batch bytes")
    total = multiply(op_bytes, shape["worker_threads"], "worker buffer bytes")
    if total > shape["buffer_bytes"] or total > shape["target_bytes"]:
        raise InvalidInput("maximum worker batch must fit buffer_bytes and target_bytes")
    local_indices = add(shape["gpu_ordinal"], shape["worker_threads"],
                        "local buffer logical indices")
    local_end = multiply(local_indices, op_bytes, "local buffer allocation end")
    if local_end > shape["buffer_bytes"]:
        raise InvalidInput("gpu_ordinal plus worker batch span exceeds buffer_bytes")
    if experiment == "e7":
        target_end = add(shape["target_offset"], total, "E7 target allocation end")
        if target_end > shape["buffer_bytes"]:
            raise InvalidInput("E7 target_offset plus worker batch span exceeds buffer_bytes")
    qd = multiply(shape["worker_threads"], max(shape["batch_requests"]),
                  "logical_qd", I32)
    if experiment == "e4":
        if shape["target_offset"] % 4096:
            raise InvalidInput("E4 target_offset must be 4096 aligned")
        if shape["target_bytes"] % shape["worker_threads"]:
            raise InvalidInput("target_bytes must divide evenly among worker_threads")
        window = shape["target_bytes"] // shape["worker_threads"]
        if window % 4096 or op_bytes > window // 2:
            raise InvalidInput("random per-thread window must be aligned and hold two maximum batches")
        integer(shape["pinned_slot_kib"], "shape.pinned_slot_kib", U64)
        slot_bytes = multiply(shape["pinned_slot_kib"], 1024, "pinned slot bytes")
        if slot_bytes > U64 - 4095:
            raise InvalidInput("rounded pinned slot size overflows uint64")
        rounded = (slot_bytes + 4095) // 4096 * 4096
        integer(shape["pinned_slots"], "shape.pinned_slots")
        multiply(rounded, shape["pinned_slots"], "pinned pool bytes")
        if slot_bytes < max(shape["block_bytes"]) or shape["pinned_slots"] < qd:
            raise InvalidInput("pinned pool must cover maximum request size and logical_qd")
    return count


def cpuset(value, label):
    value = text_value(value, label)
    if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", value):
        raise InvalidInput(f"{label} must be a CPU list such as 0-3,8")
    for item in value.split(","):
        bounds = [int(n) for n in item.split("-")]
        for n in bounds:
            integer(n, label, I32, 0)
        if bounds[0] > bounds[-1]:
            raise InvalidInput(f"{label} has a descending range")
    return value


def validate_rig(rig, shape):
    known = RIG_TEXT | RECEIPT_KEYS | {
        "schema_version", "physical_run_authorized", "source_tree_verified",
        "input_initialized", "cpuset", "numa_node", "namespace_capacity_bytes",
        "input_file", "mount_options", "endpoints",
    }
    if set(rig) - known:
        raise InvalidInput(f"rig has unknown keys: {sorted(set(rig) - known)}")
    for key, value in rig.items():
        label = "rig." + key
        if key in RIG_TEXT:
            text_value(value, label)
        elif key in ("physical_run_authorized", "source_tree_verified", "input_initialized"):
            if type(value) is not bool:
                raise InvalidInput(label + " must be a boolean")
        elif key == "schema_version":
            if integer(value, label) != 1:
                raise InvalidInput(label + " must equal 1")
        elif key == "cpuset":
            cpuset(value, label)
        elif key == "numa_node":
            integer(value, label, minimum=0)
        elif key == "namespace_capacity_bytes":
            integer(value, label, U64)
            if shape["target_offset"] + shape["target_bytes"] > value:
                raise InvalidInput("requested target range exceeds namespace_capacity_bytes")
        elif key == "input_file":
            path = absolute_path(value, label)
            if not Path(value).is_absolute():
                raise InvalidInput("rig.input_file must be absolute")
            if path == Path("/"):
                raise InvalidInput("rig.input_file cannot be a directory root")
            if shape["experiment"] == "e4" and (
                    "," in value or value != value.rstrip(" \t\r\n")):
                raise InvalidInput("E4 input_file cannot contain commas or final whitespace trimmed by tebench")
        elif key in RECEIPT_KEYS:
            if not isinstance(value, (str, dict)):
                raise InvalidInput(label + " must be a receipt reference or object")
            if isinstance(value, str):
                text_value(value, label)
        elif key == "mount_options":
            if isinstance(value, str):
                text_value(value, label)
            elif isinstance(value, list) and value:
                for item in value:
                    text_value(item, label)
            else:
                raise InvalidInput(label + " must be a string or nonempty string array")
        elif key == "endpoints":
            if not isinstance(value, dict) or set(value) - {"source", "destination"}:
                raise InvalidInput("rig.endpoints must contain source and destination objects only")
            for role, endpoint in value.items():
                if not isinstance(endpoint, dict):
                    raise InvalidInput(f"rig.endpoints.{role} must be an object")
                if set(endpoint) - set(ENDPOINT_REQUIRED):
                    raise InvalidInput(f"rig.endpoints.{role} has unknown keys")
                for field, item in endpoint.items():
                    label = f"rig.endpoints.{role}.{field}"
                    if field == "rpc_port":
                        integer(item, label, 65535)
                    elif field == "mtu":
                        integer(item, label)
                    elif field == "numa_node":
                        integer(item, label, minimum=0)
                    elif field == "cpuset":
                        cpuset(item, label)
                    elif field in RECEIPT_KEYS:
                        if not isinstance(item, (str, dict)):
                            raise InvalidInput(label + " must be a receipt reference or object")
                        if isinstance(item, str):
                            text_value(item, label)
                    elif field in ENDPOINT_REQUIRED:
                        text_value(item, label)
    return rig


def missing_setup(rig, args):
    missing = ["physical execution is not authorized in this delivery",
               "physical residency, route and source-tree evidence is not independently qualified"]
    keys = COMMON_REQUIRED + (E4_REQUIRED if args.experiment == "e4" else ())
    for key in keys:
        if key not in rig or (key in RECEIPT_KEYS and not rig[key]):
            missing.append("rig." + key + " is missing")
    if rig.get("physical_run_authorized") is not True:
        missing.append("rig.physical_run_authorized is not true")
    if rig.get("execution") != "physical":
        missing.append("rig.execution is not physical")
    if rig.get("source_revision") != REVISION:
        missing.append("rig.source_revision does not match fixed Mooncake revision")
    if rig.get("source_tree_verified") is not True:
        missing.append("rig.source_tree_verified is not true")
    if not args.source_root.is_dir():
        missing.append("Mooncake source-root is unavailable")
    if not executable_file(args.tebench):
        missing.append("tebench is missing or not executable: NEEDS_BUILD")
    receipt = rig.get("build_receipt")
    if not isinstance(receipt, dict):
        missing.append("build_receipt has no verified compile-feature metadata: NEEDS_BUILD")
    else:
        for feature in ("USE_TENT", "USE_CUDA", "liburing"):
            if receipt.get(feature) is not True:
                missing.append("build_receipt missing feature " + feature + ": NEEDS_BUILD")
        if args.experiment == "e4" and receipt.get("cufile") is not True:
            missing.append("gds-compat build_receipt missing cufile: NEEDS_BUILD")
    if args.experiment == "e4":
        if rig.get("input_initialized") is not True:
            missing.append("rig.input_initialized is not true")
        if "cufile_version" not in rig:
            missing.append("gds-compat rig.cufile_version is missing")
    else:
        endpoints = rig.get("endpoints", {})
        for role in ("source", "destination"):
            endpoint = endpoints.get(role, {})
            for key in ENDPOINT_REQUIRED:
                if key not in endpoint or (key in RECEIPT_KEYS and not endpoint[key]):
                    missing.append(f"rig.endpoints.{role}.{key} is missing")
        if endpoints.get("source", {}).get("host_id") == endpoints.get("destination", {}).get("host_id"):
            missing.append("E7 requires distinct source and destination host identities")
    return missing


def executable_file(path):
    try:
        info = path.stat()
        return stat.S_ISREG(info.st_mode) and os.access(path, os.X_OK)
    except OSError:
        return False


def common_argv(tebench, cpus, shape, segment_type, transport):
    return ["taskset", "--cpu-list", cpus, str(tebench), "--backend=tent",
            "--metadata_type=p2p", "--xport_type=" + transport,
            "--seg_type=" + segment_type, "--local_gpu_id=" + str(shape["gpu_ordinal"]),
            "--total_buffer_size=" + str(shape["buffer_bytes"])]


def add_case(argv, shape, block, batch, target, native_output):
    argv.extend([
        "--target_seg_name=" + target, "--target_offset=" + str(shape["target_offset"]),
        "--target_range_size=" + str(shape["target_bytes"]),
        "--target_access=" + shape["target_access"],
        "--start_block_size=" + str(block), "--max_block_size=" + str(block),
        "--start_batch_size=" + str(batch), "--max_batch_size=" + str(batch),
        "--start_num_threads=" + str(shape["worker_threads"]),
        "--max_num_threads=" + str(shape["worker_threads"]),
        "--duration=" + str(shape["duration_seconds"]),
        "--op_type=" + shape["op_type"], "--check_consistency=false",
        "--result_output_jsonl=" + str(native_output)])
    if shape["experiment"] == "e4":
        argv.append("--target_window_size=" + str(shape["target_bytes"] // shape["worker_threads"]))
    return argv


def prepare_output(path, protected):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise InvalidInput("output directory cannot contain symlink components")
    output_paths = (path, resolved_path(path))
    protected_paths = [variant for item in protected for variant in (item, resolved_path(item))]
    if path == Path("/") or any(
            output == item or output in item.parents
            for output in output_paths for item in protected_paths):
        raise InvalidInput("output directory cannot contain or replace an input or dependency path")
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise InvalidInput("output directory must be new or empty; existing artifacts are preserved")
    path.mkdir(parents=True, exist_ok=True)


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
        stream.write("\n")


def serialize(args, shape, rig, prepare_execution=False):
    problems = [] if prepare_execution else missing_setup(rig, args)
    status, code = ("planned", 0) if args.mode == "dry-run" or prepare_execution else ("setup_refused", 4)
    build = rig.get("build_receipt")
    needs_build = (not executable_file(args.tebench) or not isinstance(build, dict)
                   or any(build.get(key) is not True for key in ("USE_TENT", "USE_CUDA", "liburing")))
    semantics = {
        "access_contract": "batch-random-with-replacement" if args.experiment == "e4" else "fixed-target-write",
        "residency_qualification": "pending", "completion_contract": "tebench-batch-completed",
        "ratio_eligible": False,
    }
    # Deliberately retain only known identity fields, never arbitrary input or ambient secrets.
    identity_keys = RIG_TEXT | {"cpuset", "numa_node", "namespace_capacity_bytes"}
    identity = {key: value for key, value in rig.items() if key in identity_keys}
    if "endpoints" in rig:
        identity["endpoints"] = {
            role: {key: value for key, value in endpoint.items() if key not in RECEIPT_KEYS}
            for role, endpoint in rig["endpoints"].items()
        }
    plan = dict(schema_version=1, contract_version=CONTRACT, source_revision=REVISION,
                experiment=args.experiment, mode=args.mode, status=status,
                execution="none", performance_claim="none", shape=shape,
                rig_identity=identity, cells=[], setup_missing=problems, **semantics)
    protected = [args.shape, args.rig, args.source_root, args.tebench]
    for name in ("qualification", "ready_receipt"):
        value = getattr(args, name, None)
        if value is not None:
            protected.append(value)
    if "input_file" in rig:
        protected.append(absolute_path(rig["input_file"], "rig.input_file"))
    if any(output == source or source in output.parents
           for output in (args.output_dir, resolved_path(args.output_dir))
           for source in (args.source_root, resolved_path(args.source_root))):
        raise InvalidInput("output directory must be outside the Mooncake source tree")
    prepare_output(args.output_dir, protected)
    if prepare_execution:
        args.output_dir.chmod(0o700)
    for profile in PROFILES:
        for repetition in range(shape["repetitions"]):
            arms = ARMS[repetition % 3:] + ARMS[:repetition % 3] if args.experiment == "e4" else ("tcp",)
            for block in shape["block_bytes"]:
                for batch in shape["batch_requests"]:
                    for arm in arms:
                        cell_id = f"{profile}-{arm}-b{block}-q{batch}-r{repetition}"
                        relative = Path("cells") / cell_id
                        directory = args.output_dir / relative
                        directory.mkdir(parents=True, mode=0o700 if prepare_execution else 0o777)
                        config_file = relative / "config.json"
                        command_file = relative / "command.json"
                        receipt_file = relative / "receipt.json"
                        env = {"MC_TENT_CONF": str(args.output_dir / config_file)}
                        if args.experiment == "e4":
                            cpus = rig.get("cpuset", "{UNRESOLVED_CPUSET}")
                            transport = "gds" if arm == "gds-compat" else "iouring"
                            config = {} if arm == "gds-compat" else {
                                "transports": {"io_uring": {"pinned_staging": arm == "iouring-pinned"}}}
                            if arm == "iouring-pinned":
                                config["transports"]["io_uring"].update(
                                    staging_slot_kb=shape["pinned_slot_kib"], staging_slots=shape["pinned_slots"])
                            if arm == "gds-compat":
                                env["CUFILE_FORCE_COMPAT_MODE"] = "true"
                            target = "file://" + rig.get("input_file", "{UNRESOLVED_ABSOLUTE_INPUT_FILE}")
                            argv = common_argv(args.tebench, cpus, shape, "VRAM", transport)
                        else:
                            endpoints = rig.get("endpoints", {})
                            source, destination = endpoints.get("source", {}), endpoints.get("destination", {})
                            config = {"rpc_server_hostname": source.get("address", "{UNRESOLVED_SOURCE_ADDRESS}")}
                            target = "{FRESH_TARGET_SEGMENT_NAME}"
                            argv = common_argv(args.tebench, source.get("cpuset", "{UNRESOLVED_SOURCE_CPUSET}"), shape, "DRAM", "tcp")
                            argv.append("--rpc_server_port=" + str(source.get("rpc_port", "{UNRESOLVED_SOURCE_PORT}")))
                        argv = add_case(argv, shape, block, batch, target, directory / "native.jsonl")
                        command = dict(schema_version=1, cell_id=cell_id, profile=profile,
                                       arm=arm, argv=argv, env=env, config_file=str(config_file),
                                       needs_build=(needs_build or (arm == "gds-compat" and build.get("cufile") is not True)))
                        if args.experiment == "e7":
                            dest_file = relative / "target-config.json"
                            target_argv = common_argv(args.tebench, destination.get("cpuset", "{UNRESOLVED_DESTINATION_CPUSET}"), shape, "VRAM", "tcp")
                            target_argv.append("--rpc_server_port=" + str(destination.get("rpc_port", "{UNRESOLVED_DESTINATION_PORT}")))
                            command["target_command"] = {
                                "argv": target_argv, "env": {"MC_TENT_CONF": str(args.output_dir / dest_file)},
                                "config_file": str(dest_file)}
                            command["target_segment_source"] = "fresh-target-stdout"
                            write_json(args.output_dir / dest_file, {
                                "rpc_server_hostname": destination.get("address", "{UNRESOLVED_DESTINATION_ADDRESS}")})
                        write_json(args.output_dir / config_file, config)
                        write_json(args.output_dir / command_file, command)
                        cell_shape = dict(shape, block_bytes=[block], batch_requests=[batch])
                        receipt = dict(schema_version=1, contract_version=CONTRACT,
                                       experiment=args.experiment, arm=arm, profile=profile,
                                       cell_id=cell_id, mode=args.mode, status=status, execution="none",
                                       performance_claim="none", source_revision=REVISION,
                                       shape=cell_shape, rig_identity=identity, command_argv=argv,
                                       command_env=env, exit_code=code, raw_evidence=[],
                                       route_requested=arm, route_qualification="pending",
                                       correctness_scope="not_run", setup_missing=problems, **semantics)
                        if not prepare_execution or cell_id != args.cell_id:
                            if prepare_execution:
                                receipt.update(status="not_selected", exit_code=4)
                            write_json(args.output_dir / receipt_file, receipt)
                        plan["cells"].append(dict(cell_id=cell_id, profile=profile, arm=arm,
                                                  block_bytes=block, batch_requests=batch,
                                                  repetition=repetition, command_file=str(command_file),
                                                  config_file=str(config_file), receipt_file=str(receipt_file)))
    write_json(args.output_dir / "plan.json", plan)
    return code, dict(schema_version=1, contract_version=CONTRACT, status=status,
                      execution="none", performance_claim="none", ratio_eligible=False,
                      plan_file="plan.json", plan_path=str(args.output_dir / "plan.json"),
                      cell_count=len(plan["cells"]), setup_missing=problems)


def selected_cell(args, shape, rig):
    if args.profile is None or args.cell_id is None:
        raise InvalidInput("execution selection requires --profile and --cell-id")
    text_value(args.cell_id, "cell_id")
    arms = ARMS if args.experiment == "e4" else ("tcp",)
    found = None
    for arm in arms:
        for block in shape["block_bytes"]:
            for batch in shape["batch_requests"]:
                for repetition in range(shape["repetitions"]):
                    name = f"{args.profile}-{arm}-b{block}-q{batch}-r{repetition}"
                    if name == args.cell_id:
                        found = dict(cell_id=name, profile=args.profile, arm=arm,
                                     block_bytes=block, batch_requests=batch,
                                     repetition=repetition)
    if found is None:
        raise InvalidInput("cell-id does not match selected profile and shape")
    if args.experiment == "e4":
        if args.endpoint != "local" or args.ready_receipt or args.source_completion:
            raise InvalidInput("E4 requires the local endpoint")
    else:
        if args.endpoint not in ("source", "destination") or not args.campaign_id:
            raise InvalidInput("E7 requires endpoint and --campaign-id")
        text_value(args.campaign_id, "campaign_id")
        if args.endpoint == "source" and (args.ready_receipt is None or args.source_completion):
            raise InvalidInput("E7 source requires only --ready-receipt")
        if args.endpoint == "destination":
            if args.source_completion is None or args.ready_receipt:
                raise InvalidInput("E7 destination requires only --source-completion")
            inbox = args.source_completion
            if inbox.name in {"plan.json", "summary.json", "qualification.json", "command.json", "config.json",
                              "target-config.json", "receipt.json", "process.json", "native.jsonl", "stdout.raw",
                              "stderr.raw", "target-ready.json", "source-completion.json", "parsed-native.json"}:
                raise InvalidInput("completion inbox conflicts with a reserved output artifact")
            if args.output_dir not in inbox.parents or inbox.exists() or inbox.is_symlink():
                raise InvalidInput("source completion inbox must be absent under the new output directory")
            for parent in (inbox, *inbox.parents):
                if parent.is_symlink():
                    raise InvalidInput("completion inbox cannot contain symlinks")
    cell_shape = dict(shape, block_bytes=[found["block_bytes"]], batch_requests=[found["batch_requests"]])
    endpoints = rig.get("endpoints", {})
    found.update(experiment=args.experiment, shape=cell_shape, rig_identity=rig,
                 campaign_id=args.campaign_id,
                 source_host_id=endpoints.get("source", {}).get("host_id", ""),
                 destination_host_id=endpoints.get("destination", {}).get("host_id", ""),
                 expected_segment="file://" + rig.get("input_file", "{UNRESOLVED_ABSOLUTE_INPUT_FILE}")
                                  if args.experiment == "e4" else "{FRESH_TARGET_SEGMENT_NAME}")
    return found


def run_selected(args, shape, rig, execution_context=None):
    import executor
    import qualification

    cell = selected_cell(args, shape, rig)
    if execution_context is not None:
        if not isinstance(execution_context, executor.ExecutionContext) or execution_context.kind != "contract-fixture":
            raise InvalidInput("only a private fixture context may be injected")
        if execution_context.profile != args.profile or execution_context.endpoint != args.endpoint:
            raise InvalidInput("private fixture context disagrees with selection")
    serialize(args, shape, rig, prepare_execution=True)
    plan = load_object(str(args.output_dir / "plan.json"), "prepared plan")
    row = next(row for row in plan["cells"] if row["cell_id"] == args.cell_id)
    directory = args.output_dir / Path(row["command_file"]).parent
    command = load_object(str(args.output_dir / row["command_file"]), "prepared command")
    if execution_context is None:
        if args.qualification is None:
            verdict = dict(qualified=False, status="setup_refused", missing=["--qualification is required"],
                           execution="none", performance_claim="none", ratio_eligible=False)
        else:
            verdict = qualification.validate_qualification(args.qualification, args, shape, rig, cell)
        write_json(args.output_dir / "qualification.json", verdict)
        if not verdict.get("qualified") or args.mode == "check-setup":
            ok = verdict.get("qualified") is True
            receipt = dict(verdict, cell_id=args.cell_id, profile=args.profile,
                           status="setup_qualified" if ok else "setup_refused", exit_code=0 if ok else 4,
                           execution="none", performance_claim="none", ratio_eligible=False)
            write_json(directory / "receipt.json", receipt)
            return finish_selected(args, plan, row, receipt)
        context = qualification.context_from_qualification(verdict)
        command["needs_build"] = False
    else:
        context = execution_context
    if args.experiment == "e7" and args.endpoint == "source":
        ready = load_object(str(args.ready_receipt), "fresh target ready receipt")
        try:
            segment = executor.validate_ready(ready, cell, context)
        except ValueError as error:
            # Parsed evidence that does not bind this run is a setup refusal,
            # separate from malformed JSON or CLI/shape validation above.
            receipt = dict(schema_version=1, contract_version="mooncake-executor-v3",
                           cell_id=args.cell_id, profile=args.profile, status="setup_refused",
                           refusal_scope="ready_evidence", evidence_qualification="refused",
                           exit_code=4, execution="none", performance_claim="none", ratio_eligible=False,
                           setup_missing=[str(error)], errors=[str(error)],
                           raw_evidence=[str(args.ready_receipt)])
            write_json(directory / "receipt.json", receipt)
            return finish_selected(args, plan, row, receipt)
        original = "--target_seg_name={FRESH_TARGET_SEGMENT_NAME}"
        if command["argv"].count(original) != 1:
            raise InvalidInput("generated source command lacks exact target placeholder")
        command["argv"] = ["--target_seg_name=" + segment if value == original else value for value in command["argv"]]
        cell["expected_segment"] = segment
    if args.experiment == "e7" and args.endpoint == "destination":
        if args.source_completion.exists() or args.source_completion.is_symlink():
            raise InvalidInput("completion inbox is already populated")
        handle = None
        completion = None
        try:
            handle = executor.start_target(command, cell, context, directory)
            print(json.dumps(dict(status="target_ready", execution=context.kind, performance_claim="none",
                                  ready_receipt=str(directory / "target-ready.json"))), flush=True)
            while not handle.capture.closed:
                handle.capture.pump(.1)
                if args.source_completion.exists() or args.source_completion.is_symlink():
                    completion = load_object(str(args.source_completion), "source completion receipt")
                    break
                if handle.process.poll() is not None:
                    break
        except (KeyboardInterrupt, OSError, ValueError):
            if handle is None:
                raise
            completion = None
        finally:
            # Acquisition and every post-start action share the same cleanup boundary.
            if handle is not None:
                receipt = executor.stop_target(handle, completion)
    else:
        timeout = cell["shape"]["duration_seconds"] + 120
        if context.kind == "contract-fixture":
            timeout = context.qualified_receipt.get("timeout_seconds", timeout)
        receipt = executor.execute_cell(command, cell, context, directory, timeout)
        if args.experiment == "e7":
            success = receipt["exit_code"] == 0
            completion = dict(schema_version=1, campaign_id=args.campaign_id, cell_id=args.cell_id,
                              profile=args.profile, destination_host_id=cell["destination_host_id"],
                              source_host_id=cell["source_host_id"], launch_id=ready["launch_id"],
                              segment_name=segment, endpoint="source", execution=context.kind,
                              status="source_completed" if success else "source_failed",
                              source_returncode=receipt["process"]["returncode"],
                              source_cleanup_complete=receipt["process"]["cleanup_complete"],
                              source_receipt=str(directory / "receipt.json"))
            write_json(args.output_dir / "source-completion.json", completion)
    return finish_selected(args, plan, row, receipt)


def finish_selected(args, plan, selected, receipt):
    summary = dict(schema_version=1, contract_version="mooncake-executor-v3",
                   status=receipt["status"], execution=receipt["execution"],
                   performance_claim=receipt.get("performance_claim", "none"), ratio_eligible=False,
                   cell_id=args.cell_id, profile=args.profile, exit_code=receipt["exit_code"],
                   receipt_file=selected["receipt_file"], campaign_status="incomplete", rows=[])
    for row in plan["cells"]:
        summary["rows"].append(dict(cell_id=row["cell_id"], receipt_file=row["receipt_file"],
                                    status=receipt["status"] if row["cell_id"] == args.cell_id else "not_selected"))
    write_json(args.output_dir / "summary.json", summary)
    return receipt["exit_code"], summary


def main(argv=None, execution_context=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("dry-run", "check-setup", "run"))
    parser.add_argument("--experiment", required=True, choices=("e4", "e7"))
    for key in ("shape", "rig", "source-root", "tebench", "output-dir"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--profile", choices=PROFILES)
    parser.add_argument("--cell-id")
    parser.add_argument("--qualification")
    parser.add_argument("--endpoint", choices=("local", "source", "destination"), default="local")
    parser.add_argument("--campaign-id")
    parser.add_argument("--ready-receipt")
    parser.add_argument("--source-completion")
    args = parser.parse_args(argv)
    try:
        for name in ("shape", "rig", "source_root", "tebench", "output_dir"):
            setattr(args, name, absolute_path(getattr(args, name), name))
        shape, rig = load_object(str(args.shape), "shape"), load_object(str(args.rig), "rig")
        validate_shape(shape, args.experiment)
        validate_rig(rig, shape)
        for name in ("qualification", "ready_receipt", "source_completion"):
            if getattr(args, name) is not None:
                setattr(args, name, absolute_path(getattr(args, name), name))
        if execution_context is not None and getattr(execution_context, "kind", None) != "contract-fixture":
            raise InvalidInput("injected physical execution context is not accepted")
        if args.mode == "run" and args.qualification is None and execution_context is None:
            code, summary = serialize(args, shape, rig)
        elif args.mode == "run" or (args.mode == "check-setup" and args.qualification is not None):
            code, summary = run_selected(args, shape, rig, execution_context)
        else:
            code, summary = serialize(args, shape, rig)
    except (ValueError, OSError, UnicodeError, RecursionError, KeyError, TypeError) as error:
        print(json.dumps({"status": "invalid_input", "execution": "none",
                          "performance_claim": "none", "error": str(error)}), file=sys.stderr)
        return 2
    try:
        print(json.dumps(summary, sort_keys=True))
    except (BrokenPipeError, KeyboardInterrupt):
        return 1
    return code


if __name__ == "__main__":
    sys.exit(main())
