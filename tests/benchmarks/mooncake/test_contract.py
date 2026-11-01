#!/usr/bin/env python3
"""Independent Mooncake v1 CLI contract tests; no implementation imports.

Run directly. MOONCAKE_RUNNER may select root's isolated production overlay.
Absent runner returns SETUP (4), never behavioral RED. Expected values come
from CONTRACT.md; compatibility readers only normalize unspecified JSON nesting.
"""
from collections import Counter
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
RUNNER = Path(os.environ.get("MOONCAKE_RUNNER", HERE / "run.py")).resolve()
REVISION = "d01447808d10af78011e9203d53796a15a032a03"
RECEIPT_KEYS = {
    "schema_version", "contract_version", "experiment", "arm", "mode", "status",
    "execution", "performance_claim", "source_revision", "shape", "rig_identity",
    "command_argv", "command_env", "exit_code", "raw_evidence", "route_requested",
    "route_qualification", "correctness_scope", "ratio_eligible",
}


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def dictionaries(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from dictionaries(child)
    elif isinstance(value, list):
        for child in value:
            yield from dictionaries(child)


def options(argv):
    """Validate taskset transport, then parse only tebench CLI arguments."""
    if (not isinstance(argv, list) or len(argv) < 4
            or argv[:2] != ["taskset", "--cpu-list"]
            or not isinstance(argv[2], str) or not argv[2] or argv[2].startswith("-")
            or not isinstance(argv[3], str) or not argv[3] or argv[3].startswith("-")):
        raise AssertionError("expected taskset --cpu-list CPUSET TEBENCH prefix")
    found = {}
    pending = None
    for token in argv[4:]:
        if token.startswith("--"):
            if "=" in token:
                key, value = token[2:].split("=", 1)
                found[key] = value
                pending = None
            else:
                pending = token[2:]
        elif pending:
            found[pending] = token
            pending = None
    return found


class Invocation:
    def __init__(self, process, output, temp_root, requested_shape):
        self.process = process
        self.output = output
        self.temp_root = temp_root
        self.requested_shape = requested_shape
        self.artifacts = {}
        for path in sorted(output.rglob("*.json")) if output.exists() else []:
            self.artifacts[path] = json.loads(path.read_text())

    @property
    def text(self):
        return self.process.stdout + self.process.stderr + json.dumps(list(self.artifacts.values()))

    def named(self, name):
        return [value for path, value in self.artifacts.items() if path.name == name]

    def reference(self, reference):
        if not isinstance(reference, str) or Path(reference).is_absolute() or ".." in Path(reference).parts:
            raise AssertionError("artifact reference is not a relative descendant: " + repr(reference))
        resolved = (self.output / reference).resolve()
        if not resolved.is_relative_to(self.output.resolve()):
            raise AssertionError("artifact reference escapes output: " + reference)
        return resolved

    def commands(self):
        result = []
        plans = self.named("plan.json")
        if len(plans) != 1:
            raise AssertionError("exactly one public plan.json required")
        for cell in plans[0]["cells"]:
            path = self.reference(cell["command_file"])
            obj = self.artifacts[path]
            result.append((path, obj, obj["argv"], obj["env"]))
        return result

    def config(self, path, env):
        conf = env["MC_TENT_CONF"]
        candidate = Path(conf)
        if not candidate.is_absolute():
            candidates = [path.parent / candidate, self.output / candidate, self.temp_root / candidate]
            candidate = next((p for p in candidates if p.is_file()), candidates[0])
        return json.loads(candidate.read_text())


class MooncakeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RUNNER.is_file():
            raise unittest.SkipTest("SETUP: NEW_COMPONENT_NO_BEHAVIOR_BASELINE; runner absent")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mooncake-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.call_index = 0

    def invoke(self, *, shape=None, rig=None, mode="dry-run", experiment="e4", ambient=None,
               source_root=None, output_dir=None):
        self.call_index += 1
        base = self.root / str(self.call_index)
        base.mkdir()
        shape = deepcopy(shape if shape is not None else fixture(experiment + "-shape.json"))
        rig = deepcopy(rig if rig is not None else fixture(experiment + "-rig.json"))
        shape_path, rig_path = base / "shape.json", base / "rig.json"
        shape_path.write_text(json.dumps(shape))
        rig_path.write_text(json.dumps(rig))
        output = Path(output_dir) if output_dir is not None else base / "out"
        source = Path(source_root) if source_root is not None else base / "missing source $(touch BAD_SOURCE)"
        if not output.resolve().is_relative_to(self.root.resolve()) or not source.resolve().is_relative_to(self.root.resolve()):
            raise AssertionError("test paths must remain inside this test's temporary directory")
        env = dict(os.environ)
        env.update(ambient or {})
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        command = [sys.executable, str(FIXTURES / "cli_guard.py"), str(RUNNER),
                   "--mode", mode, "--experiment", experiment,
                   "--shape", str(shape_path), "--rig", str(rig_path),
                   "--source-root", str(source),
                   "--tebench", str(base / "missing tebench $(touch BAD_BENCH)"),
                   "--output-dir", str(output)]
        process = subprocess.run(command, text=True, capture_output=True, env=env,
                                 cwd=base, timeout=30, check=False)
        self.assertNotIn("CONTRACT_SIDE_EFFECT_BLOCKED", process.stdout + process.stderr,
                         "real CLI attempted forbidden subprocess/network/device side effect")
        self.assertFalse((base / "BAD_SOURCE").exists())
        self.assertFalse((base / "BAD_BENCH").exists())
        return Invocation(process, output, base, shape)

    def assert_no_performance_claim(self, result):
        for value in result.artifacts.values():
            for obj in dictionaries(value):
                if "ratio_eligible" in obj and ("status" in obj or "contract_version" in obj):
                    self.assertIs(obj["ratio_eligible"], False)
                for key, item in obj.items():
                    metric = re.search(r"throughput|latency|speedup|(^|_)io_ns$|(^|_)ratio$|bandwidth", key, re.I)
                    if metric:
                        self.assertFalse(isinstance(item, (int, float)) and not isinstance(item, bool),
                                         f"unexecuted result carries numeric performance metric {key}={item}")
                self.assertNotEqual(obj.get("status"), "PASS")
                # Nested rig facts describe intended physical execution; only
                # wrapper status objects claim what this invocation actually did.
                if "status" in obj and "execution" in obj:
                    self.assertEqual(obj["execution"], "none")
                if "performance_claim" in obj:
                    self.assertEqual(obj["performance_claim"], "none")

    def assert_planned(self, result):
        self.assertEqual(result.process.returncode, 0, result.text)
        self.assertEqual(len(result.named("plan.json")), 1, "public plan.json missing")
        plan = result.named("plan.json")[0]
        required = {"schema_version", "contract_version", "source_revision", "experiment", "mode",
                    "status", "execution", "performance_claim", "ratio_eligible", "shape", "rig_identity", "cells",
                    "access_contract", "residency_qualification", "completion_contract"}
        self.assertTrue(required <= set(plan), sorted(required - set(plan)))
        self.assertEqual(plan["schema_version"], 1)
        self.assertEqual(plan["contract_version"], "mooncake-baseline-v1")
        self.assertEqual(plan["source_revision"], REVISION)
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["mode"], "dry-run")
        self.assertEqual(plan["execution"], "none")
        self.assertEqual(plan["performance_claim"], "none")
        self.assertIs(plan["ratio_eligible"], False)
        self.assertEqual(plan["residency_qualification"], "pending")
        self.assertEqual(plan["completion_contract"], "tebench-batch-completed")
        self.assertEqual(plan["access_contract"], "batch-random-with-replacement" if plan["experiment"] == "e4" else "fixed-target-write")
        self.assertEqual(plan["shape"], result.requested_shape)
        cells = plan["cells"]
        self.assertIsInstance(cells, list)
        self.assertEqual(len({cell["cell_id"] for cell in cells}), len(cells))
        self.assertTrue(all(isinstance(cell["cell_id"], str) and cell["cell_id"] for cell in cells))
        actual = Counter()
        allowed_files = {result.output / "plan.json"}
        for cell in cells:
            self.assertTrue({"cell_id", "profile", "arm", "block_bytes", "batch_requests", "repetition",
                             "command_file", "config_file", "receipt_file"} <= set(cell))
            actual[(cell["profile"], cell["arm"], cell["block_bytes"], cell["batch_requests"], cell["repetition"])] += 1
            for key in ["command_file", "config_file", "receipt_file"]:
                self.assertTrue(result.reference(cell[key]).is_file(), key)
                allowed_files.add(result.reference(cell[key]))
            command = result.artifacts[result.reference(cell["command_file"])]
            if "target_command" in command:
                allowed_files.add(result.reference(command["target_command"]["config_file"]))
            self.assertTrue({"schema_version", "cell_id", "profile", "arm", "argv", "env", "config_file", "needs_build"} <= set(command))
            self.assertEqual(command["schema_version"], 1)
            for key in ["cell_id", "profile", "arm", "config_file"]:
                self.assertEqual(command[key], cell[key])
            self.assertIs(command["needs_build"], True, "fixture tebench is absent")
            self.assertIsInstance(command["argv"], list)
            self.assertTrue(all(isinstance(value, str) for value in command["argv"]))
            self.assertIsInstance(command["env"], dict)
            self.assertTrue(all(isinstance(key, str) and isinstance(value, str) for key, value in command["env"].items()))
        shape = plan["shape"]
        arms = ["iouring-default", "iouring-pinned", "gds-compat"] if plan["experiment"] == "e4" else ["tcp"]
        expected = Counter((profile, arm, block, batch, repetition)
                           for profile in ["native", "xdev_ext"] for arm in arms
                           for block in shape["block_bytes"] for batch in shape["batch_requests"]
                           for repetition in range(shape["repetitions"]))
        self.assertEqual(actual, expected)
        allowed_resolved = {file.resolve() for file in allowed_files}
        for path in result.output.rglob("*"):
            if path.is_file():
                self.assertIn(path.resolve(), allowed_resolved, "dry-run wrote non-plan artifact")
        summary = json.loads(result.process.stdout)
        self.assertIsInstance(summary, dict)
        self.assertIn("plan.json", json.dumps(summary))
        self.assert_no_performance_claim(result)
        return result.commands()

    def small_shape(self, experiment="e4"):
        value = fixture(experiment + "-shape.json")
        value.update(block_bytes=[1048576], batch_requests=[1], repetitions=1)
        return value

    def test_e4_three_arms_exact_flags_and_configs(self):
        """Catch wrong flags, swapped transport spelling, fallback or missing arm."""
        result = self.invoke(shape=self.small_shape())
        commands = self.assert_planned(result)
        self.assertEqual(len(commands), 6, "3 arms under native and xdev profiles")
        kinds = Counter()
        for path, obj, argv, env in commands:
            self.assertIsInstance(env, dict)
            flags = options(argv)
            want = {"backend":"tent", "metadata_type":"p2p", "seg_type":"VRAM",
                    "local_gpu_id":"0", "total_buffer_size":"1073741824",
                    "target_seg_name":"file:///planning-only/input with spaces.bin",
                    "target_offset":"0", "target_range_size":"1073741824",
                    "target_access":"random", "target_window_size":"1073741824",
                    "start_block_size":"1048576", "max_block_size":"1048576",
                    "start_batch_size":"1", "max_batch_size":"1",
                    "start_num_threads":"1", "max_num_threads":"1", "duration":"10",
                    "op_type":"read", "check_consistency":"false"}
            for key, value in want.items():
                self.assertEqual(flags.get(key), value, key)
            self.assertEqual(set(flags), set(want) | {"xport_type", "result_output_jsonl"})
            self.assertEqual(argv[:3], ["taskset", "--cpu-list", "2-5"])
            self.assertIn("missing tebench $(touch BAD_BENCH)", argv[3])
            config = result.config(path, env)
            if flags["xport_type"] == "iouring":
                pool = config["transports"]["io_uring"]
                if pool["pinned_staging"] is True:
                    self.assertEqual(config, {"transports":{"io_uring":{"pinned_staging":True,
                                                                         "staging_slot_kb":4096,
                                                                         "staging_slots":32}}})
                    kinds["pinned"] += 1
                else:
                    self.assertEqual(config, {"transports":{"io_uring":{"pinned_staging":False}}})
                    kinds["default"] += 1
                self.assertNotIn("CUFILE_FORCE_COMPAT_MODE", env)
            else:
                self.assertEqual(flags["xport_type"], "gds")
                self.assertEqual(config, {})
                self.assertEqual(env.get("CUFILE_FORCE_COMPAT_MODE"), "true")
                kinds["gds-compat"] += 1
        self.assertEqual(kinds, {"default":2, "pinned":2, "gds-compat":2})

    def test_full_documented_sweep_keeps_every_cell(self):
        """Catch silently skipped block/batch/repetition/profile cells."""
        result = self.invoke()
        commands = self.assert_planned(result)
        self.assertEqual(len(commands), 990)
        cells = Counter()
        for _, _, argv, _ in commands:
            flags = options(argv)
            self.assertEqual(flags["start_block_size"], flags["max_block_size"])
            self.assertEqual(flags["start_batch_size"], flags["max_batch_size"])
            self.assertEqual(flags["start_num_threads"], flags["max_num_threads"])
            cells[(int(flags["start_block_size"]), int(flags["start_batch_size"]))] += 1
        self.assertEqual(set(cells.values()), {30})
        self.assertEqual(len(cells), 33)

    def test_receipts_preserve_truthful_scope_and_cpu_budget(self):
        """Catch false execution/PASS/one-total-CPU or omitted qualification facts."""
        result = self.invoke(shape=self.small_shape())
        self.assert_planned(result)
        receipts = result.named("receipt.json")
        self.assertTrue(receipts, "wrapper receipt is required")
        for receipt in receipts:
            self.assertTrue(RECEIPT_KEYS <= set(receipt), sorted(RECEIPT_KEYS - set(receipt)))
            self.assertEqual(receipt["contract_version"], "mooncake-baseline-v1")
            self.assertEqual(receipt["shape"], self.small_shape())
            self.assertEqual(receipt["source_revision"], REVISION)
            self.assertIs(receipt["ratio_eligible"], False)
            identity = json.dumps(receipt["rig_identity"])
            self.assertIn("2-5", identity)
            self.assertIn("4 allowed CPUs", identity)
            self.assertNotIn(receipt["route_qualification"], ["direct", "direct-gds", "qualified"])

    def test_worker_window_offset_and_pinned_budget(self):
        """Catch per-request windows, wrong offset or underbudget pools."""
        shape = self.small_shape()
        shape.update(worker_threads=2, batch_requests=[32], pinned_slots=64,
                     target_offset=4096)
        result = self.invoke(shape=shape)
        commands = self.assert_planned(result)
        for path, _, argv, env in commands:
            flags = options(argv)
            self.assertEqual(flags["target_window_size"], "536870912")
            self.assertEqual(flags["target_offset"], "4096")
            self.assertEqual(flags["start_num_threads"], "2")
            conf = result.config(path, env)
            if conf.get("transports", {}).get("io_uring", {}).get("pinned_staging"):
                self.assertEqual(conf["transports"]["io_uring"]["staging_slots"], 64)

    def test_e7_tcp_has_local_target_and_source_plans(self):
        """Catch reversed direction, invented segment, wrong transport or SSH."""
        result = self.invoke(shape=self.small_shape("e7"), experiment="e7")
        commands = self.assert_planned(result)
        self.assertEqual(len(commands), 2)
        for path, obj, source_argv, source_env in commands:
            self.assertEqual(obj["target_segment_source"], "fresh-target-stdout")
            target = obj["target_command"]
            self.assertTrue({"argv", "env", "config_file"} <= set(target))
            flags = options(source_argv)
            self.assertEqual(source_argv[:3], ["taskset", "--cpu-list", "2-5"])
            self.assertEqual(flags["target_seg_name"], "{FRESH_TARGET_SEGMENT_NAME}")
            source_want = {"backend":"tent", "metadata_type":"p2p", "xport_type":"tcp",
                           "seg_type":"DRAM", "local_gpu_id":"0", "total_buffer_size":"1073741824",
                           "rpc_server_port":"18001",
                           "target_offset":"0", "target_range_size":"1073741824", "target_access":"fixed",
                           "start_block_size":"1048576", "max_block_size":"1048576",
                           "start_batch_size":"1", "max_batch_size":"1", "start_num_threads":"1",
                           "max_num_threads":"1", "duration":"10", "op_type":"write", "check_consistency":"false"}
            for key, value in source_want.items():
                self.assertEqual(flags.get(key), value, key)
            self.assertEqual(set(flags), set(source_want) | {"target_seg_name", "result_output_jsonl"})
            target_flags = options(target["argv"])
            self.assertEqual(target["argv"][:3], ["taskset", "--cpu-list", "6-9"])
            self.assertEqual(target_flags, {"backend":"tent", "metadata_type":"p2p", "xport_type":"tcp",
                                           "seg_type":"VRAM", "local_gpu_id":"0",
                                           "total_buffer_size":"1073741824", "rpc_server_port":"18002"})
            self.assertEqual(result.config(path, source_env), {"rpc_server_hostname":"192.0.2.1"})
            target_conf = result.reference(target["config_file"])
            self.assertEqual(json.loads(target_conf.read_text()), {"rpc_server_hostname":"192.0.2.2"})
            self.assertEqual(result.reference(obj["config_file"]), Path(source_env["MC_TENT_CONF"]).resolve()
                             if Path(source_env["MC_TENT_CONF"]).is_absolute()
                             else result.reference(source_env["MC_TENT_CONF"]))
        self.assertNotIn("pinned_staging", result.text)

    def test_unlisted_ambient_config_never_enters_commands(self):
        """Catch ambient tuning/forced transport sneaking into a default arm."""
        result = self.invoke(shape=self.small_shape(), ambient={
            "MC_IOURING_QUEUE_DEPTH":"7", "MC_FORCE_TCP":"1",
            "MOONCAKE_LOCAL_HOSTNAME":"secret-ambient-host"})
        commands = self.assert_planned(result)
        for _, _, _, env in commands:
            self.assertFalse(any(key.startswith("MC_IOURING_") for key in env))
            self.assertNotIn("MC_FORCE_TCP", env)
            self.assertNotIn("MOONCAKE_LOCAL_HOSTNAME", env)

    def test_integer_types_and_overflow_are_rejected(self):
        """Catch bool/int coercion, floats, negatives, zero counts and overflow."""
        integers = ["schema_version", "worker_threads", "buffer_bytes", "target_bytes",
                    "target_offset", "duration_seconds", "repetitions", "pinned_slot_kib",
                    "pinned_slots", "gpu_ordinal"]
        for key in integers:
            for invalid in [True, 1.0, "1", None, -1, 18446744073709551616]:
                with self.subTest(key=key, invalid=invalid):
                    shape = self.small_shape()
                    shape[key] = invalid
                    result = self.invoke(shape=shape)
                    self.assertEqual(result.process.returncode, 2, result.text)
                    self.assert_no_performance_claim(result)
        for key in ["block_bytes", "batch_requests"]:
            for invalid in [[True], [1.0], [-1], [0], [18446744073709551616], []]:
                with self.subTest(key=key, invalid=invalid):
                    shape = self.small_shape()
                    shape[key] = invalid
                    self.assertEqual(self.invoke(shape=shape).process.returncode, 2)
        for key in ["worker_threads", "buffer_bytes", "target_bytes", "duration_seconds",
                    "repetitions", "pinned_slot_kib", "pinned_slots"]:
            with self.subTest(zero=key):
                shape = self.small_shape()
                shape[key] = 0
                self.assertEqual(self.invoke(shape=shape).process.returncode, 2)

    def test_json_objects_and_complete_shapes_are_required(self):
        """Catch malformed containers, sparse input defaulting and scalar sweeps."""
        for malformed in [[], "shape", 1, True]:
            with self.subTest(shape=malformed):
                self.assertEqual(self.invoke(shape=malformed).process.returncode, 2)
        for malformed in [[], "rig", 1, True]:
            with self.subTest(rig=malformed):
                self.assertEqual(self.invoke(rig=malformed).process.returncode, 2)
        for key in self.small_shape():
            with self.subTest(missing=key):
                shape = self.small_shape()
                del shape[key]
                self.assertEqual(self.invoke(shape=shape).process.returncode, 2)
        for key in ["block_bytes", "batch_requests"]:
            for malformed in [1, "4096", None, {}]:
                with self.subTest(key=key, value=malformed):
                    shape = self.small_shape()
                    shape[key] = malformed
                    self.assertEqual(self.invoke(shape=shape).process.returncode, 2)

        for key in ["worker_threads", "repetitions", "duration_seconds", "pinned_slots", "gpu_ordinal"]:
            with self.subTest(signed32_overflow=key):
                shape = self.small_shape()
                shape[key] = 2147483648
                self.assertEqual(self.invoke(shape=shape).process.returncode, 2)
        shape = self.small_shape()
        shape["repetitions"] = 16667
        too_many = self.invoke(shape=shape)
        self.assertEqual(too_many.process.returncode, 2, too_many.text)
        self.assertFalse(too_many.output.exists(), "100002 cells must refuse before output creation")
        for port in [True, 0, -1, 65536, 1.0, "18001"]:
            with self.subTest(endpoint_port=port):
                rig = fixture("e7-rig.json")
                rig["endpoints"]["source"]["rpc_port"] = port
                self.assertEqual(self.invoke(shape=self.small_shape("e7"), rig=rig, experiment="e7").process.returncode, 2)
        for bad in ["true", 1]:
            with self.subTest(bad_authorization_type=bad):
                rig = fixture("e4-rig.json")
                rig["physical_run_authorized"] = bad
                self.assertEqual(self.invoke(shape=self.small_shape(), rig=rig).process.returncode, 2)

    def test_unknown_shape_keys_and_inconsistent_mode_are_rejected(self):
        """Catch silently accepted extensions and semantically different access."""
        for updates in [{"unknown_field":1}, {"experiment":"e7"}, {"op_type":"write"},
                        {"target_access":"fixed"}, {"schema_version":2}]:
            with self.subTest(updates=updates):
                shape = self.small_shape()
                shape.update(updates)
                self.assertEqual(self.invoke(shape=shape).process.returncode, 2)
        shape = self.small_shape("e7")
        shape["pinned_slots"] = 32
        self.assertEqual(self.invoke(shape=shape, experiment="e7").process.returncode, 2)

    def test_capacity_window_and_slot_minima_reject_bad_cells(self):
        """Catch sweep-skipping and acceptance of impossible window/pool budgets."""
        cases = [
            {"buffer_bytes":1048575},
            {"target_bytes":1048576},
            {"target_bytes":1073741823},
            {"worker_threads":3, "pinned_slots":96},
            {"pinned_slot_kib":1023},
            {"batch_requests":[32], "worker_threads":2, "pinned_slots":32},
            {"block_bytes":[1048576,4194304], "batch_requests":[32], "buffer_bytes":134217727},
        ]
        for update in cases:
            with self.subTest(update=update):
                shape = self.small_shape()
                shape.update(update)
                self.assertEqual(self.invoke(shape=shape).process.returncode, 2)

    def test_exact_budget_boundaries_and_zero_ordinal_are_legal(self):
        """Catch off-by-one minimum-window/buffer/pool rejection."""
        shape = self.small_shape()
        shape.update(block_bytes=[4096], batch_requests=[1], buffer_bytes=4096,
                     target_bytes=8192, pinned_slot_kib=4, pinned_slots=1)
        self.assert_planned(self.invoke(shape=shape))

    def test_input_path_is_regular_absolute_file_uri_and_shell_inert(self):
        """Catch device URI acceptance, relative paths and shell interpolation."""
        for bad in ["/dev/ng0n1", "/dev/nvme0n1", "relative.bin", "file:///dev/ng0n1"]:
            with self.subTest(path=bad):
                rig = fixture("e4-rig.json")
                rig["input_file"] = bad
                self.assertEqual(self.invoke(shape=self.small_shape(), rig=rig).process.returncode, 2)
        rig = fixture("e4-rig.json")
        rig["input_file"] = "/planning-only/input $(touch SHOULD_NOT_EXIST);*.bin"
        result = self.invoke(shape=self.small_shape(), rig=rig)
        for _, _, argv, _ in self.assert_planned(result):
            self.assertEqual(options(argv)["target_seg_name"],
                             "file:///planning-only/input $(touch SHOULD_NOT_EXIST);*.bin")
        self.assertFalse((result.temp_root / "SHOULD_NOT_EXIST").exists())

    def test_check_setup_lists_all_missing_prerequisites(self):
        """Catch first-error-only reporting and false setup PASS."""
        result = self.invoke(shape=self.small_shape(), rig={"schema_version":1}, mode="check-setup")
        self.assertEqual(result.process.returncode, 4, result.text)
        self.assertIn("setup_refused", result.text)
        for missing in ["tebench", "build_receipt", "cpuset", "gpu_uuid", "input_file",
                        "input_validation_receipt", "file_extent_receipt", "exclusive_window_receipt"]:
            self.assertIn(missing, result.text)
        self.assert_no_performance_claim(result)

    def test_arbitrary_rig_json_never_authorizes_run(self):
        """Catch trusting a user editable JSON boolean as execution authorization."""
        for auth in [False, True]:
            with self.subTest(authorization=auth):
                rig = fixture("e4-rig.json")
                rig["physical_run_authorized"] = auth
                result = self.invoke(shape=self.small_shape(), rig=rig, mode="run")
                self.assertEqual(result.process.returncode, 4, result.text)
                self.assertIn("setup_refused", result.text)
                self.assert_no_performance_claim(result)

    def test_unequal_pairing_claim_cannot_enable_ratio(self):
        """Catch an injected pairing claim bypassing v1 unequal-workload exclusion."""
        rig = fixture("e4-rig.json")
        rig["comparison"] = {"system":"nvme_gpu", "ratio_eligible":True,
                             "same_namespace":True, "distribution":"affine-no-replacement",
                             "timer":"first-submit-final-settle"}
        result = self.invoke(shape=self.small_shape(), rig=rig)
        # Rig extension policy is unspecified: refusing the added object is valid;
        # accepting it must still refuse causal pairing and keep ratio false.
        self.assertIn(result.process.returncode, [0, 2, 4], result.text)
        self.assert_no_performance_claim(result)
        if result.process.returncode == 0:
            self.assertTrue(result.named("receipt.json"))
            for receipt in result.named("receipt.json"):
                self.assertIs(receipt["ratio_eligible"], False)

    def test_nonphysical_execution_cannot_run(self):
        """Catch guest/host-model qualification becoming physical run authority."""
        for execution in ["kvm", "guest", "simulation", "host-model"]:
            with self.subTest(execution=execution):
                rig = fixture("e4-rig.json")
                rig.update(physical_run_authorized=True, execution=execution)
                result = self.invoke(shape=self.small_shape(), rig=rig, mode="run")
                self.assertEqual(result.process.returncode, 4, result.text)
                self.assertIn("setup_refused", result.text)
                self.assert_no_performance_claim(result)


    def assert_invalid_without_cell_artifacts(self, result):
        self.assertEqual(result.process.returncode, 2, result.text)
        self.assertEqual(result.artifacts, {}, "invalid input wrote JSON artifacts")
        if result.output.exists():
            self.assertFalse(any(path.is_file() for path in result.output.rglob("*")),
                             "invalid input wrote cell artifacts")
        self.assert_no_performance_claim(result)

    def test_output_inside_resolved_source_alias_is_refused(self):
        """MC-R1: catch lexical-only source/output containment checks."""
        for spelling in ["resolved", "declared"]:
            with self.subTest(output_spelling=spelling):
                actual = self.root / (spelling + " actual upstream")
                actual.mkdir()
                sentinel = actual / "untouched-source.txt"
                sentinel.write_text("upstream test sentinel; preserve exact content\n")
                alias = self.root / (spelling + " source alias $(touch NEVER)")
                alias.symlink_to(actual, target_is_directory=True)
                output = (actual if spelling == "resolved" else alias) / "planned-output"
                result = self.invoke(shape=self.small_shape(), source_root=alias, output_dir=output)
                self.assert_invalid_without_cell_artifacts(result)
                self.assertEqual(sentinel.read_text(), "upstream test sentinel; preserve exact content\n")
                self.assertEqual({path.relative_to(actual) for path in actual.rglob("*") if path.is_file()},
                                 {Path("untouched-source.txt")})

    def test_e4_uri_rejects_comma_and_trailing_whitespace(self):
        """MC-R2: catch upstream URI splitting/trimming changing the target path."""
        for invalid in ["/planning-only/input,second.bin", "/planning-only/input.bin ",
                        "/planning-only/input.bin\t", "/planning-only/input.bin\n",
                        "/planning-only/input.bin\r"]:
            with self.subTest(input_file=invalid):
                rig = fixture("e4-rig.json")
                rig["input_file"] = invalid
                self.assert_invalid_without_cell_artifacts(self.invoke(shape=self.small_shape(), rig=rig))
        rig = fixture("e4-rig.json")
        rig["input_file"] = "/planning-only/internal spaces stay literal.bin"
        result = self.invoke(shape=self.small_shape(), rig=rig)
        for _, _, argv, _ in self.assert_planned(result):
            self.assertEqual(options(argv)["target_seg_name"],
                             "file:///planning-only/internal spaces stay literal.bin")

    def test_e7_target_offset_uses_actual_worker_batch_allocation(self):
        """MC-R3: catch target_range passing while actual worker batches overrun."""
        shape = self.small_shape("e7")
        shape.update(block_bytes=[4096], batch_requests=[2], worker_threads=2,
                     buffer_bytes=24576, target_bytes=16384, target_offset=8192)
        # target_bytes covers 2*(4096*2)=16384 worker-batch bytes.
        # 8192 + 2*(4096*2) = 24576, exactly the selected GPU buffer.
        result = self.invoke(shape=shape, experiment="e7")
        for _, _, argv, _ in self.assert_planned(result):
            self.assertEqual(options(argv)["target_offset"], "8192")
            self.assertEqual(options(argv)["total_buffer_size"], "24576")
        # The actual allocation sum is 8193+16384=24577 and must refuse
        # without enlarging the selected buffer or changing the offset.
        shape["target_offset"] = 8193
        self.assert_invalid_without_cell_artifacts(self.invoke(shape=shape, experiment="e7"))

    def test_local_buffer_includes_requested_gpu_ordinal(self):
        """MC-R4: catch ignored/rewritten ordinal in local buffer admission."""
        for experiment in ["e4", "e7"]:
            with self.subTest(experiment=experiment):
                shape = self.small_shape(experiment)
                shape.update(block_bytes=[4096], batch_requests=[2], worker_threads=2,
                             buffer_bytes=16384, target_bytes=32768 if experiment == "e4" else 16384,
                             gpu_ordinal=0)
                if experiment == "e4":
                    shape.update(pinned_slot_kib=4, pinned_slots=4)
                # Ordinal zero: (0+2)*(4096*2)=16384 exactly.
                zero = self.invoke(shape=shape, experiment=experiment)
                for _, _, argv, _ in self.assert_planned(zero):
                    self.assertEqual(options(argv)["local_gpu_id"], "0")
                # Ordinal one needs 24576; retain all other requested facts.
                shape["gpu_ordinal"] = 1
                self.assert_invalid_without_cell_artifacts(self.invoke(shape=shape, experiment=experiment))
                shape["buffer_bytes"] = 24576
                one = self.invoke(shape=shape, experiment=experiment)
                for _, _, argv, _ in self.assert_planned(one):
                    self.assertEqual(options(argv)["local_gpu_id"], "1")
                    self.assertEqual(options(argv)["total_buffer_size"], "24576")

    def test_block_doubling_uint64_boundary_is_admitted_safely(self):
        """MC-R5: catch post-cell unsigned block doubling overflow with start=max."""
        shape = self.small_shape("e7")
        shape.update(block_bytes=[9223372036854771712], batch_requests=[1], worker_threads=1,
                     buffer_bytes=9223372036854771712, target_bytes=9223372036854771712)
        # Largest 4096-aligned block <=UINT64_MAX//2: 2**63-4096.
        # Symbolic byte budgets only, two cells, no allocations.
        result = self.invoke(shape=shape, experiment="e7")
        for _, _, argv, _ in self.assert_planned(result):
            self.assertEqual(options(argv)["start_block_size"], "9223372036854771712")
            self.assertEqual(options(argv)["max_block_size"], "9223372036854771712")
        shape.update(block_bytes=[9223372036854775808], buffer_bytes=9223372036854775808,
                     target_bytes=9223372036854775808)
        self.assert_invalid_without_cell_artifacts(self.invoke(shape=shape, experiment="e7"))

    def test_thread_doubling_int32_boundary_is_admitted_safely(self):
        """MC-R5: catch post-cell signed thread doubling overflow with start=max."""
        shape = self.small_shape("e7")
        shape.update(block_bytes=[4096], batch_requests=[1], worker_threads=1073741823,
                     buffer_bytes=4398046507008, target_bytes=4398046507008)
        # INT32_MAX//2 threads; 1073741823*4096=4398046507008 symbolic bytes.
        result = self.invoke(shape=shape, experiment="e7")
        for _, _, argv, _ in self.assert_planned(result):
            self.assertEqual(options(argv)["start_num_threads"], "1073741823")
            self.assertEqual(options(argv)["max_num_threads"], "1073741823")
        shape.update(worker_threads=1073741824, buffer_bytes=4398046511104,
                     target_bytes=4398046511104)
        self.assert_invalid_without_cell_artifacts(self.invoke(shape=shape, experiment="e7"))


if __name__ == "__main__":
    if not RUNNER.is_file():
        print("SETUP: NEW_COMPONENT_NO_BEHAVIOR_BASELINE: runner absent: " + str(RUNNER), file=sys.stderr)
        raise SystemExit(4)
    unittest.main(verbosity=2)
