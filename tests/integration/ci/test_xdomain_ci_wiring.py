# SPDX-License-Identifier: GPL-2.0
"""CI must execute the frozen XDOMAIN host entrypoints and reject lost failures.

The external command recorder replaces expensive child tests, not the runner or
the CI shell. No GPU, SDK, GitHub, or server operation happens in this suite.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = (Path(json.loads((ROOT / "view.json").read_text())["canonical_root"])
               if (ROOT / "view.json").is_file() else ROOT)
RUNNER = Path("tools/ci/check_xdomain_host.py")
RUNNER_COMMAND = r'python3\s+(?:-I\s+)?(?:"\$GITHUB_WORKSPACE/)?tools/ci/check_xdomain_host\.py(?:"|\b)'
PREPARE_COMMAND = r'python3\s+(?:"\$GITHUB_WORKSPACE/)?tools/build/prepare_xdomain_host_inputs\.py(?:"|\b)'
PEER = "kernel/tools/testing/selftests/xdev_ext_mech/peer_graph/"
EVAL = "tests/eval/xdomain/"
REQUIRED = tuple(PEER + name + ".py" for name in (
    "xdomain_identity_test", "xdomain_kfunc_test", "xdomain_program_test",
    "xdomain_login_test", "tb_protocol_handler_lifetime_test",
    "tbnet_handler_teardown_test", "xdomain_ring_test", "xdomain_nhi_test",
    "xdomain_class_test", "xdomain_review_geometry_test", "xdomain_review_protocol_test", "session_stop_clock_test", "xdomain_guest_verdict_test",
    "netfam_rel_kfunc_test", "class_table_source_test", "class_bind_test",
    "xdomain_review_lifecycle_test",
    "xdomain_review_retry_test",
    "xdomain_review_readiness_test",
    "xdomain_review_stats_ring_test",
    "requester_retention_test",
    "xdomain_review_retention_ring_test",
    "xdomain_login_reply_test", "xdomain_review_tbnet_test",
    "xdomain_review_stop_epoch_test",
    "xdomain_production_poll_test",
)) + (
    "kernel/tools/testing/selftests/xdev_ext_mech/core_lifecycle/stop_report_test.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/core_lifecycle/ordered_frames_test.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/core_lifecycle/ordered_frames_worker_test.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/user_stage/run.py",
    "gpu/tests/nv_xdev_ext_peer_raw_bus_source_test.py",
) + tuple(EVAL + name + ".py" for name in (
    "test_epoch_control", "test_control_guard", "test_gpu_contract", "test_build",
    "test_contract", "test_retention", "test_oracle", "test_cases",
    "test_action_provider", "test_case_dispatch", "test_platform_facts",
    "test_native_barrier", "test_durable_failure", "test_native_trace_owner",
    "test_c2_terminals", "test_create_refusal", "test_owner_close",
    "test_runtime_package", "test_stop_report", "test_observer", "test_uapi_search",
)) + (
    "kernel/tools/testing/selftests/xdev_ext_mech/xdomain/test_prepared_inputs.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/xdomain/stack_test.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/xdomain/test_mutations.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/xdomain/nhi_stack_test.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/xdomain/test_nhi_stack_mutations.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/xdomain/stack_environment_test.py",
)
CANONICAL_REQUIRED = (
    "tests/network/xdomain/early/run.py",
    "tests/network/xdomain/early/kfunc_test.py",
    "tests/core/library/peer_wait/run.py",
    "tests/network/xdomain/probe/probe_gate_test.py",
    "tests/network/xdomain/probe/probe_wire_test.py",
    "tests/network/xdomain/probe/probe_transport_test.py",
    "tests/core/admission_report/run.py",
    "tests/core/library/create_report/run.py",
    "tests/network/xdomain/diagnostics/run.py",
    "tests/network/xdomain/diagnostics/stack_run.py",
    "tests/core/library/stage_diag/run.py",
    "tests/compute/user_stage/user_stop_origin_test.py",
)


class CIWiring(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xdomain-ci-contract-")
        self.addCleanup(self.temp.cleanup)
        self.tree = Path(self.temp.name)
        self.bin = self.tree / "bin"
        self.bin.mkdir()
        self.record = self.tree / "commands.jsonl"
        recorder = self.bin / "python3"
        recorder.write_text("#!" + sys.executable + "\n" + r'''
import json, os, sys
from pathlib import Path
with open(os.environ["RECORDER_FILE"], "a") as out:
    out.write(json.dumps(sys.argv[1:]) + "\n")
missing = os.environ.get("RECORDER_REMOVE", "")
if missing:
    Path(missing).unlink(missing_ok=True)
target = os.environ.get("RECORDER_TARGET", "")
if target in sys.argv[1:]:
    print(os.environ.get("RECORDER_OUTPUT", ""), flush=True)
    raise SystemExit(int(os.environ.get("RECORDER_EXIT", "0")))
print("ok 1 - controlled external child", flush=True)
''')
        recorder.chmod(0o755)
        isolated = {key: value for key, value in os.environ.items()
                    if key not in ("XDEV_EXT_CANONICAL_ROOT", "XDEV_EXT_SOURCE_VIEW")}
        self.env = dict(isolated, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        CC="gcc", CXX="g++", RECORDER_FILE=str(self.record))

    def prepare_runner(self):
        product = json.loads((SOURCE_ROOT / "source-layout.json").read_text())
        by_source = {entry["source"]: entry for entry in product["files"]}
        by_logical = {}
        for entry in product["files"]:
            logical = (entry["logical_path"] if "logical_path" in entry else
                       {"linux": "kernel", "nvidia": "gpu"}[entry["component"]]
                       + "/" + entry["native_path"])
            by_logical[logical] = entry
        self.sources = {name: by_logical[name]["source"] for name in REQUIRED}
        files = {self.sources[name]: by_logical[name] for name in REQUIRED}
        files.update({name: by_source[name] for name in CANONICAL_REQUIRED})
        lock_name = product["dependency_lock"]
        lock = json.loads((SOURCE_ROOT / lock_name).read_text())
        nhi = ("tests/support/fixtures/upstream/linux-" +
               lock["components"]["linux"]["commit"] + "/nhi_regs.h")
        dependencies = (str(RUNNER), "tools/layout.py", lock_name, nhi)
        files.update({name: by_source[name] for name in dependencies})
        for name in files:
            destination = self.tree / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if name in dependencies:
                shutil.copy2(SOURCE_ROOT / name, destination)
            else:
                destination.write_text("# External child boundary; not test evidence.\n")
        manifest = dict(product, files=list(files.values()))
        (self.tree / "source-layout.json").write_text(json.dumps(manifest))
        # Real layout provenance requires a real private checkout. Neither Git
        # metadata nor a generated view in the caller's product is modified.
        subprocess.run(["git", "init", "-q", str(self.tree)], env=self.env, check=True)
        subprocess.run(["git", "-C", str(self.tree), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit",
                        "--allow-empty", "-qm", "isolated runner fixture"],
                       env=self.env, check=True)

    def run_runner(self, target="", output="", code=0, remove=""):
        env = dict(self.env, RECORDER_TARGET=target, RECORDER_OUTPUT=output,
                   RECORDER_EXIT=str(code), RECORDER_REMOVE=str(remove))
        return subprocess.run([sys.executable, str(self.tree / RUNNER),
                               "--log-dir", str(self.tree / "logs")],
                              cwd=self.tree, env=env, capture_output=True,
                              text=True, timeout=30)

    def calls(self):
        return [json.loads(line) for line in self.record.read_text().splitlines()]

    def test_shared_runner_executes_every_frozen_entrypoint_without_discovery_skips(self):
        self.prepare_runner()
        run = self.run_runner()
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        calls = self.calls()
        for name in (*REQUIRED, *CANONICAL_REQUIRED):
            with self.subTest(entrypoint=name):
                matches = [call for call in calls if name in call]
                self.assertEqual(len(matches), 1, "required entrypoint not executed exactly once: " + name)
                self.assertEqual(matches[0][0], name)
                self.assertNotIn("-I", matches[0], "trusted project entrypoints require sibling imports")
                if name in CANONICAL_REQUIRED:
                    self.assertEqual(matches[0][matches[0].index("--source-root") + 1],
                                     str(self.tree))
        view = json.loads((self.tree / "build/source-view/view.json").read_text())
        self.assertEqual(view["canonical_root"], str(self.tree))
        self.assertTrue(any((self.tree / "logs").rglob("*.log")), "runner did not persist child logs")

    def test_child_nonzero_cannot_be_lost_by_runner(self):
        self.prepare_runner()
        run = self.run_runner(REQUIRED[0], "controlled child failure", 37)
        self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn(REQUIRED[0], run.stdout + run.stderr)

    def test_runner_rejects_successful_child_with_failed_or_skipped_cases(self):
        self.prepare_runner()
        for bad in ("not ok 1 - injected", "ok 1 - injected # SKIP absent hardware",
                    "SKIP: unavailable",
                    "OK (skipped=1)", "test_case ... skipped 'unavailable'"):
            with self.subTest(output=bad):
                run = self.run_runner(REQUIRED[0], bad)
                self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_missing_full_stack_or_mutation_is_failure_instead_of_optional_skip(self):
        self.prepare_runner()
        for missing in (*REQUIRED[-2:], CANONICAL_REQUIRED[-1]):
            with self.subTest(entrypoint=missing):
                file = (self.tree / missing if missing in CANONICAL_REQUIRED else
                        self.tree / "build/source-view" / missing)
                # Remove after real materialization, at the first external
                # child boundary, to reach the runner's actual missing check.
                run = self.run_runner(remove=file)
                self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn(missing, run.stdout + run.stderr)
                records = json.loads((self.tree / "logs/manifest.json").read_text())["commands"]
                rejected = next(row for row in records if row["argv"][1] == missing)
                self.assertEqual(rejected["returncode"], 127)
                self.assertEqual(rejected["reason"], "missing required entrypoint")
                file.write_text("# restored controlled child\n")

    def workflow_step(self):
        source = (ROOT / ".github/workflows/host.yml").read_text()
        self.assertRegex(source, r"cc:\s*\[gcc\]", "XDOMAIN host CI must retain GCC-only matrix")
        steps = re.split(r"(?m)^      - ", source)[1:]
        candidates = [step for step in steps if re.search(RUNNER_COMMAND, step)]
        self.assertEqual(len(re.findall(RUNNER_COMMAND, source)), 1,
                         "CI must invoke the shared XDOMAIN runner exactly once")
        self.assertEqual(len(candidates), 1, "CI must invoke exactly one shared XDOMAIN runner step")
        step = candidates[0]
        self.assertNotIn("continue-on-error: true", step)
        self.assertNotIn("if: false", step)
        match = re.search(r"(?m)^        run: \|\s*\n((?:          .*\n|\n)+)", step)
        self.assertIsNotNone(match, "XDOMAIN step needs its own shell failure/skip log guard")
        return "\n".join(line[10:] for line in match.group(1).splitlines())

    def test_actual_ci_shell_propagates_exit_and_rejects_fail_skip_logs(self):
        block = self.workflow_step()
        env = dict(self.env, RUNNER_TEMP=str(self.tree), GITHUB_WORKSPACE=str(self.tree),
                   RECORDER_TARGET=str(self.tree / RUNNER))
        for output, code in (("ok 1 - injected", 0), ("child exited nonzero", 37),
                             ("not ok 1 - injected", 0),
                             ("ok 1 - injected # SKIP unavailable", 0),
                             ("SKIP: unavailable", 0),
                             ("OK (skipped=1)", 0),
                             ("test_case ... skipped 'unavailable'", 0)):
            with self.subTest(output=output, code=code):
                run = subprocess.run(["bash", "-c", block], cwd=self.tree,
                                     env=dict(env, RECORDER_OUTPUT=output, RECORDER_EXIT=str(code)),
                                     capture_output=True, text=True, timeout=10)
                if output == "ok 1 - injected":
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                else:
                    self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_locked_nhi_input_prepared_before_first_peer_consumer_and_closure(self):
        source = (ROOT / ".github/workflows/host.yml").read_text()
        steps = re.split(r"(?m)^      - ", source)[1:]
        prepare = [index for index, step in enumerate(steps)
                   if re.search(PREPARE_COMMAND, step)]
        peer = [index for index, step in enumerate(steps)
                if step.startswith("name: Peer control and lifetime checks\n")]
        closure = [index for index, step in enumerate(steps)
                   if re.search(RUNNER_COMMAND, step)]
        self.assertTrue(prepare, "locked NHI input preparation step is missing")
        self.assertEqual(len(peer), 1, "existing Peer consumer step is missing or duplicated")
        self.assertEqual(len(closure), 1, "shared closure consumer step is missing or duplicated")
        self.assertLess(min(prepare), peer[0],
                        "NHI fixture already runs through Peer Makefile wildcard; prepare the locked NHI input first")
        self.assertLess(min(prepare), closure[0],
                        "shared closure must consume the prepared locked NHI input")

    def test_actual_owner_metadata_rejects_missing_configured_headers_without_private_fallback(self):
        # A missing configured official header must fail even if the author's
        # workstation has another SDK. No fake cuda.h/compiler is introduced.
        official = self.tree / "official-runtime-headers"
        run = subprocess.run([sys.executable, "-I", str(ROOT / EVAL / "test_owner_close.py")],
                             env=dict(self.env, CUDA_HOME=str(official)), cwd=self.tree,
                             capture_output=True, text=True, timeout=20)
        self.assertNotEqual(run.returncode, 0, "missing configured headers must fail")
        self.assertIn(str(official / "include/cuda.h"), run.stdout + run.stderr,
                      "actual metadata test ignored configured CUDA_HOME")
        self.assertIn("UNAVAILABLE", run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
