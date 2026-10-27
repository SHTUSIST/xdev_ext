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
RUNNER = Path("scripts/check_xdomain_host.py")
PEER = "kernel/tools/testing/selftests/xdev_ext_mech/peer_graph/"
EVAL = "tests/eval/xdomain/"
REQUIRED = tuple(PEER + name + ".py" for name in (
    "xdomain_identity_test", "xdomain_kfunc_test", "xdomain_program_test",
    "xdomain_login_test", "tb_protocol_handler_lifetime_test",
    "tbnet_handler_teardown_test", "xdomain_ring_test", "xdomain_nhi_test",
    "xdomain_class_test", "session_stop_clock_test", "xdomain_guest_verdict_test",
    "netfam_rel_kfunc_test", "class_table_source_test", "class_bind_test",
)) + (
    "kernel/tools/testing/selftests/xdev_ext_mech/core_lifecycle/stop_report_test.py",
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
with open(os.environ["RECORDER_FILE"], "a") as out:
    out.write(json.dumps(sys.argv[1:]) + "\n")
target = os.environ.get("RECORDER_TARGET", "")
if target in sys.argv[1:]:
    print(os.environ.get("RECORDER_OUTPUT", ""), flush=True)
    raise SystemExit(int(os.environ.get("RECORDER_EXIT", "0")))
print("ok 1 - controlled external child", flush=True)
''')
        recorder.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        CC="gcc", CXX="g++", RECORDER_FILE=str(self.record))

    def prepare_runner(self):
        self.assertTrue((ROOT / RUNNER).is_file(), "shared XDOMAIN CI runner is missing")
        (self.tree / RUNNER).parent.mkdir(parents=True)
        shutil.copy2(ROOT / RUNNER, self.tree / RUNNER)
        for name in REQUIRED:
            file = self.tree / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("# External child boundary; not test evidence.\n")

    def run_runner(self, target="", output="", code=0):
        env = dict(self.env, RECORDER_TARGET=target, RECORDER_OUTPUT=output,
                   RECORDER_EXIT=str(code))
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
        for name in REQUIRED:
            with self.subTest(entrypoint=name):
                matches = [call for call in calls if name in call]
                self.assertEqual(len(matches), 1, "required entrypoint not executed exactly once: " + name)
                self.assertEqual(matches[0][0], name)
                self.assertNotIn("-I", matches[0], "trusted project entrypoints require sibling imports")
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
        for missing in REQUIRED[-2:]:
            with self.subTest(entrypoint=missing):
                file = self.tree / missing
                file.unlink()
                run = self.run_runner()
                self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn(missing, run.stdout + run.stderr)
                file.write_text("# restored controlled child\n")

    def workflow_step(self):
        source = (ROOT / ".github/workflows/host.yml").read_text()
        self.assertRegex(source, r"cc:\s*\[gcc\]", "XDOMAIN host CI must retain GCC-only matrix")
        steps = re.split(r"(?m)^      - ", source)[1:]
        candidates = [step for step in steps if re.search(
            r"(?m)^\s+(?:python3\s+)?scripts/check_xdomain_host\.py\b", step)]
        # Also accept shell prefixes such as `timeout` and the ordinary python3 command.
        if not candidates:
            candidates = [step for step in steps if re.search(
                r"(?m)^\s+[^#\n]*python3\s+(?:-I\s+)?scripts/check_xdomain_host\.py\b", step)]
        self.assertEqual(len(candidates), 1, "CI must invoke exactly one shared XDOMAIN runner step")
        step = candidates[0]
        self.assertNotIn("continue-on-error: true", step)
        self.assertNotIn("if: false", step)
        match = re.search(r"(?m)^        run: \|\s*\n((?:          .*\n|\n)+)", step)
        self.assertIsNotNone(match, "XDOMAIN step needs its own shell failure/skip log guard")
        return "\n".join(line[10:] for line in match.group(1).splitlines())

    def test_actual_ci_shell_propagates_exit_and_rejects_fail_skip_logs(self):
        block = self.workflow_step()
        env = dict(self.env, RUNNER_TEMP=str(self.tree), RECORDER_TARGET=str(RUNNER))
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
        prepare = [index for index, step in enumerate(steps) if re.search(
            r"(?m)^\s+[^#\n]*python3\s+scripts/prepare_xdomain_host_inputs\.py\b", step)]
        peer = [index for index, step in enumerate(steps)
                if step.startswith("name: Peer control and lifetime checks\n")]
        closure = [index for index, step in enumerate(steps) if re.search(
            r"(?m)^\s+[^#\n]*python3\s+scripts/check_xdomain_host\.py\b", step)]
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
