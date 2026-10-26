#!/usr/bin/env python3
"""Host checks of build_cuda_arms.py: refusal, coverage and command lines.

This host has no CUDA SDK.  FakeToolchainReceipt uses a recording stand-in
for nvcc and a tiny shared library exporting the driver symbol names, only to
exercise the receipt bookkeeping (hashes, statuses, exit codes); it proves
nothing about the official SDK.  Run: python3 tests/eval/test_build_cuda_arms.py -v
"""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "build_cuda_arms.py"
INVENTORY = HERE / "cuda_builder_inventory.py"
CC = shlex.split(os.environ.get("CC", "cc"))


def load():
    spec = importlib.util.spec_from_file_location("build_cuda_arms", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def invoke(*args, env=None):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True,
                          text=True, env=env, timeout=120)


class Refusal(unittest.TestCase):
    def test_cuda_home_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = invoke("--out", tmp)
            self.assertEqual(p.returncode, 2, p.stderr)

    def test_absent_nvcc_refused_with_exit_4_and_no_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "cuda-12.8"
            (home / "include").mkdir(parents=True)
            out = Path(tmp) / "out"
            p = invoke("--cuda-home", str(home), "--out", str(out))
            self.assertEqual(p.returncode, 4, p.stdout + p.stderr)
            row = json.loads(p.stdout)
            self.assertEqual(row["status"], "unavailable")
            self.assertIn("nvcc", row["reason"])
            self.assertFalse(out.exists())

    def test_nvcc_on_path_is_not_used(self):
        """Only CUDA_HOME/bin/nvcc counts: an nvcc on PATH is ignored."""
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = Path(tmp) / "bin"
            fake_bin.mkdir()
            nvcc = fake_bin / "nvcc"
            nvcc.write_text("#!/bin/sh\nexit 0\n")
            nvcc.chmod(0o755)
            home = Path(tmp) / "home"
            home.mkdir()
            env = dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ["PATH"])
            p = invoke("--cuda-home", str(home), "--out", str(Path(tmp) / "out"), env=env)
            self.assertEqual(p.returncode, 4, p.stdout + p.stderr)


class Coverage(unittest.TestCase):
    def setUp(self):
        self.m = load()

    def dedicated(self):
        self.assertTrue(INVENTORY.is_file(), "missing dedicated CUDA builder inventory")
        spec = importlib.util.spec_from_file_location("cuda_builder_inventory", INVENTORY)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.DEDICATED_BUILDERS

    def test_every_cuda_source_is_an_arm(self):
        sources = {str(p.relative_to(HERE)) for p in HERE.rglob("*")
                   if p.suffix in (".cu", ".cc") and ".build" not in p.parts and "build" not in p.parts}
        covered = {src for arm in self.m.ARMS for src in arm.sources}
        dedicated = [src for entry in self.dedicated() for src in entry["sources"]]
        self.assertEqual(len(dedicated), len(set(dedicated)), "duplicate dedicated source")
        self.assertFalse(covered & set(dedicated), "dedicated source also in ordinary builder")
        covered.update(dedicated)
        # This observer compiles benchmark control flow on the host.
        self.assertEqual(sources - covered, {"gds/_campaign_fixture.cc"})
        self.assertIn("bench_cuda_staging.c", covered)

    def test_dedicated_entries_have_real_cli_and_required_inputs(self):
        for entry in self.dedicated():
            with self.subTest(builder=entry["name"]):
                script = HERE / entry["entrypoint"]
                self.assertTrue(script.is_file())
                for source in entry["sources"]:
                    self.assertTrue((HERE / source).is_file())
                    self.assertNotIn(source, self.m.NOT_ARMS)
                self.assertTrue((HERE / entry["dependency_lock"]).is_file())
                help_run = subprocess.run([sys.executable, str(script), "--help"],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(help_run.returncode, 0, help_run.stderr)
                for option in entry["required_args"]:
                    self.assertIn(option, help_run.stdout)
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / "output"
                    # Every required input must be enforced by the real CLI.
                    for missing in entry["required_args"]:
                        args = [value for option in entry["required_args"]
                                if option != missing for value in (option, str(out))]
                        refused = subprocess.run([sys.executable, str(script), *args],
                            capture_output=True, text=True, timeout=10)
                        self.assertEqual(refused.returncode, 2, refused.stderr)
                        self.assertIn(missing, refused.stderr)
                        self.assertFalse(out.exists())

    def test_xdomain_owner_inventory_matches_its_real_translation_units(self):
        entry = next((e for e in self.dedicated() if e["name"] == "xdomain_owner"), None)
        self.assertIsNotNone(entry, "missing dedicated real XDOMAIN owner builder")
        self.assertEqual(entry["entrypoint"], "xdomain/build.py")
        self.assertEqual(entry["required_args"], ("--cuda-home", "--out"))
        self.assertEqual(entry["dependency_lock"], "../../sources.lock.json")
        self.assertEqual(entry["kind"], "cuda-owner")
        self.assertEqual(entry["needs"], ("cuda-sdk", "libbpf"))
        spec = importlib.util.spec_from_file_location("xdomain_owner_builder",
                                                   HERE / entry["entrypoint"])
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        units = {str(p.relative_to(HERE))
                 for p in builder.required_sources(HERE / "xdomain")
                 if p.suffix in (".c", ".cc", ".cu")}
        self.assertEqual(units, {
            "xdomain/check_contract.c", "xdomain/epoch_control.c",
            "xdomain/gpu_adapter.cc", "xdomain/agent_supervisor.cc",
            "xdomain/xdomain_agent.cc", "xdomain/native_trace_owner.cc",
            "xdomain/xdomain_gpu_pattern.cu"})
        self.assertEqual(set(entry["sources"]), units)
        # This is the project source pin, not an invented CUDA SDK pin.
        lock = json.loads((HERE / entry["dependency_lock"]).read_text())
        self.assertEqual(set(lock["components"]), {"linux", "nvidia"})

    def test_xdomain_test_sources_have_their_actual_host_contract_entries(self):
        owners = {
            "gpu_contract_test.cc": ("test_gpu_contract.py", ("cuda-headers",)),
            "native_trace_owner_test.cc": ("test_native_trace_owner.py", ()),
            "durable_failure_test_owner.cc": ("test_durable_failure.py", ()),
            "create_refusal_test_owner.cc": ("test_create_refusal.py", ()),
            "retention_test_owner.cc": ("test_retention.py", ()),
            "owner_close_test.cc": ("test_owner_close.py", ("cuda-headers", "libbpf")),
        }
        entries = self.dedicated()
        for source, (script, needs) in owners.items():
            with self.subTest(source=source):
                matches = [e for e in entries if "xdomain/" + source in e["sources"]]
                self.assertEqual(len(matches), 1, "source must have exactly one real owner")
                entry = matches[0]
                self.assertEqual(entry["sources"], ("xdomain/" + source,))
                self.assertEqual(entry["entrypoint"], "xdomain/" + script)
                self.assertEqual(entry["kind"], "host-contract")
                self.assertEqual(entry["required_args"], ())
                self.assertEqual(entry["needs"], needs)
                self.assertEqual(entry["dependency_lock"], "../../sources.lock.json")

    def test_bam_entry_refuses_missing_sdk_without_artifact(self):
        entry = next(e for e in self.dedicated() if e["name"] == "bam_native")
        self.assertEqual(entry["sources"], ("bam/bench_native.cu",))
        self.assertEqual(entry["entrypoint"], "bam/build_native.py")
        self.assertEqual(entry["dependency_lock"], "bam/native.lock.json")
        self.assertEqual(entry["required_args"], ("--upstream", "--cuda-root", "--output"))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "output"
            refused = subprocess.run([sys.executable, str(HERE / entry["entrypoint"]),
                "--upstream", tmp, "--cuda-root", str(Path(tmp) / "missing-sdk"),
                "--output", str(out)], capture_output=True, text=True, timeout=10)
            self.assertEqual(refused.returncode, 4, refused.stderr)
            self.assertIn("official CUDA SDK", refused.stderr)
            self.assertEqual(refused.stdout, "")
            self.assertFalse(out.exists())

    def test_bam_entry_checks_real_git_pin_and_cleanliness(self):
        entry = next(e for e in self.dedicated() if e["name"] == "bam_native")
        script = HERE / entry["entrypoint"]
        spec = importlib.util.spec_from_file_location("dedicated_bam_builder", script)
        module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(script.parent))
        try:
            spec.loader.exec_module(module)
        finally:
            sys.path.pop(0)
        # Exercise the actual Git dependency gate, without a CUDA stand-in.
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp)
            def git(*args):
                return subprocess.check_output(["git", "-C", tmp, *args],
                    text=True, stderr=subprocess.STDOUT).strip()
            git("init", "-q")
            (tree / "input").write_text("clean input\n")
            git("add", "input")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "-qm", "dependency gate fixture")
            revision = git("rev-parse", "HEAD")
            module.check_tree(tree, revision)
            with self.assertRaisesRegex(ValueError, "wrong upstream/submodule revision"):
                module.check_tree(tree, "0" * 40)
            (tree / "input").write_text("dirty input\n")
            with self.assertRaisesRegex(ValueError, "must be pristine"):
                module.check_tree(tree, revision)

    def test_chain_dynamic_cuda_path_is_an_actual_build_arm(self):
        arm = next((a for a in self.m.ARMS if a.name == 'chain_bench'), None)
        self.assertIsNotNone(arm)
        self.assertIn('chains/chain_bench.c', arm.sources)
        self.assertIn('chains/chain_session.c', arm.sources)
        self.assertIn('chains/chain_staged.c', arm.sources)
        self.assertIn('bpf', arm.needs)

    def test_driver_symbol_sources(self):
        names = self.m.driver_symbols()
        for symbol in ("cuInit", "cuMemHostRegister_v2", "cuMemcpyHtoDAsync_v2",
                       "cuDeviceGetByPCIBusId", "cuStreamQuery", "cuCtxCreate_v2"):
            self.assertIn(symbol, names)
        files = {str(p) for p in self.m.SYMBOL_SOURCES}
        self.assertTrue(any(f.endswith("chains/chain_cuda.h") for f in files))
        self.assertTrue(any(f.endswith("bench_cuda_staging.c") for f in files))
        self.assertTrue(any(f.endswith("xdev_ext_mech_cuda.h") for f in files))


class Commands(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.home = Path("/usr/local/cuda-12.8")
        self.out = Path("/tmp/out")
        self.tc = self.m.Toolchain(cuda_home=self.home, nvcc=self.home / "bin/nvcc",
                                   arch="sm_80", cc=["cc"], cufile_dir=self.home / "lib64",
                                   uring=["-luring"], bpf=["-lbpf", "-lelf", "-lz"])

    def arm(self, name):
        return next(a for a in self.m.ARMS if a.name == name)

    def test_chain_host_build_links_libbpf_and_cuda_loader(self):
        arm = self.arm('chain_bench')
        command = arm.commands(self.tc, self.out)[-1]
        self.assertEqual(command[0], 'cc')
        self.assertIn('-lbpf', command)
        self.assertIn('-ldl', command)
        self.assertTrue(any(p.endswith('chain_session.c') for p in command))

    def test_explicit_host_cxx_is_passed_to_every_nvcc_arm(self):
        self.tc.host_cxx = Path('/usr/bin/g++-14')
        for arm in self.m.ARMS:
            if arm.kind == 'host-c':
                continue
            command = arm.commands(self.tc, self.out)[-1]
            self.assertIn('-ccbin', command)
            self.assertEqual(command[command.index('-ccbin') + 1], '/usr/bin/g++-14')
            self.assertNotIn('--allow-unsupported-compiler', command)

    def test_cuda_sources_compile_with_the_sdk_nvcc(self):
        for name in ("afxdp_cuda", "udp_pinned_cuda", "bench_host_compute"):
            with self.subTest(arm=name):
                steps = self.arm(name).commands(self.tc, self.out)
                command = steps[-1]
                self.assertEqual(command[0], str(self.home / "bin/nvcc"))
                for flag in ("-std=c++17", "--cudart=shared", "-arch=sm_80"):
                    self.assertIn(flag, command)
                self.assertEqual(command[command.index("-o") + 1], str(self.out / name))

    def test_host_cc_arms_also_go_through_nvcc(self):
        for name, extra in (("bench_uring_cuda", "-luring"), ("bench_cufile_batch", "-lcufile"),
                            ("bench_cufile", "-lcufile")):
            with self.subTest(arm=name):
                command = self.arm(name).commands(self.tc, self.out)[-1]
                self.assertEqual(command[0], str(self.home / "bin/nvcc"))
                self.assertIn("--cudart=shared", command)
                self.assertIn(extra, command)
                self.assertTrue(any("-Werror" in c for c in command))

    def test_afxdp_links_the_redirect_helper(self):
        steps = self.arm("afxdp_cuda").commands(self.tc, self.out)
        self.assertEqual(len(steps), 2)
        helper = steps[0]
        self.assertEqual(helper[0], "cc")
        self.assertTrue(helper[-1].endswith("xdev_ext_xsk_redirect.o") or "-c" in helper)
        self.assertIn("-lbpf", steps[1])

    def test_staging_bench_is_host_c_with_dlopen(self):
        command = self.arm("bench_cuda_staging").commands(self.tc, self.out)[-1]
        self.assertEqual(command[0], "cc")
        self.assertIn("-ldl", command)


class FakeToolchainReceipt(unittest.TestCase):
    """Receipt bookkeeping with stand-ins; see the module docstring."""

    def setUp(self):
        self.m = load()
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.home = root / "cuda"
        (self.home / "bin").mkdir(parents=True)
        (self.home / "lib64/stubs").mkdir(parents=True)
        (self.home / "include").mkdir()
        nvcc = self.home / "bin/nvcc"
        nvcc.write_text("#!%s\nimport sys\nargs = sys.argv[1:]\n"
                        "if args == ['--version']:\n    print('nvcc stand-in release 0.0'); raise SystemExit\n"
                        "out = args[args.index('-o') + 1]\nopen(out, 'w').write(' '.join(args))\n"
                        % sys.executable)
        nvcc.chmod(0o755)
        symbols = root / "stub.c"
        symbols.write_text("".join("int %s(void) { return 0; }\n" % s for s in self.m.driver_symbols()))
        built = subprocess.run([*CC, "-shared", "-fPIC", str(symbols), "-o",
                                str(self.home / "lib64/stubs/libcuda.so")], capture_output=True, text=True)
        self.assertEqual(built.returncode, 0, built.stderr)
        self.out = root / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def test_receipt_records_versions_hashes_and_unavailable_arms(self):
        p = invoke("--cuda-home", str(self.home), "--out", str(self.out))
        receipt = json.loads((self.out / "cuda-arms-receipt.json").read_text())
        self.assertEqual(receipt["schema"], "cuda-arms-build-v1")
        self.assertEqual(receipt["execution"], "not-run")
        self.assertIn("stand-in release", receipt["nvcc_version"])
        self.assertEqual(len(receipt["nvcc_sha256"]), 64)
        arms = {a["name"]: a for a in receipt["arms"]}
        self.assertEqual(set(arms), {a.name for a in self.m.ARMS})
        # No cufile.h/cuda_runtime_api.h in this home: those arms are unavailable.
        self.assertEqual(arms["bench_cufile"]["status"], "unavailable")
        built = [a for a in arms.values() if a["status"] == "built"]
        self.assertTrue(built)
        for arm in built:
            self.assertEqual(len(arm["output_sha256"]), 64)
            self.assertTrue(all(len(s["sha256"]) == 64 for s in arm["sources"]))
        self.assertEqual(receipt["driver_symbols"]["missing"], [])
        self.assertEqual(p.returncode, 4, p.stdout + p.stderr)
        self.assertEqual(json.loads(p.stdout)["status"], receipt["status"])

    def test_host_cxx_identity_is_recorded(self):
        host_cxx = Path(shutil.which('g++')).resolve()
        p = invoke('--cuda-home', str(self.home), '--out', str(self.out),
                   '--host-cxx', str(host_cxx))
        self.assertEqual(p.returncode, 4, p.stderr)
        receipt = json.loads((self.out / 'cuda-arms-receipt.json').read_text())
        self.assertEqual(receipt['host_cxx']['path'], str(host_cxx))
        self.assertEqual(len(receipt['host_cxx']['sha256']), 64)
        self.assertTrue(receipt['host_cxx']['version'])

    def test_missing_driver_symbol_fails(self):
        stub = self.home / "lib64/stubs/libcuda.so"
        src = Path(self.tmp.name) / "short.c"
        src.write_text("int cuInit(void) { return 0; }\n")
        subprocess.run([*CC, "-shared", "-fPIC", str(src), "-o", str(stub)], check=True)
        p = invoke("--cuda-home", str(self.home), "--out", str(self.out))
        receipt = json.loads((self.out / "cuda-arms-receipt.json").read_text())
        self.assertIn("cuMemHostRegister_v2", receipt["driver_symbols"]["missing"])
        self.assertEqual(p.returncode, 1)


if __name__ == "__main__":
    unittest.main()
