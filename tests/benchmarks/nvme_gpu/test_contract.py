#!/usr/bin/env python3
"""Host contract tests of the NVMe<->GPU arms; never simulate a GPU or NVMe.

Run with python3 tests/eval/nvme_gpu/test_contract.py -v.  NVME_GPU_CUDA_ROOT
optionally names an official SDK for the build-only check.  No test runs a
campaign on a host exposing an NVIDIA device.
"""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SDK = Path(os.environ.get("NVME_GPU_CUDA_ROOT", "/usr/local/cuda"))
SPEC = importlib.util.spec_from_file_location("nvme_gpu_run", HERE / "run.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


def function_body(source, signature):
    """Text of the brace-balanced body that follows @signature."""
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        depth += {"{": 1, "}": -1}.get(source[i], 0)
        if not depth:
            return source[brace:i + 1]
    raise ValueError("unbalanced body")


class Built(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="nvme-gpu-test-")
        cls.out = Path(cls.temp.name)
        cc = shutil.which(os.environ.get("CC", "cc"))
        if not cc:
            raise unittest.SkipTest("no C compiler")
        flags = ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"]
        subprocess.run([cc] + flags + ["-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                        str(HERE / "test_core.c"), "-o", str(cls.out / "test_core")], check=True)
        subprocess.run([cc] + flags + [str(HERE / "session_nvme_ce.c"),
                        str(REPO / "kernel/tools/xdev_ext_gpu_identity.c"), "-ldl",
                        "-o", str(cls.out / "session_nvme_ce")], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_core_rules(self):
        result = subprocess.run([str(self.out / "test_core")], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"nvme_gpu core: \d+ checks, 0 failures")

    def session(self, *extra, base=True):
        args = ["--direction", "load", "--ng", "/nonexistent/ng0n1", "--slba", "0",
                "--lba-size", "512", "--file", "/nonexistent/window", "--ce-dev",
                "/dev/xdev_ext_ce_sim", "--ce-va", "0", "--size", "8192", "--qd", "4",
                "--window-bytes", "65536"] if base else []
        result = subprocess.run([str(self.out / "session_nvme_ce")] + args + list(extra),
                                text=True, capture_output=True, timeout=30)
        if result.returncode:
            self.assertEqual(result.stdout, "", "no result record on failure")
        return result

    def test_session_usage_errors(self):
        self.assertEqual(self.session(base=False).returncode, 2)
        for extra in (["--unknown"], ["--size", "4097"], ["--qd", "0"], ["--qd", "257"],
                      ["--size", "+8192"], ["--window-bytes", "65537"], ["--ce-alloc"],
                      ["--lba-size", "1000"], ["--frame-size", "3000"], ["--pattern", "random"],
                      ["--direction", "both"], ["positional"], ["--file-offset", "100"],
                      ["--qd", "16"]):
            with self.subTest(extra=extra):
                self.assertEqual(self.session(*extra).returncode, 2)

    def test_guest_cases_reach_the_device_check(self):
        """Every case of guest_correctness.sh passes the parser: exit 4 here, never 2."""
        script = (HERE / "guest_correctness.sh").read_text()
        loop = re.search(r'for case in ((?:"[0-9 ]+" ?)+); do', script)
        self.assertIsNotNone(loop, "case loop of guest_correctness.sh")
        cases = [tuple(int(v) for v in c.split()) for c in re.findall(r'"([0-9 ]+)"', loop.group(1))]
        self.assertGreaterEqual(len(cases), 3)
        # As many blocks as slots, and more: the two oracle regimes of the load arm.
        self.assertIn(True, [w // s == q for s, q, w in cases])
        self.assertIn(True, [w // s > q for s, q, w in cases])
        for size, qd, window in cases:
            for direction in ("load", "save"):
                with self.subTest(size=size, qd=qd, window=window, direction=direction):
                    result = self.session("--direction", direction, "--size", str(size),
                                          "--qd", str(qd), "--window-bytes", str(window),
                                          "--passes", "2", "--timeout-ms", "60000")
                    self.assertEqual(result.returncode, 4, result.stderr)
                    self.assertIn("O_DIRECT", result.stderr)
        refusal = re.search(r'--size (\d+) --qd (\d+) --window-bytes (\d+) --pattern rand', script)
        self.assertIsNotNone(refusal)
        result = self.session("--size", refusal.group(1), "--qd", refusal.group(2),
                              "--window-bytes", refusal.group(3), "--pattern", "rand")
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn("linear", result.stderr)

    def test_session_capability_refusals(self):
        for extra, text in ((["--pattern", "rand"], "linear"),
                            (["--qd", "65", "--window-bytes", "1048576"], "depth"),
                            ([], "O_DIRECT")):
            with self.subTest(extra=extra):
                result = self.session(*extra)
                self.assertEqual(result.returncode, 4, result.stderr)
                self.assertIn("SKIP", result.stderr)
                self.assertIn(text, result.stderr)


class TimedRegionPolicy(unittest.TestCase):
    """The oracle never runs inside a timed region (no per-I/O checksum)."""

    def check(self, path, signature):
        body = function_body((HERE / path).read_text(), signature)
        for forbidden in ("xg_compare", "xg_identify", "xg_fill", "cudaMemcpy(", "verify_window",
                          "fill_window", "direct_io"):
            self.assertNotIn(forbidden, body, "%s in the timed region of %s" % (forbidden, path))
        return body

    def test_staged_pass(self):
        body = self.check("bench_uring_cuda.cc", "int pass(Run &r, uint64_t p, uint64_t &io_ns)")
        self.assertIn("io_uring_prep_read_fixed", (HERE / "bench_uring_cuda.cc").read_text())
        self.assertIn("cudaMemcpyAsync", (HERE / "bench_uring_cuda.cc").read_text())
        self.assertIn("nvme_inflight < qd", body)

    def test_cufile_passes(self):
        self.check("bench_cufile_batch.cc", "int pass_batch(Run &r, uint64_t p, uint64_t &io_ns)")
        self.check("bench_cufile_batch.cc", "int pass_async(Run &r, uint64_t p, uint64_t &io_ns)")
        source = (HERE / "bench_cufile_batch.cc").read_text()
        for api in ("cuFileBatchIOSubmit", "cuFileBatchIOGetStatus", "cuFileReadAsync",
                    "cuFileWriteAsync", "cuFileStreamRegister", "CU_FILE_ALLOW_COMPAT_MODE"):
            self.assertIn(api, source)

    def test_session_pass(self):
        body = self.check("session_nvme_ce.c", "static int sn_session(")
        self.assertLess(body.index("t0 = es_now_ns()"), body.index("es_start("))
        self.assertLess(body.index("es_wait_terminal("), body.index("t1 = es_now_ns()"))

    def test_baselines_offer_blocking_completion(self):
        """Each baseline can sleep in the kernel for completions, like the session's eventfd."""
        staged = (HERE / "bench_uring_cuda.cc").read_text()
        cufile = (HERE / "bench_cufile_batch.cc").read_text()
        for source in (staged, cufile):
            self.assertIn('"completion-wait"', source)
            self.assertIn('"destination"', source)
            self.assertIn("cudaEventBlockingSync", source)
            self.assertIn("cudaEventSynchronize(", source)
            self.assertIn('\\"completion_wait\\":\\"%s\\"', source)
            self.assertIn('\\"destination\\":\\"%s\\"', source)
        self.assertIn("io_uring_wait_cqe_timeout(", staged)
        # Batch status waits for a whole wave with a deadline instead of a zero timeout.
        self.assertRegex(cufile, r"cuFileBatchIOGetStatus\(w\.handle, block \? w\.outstanding : 0,")
        session = (HERE / "session_nvme_ce.c").read_text()
        self.assertIn('\\"completion_wait\\":\\"block\\"', session)
        self.assertIn('\\"destination\\":\\"slot-ring\\"', session)

    def test_guest_script_parses(self):
        result = subprocess.run(["sh", "-n", str(HERE / "guest_correctness.sh")],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_provenance_recorded(self):
        source = (HERE / "session_nvme_ce.c").read_text()
        self.assertIn("69e46d263a35d1d5b3825c401597700c8ea15978", source)
        self.assertIn("5fe24476abe1d90faead86c2e101338c4d1a0ce2e56af76065e9cab37d3eb0d6", source)


class RunnerPure(unittest.TestCase):
    def setUp(self):
        self.common = dict(schema_version=1, direction="load", size=8192, qd=4, pattern="seq",
                           window_bytes=65536, passes=2, operations=16, io_bytes=131072,
                           io_ns=5, cpu_us=0, host_busy_us=0, status="pass",
                           destination="slot-ring", completion_wait="block")
        self.records = {
            "uring-cuda": dict(self.common, arm="uring-cuda", execution="physical-cuda",
                               verified_bytes=65536, performance_claim="physical",
                               route="nvme-read-fixed>registered-host>cuda-h2d-async"),
            "gds-batch": dict(self.common, arm="gds-batch", execution="physical-cuda-cufile",
                              verified_bytes=65536, compat_allowed=False, native_operations=16,
                              performance_claim="physical", route="nvme>gpu-direct"),
            "session": dict(self.common, arm="session", execution="physical-gpu-ce",
                            performance_claim="physical", slots_used=4, verified_bytes=65536,
                            route="nvme-read>shared-host-frame>ce-h2d"),
        }

    def test_valid_records(self):
        for arm, record in self.records.items():
            with self.subTest(arm=arm):
                RUN.validate(record, arm, "load", 8192, 4, "seq", 65536, 2)

    def test_mutated_records_rejected(self):
        for arm, record in self.records.items():
            for key, value in record.items():
                for bad in (None, "x", -1, value + 1 if type(value) is int else not value):
                    if key == "io_ns" and type(bad) is int and bad >= 1:
                        continue
                    if key in ("cpu_us", "host_busy_us") and type(bad) is int and bad >= 0:
                        continue
                    if bad == value and type(bad) is type(value):
                        continue
                    mutated = dict(record, **{key: bad})
                    with self.subTest(arm=arm, key=key, bad=bad), self.assertRaises(ValueError):
                        RUN.validate(mutated, arm, "load", 8192, 4, "seq", 65536, 2)
        stand_in = dict(self.records["session"], execution="kvm-ce-sim")
        with self.assertRaises(ValueError):
            RUN.validate(stand_in, "session", "load", 8192, 4, "seq", 65536, 2)
        RUN.validate(dict(stand_in, performance_claim="none"), "session", "load", 8192, 4,
                     "seq", 65536, 2)
        with self.assertRaises(ValueError):
            RUN.validate(dict(self.records["gds-batch"], compat_allowed=True), "gds-batch",
                         "load", 8192, 4, "seq", 65536, 2)
        with self.assertRaises(ValueError):
            RUN.validate(dict(self.records["session"], slots_used=3), "session", "load", 8192, 4,
                         "seq", 65536, 2)

    def test_destinations_are_never_mixed(self):
        """A campaign compares arms that land blocks in the same device layout."""
        window = dict(self.records["uring-cuda"], destination="window", verified_bytes=131072)
        RUN.validate(window, "uring-cuda", "load", 8192, 4, "seq", 65536, 2, destination="window")
        for record, destination in ((window, "slot-ring"), (self.records["uring-cuda"], "window"),
                                    (dict(self.records["session"], destination="window"), "window")):
            with self.subTest(record=record["destination"], campaign=destination), \
                    self.assertRaises(ValueError):
                RUN.validate(record, record["arm"], "load", 8192, 4, "seq", 65536, 2,
                             destination=destination)
        # A slot-ring load reads back qd slots per pass; a window load the whole window.
        with self.assertRaises(ValueError):
            RUN.validate(dict(window, verified_bytes=65536), "uring-cuda", "load", 8192, 4, "seq",
                         65536, 2, destination="window")
        save = dict(self.records["uring-cuda"], direction="save", verified_bytes=131072,
                    route="cuda-d2h-async>registered-host>nvme-write-fixed")
        RUN.validate(save, "uring-cuda", "save", 8192, 4, "seq", 65536, 2)
        with self.assertRaises(ValueError):
            RUN.validate(dict(save, verified_bytes=65536), "uring-cuda", "save", 8192, 4, "seq",
                         65536, 2)

    def test_completion_wait_is_recorded_and_matched(self):
        for arm, record in self.records.items():
            with self.subTest(arm=arm):
                RUN.validate(record, arm, "load", 8192, 4, "seq", 65536, 2, completion_wait="block")
        poll = dict(self.records["uring-cuda"], completion_wait="poll")
        RUN.validate(poll, "uring-cuda", "load", 8192, 4, "seq", 65536, 2, completion_wait="poll")
        for record, wait in ((poll, "block"), (self.records["uring-cuda"], "poll"),
                             (dict(self.records["session"], completion_wait="poll"), "poll")):
            with self.subTest(record=record["completion_wait"], campaign=wait), \
                    self.assertRaises(ValueError):
                RUN.validate(record, record["arm"], "load", 8192, 4, "seq", 65536, 2,
                             completion_wait=wait)

    def test_session_save_uses_every_slot(self):
        save = dict(self.records["session"], direction="save", verified_bytes=131072,
                    route="ce-d2h>shared-host-frame>nvme-write")
        RUN.validate(save, "session", "save", 8192, 4, "seq", 65536, 2)
        for slots in (0, 1, 3, 5):
            with self.subTest(slots=slots), self.assertRaises(ValueError):
                RUN.validate(dict(save, slots_used=slots), "session", "save", 8192, 4, "seq",
                             65536, 2)

    def test_parse_record(self):
        RUN.parse_record('{"a": 1}\n')
        for text in ('{"a": 1}', '{"a": 1}\n{"a": 1}\n', '{"a": 1, "a": 2}\n', '{"a": NaN}\n',
                     'log\n{"a": 1}\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                RUN.parse_record(text)

    def test_sizes_and_qd(self):
        self.assertEqual(RUN.size_list("4096..4194304")[0], 4096)
        self.assertEqual(len(RUN.size_list("4096..4194304")), 11)
        self.assertEqual(RUN.size_list("8192,4096"), [8192, 4096])
        for text in ("4096..3000000", "1..4096", "4097", "8192,8192", "0x1000", "8388608"):
            with self.subTest(text=text), self.assertRaises(Exception):
                RUN.size_list(text)
        self.assertEqual(RUN.qd_list("1,32,256"), [1, 32, 256])
        for text in ("0", "257", "1,1", "", "-1"):
            with self.subTest(text=text), self.assertRaises(Exception):
                RUN.qd_list(text)

    def test_extent_merging(self):
        mib = 1 << 20
        self.assertEqual(RUN.single_run([(0, 10 * mib, 2 * mib, 0),
                                         (2 * mib, 12 * mib, 2 * mib, 0)], 4 * mib), 10 * mib)
        for extents in ([(0, 10 * mib, 2 * mib, 0), (2 * mib, 13 * mib, 2 * mib, 0)],
                        [(4096, 10 * mib, 4 * mib, 0)],
                        [(0, 10 * mib, 2 * mib, 0)],
                        [(0, 10 * mib, 4 * mib, RUN.FIEMAP_EXTENT_UNWRITTEN)],
                        [(0, 10 * mib, 4 * mib, RUN.FIEMAP_EXTENT_SHARED)]):
            with self.subTest(extents=extents), self.assertRaises(ValueError):
                RUN.single_run(extents, 4 * mib)

    def test_mapping_probe_refuses_on_failure(self):
        class Args:
            ng, ce_dev, ce_alloc, passes, timeout_ms, window_bytes = \
                "/dev/ng0n1", "/dev/xdev_ext_ce_sim", False, 2, 1000, 8 << 20
        for program in ("false", "true"):  # exit 1, and exit 0 without a record
            with self.subTest(program=program):
                self.assertFalse(RUN.mapping_verified(shutil.which(program), Args, "/nonexistent",
                                                      (0, 512)))

    def test_cell_support(self):
        self.assertIsNone(RUN.cell_supported("session", 64, "seq", "slot-ring"))
        self.assertIsNotNone(RUN.cell_supported("session", 128, "seq", "slot-ring"))
        self.assertIsNotNone(RUN.cell_supported("session", 1, "rand", "slot-ring"))
        self.assertIsNotNone(RUN.cell_supported("session", 1, "seq", "window"))
        self.assertIsNotNone(RUN.cell_supported("gds-direct", 32, "seq", "window"))
        self.assertIsNotNone(RUN.cell_supported("gds-direct", 1, "seq", "slot-ring"))
        self.assertIsNone(RUN.cell_supported("gds-direct", 1, "seq", "window"))
        for arm in ("uring-cuda", "gds-batch", "gds-async"):
            for destination in ("slot-ring", "window"):
                with self.subTest(arm=arm, destination=destination):
                    self.assertIsNone(RUN.cell_supported(arm, 256, "rand", destination))

    def test_odd_batch_depth_is_not_an_equal_qd_cell(self):
        for qd in (3, 5, 255):
            for destination in ("slot-ring", "window"):
                for pattern in ("seq", "rand"):
                    with self.subTest(qd=qd, destination=destination, pattern=pattern):
                        self.assertIsNotNone(RUN.cell_supported("gds-batch", qd,
                                                               pattern, destination))

    def test_batch_one_even_and_async_odd_depths_remain_supported(self):
        for destination in ("slot-ring", "window"):
            for arm, depths in (("gds-batch", (1, 2, 4, 256)),
                                ("gds-async", (1, 3, 5, 255)),
                                ("uring-cuda", (1, 3, 5, 255))):
                for qd in depths:
                    with self.subTest(arm=arm, qd=qd, destination=destination):
                        self.assertIsNone(RUN.cell_supported(arm, qd, "seq", destination))


class RunnerCLI(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, str(HERE / "run.py")] + list(args), text=True,
                              capture_output=True, timeout=300)

    def test_help(self):
        result = self.invoke("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("gds-batch", result.stdout)

    def test_usage_errors(self):
        for args in ([], ["--arms", "uring-cuda", "--sizes", "4097", "--qd", "1", "--build-only"],
                     ["--arms", "cpu", "--sizes", "4096", "--qd", "1", "--build-only"],
                     ["--arms", "uring-cuda", "--sizes", "4096", "--qd", "1"],
                     ["--arms", "session", "--sizes", "4096", "--qd", "1", "--directory", "/"],
                     ["--arms", "uring-cuda", "--sizes", "4194304", "--qd", "256",
                      "--window-bytes", "4194304", "--build-only"]):
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_build_only_without_sdk_is_refused_not_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.invoke("--arms", "session,uring-cuda,gds-batch", "--sizes", "4096",
                                 "--qd", "1", "--build-only", "--cuda-root", tmp + "/missing",
                                 "--build-dir", tmp + "/build")
            self.assertEqual(result.returncode, 4, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertIn("Built session", result.stderr)
            self.assertRegex(result.stderr, r"uring-cuda: official CUDA development headers unavailable")
            self.assertRegex(result.stderr, r"gds-batch: official CUDA/cuFile development headers unavailable")
            self.assertTrue((Path(tmp) / "build/session_nvme_ce").is_file())

    def test_campaign_without_device_is_not_run(self):
        if Path("/dev/nvidiactl").exists():
            self.skipTest("physical NVIDIA device present: host suite does not run hardware")
        with tempfile.TemporaryDirectory() as tmp:
            result = self.invoke("--arms", "uring-cuda", "--sizes", "4096", "--qd", "1",
                                 "--directory", tmp, "--cuda-root", tmp + "/missing",
                                 "--build-dir", tmp + "/build")
            self.assertEqual(result.returncode, 4, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), [])

    def test_official_sdk_build_only(self):
        if not (SDK / "include/cufile.h").is_file():
            self.skipTest("official CUDA/cuFile SDK not installed; refusal path tested above")
        with tempfile.TemporaryDirectory() as tmp:
            result = self.invoke("--arms", "uring-cuda,gds-batch", "--sizes", "4096", "--qd", "1",
                                 "--build-only", "--cuda-root", str(SDK), "--build-dir", tmp)
            self.assertIn(result.returncode, (0, 4), result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertIn("Built gds-batch", result.stderr)


if __name__ == "__main__":
    unittest.main()
