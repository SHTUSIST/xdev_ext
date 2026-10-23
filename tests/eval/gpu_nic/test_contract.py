#!/usr/bin/env python3
"""Host contract tests of the GPU<->NIC arms; never simulate a GPU or NIC.

Run with python3 tests/eval/gpu_nic/test_contract.py -v.  The NXP peer runs
for real over loopback UDP; nothing here exercises AF_XDP, a CE backend or
CUDA, and no record of this suite is performance data.
"""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
KERNEL = REPO / "kernel"
SPEC = importlib.util.spec_from_file_location("gpu_nic_run", HERE / "run.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)
CC = shutil.which(os.environ.get("CC", "cc"))
FLAGS = ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"]


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        depth += {"{": 1, "}": -1}.get(source[i], 0)
        if not depth:
            return source[brace:i + 1]
    raise ValueError("unbalanced body")


@unittest.skipUnless(CC, "no C compiler")
class HostPrograms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="gpu-nic-test-")
        cls.out = Path(cls.temp.name)
        ubsan = ["-fsanitize=undefined", "-fno-sanitize-recover=undefined"]
        builds = {
            "test_core": [str(HERE / "test_core.c")] + ubsan,
            "test_core_sse": [str(HERE / "test_core.c"), "-msse4.2"] + ubsan,
            "ce_position": ["-I", str(KERNEL), str(HERE / "test_ce_stage_position.c")] + ubsan,
            "nxp_peer": [str(HERE / "nxp_peer.c"), "-msse4.2"],
            "session_gpu_nic": [str(HERE / "session_gpu_nic.c"),
                                str(KERNEL / "tools/xdev_ext_xsk_redirect.c"),
                                str(KERNEL / "tools/xdev_ext_gpu_identity.c"),
                                "-lbpf", "-lelf", "-lz", "-ldl"],
        }
        for name, args in builds.items():
            subprocess.run([CC] + FLAGS + args + ["-o", str(cls.out / name)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_binary(self, name, *args, timeout=60):
        return subprocess.run([str(self.out / name)] + [str(a) for a in args], text=True,
                              capture_output=True, timeout=timeout)

    def test_core_rules(self):
        for name in ("test_core", "test_core_sse"):
            with self.subTest(name=name):
                result = self.run_binary(name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertRegex(result.stdout, r"gpu_nic core: \d+ checks, 0 failures")

    def test_core_admits_ce_first_and_last(self):
        result = self.run_binary("ce_position")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"CE stage position admission: \d+ checks, 0 failures")

    def peer_pair(self, send_extra, recv_extra, recv_timeout=10000, port=0):
        port = port or 42000 + (os.getpid() % 2000) * 2
        common = ["--wire-session", "270019", "--size", "65536", "--messages", "40", "--mtu", "1500"]
        receiver = subprocess.Popen(
            [str(a) for a in [self.out / "nxp_peer", "recv", "--local-ip", "127.0.0.1",
                              "--local-port", port, "--timeout-ms", recv_timeout] +
             common + recv_extra],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        line = receiver.stderr.readline()
        self.assertIn("XDEV_EVAL_READY role=recv", line)
        # Loopback UDP drops when the sender outruns the receiver: pace the batches.
        sender = self.run_binary("nxp_peer", "send", "--local-ip", "127.0.0.1",
                                 "--local-port", port + 1, "--peer-ip", "127.0.0.1",
                                 "--peer-port", port, "--gap-us", "200", *(common + send_extra))
        out, err = receiver.communicate(timeout=30)
        return sender, receiver.returncode, out, err

    def test_peer_window_round_trip(self):
        sender, rc, out, err = self.peer_pair(["--window-groups", "4"], ["--expect", "window:4"])
        self.assertEqual(sender.returncode, 0, sender.stderr)
        self.assertEqual(rc, 0, err)
        record = RUN.NG.parse_record(out)
        RUN.validate_peer(record, "recv", 80, 32768)
        RUN.validate_peer(RUN.NG.parse_record(sender.stdout), "send", 80, 32768)

    def test_peer_slots_round_trip(self):
        _, rc, out, err = self.peer_pair(["--window-groups", "3"], ["--expect", "slots:3"],
                                         port=43900)
        self.assertEqual(rc, 0, err)
        self.assertEqual(RUN.NG.parse_record(out)["verified_groups"], 80)

    def test_peer_rejects_foreign_payload(self):
        for send_extra, recv_extra, port in ((["--window-groups", "4"], ["--expect", "window:5"], 43910),
                                             (["--window-groups", "4"], ["--expect", "slots:3"], 43920),
                                             (["--window-groups", "4", "--seed", "2"],
                                              ["--expect", "window:4"], 43930)):
            with self.subTest(send=send_extra, recv=recv_extra):
                _, rc, out, err = self.peer_pair(send_extra, recv_extra, port=port)
                self.assertEqual(rc, 1, err)
                self.assertEqual(out, "")
                self.assertRegex(err, r"foreign payload|missing, reordered or corrupt")

    def test_peer_times_out_without_success(self):
        result = self.run_binary("nxp_peer", "recv", "--local-ip", "127.0.0.1", "--local-port",
                                 43940, "--wire-session", 1, "--size", 4096, "--messages", 1,
                                 "--mtu", 1500, "--expect", "window:1", "--timeout-ms", 300)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("timeout", result.stderr)

    def test_peer_usage(self):
        for args in ([], ["both"], ["send", "--local-ip", "127.0.0.1"],
                     ["recv", "--local-ip", "127.0.0.1", "--local-port", "1", "--wire-session", "1",
                      "--size", "4096", "--messages", "1", "--mtu", "1500"],
                     ["recv", "--local-ip", "127.0.0.1", "--local-port", "1", "--wire-session", "1",
                      "--size", "4096", "--messages", "1", "--mtu", "1500", "--expect", "slots:65"]):
            with self.subTest(args=args):
                self.assertEqual(self.run_binary("nxp_peer", *args).returncode, 2)

    def session_args(self, **changes):
        options = {"direction": "ingest", "ifname": "lo", "ce-dev": "/nonexistent/xdev_ext_ce_sim",
                   "ce-va": "0", "size": "4096", "messages": "8", "depth": "4",
                   "wire-session": "270019", "local-ip": "192.0.2.2", "peer-ip": "192.0.2.1",
                   "local-port": "12345", "peer-port": "54321", "peer-mac": "02:00:00:00:00:01",
                   "local-mac": "02:00:00:00:00:02"}
        options.update(changes)
        args = []
        for key, value in options.items():
            if value is not None:
                args += ["--" + key] + ([] if value is True else [value])
        return args

    def test_session_cli(self):
        self.assertEqual(self.run_binary("session_gpu_nic").returncode, 2)
        for changes in ({"direction": "both"}, {"size": "100"}, {"depth": "65"},
                        {"wire-session": "0"}, {"ce-alloc": True}, {"peer-mac": "02:00"},
                        {"local-port": "70000"}, {"direction": "egress", "window-groups": "8"}):
            with self.subTest(changes=changes):
                result = self.run_binary("session_gpu_nic", *self.session_args(**changes))
                self.assertIn(result.returncode, (2,), result.stderr)
                self.assertEqual(result.stdout, "")
        # A size that is not whole groups on the link is a usage error, after the MTU query.
        result = self.run_binary("session_gpu_nic", *self.session_args(size="40968"))
        self.assertEqual(result.returncode, 2, result.stderr)
        for changes, text in (({"ifname": "xdevnonexist0"}, "No such device"),
                              ({}, "CE device")):
            with self.subTest(changes=changes):
                result = self.run_binary("session_gpu_nic", *self.session_args(**changes))
                self.assertEqual(result.returncode, 4, result.stderr)
                self.assertIn("SKIP", result.stderr)
                self.assertIn(text, result.stderr)
                self.assertEqual(result.stdout, "")


class SourcePolicy(unittest.TestCase):
    def test_ce_bind_has_no_stage_position_rule(self):
        source = (KERNEL / "io_uring/xdev_ext_mech_ce.c").read_text()
        body = function_body(source, "static int xdev_ext_ce_bind(")
        self.assertIn("XDEV_EXT_MECH_DIR_TO_DEVICE", body)
        for token in ("st->index", "nr_stages", "->st["):
            self.assertNotIn(token, body)

    def test_oracles_stay_outside_timed_regions(self):
        forbidden = ("gn_check_slots", "xg_compare", "xg_identify", "xg_fill", "cudaMemcpy(")
        for path, signature in (("afxdp_cuda.cu", "int ingest(Run &r, uint64_t &io_ns)"),
                                ("afxdp_cuda.cu", "int egress(Run &r, uint64_t &io_ns)"),
                                ("udp_pinned_cuda.cu", "int ingest(Run &r, uint64_t &io_ns)"),
                                ("udp_pinned_cuda.cu", "int egress(Run &r, uint64_t &io_ns)")):
            body = function_body((HERE / path).read_text(), signature)
            for token in forbidden:
                with self.subTest(path=path, signature=signature, token=token):
                    self.assertNotIn(token, body)
        source = (HERE / "session_gpu_nic.c").read_text()
        timed = source[source.index("t0 = es_now_ns();"):source.index("t1 = es_now_ns();")]
        for token in forbidden + ("es_ce_access",):
            self.assertNotIn(token, timed)

    def test_baselines_copy_whole_groups(self):
        udp = (HERE / "udp_pinned_cuda.cu").read_text()
        afxdp = (HERE / "afxdp_cuda.cu").read_text()
        for signature in ("int ingest(Run &r, uint64_t &io_ns)", "int egress(Run &r, uint64_t &io_ns)"):
            with self.subTest(signature=signature):
                # recvmmsg/sendmmsg scatter [header, payload at its group offset]: one copy a group.
                self.assertEqual(function_body(udp, signature).count("cudaMemcpyAsync("), 1)
        self.assertIn("msg_iovlen = 2", udp)
        self.assertIn("MSG_TRUNC", udp)
        self.assertIn("gn_group_copy(", afxdp)
        self.assertIn("cudaMemcpy2DAsync(", afxdp)
        self.assertIn("gn_chunks_strided(", afxdp)
        self.assertNotIn("cudaMemcpyAsync(", function_body(afxdp, "int egress(Run &r, uint64_t &io_ns)"))

    def test_baselines_offer_blocking_completion(self):
        for path in ("udp_pinned_cuda.cu", "afxdp_cuda.cu"):
            source = (HERE / path).read_text()
            with self.subTest(path=path):
                self.assertIn('"completion-wait"', source)
                self.assertIn("cudaEventBlockingSync", source)
                self.assertIn("cudaEventSynchronize(", source)
                self.assertIn("poll(", source)
                self.assertIn('\\"completion_wait\\":\\"%s\\"', source)
                self.assertIn('\\"copies_per_group\\":%u', source)
        self.assertIn('\\"completion_wait\\":\\"block\\"', (HERE / "session_gpu_nic.c").read_text())

    def test_baselines_register_once(self):
        afxdp = (HERE / "afxdp_cuda.cu").read_text()
        udp = (HERE / "udp_pinned_cuda.cu").read_text()
        self.assertEqual(afxdp.count("cudaHostRegister(r.x.umem"), 1)
        self.assertEqual(udp.count("cudaHostAlloc("), 1)
        for text in (afxdp, udp):
            self.assertIn("cudaMemcpyAsync", text)
            self.assertIn("cudaEventRecord", text)
        self.assertIn("xdev_ext_mp_rx_parse", afxdp)
        self.assertIn("xdev_ext_mp_rx_order", afxdp)


class RunnerPure(unittest.TestCase):
    def setUp(self):
        self.ingest = dict(schema_version=1, arm="session", direction="ingest", size=65536,
                           messages=10, groups=20, group_bytes=32768, depth=4, io_bytes=655360,
                           slots_used=4, oracle="device-slot-group-images", io_ns=9, cpu_us=0,
                           host_busy_us=0, execution="physical-gpu-ce",
                           route="afxdp-rx>shared-host-frame>ce-h2d",
                           performance_claim="physical", completion_wait="block", status="pass")
        # MTU 1500: 32768-byte groups of 23 segments, 22 of 1432 bytes and one of 1264.
        self.baseline = dict(self.ingest, arm="udp-pinned-cuda", execution="physical-cuda",
                             route="udp-recvmmsg>pinned-host>cuda-h2d-async", seg_len=1432,
                             frames=23, copies_per_group=1, copy_calls=20, fallback_groups=0)

    def test_valid_and_mutated_arm_records(self):
        RUN.validate_arm(self.ingest, "session", "ingest", 65536, 10, 4)
        egress = dict(self.baseline, arm="afxdp-cuda", direction="egress", slots_used=0,
                      oracle="peer-receipt-required", copies_per_group=2, copy_calls=40,
                      route="cuda-d2h-async>registered-umem>afxdp-tx")
        RUN.validate_arm(egress, "afxdp-cuda", "egress", 65536, 10, 4)
        for key in self.ingest:
            for bad in (None, "x", -1, True):
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                    RUN.validate_arm(dict(self.ingest, **{key: bad}), "session", "ingest", 65536, 10, 4)
        for changes in (dict(groups=19), dict(io_bytes=1), dict(slots_used=3),
                        dict(execution="kvm-ce-sim"), dict(oracle="peer-receipt-required"),
                        dict(group_bytes=24576), dict(arm="afxdp-cuda")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                RUN.validate_arm(dict(self.ingest, **changes), "session", "ingest", 65536, 10, 4)
        RUN.validate_arm(dict(self.ingest, execution="kvm-ce-sim", performance_claim="none"),
                         "session", "ingest", 65536, 10, 4)

    def test_baseline_copy_counts(self):
        """Each baseline records how many CUDA copy calls a group took."""
        RUN.validate_arm(self.baseline, "udp-pinned-cuda", "ingest", 65536, 10, 4)
        for key in ("seg_len", "frames", "copies_per_group", "copy_calls", "fallback_groups"):
            with self.subTest(missing=key), self.assertRaises(ValueError):
                record = dict(self.baseline)
                del record[key]
                RUN.validate_arm(record, "udp-pinned-cuda", "ingest", 65536, 10, 4)
        # One copy per group in each direction for the UDP arm: never one per segment.
        for changes in (dict(copies_per_group=23, copy_calls=460), dict(copy_calls=460),
                        dict(copy_calls=21), dict(frames=22), dict(fallback_groups=1)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                RUN.validate_arm(dict(self.baseline, **changes), "udp-pinned-cuda", "ingest",
                                 65536, 10, 4)
        egress = dict(self.baseline, direction="egress", oracle="peer-receipt-required",
                      slots_used=0, route="cuda-d2h-async>pinned-host>udp-sendmmsg")
        RUN.validate_arm(egress, "udp-pinned-cuda", "egress", 65536, 10, 4)
        # AF_XDP egress: a 2D copy of the 22 full segments plus the tail; no fallback.
        tx = dict(egress, arm="afxdp-cuda", route="cuda-d2h-async>registered-umem>afxdp-tx",
                  copies_per_group=2, copy_calls=40)
        RUN.validate_arm(tx, "afxdp-cuda", "egress", 65536, 10, 4)
        for changes in (dict(copies_per_group=1, copy_calls=20), dict(fallback_groups=2,
                                                                       copy_calls=82)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                RUN.validate_arm(dict(tx, **changes), "afxdp-cuda", "egress", 65536, 10, 4)
        # AF_XDP ingest: strided chunks take the 2D copy, other groups one copy per segment.
        rx = dict(self.baseline, arm="afxdp-cuda", route="afxdp-rx>registered-umem>cuda-h2d-async",
                  copies_per_group=2, fallback_groups=3, copy_calls=17 * 2 + 3 * 23)
        RUN.validate_arm(rx, "afxdp-cuda", "ingest", 65536, 10, 4)
        for changes in (dict(copy_calls=104), dict(fallback_groups=21), dict(fallback_groups=-1)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                RUN.validate_arm(dict(rx, **changes), "afxdp-cuda", "ingest", 65536, 10, 4)

    def test_completion_wait_is_recorded_and_matched(self):
        RUN.validate_arm(self.baseline, "udp-pinned-cuda", "ingest", 65536, 10, 4,
                         completion_wait="block")
        poll = dict(self.baseline, completion_wait="poll")
        RUN.validate_arm(poll, "udp-pinned-cuda", "ingest", 65536, 10, 4, completion_wait="poll")
        for record, arm, wait in ((poll, "udp-pinned-cuda", "block"),
                                  (self.baseline, "udp-pinned-cuda", "poll"),
                                  (dict(self.ingest, completion_wait="poll"), "session", "poll")):
            with self.subTest(arm=arm, wait=wait), self.assertRaises(ValueError):
                RUN.validate_arm(record, arm, "ingest", 65536, 10, 4, completion_wait=wait)

    def test_peer_records(self):
        recv = dict(role="recv", groups=20, group_bytes=32768, io_bytes=655360,
                    verified_groups=20, status="pass")
        RUN.validate_peer(recv, "recv", 20, 32768)
        for changes in (dict(verified_groups=19), dict(groups=19), dict(status="fail"),
                        dict(role="send"), dict(io_bytes=0)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                RUN.validate_peer(dict(recv, **changes), "recv", 20, 32768)

    def test_sizes(self):
        self.assertEqual(RUN.size_list("64..4194304")[:2], [64, 128])
        self.assertEqual(len(RUN.size_list("64..4194304")), 17)
        for text in ("32", "65", "64,64", "64..100", "8388608"):
            with self.subTest(text=text), self.assertRaises(Exception):
                RUN.size_list(text)


class ListenerRefusal(unittest.TestCase):
    """An ingest arm that refuses before READY is a not_run cell, not a failed campaign."""

    def program(self, directory, name, body):
        path = Path(directory) / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
        return path

    def cell(self, arm_body):
        with tempfile.TemporaryDirectory() as tmp:
            arm = self.program(tmp, "arm", arm_body)
            peer = self.program(tmp, "peer", "echo peer must not start >&2\nexit 1\n")
            args = RUN.arguments(["--arms", "session", "--direction", "nic-gpu", "--sizes", "4096",
                                  "--ifname", "lo", "--local-ip", "127.0.0.1", "--peer-ip",
                                  "127.0.0.1", "--peer-mac", "02:00:00:00:00:01", "--ce-dev",
                                  "/nonexistent", "--timeout-ms", "1000"])
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                try:
                    return RUN.run_cell(args, "session", arm, peer, 4096, 0), err.getvalue()
                except RuntimeError as error:
                    return error, err.getvalue()

    def test_exit_4_before_ready_is_not_run(self):
        result, err = self.cell("echo 'SKIP: CE device: No such file or directory' >&2\nexit 4\n")
        self.assertIsNone(result)
        self.assertIn("SKIP: CE device", err)
        self.assertNotIn("peer must not start", err)

    def test_failure_before_ready_still_fails(self):
        result, _ = self.cell("echo broken >&2\nexit 1\n")
        self.assertIsInstance(result, RuntimeError)


class RunnerCLI(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, str(HERE / "run.py")] + list(args), text=True,
                              capture_output=True, timeout=300)

    def test_usage_errors(self):
        for args in ([], ["--arms", "session", "--direction", "nic-gpu"],
                     ["--arms", "rdma", "--direction", "nic-gpu", "--shape", "ingest", "--build-only"],
                     ["--arms", "session", "--direction", "nic-gpu", "--shape", "ingest",
                      "--sizes", "64", "--build-only"],
                     ["--arms", "afxdp-cuda", "--direction", "nic-gpu", "--shape", "ingest"],
                     ["--arms", "afxdp-cuda", "--direction", "nic-gpu", "--shape", "ingest",
                      "--depth", "65", "--build-only"]):
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")

    @unittest.skipUnless(CC, "no C compiler")
    def test_build_only_without_sdk_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.invoke("--arms", "session,afxdp-cuda,udp-pinned-cuda", "--direction",
                                 "gpu-nic", "--shape", "egress", "--build-only",
                                 "--cuda-root", tmp + "/missing", "--build-dir", tmp + "/build")
            self.assertEqual(result.returncode, 4, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertIn("Built session", result.stderr)
            self.assertIn("Built nxp_peer", result.stderr)
            self.assertIn("afxdp-cuda: official CUDA development headers unavailable", result.stderr)

    @unittest.skipUnless(CC, "no C compiler")
    def test_campaign_without_interface_is_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.invoke("--arms", "udp-pinned-cuda", "--direction", "nic-gpu", "--sizes",
                                 "4096", "--ifname", "xdevnonexist0", "--local-ip", "192.0.2.2",
                                 "--peer-ip", "192.0.2.1", "--peer-mac", "02:00:00:00:00:01",
                                 "--cuda-root", tmp + "/missing", "--build-dir", tmp + "/build")
            self.assertEqual(result.returncode, 4, result.stderr)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
