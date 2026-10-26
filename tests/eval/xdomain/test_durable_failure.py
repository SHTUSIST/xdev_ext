#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Result-evidence I/O failure must retain the real guard and owner resources.

The owner uses only an eventfd surrogate. SIGKILL below is explicit test-only
teardown, never production cleanup or proof of native/device release.
"""
import errno
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent


class DurableFailure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="tb-durable-build-")
        cls.addClassCleanup(cls.build.cleanup)
        build = Path(cls.build.name)
        objects = []
        for name, compiler, standard in (
            ("check_contract.c", "gcc", "c11"),
            ("agent_supervisor.cc", "g++", "c++17"),
            ("durable_failure_test_owner.cc", "g++", "c++17"),
        ):
            output = build / (name + ".o")
            command = [compiler, "-std=" + standard, "-Wall", "-Wextra",
                       "-Werror", "-pthread", "-I", str(HERE), "-c",
                       str(HERE / name), "-o", str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                raise AssertionError("real-source compile failed: " +
                                     result.stdout + result.stderr)
            objects.append(str(output))
        cls.binary = build / "durable-owner"
        result = subprocess.run(["g++", "-pthread", *objects, "-o", str(cls.binary)],
                                capture_output=True, text=True)
        if result.returncode:
            raise AssertionError("real-source link failed: " +
                                 result.stdout + result.stderr)

    def test_post_acquire_result_write_failure_latches_actual_guard_and_retains(self):
        with tempfile.TemporaryDirectory(prefix="tb-durable-surrogate-") as directory:
            os.chmod(directory, 0o700)
            release_read, release_write = os.pipe()
            probe_read, probe_write = os.pipe()
            process = subprocess.Popen(
                [str(self.binary), directory, str(release_read), str(probe_write)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, pass_fds=(release_read, probe_write))
            os.close(release_read)
            os.close(probe_write)
            try:
                identity = dict(version=1, run_id="durable-failure", sha="a" * 40,
                                role="tx", case="functional-epochs",
                                direction="a-to-b", epoch=3, request_id=1)
                payload = dict(mode="single-group", groups=1, first_seq=7, seed=9,
                               gpu_bdf="0000:01:00.0", nvidia_node="/dev/nvidia0",
                               link_token=901, channel=0, flags=0,
                               geometry=dict(allocation_bytes=65536,
                                             group_bytes=4096, frame_size=65536,
                                             seg_len=4096, depth=1, native_elems=1),
                               observer_object="observer.bpf.o", ptx_path="pattern.ptx")
                request = dict(identity=identity, command="prepare", deadline_ms=3000,
                               part_index=0, part_count=1, payload=payload)
                raw = json.dumps(request, separators=(",", ":")).encode()
                process.stdin.write(struct.pack("!I", len(raw)) + raw)
                process.stdin.flush()
                deadline = time.monotonic() + 5

                def exact(fd, count):
                    data = b""
                    while len(data) < count:
                        remaining = deadline - time.monotonic()
                        self.assertGreater(remaining, 0, "bounded read expired")
                        self.assertTrue(select.select([fd], [], [], remaining)[0],
                                        "supervisor/probe did not respond")
                        chunk = os.read(fd, count - len(data))
                        self.assertTrue(chunk, "unexpected owner EOF")
                        data += chunk
                    return data

                size = struct.unpack("!I", exact(process.stdout.fileno(), 4))[0]
                self.assertTrue(0 < size <= 1048576)
                response = json.loads(exact(process.stdout.fileno(), size))
                # Only release independent observation after the supervisor has
                # handled the returned result; no sleep or owner-claimed phase.
                os.write(release_write, b"P")
                line = bytearray()
                while not line.endswith(b"\n"):
                    line.extend(exact(probe_read, 1))
                    self.assertLess(len(line), 4096)
                probe = json.loads(line)
                evidence = next(Path(directory).glob("owner-*.jsonl"))
                records = [json.loads(s) for s in evidence.read_text().splitlines()]
                observed = dict(response=response, actual_guard=probe,
                                durable_events=[r["event"] for r in records])
                detail = json.dumps(observed, sort_keys=True)
                # /dev/full cannot contain a truthful terminal append. Preserve
                # the original intent and assert retention via independent proof;
                # do not invent a durable HELD record or certified reclamation.
                self.assertEqual(observed["durable_events"], ["initial", "intent"], detail)
                self.assertIsNone(process.poll(), detail)
                self.assertEqual(probe["resource_fd_alive"], 1, detail)
                self.assertEqual(probe["held"], 1, detail)
                self.assertEqual(probe["permissions"], 0, detail)
                self.assertNotEqual(probe["hold_reasons"], 0, detail)
                for key in ("control_admission", "start_admission", "free_admission"):
                    self.assertEqual(probe[key], -errno.EPERM, detail)
                self.assertEqual(response["identity"], identity, detail)
                self.assertIs(response["held"], True, detail)
                self.assertEqual(response["phase"], "HELD", detail)
                self.assertEqual(response["fate"], "HELD", detail)
                self.assertEqual(response["cleanup_permissions"], 0, detail)
                self.assertLess(response["error"], 0, detail)
                self.assertNotEqual(response["evidence"]["hold_reasons"], 0, detail)
            finally:
                # Explicit eventfd-only surrogate teardown; no real device owner.
                process.kill()
                process.wait(timeout=3)
                process.stdin.close()
                process.stdout.close()
                process.stderr.close()
                os.close(release_write)
                os.close(probe_read)


if __name__ == "__main__":
    unittest.main()
