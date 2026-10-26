#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual-supervisor CREATE_UNKNOWN notification regressions; eventfd only."""
import errno
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
IDENTITY = dict(version=1, run_id="create-refusal-regression", sha="a"*40,
                role="tx", case="functional-epochs", direction="a-to-b", epoch=3)


def request(command="prepare", deadline=2000, request_id=1):
    payload = dict(mode="single-group", groups=1, first_seq=7, seed=9,
                   gpu_bdf="0000:01:00.0", nvidia_node="/dev/nvidia0",
                   link_token=901, channel=0, flags=0,
                   geometry=dict(allocation_bytes=65536, group_bytes=4096,
                                 frame_size=65536, seg_len=4096, depth=1, native_elems=1),
                   observer_object="observer.bpf.o", ptx_path="pattern.ptx")
    return dict(identity=dict(IDENTITY, request_id=request_id), command=command,
                deadline_ms=deadline, part_index=0, part_count=1,
                payload=payload if command=="prepare" else {"reason":"independent cancellation"})


def send(stream, value):
    body=json.dumps(value,separators=(",", ":")).encode()
    stream.write(struct.pack("!I",len(body))+body);stream.flush()


class CreateRefusal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build=tempfile.TemporaryDirectory(prefix="tb-create-refusal-build-")
        cls.addClassCleanup(cls.build.cleanup)
        folder=Path(cls.build.name);objects=[]
        for name in ("check_contract.c","agent_supervisor.cc","create_refusal_test_owner.cc"):
            compiler="gcc" if name.endswith(".c") else "g++"
            obj=folder/(name+".o")
            cmd=[compiler,"-std="+("c11" if compiler=="gcc" else "c++17"),
                 "-Wall","-Wextra","-Werror","-pthread","-I",str(HERE),"-c",str(HERE/name),"-o",str(obj)]
            built=subprocess.run(cmd,capture_output=True,text=True)
            if built.returncode:raise AssertionError("actual-source compile: "+built.stderr)
            objects.append(str(obj))
        cls.binary=folder/"refusal-owner"
        built=subprocess.run(["g++","-pthread",*objects,"-o",str(cls.binary)],capture_output=True,text=True)
        if built.returncode:raise AssertionError("actual-source link: "+built.stderr)

    def exact(self, fd, n, seconds=1):
        end=time.monotonic()+seconds;data=b""
        while len(data)<n:
            remain=end-time.monotonic()
            self.assertGreater(remain,0,"terminal notification exceeded bounded wait")
            self.assertTrue(select.select([fd],[],[],remain)[0],"terminal notification missing after owner/deadline")
            chunk=os.read(fd,n-len(data));self.assertTrue(chunk,"unexpected process EOF");data+=chunk
        return data

    def response(self,p):
        n=struct.unpack("!I",self.exact(p.stdout.fileno(),4))[0]
        self.assertTrue(0<n<=1048576)
        return json.loads(self.exact(p.stdout.fileno(),n))

    def run_mode(self, mode):
        with tempfile.TemporaryDirectory(prefix="tb-create-refusal-surrogate-") as directory:
            os.chmod(directory,0o700);release_r,release_w=os.pipe();ready_r,ready_w=os.pipe()
            p=subprocess.Popen([str(self.binary),mode,directory,str(release_r),str(ready_w)],
                               stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                               pass_fds=(release_r,ready_w))
            os.close(release_r);os.close(ready_w)
            try:
                send(p.stdin,request(deadline=150 if mode=="deadline" else 2000))
                line=b""
                while not line.endswith(b"\n"):line+=self.exact(ready_r,1)
                probe=json.loads(line);self.assertEqual(probe["held"],1);self.assertEqual(probe["permissions"],0)
                self.assertTrue(Path(f"/proc/{p.pid}/fd/{probe['fd']}").exists())
                if mode=="cancel":send(p.stdin,request("cancel",request_id=2))
                if mode=="signal":os.kill(p.pid,signal.SIGTERM)
                blocked=mode in ("deadline","cancel","signal","additional")
                if not blocked:os.write(release_w,b"R")
                result=self.response(p)
                self.assertIs(result["held"],True,result);self.assertEqual(result["phase"],"HELD",result)
                self.assertEqual(result["fate"],"HELD",result);self.assertEqual(result["cleanup_permissions"],0,result)
                self.assertLess(result["error"],0,result)
                self.assertEqual(result["identity"],dict(IDENTITY,request_id=2 if mode=="cancel" else 1),result)
                if mode=="refusal":
                    self.assertEqual(result["error"],-errno.EXDEV,result)
                    self.assertEqual(result["payload"]["create_error"],-errno.EXDEV,result)
                    self.assertIsNone(result["payload"]["stage_caps"],result)
                    self.assertEqual(result["payload"]["session_id"],0,result)
                if blocked:os.write(release_w,b"R")
                self.assertIsNone(p.poll());self.assertTrue(Path(f"/proc/{p.pid}/fd/{probe['fd']}").exists())
                records=[json.loads(x) for x in next(Path(directory).glob("owner-*.jsonl")).read_text().splitlines()]
                self.assertIn("held",[r["event"] for r in records])
            finally:
                # Explicit teardown only for this eventfd-only independent fixture.
                p.kill();p.wait(timeout=3)
                p.stdin.close();p.stdout.close();p.stderr.close();os.close(release_w);os.close(ready_r)

    def test_empty_error_result_has_bounded_held_notification(self):self.run_mode("empty")
    def test_throw_after_create_unknown_has_bounded_held_notification(self):self.run_mode("throw")
    def test_nonempty_refusal_preserves_actual_errno_and_payload(self):self.run_mode("refusal")
    def test_deadline_not_deferred_by_blocked_admission_capture(self):self.run_mode("deadline")
    def test_cancel_not_deferred_by_blocked_admission_capture(self):self.run_mode("cancel")
    def test_signal_not_deferred_by_blocked_admission_capture(self):self.run_mode("signal")
    def test_additional_protocol_hold_is_immediate_while_owner_blocked(self):self.run_mode("additional")


if __name__=="__main__":unittest.main(verbosity=2)
