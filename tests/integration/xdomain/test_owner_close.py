#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual owner close receipt/trace boundaries, no successful fake CUDA calls."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
# Shared test-only UAPI shape, never production-derived expected values.
from test_contract import terminal_stats
IDENTITY=dict(version=1,run_id="pair-close-regression",sha="a"*40,role="tx",
              case="bringup",direction="a-to-b",epoch=3)


def receipt(role):
    payload=terminal_stats(101 if role=="tx" else 202,1,stopped=True)
    payload.update(stop_proved=True,first_error=0,stop_error=0)
    return dict(identity=dict(IDENTITY,role=role,request_id=5),command="stop",
                phase="DRAINED_SAFE",fate="SAFE",error=0,held=False,
                cleanup_permissions=1,evidence={},part_index=0,part_count=1,payload=payload)


class OwnerClose(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build=tempfile.TemporaryDirectory(prefix="tb-owner-close-build-")
        cls.addClassCleanup(cls.build.cleanup);folder=Path(cls.build.name);objects=[]
        cuda=Path(os.environ.get("CUDA_HOME", "/usr/local/cuda"))/"include"
        if not (cuda/"cuda.h").is_file():
            raise AssertionError("UNAVAILABLE: official CUDA_HOME/include/cuda.h required: "+str(cuda/"cuda.h"))
        # Official declarations only. Every GPU/CUDA runtime entry in the test
        # process is a fail-stop trap, never a result or payload substitute.
        includes=["-I",str(HERE),"-iquote",str(HERE.parents[2]/"kernel/include/uapi"),"-I",str(cuda)]
        for name in ("check_contract.c","epoch_control.c","agent_supervisor.cc","native_trace_owner.cc","owner_close_test.cc"):
            compiler="gcc" if name.endswith(".c") else "g++";obj=folder/(name+".o")
            cmd=[compiler,"-std="+("c11" if compiler=="gcc" else "c++17"),"-Wall","-Wextra","-Werror","-pthread",*includes]
            if compiler=="g++":cmd+=["-fno-access-control"]
            cmd += ["-c",str(HERE/name),"-o",str(obj)]
            built=subprocess.run(cmd,capture_output=True,text=True)
            if built.returncode:raise AssertionError("actual-source compile: "+built.stderr)
            objects.append(str(obj))
        cls.binary=folder/"owner-close"
        cmd=["g++","-pthread",*objects,"-Wl,--wrap=mkdir","-Wl,--wrap=rmdir",
             "-Wl,--wrap=tb_guard_begin","-lbpf","-lelf","-lz","-o",str(cls.binary)]
        built=subprocess.run(cmd,capture_output=True,text=True)
        if built.returncode:raise AssertionError("actual-source link: "+built.stderr)

    def run_case(self,scenario,pair):
        with tempfile.TemporaryDirectory(prefix="tb-owner-close-metadata-") as directory:
            os.chmod(directory,0o700);wire=Path(directory)/"close.json"
            wire.write_text(json.dumps(dict(identity=dict(IDENTITY,request_id=6),command="close",
                                deadline_ms=2000,part_index=0,part_count=1,
                                payload={} if pair is None else dict(stop_receipts=pair))))
            run=subprocess.run([str(self.binary),scenario,directory,str(wire)],capture_output=True,text=True,timeout=5)
            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            self.assertIn("PASS "+scenario,run.stdout)

    def test_valid_pair_grants_actual_cleanup_permission_before_any_gpu_call(self):
        self.run_case("pair-valid",[receipt("tx"),receipt("rx")])
    def test_missing_pair_rejected_even_when_pair_permission_already_exists(self):
        self.run_case("pair-missing",None)
    def test_foreign_epoch_pair_never_reaches_cleanup(self):
        pair=[receipt("tx"),receipt("rx")];pair[1]["identity"]["epoch"]=4;self.run_case("pair-foreign",pair)
    def test_replayed_local_stop_request_never_reaches_cleanup(self):
        pair=[receipt("tx"),receipt("rx")];pair[0]["identity"]["request_id"]=4;self.run_case("pair-replay",pair)
    def test_foreign_local_session_never_reaches_cleanup(self):
        pair=[receipt("tx"),receipt("rx")];pair[0]["payload"]["stats"]["session_id"]=999;self.run_case("pair-session",pair)
    def test_duplicate_role_pair_never_reaches_cleanup(self):
        self.run_case("pair-duplicate",[receipt("tx"),receipt("tx")])
    def test_safe_trace_cleanup_is_admitted_and_removes_only_owned_instance(self):
        self.run_case("trace-safe",[receipt("tx"),receipt("rx")])
    def test_held_before_trace_cleanup_admission_retains_actual_instance(self):
        self.run_case("trace-held",[receipt("tx"),receipt("rx")])


if __name__=="__main__":unittest.main(verbosity=2)
