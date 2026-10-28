#!/usr/bin/env python3
"""Independent CLI/result/ownership acceptance; never run VM performance."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_oracle import PROFILE, reference_file

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "run.py"
FIELDS = set("schema status scenario mode backend transport record_bytes payload_bytes "
    "burst_packets depth bursts actors expected_packets validated_packets validated_bytes "
    "read_bytes send_bytes unexpected_packets duplicates missing byte_mismatches "
    "local_release_complete receiver_receipt guards_ok registration_calls read_submissions "
    "send_submissions read_cqes send_result_cqes send_notif_cqes zc_copied_packets "
    "session_stats stop_ret scope source_sha".split())
OPTIONAL = "registration_calls read_cqes send_result_cqes send_notif_cqes zc_copied_packets session_stats stop_ret".split()


def validate_result(record, profile, backend="posix"):
    if type(record) is not dict or set(record) != FIELDS:
        raise ValueError("unexpected/missing result field")
    count = profile["actors"] * profile["bursts"] * profile["burst_packets"]
    expected = dict(schema=1, status="ok", scenario="hft_replay", mode="correctness",
        backend=backend, transport="udp", record_bytes=profile["record_bytes"],
        payload_bytes=profile["payload_bytes"], burst_packets=profile["burst_packets"],
        depth=profile["depth"], bursts=profile["bursts"], actors=profile["actors"],
        expected_packets=count, validated_packets=count,
        validated_bytes=count*profile["payload_bytes"], read_bytes=count*profile["payload_bytes"],
        send_bytes=count*(profile["payload_bytes"]+40), unexpected_packets=0,
        duplicates=0, missing=0, byte_mismatches=0, local_release_complete=True,
        receiver_receipt=True, guards_ok=True, read_submissions=count, send_submissions=count,
        source_sha=hashlib.sha256(reference_file(profile)).hexdigest(),
        scope="physical-native-correctness" if backend == "session" else "buffered-host-correctness")
    for field, wanted in expected.items():
        if type(record[field]) is not type(wanted) or record[field] != wanted:
            raise ValueError("invalid result field: " + field)
    if backend == "posix":
        if any(record[key] is not None for key in OPTIONAL):
            raise ValueError("invented POSIX backend counter")
    elif backend == "uring-fixed-zc":
        for key, wanted in (("registration_calls", profile["actors"]),
                            ("read_cqes", count), ("send_result_cqes", count)):
            if type(record[key]) is not int or record[key] != wanted:
                raise ValueError("wrong registered counter")
        notif, copied = record["send_notif_cqes"], record["zc_copied_packets"]
        if type(notif) is not int or type(copied) is not int or not 0 <= copied <= notif <= count:
            raise ValueError("invalid notification/copy accounting")
        if record["session_stats"] is not None or record["stop_ret"] is not None:
            raise ValueError("invented session stats")
    elif backend == "session":
        if any(record[key] is not None for key in OPTIONAL[:-2]):
            raise ValueError("invented session userspace CQ counter")
        if type(record["stop_ret"]) is not int or record["stop_ret"] != 0:
            raise ValueError("STOP did not establish release")
        wanted = dict(batches_done=count, read_submitted=count, read_completed=count,
            send_submitted=count, send_completed=count, state="ACTIVE", batches_abort=0,
            rejects=0, sequestered=0, timeouts=0, protocol_err=0, last_err=0, inflight=0)
        stats = record["session_stats"]
        if type(stats) is not dict or set(stats) != set(wanted):
            raise ValueError("wrong session stats fields")
        for key, value in wanted.items():
            if type(stats[key]) is not type(value) or stats[key] != value:
                raise ValueError("session not fully quiescent: " + key)
    else:
        raise ValueError("unsupported backend")


def valid_record(profile, backend="posix"):
    """Test fixture only; never a substitute for a runtime producer result."""
    count = profile["actors"]*profile["bursts"]*profile["burst_packets"]
    record = dict(schema=1,status="ok",scenario="hft_replay",mode="correctness",
        backend=backend,transport="udp",record_bytes=profile["record_bytes"],
        payload_bytes=profile["payload_bytes"],burst_packets=profile["burst_packets"],
        depth=profile["depth"],bursts=profile["bursts"],actors=profile["actors"],
        expected_packets=count,validated_packets=count,validated_bytes=count*profile["payload_bytes"],
        read_bytes=count*profile["payload_bytes"],send_bytes=count*(profile["payload_bytes"]+40),
        unexpected_packets=0,duplicates=0,missing=0,byte_mismatches=0,
        local_release_complete=True,receiver_receipt=True,guards_ok=True,
        read_submissions=count,send_submissions=count,
        source_sha=hashlib.sha256(reference_file(profile)).hexdigest(),
        scope="physical-native-correctness" if backend == "session" else "buffered-host-correctness")
    record.update(dict.fromkeys(OPTIONAL))
    if backend == "uring-fixed-zc":
        record.update(registration_calls=profile["actors"],read_cqes=count,
                      send_result_cqes=count,send_notif_cqes=count,zc_copied_packets=0)
    if backend == "session":
        record.update(stop_ret=0,session_stats=dict(batches_done=count,
            read_submitted=count,read_completed=count,send_submitted=count,send_completed=count,
            state="ACTIVE",batches_abort=0,rejects=0,sequestered=0,timeouts=0,
            protocol_err=0,last_err=0,inflight=0))
    return record


class StrictResultTests(unittest.TestCase):
    def test_valid_fixtures_all_three_arms(self):
        for backend in ("posix", "uring-fixed-zc", "session"):
            validate_result(valid_record(PROFILE, backend), PROFILE, backend)

    def test_all_field_mutations_rejected(self):
        valid = valid_record(PROFILE)
        for key, value in valid.items():
            replacements = [True, False, 0, -1, "wrong", {}, []]
            for replacement in replacements:
                if type(value) is type(replacement) and value == replacement:
                    continue
                with self.subTest(field=key, replacement=replacement):
                    mutant = dict(valid, **{key: replacement})
                    with self.assertRaises(ValueError):
                        validate_result(mutant, PROFILE)
            mutant = dict(valid); del mutant[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                validate_result(mutant, PROFILE)
        for key in ("elapsed_ns", "throughput", "p50", "p99", "latency", "speedup"):
            with self.subTest(forbidden=key), self.assertRaises(ValueError):
                validate_result(dict(valid, **{key: 1}), PROFILE)

    def test_session_error_inflight_or_nonzero_stop_rejected(self):
        valid = valid_record(PROFILE, "session")
        for key in valid["session_stats"]:
            mutant = copy.deepcopy(valid)
            mutant["session_stats"][key] = "UNKNOWN" if key == "state" else True
            with self.subTest(field=key), self.assertRaises(ValueError):
                validate_result(mutant, PROFILE, "session")
        for stop in (False, -11, 1, None):
            with self.subTest(stop=stop), self.assertRaises(ValueError):
                validate_result(dict(valid, stop_ret=stop), PROFILE, "session")

    def test_registered_copy_and_notification_counts_rejected(self):
        valid = valid_record(PROFILE, "uring-fixed-zc")
        for changes in (dict(registration_calls=16), dict(read_cqes=15),
                        dict(send_result_cqes=True), dict(send_notif_cqes=17),
                        dict(send_notif_cqes=0,zc_copied_packets=1),
                        dict(zc_copied_packets=-1)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_result(dict(valid, **changes), PROFILE, "uring-fixed-zc")


class CLIContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".contract-test-", dir=HERE)
        self.root = Path(self.temp.name)
        self.sentinel = self.root / "preexisting-user-file"
        self.sentinel.write_bytes(b"immutable input sentinel\x00"*71)
        self.before = self.snapshot()

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self):
        return {str(p.relative_to(self.root)):
                (p.stat().st_ino,p.stat().st_mode,p.stat().st_mtime_ns,
                 hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
                for p in self.root.rglob("*")}

    def invoke(self, *args):
        result = subprocess.run([sys.executable,str(RUNNER),"--directory",str(self.root),*args],
            text=True,capture_output=True,timeout=120)
        self.assertTrue(RUNNER.is_file(),"absent runner; actual subprocess exit="+
                        str(result.returncode)+" stderr="+result.stderr)
        self.assertEqual(self.snapshot(),self.before,"existing data changed or temporary artifacts remain")
        return result

    def assert_refusal(self, result, code):
        self.assertEqual(result.returncode, code, result.stdout+result.stderr)
        self.assertEqual(result.stdout, "")
        if code == 4:
            records = []
            for line in result.stderr.splitlines():
                try: records.append(json.loads(line))
                except ValueError: pass
            self.assertTrue(records,"capability refusal must have structured stderr")
            record = records[-1]
            self.assertIn(record.get("status"),("not_run_capability","not_run_hardware"))
            self.assertIs(record.get("start_issued"),False)
            self.assertFalse(set(record) & {"elapsed_ns","throughput","p50","p99","io_ns"})

    def test_help(self):
        result=self.invoke("--help")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("uring-fixed-zc",result.stdout)

    def test_invalid_cli_before_dependencies_or_creation(self):
        for args in (("--backend","fake"),("--mode","wrong"),("--unknown",),
                     ("positional",),("--actors","2"),("--burst","0"),
                     ("--burst","33"),("--depth","0"),("--depth","9"),
                     ("--bursts","33"),("--records","65"),("--payload","513"),
                     ("--seed",str(2**64)),("--seed","-1"),
                     ("--backend","posix","--backend","session"),
                     ("--depth","1","--depth","2")):
            with self.subTest(args=args): self.assert_refusal(self.invoke(*args),2)
        for value in ("+1"," 1","1 ","1.0","1e0","١","True",""):
            with self.subTest(numeric=value):
                self.assert_refusal(self.invoke("--seed",value),2)

    def test_invalid_directory_not_created_or_truncated(self):
        for directory in (self.root/"missing",self.sentinel):
            # Avoid duplicate --directory so the directory check itself is exercised.
            result=subprocess.run([sys.executable,str(RUNNER),"--directory",str(directory)],
                                  text=True,capture_output=True,timeout=15)
            self.assertTrue(RUNNER.is_file(),"absent runner: "+result.stderr)
            self.assert_refusal(result,2)
            self.assertEqual(self.snapshot(),self.before)

    def test_session_missing_native_gates_no_start(self):
        self.assert_refusal(self.invoke("--backend","session","--mode","correctness"),4)

    def test_performance_refused_before_workload(self):
        self.assert_refusal(self.invoke("--mode","performance"),4)

    def test_real_posix_default_and_four_actor_defaults_and_tail(self):
        cases = [dict(actors=1),dict(actors=4),
                 dict(actors=1,burst_packets=1,bursts=1,depth=8),
                 dict(actors=4,burst_packets=3,bursts=2,depth=4,
                      record_bytes=128,payload_bytes=1024),
                 dict(actors=4,burst_packets=8,bursts=1,depth=1,
                      record_bytes=256,payload_bytes=512)]
        for changes in cases:
            profile=dict(PROFILE,record_bytes=64,payload_bytes=512,burst_packets=32,
                         depth=8,bursts=8,actors=1,seed=1)
            profile.update(changes)
            args=["--backend","posix","--mode","correctness"]
            for option,field in (("--actors","actors"),("--burst","burst_packets"),
                                 ("--bursts","bursts"),("--depth","depth"),
                                 ("--records","record_bytes"),("--payload","payload_bytes")):
                args += [option,str(profile[field])]
            with self.subTest(profile=profile):
                result=self.invoke(*args)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(len(result.stdout.splitlines()),1)
                validate_result(json.loads(result.stdout),profile)

    def test_real_registered_arm_capability_or_complete_oracle(self):
        result=self.invoke("--backend","uring-fixed-zc","--burst","1","--bursts","1")
        if result.returncode == 4:
            self.assert_refusal(result,4)
        else:
            self.assertEqual(result.returncode,0,result.stderr)
            profile=dict(PROFILE,record_bytes=64,payload_bytes=512,burst_packets=1,
                         depth=8,bursts=1,actors=1,seed=1)
            self.assertEqual(len(result.stdout.splitlines()),1)
            validate_result(json.loads(result.stdout),profile,"uring-fixed-zc")


class OwnershipBuildTests(unittest.TestCase):
    def test_actual_header_seam_compiles_and_runs(self):
        compiler=shutil.which("cc")
        self.assertIsNotNone(compiler,"C compiler required for ownership acceptance")
        with tempfile.TemporaryDirectory(prefix=".ownership-test-",dir=HERE) as directory:
            output=str(Path(directory)/"ownership")
            result=subprocess.run([compiler,"-std=c11","-Wall","-Wextra","-Werror",
                "-I",str(HERE),str(HERE/"test_ownership.c"),"-o",output],
                text=True,capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([output],text=True,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("7 groups PASS",result.stdout)


if __name__ == "__main__":
    unittest.main()
