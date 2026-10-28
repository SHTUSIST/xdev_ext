#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent CPU planning/command contract; no build, SDK, peer or device."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
for ancestor in HERE.parents:
    choices = (ancestor / "tests/support/benchmarks/test_cpu_timer.py",
               ancestor / "tests/eval/common/test_cpu_timer.py")
    support = next((path for path in choices if path.is_file()), None)
    if support:
        break
else:
    raise RuntimeError("SETUP: CPU timer test support is not mapped")
spec = importlib.util.spec_from_file_location("independent_cpu_timer_test_support", support)
SUPPORT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SUPPORT)

RIG = {
    "nvme_src": {"ng": "/nonexistent/ng0n1", "block": "/nonexistent/nvme0n1", "slba": 0,
                 "nlb": 1048576, "lba_bytes": 512},
    "nvme_dst": {"ng": "/nonexistent/ng1n1", "block": "/nonexistent/nvme1n1", "slba": 2048,
                 "nlb": 1048576, "lba_bytes": 512},
    "tx": {"ifname": "cpu-plan-tx", "queue": 0, "mac": "02:00:00:00:00:01",
           "ip": "192.0.2.1", "port": 54321, "mtu": 1500},
    "rx": {"ifname": "cpu-plan-rx", "queue": 0, "mac": "02:00:00:00:00:02",
           "ip": "192.0.2.2", "port": 12345, "mtu": 1500},
    "ce": {"dev": "/nonexistent/ce", "len": 4194304, "tx_va": 0, "rx_va": 4194304},
    "attached": ["nxp_nvme_ops", "nxp_afxdp_ops", "ce_plan_ops"],
    "nxp_session": 270019,
}

class UserspaceCpuPlanning(SUPPORT.RunnerContract):
    runner = HERE / "run.py"

    def test_both_waits_forward_cpu_owner_options_to_the_chain_runner(self):
        for wait in ("poll", "eventfd"):
            for load in ("closed", "sustained"):
                with self.subTest(wait=wait, load=load):
                    def options(root):
                        rig = root / "rig.json"
                        rig.write_text(json.dumps(RIG))
                        return ["--rig", str(rig), "--chain", "nvme-nic", "--wait", wait,
                                "--load", load, "--sizes", "4096", "--depth", "8", "--seed", "17",
                                "--pairs", "1", "--records", "32", "--warmup-records", "4",
                                "--out-dir", str(root / "original-results")]
                    documents, root = self.execute_plan(options)
                    self.assert_cpu_disclosure(documents, root, clock="CLOCK_MONOTONIC_RAW")
                    rows = [doc for doc in documents if isinstance(doc, dict) and "arm" in doc]
                    self.assertTrue(rows)
                    self.assertEqual({r["arm"] for r in rows}, {"userspace-shared"})
                    self.assertEqual({r["wait"] for r in rows}, {wait})


if __name__ == "__main__":
    unittest.main()
