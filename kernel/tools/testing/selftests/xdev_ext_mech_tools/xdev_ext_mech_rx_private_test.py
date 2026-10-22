#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host regressions for per-stage RX transactions and finite CE campaigns.

Actual BPF callbacks and actual C envelope/frame-accessor definitions execute
under UBSan. Host adapters supply storage/dispatch only, never protocol state
transitions. Small source guards cover verifier registration and CLI placement.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def definition(path, marker, terminator="}"):
    src = (ROOT / path).read_text()
    start = src.index(marker)
    opening = src.index("{", start)
    depth, at = 1, opening + 1
    while depth:
        depth += (src[at] == "{") - (src[at] == "}")
        at += 1
    if terminator == "};":
        at += 1
    return src[start:at] + "\n"


class PrivateRxTests(unittest.TestCase):
    def execute(self, filename, chunks=None):
        source = (HERE / filename).read_text()
        for name, chunk in (chunks or {}).items():
            source = source.replace("/* PRODUCTION_" + name + " */", chunk)
        defines = []
        if "xdev_ext_mech_ctl_ce_window_ok(" in (ROOT / "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h").read_text():
            defines.append("-DXDEV_EXT_TEST_HAS_CE_WINDOW=1")
        if "__bpf_kfunc __u8 *bpf_xdev_ext_afxdp_state(" in (ROOT / "net/xdp/xsk_xdev_ext_mech.c").read_text():
            defines.append("-DXDEV_EXT_TEST_HAS_STATE=1")
        with tempfile.TemporaryDirectory(prefix="xdev_ext-rx-private-") as tmp:
            src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
            src.write_text(source)
            command = [os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g",
                       "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                       "-fno-sanitize-recover=undefined", "-I" + str(ROOT),
                       "-I" + str(ROOT / "tools/testing/selftests/xdev_ext_mech/cref/host"),
                       *defines, str(src), "-o", str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, "host harness must compile before behavioral assertions:\n" + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_two_pools_keep_independent_candidate_and_canonical_order(self):
        self.execute("xdev_ext_mech_rx_private_fixture.c")

    def test_result_envelope_denies_payload_and_state_kfunc_gate(self):
        chunks = {
            "FRAME": definition("include/linux/xdev_ext_mech.h", "struct xdev_ext_mech_frame {", "};"),
            "CALL": definition("include/linux/xdev_ext_mech.h", "struct xdev_ext_mech_call {", "};"),
            "CALL_OF": definition("include/linux/xdev_ext_mech.h", "static inline struct xdev_ext_mech_call *\nxdev_ext_mech_call_of("),
            "ARGS": definition("include/linux/xdev_ext_mech.h", "struct xdev_ext_mech_call_args {", "};"),
            "FRAME_BYTES": definition("io_uring/xdev_ext_mech_ops.c", "static u8 *xdev_ext_mech_frame_bytes("),
            "BPF_FRAME": definition("io_uring/xdev_ext_mech_ops.c", "__bpf_kfunc __u8 *bpf_xdev_ext_frame("),
            "BPF_CRC": definition("io_uring/xdev_ext_mech_ops.c", "__bpf_kfunc __u32 bpf_xdev_ext_frame_crc32c("),
            "RX_CALL": definition("net/xdp/xsk_xdev_ext_mech.c", "static int xsk_xdev_ext_mech_rx_call("),
            "STATE": "",
        }
        if "__bpf_kfunc __u8 *bpf_xdev_ext_afxdp_state(" in (ROOT / "net/xdp/xsk_xdev_ext_mech.c").read_text():
            chunks["STATE"] = definition("net/xdp/xsk_xdev_ext_mech.c", "__bpf_kfunc __u8 *bpf_xdev_ext_afxdp_state(")
        self.execute("xdev_ext_mech_rx_result_fixture.c", chunks)

    def test_ce_campaign_slots_never_wrap(self):
        self.execute("xdev_ext_mech_ce_window_test.c")

    def test_state_is_256_bytes_and_complete_only_kfunc(self):
        header = (ROOT / "include/uapi/linux/xdev_ext_mech.h").read_text()
        self.assertTrue(re.search(r"#define\s+XDEV_EXT_AFXDP_MECH_STATE_SIZE\s+256U?\b", header), "AF_XDP stage state must declare the frozen 256-byte size")
        source = (ROOT / "net/xdp/xsk_xdev_ext_mech.c").read_text()
        self.assertRegex(source, r"bpf_state\s*\[\s*XDEV_EXT_AFXDP_MECH_STATE_SIZE\s*/\s*sizeof\s*\(\s*__u64\s*\)\s*\]")
        complete = source.split("BTF_SET_START(xsk_xdev_ext_mech_complete_kfuncs)", 1)[1].split("BTF_SET_END", 1)[0]
        build = source.split("BTF_SET_START(xsk_xdev_ext_mech_build_kfuncs)", 1)[1].split("BTF_SET_END", 1)[0]
        self.assertIn("bpf_xdev_ext_afxdp_state", complete)
        self.assertNotIn("bpf_xdev_ext_afxdp_state", build)
        self.assertRegex(source, r"BTF_ID_FLAGS\(func,\s*bpf_xdev_ext_afxdp_state,\s*KF_TRUSTED_ARGS\s*\|\s*KF_RET_NULL\)")

    def test_nxp_protocol_state_has_no_global_candidate_or_global_lock(self):
        source = (ROOT / "tools/xdev_ext_mech/nxp_mech.bpf.c").read_text()
        # A state type contains these fields; standalone .bss declarations must disappear.
        self.assertFalse(re.search(r"(?m)^struct xdev_ext_mp_rx_order\s+rx_(?:order|candidate)\s*;", source), "NXP canonical/candidate order must not live in global BSS")
        self.assertNotRegex(source, r"(?m)^__u(?:32|64)\s+rx_candidate_\w+\s*;")
        self.assertNotRegex(source, r"bpf_spin_lock|__sync_lock|__sync_val_compare_and_swap")
        self.assertIn("bpf_xdev_ext_afxdp_state", source)

    def test_cli_guards_ce_campaign_before_io(self):
        for marker in ("static int cmd_ce_chain(", "static int cmd_nic_nvme("):
            with self.subTest(command=marker):
                fn = definition("tools/xdev_ext_mech/xdev_ext_mech_ctl.c", marker)
                guard = fn.find("xdev_ext_mech_ctl_ce_window_ok(")
                self.assertGreaterEqual(guard, 0, "finite CE campaign must reject an oversized window before CREATE/IO")
                io = re.search(r"\b(?:open|ctl_ring_open|ctl_xsk_open|ctl_source_run|ctl_create|ctl_start)\s*\(", fn)
                self.assertIsNotNone(io)
                self.assertLess(guard, io.start(), "window guard must precede all device/ring setup")
                self.assertRegex(fn[guard:io.start()], r"return\s+-E(?:INVAL|RANGE|2BIG)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
