#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract of the mechanism programs in tools/xdev_ext_mech.

The KVM harness compiles and verifies the BPF objects; xdev_ext_cpu_bpf_test.py
also checks CPU BPF target compilation. These checks hold the shape the harness
and the verifier rely on: the struct_ops
map names of the control-tool CLI, the globals it sets, constant view sizes,
a NULL check on every view, and no UAPI constant that vmlinux.h lacks.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
TOOLS = ROOT / "tools/xdev_ext_mech"

PROGRAMS = {
    "nvme_s0.bpf.c": {
        "maps": {"nvme_s0_ops": "xdev_ext_nvme_mech_ops"},
        "globals": ["mode"],
    },
    "nxp_mech.bpf.c": {
        "maps": {"nxp_afxdp_ops": "xdev_ext_afxdp_mech_ops",
                 "nxp_nvme_ops": "xdev_ext_nvme_mech_ops"},
        "globals": ["nxp_session", "key_base", "nvme_mode"],
    },
    "ce_plan.bpf.c": {
        "maps": {"ce_plan_ops": "xdev_ext_ce_mech_ops"},
        "globals": [],
    },
}

VIEWS = ("bpf_xdev_ext_info", "bpf_xdev_ext_desc", "bpf_xdev_ext_cqe", "bpf_xdev_ext_frame",
         "bpf_xdev_ext_afxdp_hdr")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def calls(text: str, name: str):
    """Argument strings of every call of @name (nested parentheses kept)."""
    for match in re.finditer(rf"\b{name}\(", text):
        depth, pos = 1, match.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(text[pos], 0)
            pos += 1
        yield match.start(), text[match.end():pos - 1]


def split_args(args: str):
    out, depth, cur = [], 0, ""
    for ch in args:
        if ch == "," and not depth:
            out.append(cur.strip())
            cur = ""
            continue
        depth += {"(": 1, ")": -1}.get(ch, 0)
        cur += ch
    out.append(cur.strip())
    return out


def function_body(text: str, name: str) -> str:
    start = re.search(rf"BPF_PROG\({name},", text)
    if not start:
        raise AssertionError(f"missing program {name}")
    brace = text.index("{", start.end())
    depth = 0
    for pos in range(brace, len(text)):
        depth += {"{": 1, "}": -1}.get(text[pos], 0)
        if not depth:
            return text[brace:pos + 1]
    raise AssertionError(f"unterminated program {name}")


class ProgramSourceTest(unittest.TestCase):
    def setUp(self):
        self.sources = {name: strip_comments((TOOLS / name).read_text())
                        for name in PROGRAMS}

    def test_struct_ops_maps(self):
        for name, spec in PROGRAMS.items():
            text = self.sources[name]
            found = dict(re.findall(
                r'SEC\("\.struct_ops\.link"\)\s*struct (\w+) (\w+) =', text))
            found = {var: typ for typ, var in found.items()}
            self.assertEqual(found, spec["maps"], name)
            for var in spec["maps"]:
                body = text[text.index(f" {var} ="):]
                body = body[:body.index("};")]
                self.assertIn(".abi_version = " + ("XDEV_EXT_MP_CE_ABI_VERSION" if name == "ce_plan.bpf.c" else "XDEV_EXT_MP_ABI_VERSION"), body)
                self.assertIn(".build =", body)
                self.assertIn(".complete =", body)
                self.assertNotIn(".prepare", body)
            self.assertIn('char LICENSE[] SEC("license") = "GPL";', text)

    def test_cli_globals(self):
        for name, spec in PROGRAMS.items():
            declared = re.findall(r"^(?:__u32|__u64) (\w+)(?: = [^;]+)?;",
                                  self.sources[name], re.M)
            self.assertEqual(sorted(declared), sorted(spec["globals"]), name)

    def test_only_mirrored_constants(self):
        # vmlinux.h has no UAPI macro and only instantiated enums.
        for name, text in self.sources.items():
            for token in re.findall(r"\b(?:XDEV_EXT_MECH|XDEV_EXT_CE|NVME|XDP)_[A-Z_]+",
                                    text):
                self.fail(f"{name}: UAPI constant {token}")

    def test_includes(self):
        allowed = {'"vmlinux.h"', "<bpf/bpf_helpers.h>",
                   "<bpf/bpf_tracing.h>", '"xdev_ext_mech_prog.h"',
                   '"xdev_ext_mech_kfunc.h"'}
        for name, text in self.sources.items():
            self.assertTrue(text.lstrip().startswith(
                "#define BPF_NO_KFUNC_PROTOTYPES"), name)
            for inc in re.findall(r"#include (\S+)", text):
                self.assertIn(inc, allowed, name)

    def test_view_sizes_are_constants(self):
        # rdonly_buf_size / rdwr_buf_size must be known to the verifier.
        for name, text in self.sources.items():
            for view in VIEWS:
                for _, args in calls(text, view):
                    size = split_args(args)[-1]
                    self.assertRegex(size, r"^(sizeof\(.*\)|XDEV_EXT_MP_[A-Z_]+)$",
                                     f"{name}: {view}({args})")

    def test_views_are_null_checked(self):
        for name, text in self.sources.items():
            for view in VIEWS:
                for start, _ in calls(text, view):
                    line = text[text.rindex("\n", 0, start) + 1:]
                    target = re.match(r"\s*(\w+) = ", line)
                    self.assertIsNotNone(target, f"{name}: {view} unassigned")
                    rest = text[start:start + 400]
                    self.assertRegex(rest, rf"!{target.group(1)}\b",
                                     f"{name}: {view} result unchecked")

    def test_rx_complete_holds_at_serialized_generic_and_native_callsites(self):
        text = self.sources["nxp_mech.bpf.c"]
        body = function_body(text, "nxp_afxdp_complete")
        self.assertRegex(body, r"callsite != XDEV_EXT_MP_SITE_RX_GENERIC &&\s*"
                               r"mctx->callsite != XDEV_EXT_MP_SITE_RX_NATIVE\)\s*"
                               r"return XDEV_EXT_MP_PUBLISH;")
        rx = function_body(text, "nxp_rx_complete") if "BPF_PROG(nxp_rx_" \
            in text else text[text.index("nxp_rx_complete("):]
        # CRC before order; order before the hold intent.
        crc = rx.index("xdev_ext_mp_nxp_crc_ok(")
        order = rx.index("xdev_ext_mp_rx_order(")
        hold = rx.index("bpf_xdev_ext_afxdp_hold(")
        self.assertLess(crc, order)
        self.assertLess(order, hold)
        self.assertIn("XDEV_EXT_MP_RX_FOREIGN", rx[:crc])

    def test_kfunc_declarations(self):
        text = (TOOLS / "xdev_ext_mech_kfunc.h").read_text()
        for view in VIEWS:
            self.assertRegex(text, rf"extern __u8 \*{view}\([^;]*"
                                   r"const size_t (rdonly|rdwr)_buf_size\) "
                                   r"__ksym;")
        self.assertIn("bpf_xdev_ext_crc32c(const void *buf, __u32 buf__sz", text)
        self.assertIn("bpf_xdev_ext_afxdp_hold(", text)

    def test_kfuncs_match_the_contract(self):
        # A BPF call passes at most five arguments in R1-R5; the verifier
        # refuses a kfunc with more (MAX_BPF_FUNC_REG_ARGS).
        def protos(text, prefix):
            return {m.group(1): " ".join(m.group(2).split())
                    for m in re.finditer(
                        rf"^{prefix}[\w ]*?\*?(bpf_xdev_ext_\w+)\(([^;]*)\)"
                        r"(?: __ksym)?;", text, re.M)}

        contract = protos(strip_comments(
            (ROOT / "include/linux/xdev_ext_mech.h").read_text()), "")
        ours = protos(strip_comments(
            (TOOLS / "xdev_ext_mech_kfunc.h").read_text()), "extern ")
        self.assertEqual(sorted(ours), sorted(contract))
        for name, params in contract.items():
            self.assertLessEqual(len(params.split(",")), 5, name)
            self.assertEqual(ours[name], params, name)


def c_function(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for pos in range(brace, len(text)):
        depth += {"{": 1, "}": -1}.get(text[pos], 0)
        if not depth:
            return text[brace:pos + 1]
    raise AssertionError(f"unterminated function: {signature}")


class CtlSourceTest(unittest.TestCase):
    """xdev_ext_mech_ctl: the CLI contract and the order of its setup steps."""

    def setUp(self):
        self.ctl = strip_comments((TOOLS / "xdev_ext_mech_ctl.c").read_text())
        self.make = (TOOLS / "Makefile").read_text()

    def test_subcommands(self):
        for cmd in ("attach", "detach", "nic-nvme", "nvme-nic", "ce-chain",
                    "stats"):
            self.assertIn(f'{{ "{cmd}", cmd_', self.ctl)

    def test_options(self):
        for opt in ("obj", "map", "pin", "set", "ifname", "queue",
                    "drv-mode", "src-ng", "dst-ng", "slba", "nlb",
                    "dst-slba", "dst-nlb", "groups", "depth",
                    "group-bytes", "timeout-ms", "local-mac", "peer-mac",
                    "local-ip", "peer-ip", "local-port", "peer-port",
                    "ce-dev", "ce-va", "ce-len", "chain", "session",
                    "expect-window-reject", "detach-mid-run", "fq-dup",
                    "shared-umem-probe", "close-inflight", "expect-unbind",
                    "expect-timeout", "quiet-wait", "copy"):
            self.assertRegex(self.ctl, rf'\{{ "{opt}", ')

    def test_zero_copy_required_by_default(self):
        opened = c_function(self.ctl, "static int ctl_xsk_open(")
        self.assertIn("xdev_ext_mech_ctl_xsk_flags(copy_mode)", opened)
        self.assertIn("XDP_OPTIONS", opened)
        self.assertIn("xdev_ext_mech_ctl_xsk_mode_check", opened)
        rx = c_function(self.ctl, "static int cmd_nic_nvme(")
        self.assertIn("!o->copy_mode || o->drv_mode", rx)
        self.assertIn("case OPT_COPY: o->copy_mode = true; break;", self.ctl)

    def test_markers_come_from_the_core(self):
        # Core owns the common reports and transport counters. Socket RX uses
        # the same public markers with its START-loan ledger; NIC accounting
        # is an informational CLI line, rather than a PASS/FAIL verdict.
        literals = set(re.findall(r'"(XDEV_EXT_MECH_[A-Z_0-9]+)[=" ]', self.ctl))
        self.assertEqual(literals, {
            "XDEV_EXT_MECH_TRANSPORT", "XDEV_EXT_MECH_FINALIZE",
            "XDEV_EXT_MECH_READY", "XDEV_EXT_MECH_ATTACH",
            "XDEV_EXT_MECH_DETACH", "XDEV_EXT_MECH_RING_EXIT_CLOSE",
            "XDEV_EXT_MECH_NIC_ACCOUNTING", "XDEV_EXT_MECH_NIC_NVME_E2E",
            "XDEV_EXT_MECH_NIC_CE_NVME_E2E"})
        for report in ("nic_nvme", "fq_dup", "window_reject", "native_copy",
                       "group_timeout", "shared_umem", "prog_detach",
                       "ring_exit", "unbind", "nvme_nic", "ce_chain", "nic_ce_nvme"):
            self.assertIn(f"xdev_ext_mech_ctl_report_{report}(", self.ctl)
        self.assertIn("xdev_ext_mech_ctl_stats_line(", self.ctl)
        core = strip_comments((TOOLS / "xdev_ext_mech_ctl_core.h").read_text())
        counters = c_function(core,
            "static inline void xdev_ext_mech_ctl_print_transport_counters(")
        self.assertIn('"XDEV_EXT_MECH_TRANSPORT_COUNTERS ', counters)
        self.assertIn("xdev_ext_mech_ctl_print_transport_counters(session,&counters)",
                      self.ctl)
        socket = c_function(self.ctl, "static bool ctl_socket_rx_report(")
        for marker in ("NIC_NVME_E2E", "NIC_CE_NVME_E2E"):
            self.assertIn(f'"XDEV_EXT_MECH_{marker}=%s ', socket)
        self.assertIn("xdev_ext_mech_ctl_line(", socket)
        accounting = c_function(self.ctl, "static void ctl_print_nic_accounting(")
        self.assertIn('"XDEV_EXT_MECH_NIC_ACCOUNTING ', accounting)

    def test_quiet_wait(self):
        # The quiet receiver blocks SIGUSR1 before anything can signal it,
        # names its pid and eventfd before READY, then after READY takes one
        # sigtimedwait(), one eventfd read and one STATS; only a run that is
        # not done then falls back to the ordinary wait.
        self.assertIn("case OPT_QUIET_WAIT: o->quiet_wait = true; break;",
                      self.ctl)
        main = c_function(self.ctl, "int main(")
        self.assertIn('xdev_ext_mech_ctl_quiet_check(o.quiet_wait,', main)
        nic = c_function(self.ctl, "static int cmd_nic_nvme(")
        self.assertIn("xdev_ext_mech_ctl_quiet_check(o->quiet_wait, true, arms,", nic)
        order = [nic.index(step) for step in (
            "sigprocmask(SIG_BLOCK,", "ctl_create(",
            "xdev_ext_mech_ctl_quiet_line(", 'printf("XDEV_EXT_MECH_READY ',
            "ctl_quiet_wait(")]
        self.assertEqual(order, sorted(order))
        quiet = c_function(self.ctl, "static int ctl_quiet_wait(")
        for step, count in (("sigtimedwait(", 1), ("read(", 1),
                            ("ctl_stats(", 1), ("ctl_wait(", 1),
                            ("poll(", 0), ("usleep(", 0)):
            self.assertEqual(quiet.count(step), count, step)
        flat = " ".join(quiet.split())
        self.assertLess(flat.index("fallback = !xdev_ext_mech_ctl_quiet_done("),
                        flat.index("if (!fallback) return 0;"))
        self.assertLess(flat.index("if (!fallback) return 0;"),
                        flat.index("return ctl_wait("))

    def test_attach_order(self):
        body = c_function(self.ctl, "static int cmd_attach(")
        order = [body.index(step) for step in (
            "bpf_object__open_file(", "ctl_set_global(",
            "bpf_object__load(", "bpf_map__attach_struct_ops(",
            "bpf_link__pin(", "bpf_link__disconnect(",
            "bpf_link__destroy(")]
        self.assertEqual(order, sorted(order))
        sets = c_function(self.ctl, "static int ctl_set_global(")
        self.assertLess(sets.index("xdev_ext_mech_ctl_set_value("),
                        sets.index("bpf_map__set_initial_value("))

    def test_detach_unpins_after_detach(self):
        body = c_function(self.ctl, "static int ctl_detach_pin(")
        self.assertLess(body.index("bpf_link_detach("), body.index("unlink("))

    def test_create_before_the_fill_ring(self):
        # CREATE refuses a socket whose fill or RX ring is not empty.
        for cmd in ("cmd_nic_nvme", "ctl_run_source"):
            body = c_function(self.ctl, f"static int {cmd}(")
            create = body.index("ctl_create(")
            self.assertLess(create, body.index("ctl_fq_fill("), cmd)
        body = c_function(self.ctl, "static int cmd_nic_nvme(")
        self.assertLess(body.index("ctl_create("),
                        body.index("xdev_ext_xsk_redirect_attach("))
        self.assertLess(body.index("xdev_ext_xsk_redirect_attach("),
                        body.index('"XDEV_EXT_MECH_READY'))

    def test_source_windows_are_read_only(self):
        # A READ stage never needs to write its namespace.
        self.assertRegex(self.ctl, r"open\(o->src_ng, O_RDONLY")

    def test_makefile_contract(self):
        for var in ("BUILD_DIR", "VMLINUX_BTF", "CC", "CLANG", "BPFTOOL"):
            self.assertRegex(self.make, rf"(?m)^{var} \?=", var)
        self.assertRegex(self.make, r"(?m)^all: ")
        self.assertIn("btf dump file $(VMLINUX_BTF) format c", self.make)
        for name in PROGRAMS:
            self.assertIn(name.replace(".bpf.c", ""), self.make)
        self.assertIn("$(BUILD_DIR)/xdev_ext_mech_ctl", self.make)
        self.assertNotIn("-static", self.make)
        self.assertIn("../xdev_ext_xsk_redirect.c", self.make)


if __name__ == "__main__":
    unittest.main(verbosity=2)
