#!/usr/bin/env python3
"""Host contract tests of the DPDK net_af_xdp baseline; no DPDK, NIC or GPU.

Run with python3 tests/eval/dpdk_tb/test_contract.py -v.  The framing,
reassembly and argument handling run for real (test_wire.c); the build and
hugepage scripts run in their print-only modes; the program source is
checked for the defaults the evaluation policy requires.  No record of this
suite is performance data.
"""
import importlib.util
import json
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
CC = shutil.which(os.environ.get("CC", "cc"))
SPEC = importlib.util.spec_from_file_location("dpdk_tb_build", HERE / "build.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def strip_c_comments(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


class WireTest(unittest.TestCase):
    def test_wire_logic(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "test_wire"
            subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                            str(HERE / "test_wire.c"), "-o", str(binary)], check=True)
            out = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("dpdk_tb wire: PASS", out.stdout)


class BuildScriptTest(unittest.TestCase):
    def test_pinned_release(self):
        self.assertEqual(BUILD.DPDK_VERSION, "24.11.8")
        self.assertEqual(BUILD.DPDK_URL, "https://fast.dpdk.org/rel/dpdk-24.11.8.tar.xz")
        self.assertEqual(BUILD.DPDK_SHA256,
                         "f3dbfac841b2db8e53a97d68a5e14ebc943327a955f0afb97f8c14f544fbc4aa")

    def test_meson_builds_only_what_the_baseline_needs(self):
        opts = BUILD.meson_options()
        self.assertIn("-Denable_drivers=net/af_xdp,mempool/ring,bus/vdev", opts)
        self.assertIn("-Ddefault_library=static", opts)
        self.assertIn("-Dbuildtype=release", opts)
        # no machine-specific or tuning switches: the release's defaults apply
        for opt in opts:
            self.assertNotRegex(opt, r"cpu_instruction_set|max_lcores|c_args|platform")

    def test_vdev_is_the_documented_single_queue_form(self):
        self.assertEqual(BUILD.vdev_arg("thunderbolt0"),
                         "net_af_xdp0,iface=thunderbolt0,start_queue=0,queue_count=1")
        for word in ("force_copy", "busy_budget", "xdp_prog", "shared_umem"):
            self.assertNotIn(word, BUILD.vdev_arg("thunderbolt0"))
        with self.assertRaises(ValueError):
            BUILD.vdev_arg("eth0,force_copy=1")

    def test_devices_without_native_xdp_get_the_redirect_program(self):
        # libxdp turns "no mode flag" into native mode; a device without
        # ndo_bpf (thunderbolt-net) needs the PMD's xdp_prog path instead.
        self.assertEqual(
            BUILD.vdev_arg("thunderbolt0", xdp_prog="/opt/tb/tb_xsk_redirect.o"),
            "net_af_xdp0,iface=thunderbolt0,start_queue=0,queue_count=1,"
            "xdp_prog=/opt/tb/tb_xsk_redirect.o")
        for bad in ("relative.o", "/a,b.o", "/a b.o"):
            with self.assertRaises(ValueError):
                BUILD.vdev_arg("thunderbolt0", xdp_prog=bad)

    def test_plan_builds_the_redirect_program(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = subprocess.run([sys.executable, str(HERE / "build.py"), "--print-commands",
                                  "--build-dir", str(Path(tmp) / "b"), "--gpu", "none"],
                                 capture_output=True, text=True)
            plan = json.loads(out.stdout)
            bpf = [s for s in plan["steps"] if s["step"] == "bpf"]
            self.assertEqual(len(bpf), 1)
            argv = bpf[0]["argv"]
            self.assertIn("-target", argv)
            self.assertEqual(argv[argv.index("-target") + 1], "bpf")
            self.assertTrue(argv[-1].endswith("tb_xsk_redirect.o"))
            self.assertEqual(plan["xdp_prog"], argv[-1])

    def test_print_commands_is_side_effect_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "absent"
            out = subprocess.run([sys.executable, str(HERE / "build.py"), "--print-commands",
                                  "--build-dir", str(target), "--gpu", "cuda",
                                  "--cuda-root", "/usr/local/cuda"],
                                 capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            plan = json.loads(out.stdout)
            self.assertFalse(target.exists())
            self.assertEqual(plan["dpdk_version"], "24.11.8")
            steps = [s["step"] for s in plan["steps"]]
            self.assertEqual(steps, ["download", "verify", "extract", "meson", "ninja",
                                     "compile", "bpf"])
            last = plan["steps"][-1]
            last = plan["steps"][-2]
            compile_cmd = " ".join(last["argv"] + last["extra_libs"])
            self.assertIn("tb_gpu_cuda.c", compile_cmd)
            self.assertIn("-lcudart", compile_cmd)
            self.assertIn("--static", " ".join(plan["steps"][-2]["pkg_config"]))

    def test_host_stand_in_build_is_labelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = subprocess.run([sys.executable, str(HERE / "build.py"), "--print-commands",
                                  "--build-dir", str(Path(tmp) / "b"), "--gpu", "none"],
                                 capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            plan = json.loads(out.stdout)
            last = plan["steps"][-2]
            compile_cmd = " ".join(last["argv"] + last["extra_libs"])
            self.assertIn("tb_gpu_host.c", compile_cmd)
            self.assertNotIn("cudart", compile_cmd)

    def test_refuses_relative_or_repo_build_dir(self):
        for bad in ("relative/dir", str(HERE / "build")):
            out = subprocess.run([sys.executable, str(HERE / "build.py"), "--print-commands",
                                  "--build-dir", bad], capture_output=True, text=True)
            self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        out = subprocess.run([sys.executable, str(HERE / "build.py"), "--print-commands",
                              "--build-dir", "/tmp/x", "--gpu", "cuda"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 2, "--gpu cuda needs --cuda-root")


class HugepageScriptTest(unittest.TestCase):
    SCRIPT = HERE / "hugepages.sh"

    def run_script(self, *args):
        return subprocess.run(["bash", str(self.SCRIPT), *args], capture_output=True, text=True)

    def test_dry_run_prints_and_changes_nothing(self):
        out = self.run_script("--dry-run", "--pages", "512", "--mount", "/dev/hugepages-tb")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages",
                      out.stdout)
        self.assertIn("mount -t hugetlbfs -o pagesize=2M nodev /dev/hugepages-tb", out.stdout)
        self.assertFalse(Path("/dev/hugepages-tb").exists())

    def test_rejects_bad_arguments(self):
        for args in (("--pages", "lots"), ("--pages", "0"), ("--frobnicate",),
                     ("--mount", "relative")):
            out = self.run_script("--dry-run", *args)
            self.assertEqual(out.returncode, 2, (args, out.stdout, out.stderr))


class ProgramSourceTest(unittest.TestCase):
    def setUp(self):
        self.src = strip_c_comments((HERE / "dpdk_tb.c").read_text())
        self.cuda = strip_c_comments((HERE / "tb_gpu_cuda.c").read_text())
        self.host = strip_c_comments((HERE / "tb_gpu_host.c").read_text())

    def test_port_uses_pmd_defaults(self):
        # zero descriptors means the PMD's default ring size
        self.assertRegex(self.src, r"rte_eth_rx_queue_setup\([^;]*,\s*0\s*,")
        self.assertRegex(self.src, r"rte_eth_tx_queue_setup\([^;]*,\s*0\s*,")
        self.assertRegex(self.src, r"struct rte_eth_conf\s+conf\s*=\s*\{\s*0\s*\}")
        for tuned in ("rxmode.mtu", "rte_eth_dev_set_mtu", "offloads", "rss_conf"):
            self.assertNotIn(tuned, self.src)
        self.assertIn("RTE_MBUF_DEFAULT_BUF_SIZE", self.src)

    def test_receive_and_send_cross_gpu_memory(self):
        self.assertIn("tb_gpu_h2d", self.src)
        self.assertIn("tb_gpu_d2h", self.src)
        self.assertIn("tb_host_register", self.src)
        self.assertIn("cudaMemcpyAsync", self.cuda)
        self.assertIn("cudaHostRegister", self.cuda)
        self.assertIn("cudaStreamSynchronize", self.cuda)
        self.assertNotIn("cuda", self.host.replace("tb_gpu", ""))

    def test_records_say_what_ran(self):
        for key in ('"dpdk_version"', '"vdev"', '"xdp_attach_mode"', '"xsk_zerocopy"',
                    '"mtu"', '"frames_per_msg"', '"gpu"', '"verified_messages"'):
            # keys sit inside C string literals, so their quotes are escaped
            self.assertIn(key.replace('"', '\\"'), self.src)

    def test_host_stand_in_is_not_a_gpu(self):
        self.assertIn("correctness only", self.host)


class VmCheckScriptTest(unittest.TestCase):
    SCRIPT = HERE / "vm_check.sh"

    def test_parses_and_needs_its_inputs(self):
        self.assertEqual(subprocess.run(["bash", "-n", str(self.SCRIPT)]).returncode, 0)
        out = subprocess.run(["bash", str(self.SCRIPT)], capture_output=True, text=True)
        self.assertEqual(out.returncode, 2)
        out = subprocess.run(["bash", str(self.SCRIPT), "--work", "rel", "--bin", "/bin/true"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 2)

    def test_guest_uses_the_same_vdev_form_and_verifies_everything(self):
        text = self.SCRIPT.read_text()
        self.assertIn("--vdev net_af_xdp0,iface=\\$3,start_queue=0,queue_count=1", text)
        self.assertIn("--verify all", text)
        self.assertIn("correctness only", text)


class RedirectProgramTest(unittest.TestCase):
    SRC = HERE / "tb_xsk_redirect.bpf.c"

    def test_same_behaviour_as_the_libxdp_default(self):
        # libxdp v1.6.2 lib/libxdp/xsk_def_xdp_prog.c: XSKMAP of 64 queue ids,
        # redirect by rx_queue_index, XDP_PASS when no socket is bound.
        text = strip_c_comments(self.SRC.read_text())
        self.assertIn("BPF_MAP_TYPE_XSKMAP", text)
        self.assertRegex(text, r"max_entries,\s*64")
        self.assertRegex(text, r"\}\s*xsks_map\s+SEC\(\"\.maps\"\)")
        self.assertIn('SEC("xdp")', text)
        self.assertIn("bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS)", text)
        self.assertIn('SEC("license")', text)

    @unittest.skipUnless(shutil.which("clang") and Path("/usr/include/bpf/bpf_helpers.h").exists(),
                         "needs clang and libbpf headers")
    def test_compiles_to_an_xdp_object_with_the_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj = Path(tmp) / "p.o"
            subprocess.run(BUILD.bpf_command(self.SRC, obj), check=True)
            dump = subprocess.run(["llvm-objdump", "-h", "-t", str(obj)], capture_output=True,
                                  text=True, check=True).stdout
            self.assertRegex(dump, r"\sxdp\s")
            self.assertIn(".maps", dump)
            self.assertIn("xsks_map", dump)


if __name__ == "__main__":
    unittest.main()
