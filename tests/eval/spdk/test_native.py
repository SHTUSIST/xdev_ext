#!/usr/bin/env python3
"""Native SPDK arm: source, ownership, build and admission checks on a host.

No test here reaches a device, downloads SPDK or measures anything.  The
official-header syntax check runs only when SPDK_INCLUDE_DIR names the
include/ directory of an official SPDK checkout at the pinned release.
Run: python3 tests/eval/spdk/test_native.py -v
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SOURCE = HERE / "bench_nvme_pipeline.c"
CC = shlex.split(os.environ.get("CC", "cc"))


def load(name):
    spec = importlib.util.spec_from_file_location("spdk_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_block():
    text = SOURCE.read_text()
    match = re.search(r"^#ifdef XDEV_EXT_SPDK_NATIVE\n(.*?)^#endif /\* XDEV_EXT_SPDK_NATIVE \*/",
                      text, re.S | re.M)
    return match.group(1) if match else ""


def function_body(text, name):
    match = re.search(r"^[a-z].*\b%s\([^;{]*\)\n\{\n(.*?)^\}" % re.escape(name), text, re.S | re.M)
    return match.group(1) if match else ""


class NativeSource(unittest.TestCase):
    def setUp(self):
        self.native = native_block()
        self.assertTrue(self.native, "feature absent: no XDEV_EXT_SPDK_NATIVE body")

    def test_official_headers_only(self):
        for header in ("spdk/env.h", "spdk/nvme.h", "spdk/stdinc.h"):
            self.assertIn('#include "%s"' % header, self.native)
        # No invented declarations or compatibility structures.
        self.assertNotRegex(self.native, r"struct spdk_[a-z_]+\s*\{")
        self.assertNotRegex(self.native, r"^(?:extern\s+)?\w[\w\s\*]*\bspdk_\w+\([^)]*\);", )

    def test_actual_workload_calls(self):
        for call in ("spdk_env_opts_init", "spdk_env_init", "spdk_pci_addr_parse",
                     "spdk_nvme_trid_populate_transport", "spdk_nvme_ctrlr_get_default_ctrlr_opts",
                     "spdk_nvme_connect", "spdk_nvme_ctrlr_get_ns", "spdk_nvme_ns_is_active",
                     "spdk_nvme_ns_get_csi", "spdk_nvme_ns_get_sector_size",
                     "spdk_nvme_ns_get_extended_sector_size", "spdk_nvme_ns_get_md_size",
                     "spdk_nvme_ns_get_pi_type", "spdk_nvme_ns_get_num_sectors",
                     "spdk_nvme_ns_get_max_io_xfer_size", "spdk_nvme_ctrlr_alloc_io_qpair",
                     "spdk_zmalloc", "spdk_nvme_ns_cmd_read", "spdk_nvme_qpair_process_completions",
                     "spdk_nvme_qpair_get_failure_reason", "spdk_nvme_ctrlr_is_failed",
                     "spdk_nvme_ctrlr_cmd_abort_ext", "spdk_nvme_ctrlr_process_admin_completions",
                     "spdk_nvme_ctrlr_free_io_qpair", "spdk_free", "spdk_nvme_detach",
                     "spdk_env_fini"):
            with self.subTest(call=call):
                self.assertIn(call + "(", self.native)

    def test_exact_target_and_private_environment(self):
        self.assertNotIn("spdk_nvme_probe(", self.native, "no discovery across controllers")
        self.assertRegex(self.native, r"\.opts_size = sizeof")
        self.assertLess(self.native.index(".opts_size = sizeof"),
                        self.native.index("spdk_env_opts_init("),
                        "opts_size must be set before spdk_env_opts_init() reads it")
        self.assertIn(".shm_id = -1", self.native)
        self.assertIn(".num_pci_addr = 1", self.native)
        self.assertIn(".pci_allowed = ", self.native)
        self.assertIn("transport_retry_count = 0", self.native)
        self.assertIn("SPDK_NVME_TRANSPORT_PCIE", self.native)

    def test_one_dma_allocation_and_one_owner(self):
        self.assertEqual(self.native.count("spdk_zmalloc("), 1)
        self.assertEqual(self.native.count("spdk_nvme_ns_cmd_read("), 1)
        self.assertIn('#include "spdk_owner.h"', SOURCE.read_text())
        self.assertNotIn("pthread_cancel", SOURCE.read_text())
        self.assertNotRegex(SOURCE.read_text(), r"\bvolatile\b")

    def test_quarantine_never_releases_unknown(self):
        body = function_body(self.native, "native_quarantine")
        self.assertTrue(body, "feature absent: native_quarantine()")
        self.assertIn("sp_can_release", body)
        release = body.split("sp_can_release", 1)[0]
        for call in ("spdk_free", "spdk_nvme_ctrlr_free_io_qpair", "spdk_nvme_detach",
                     "spdk_env_fini", "exit(", "return"):
            self.assertNotIn(call, release, "released before quiescence: " + call)

    def test_no_oracle_inside_timing(self):
        body = function_body(self.native, "native_run")
        self.assertTrue(body, "feature absent: native_run()")
        start = body.index("t0 = now_ns()")
        end = body.index("t1 = now_ns()")
        timed = body[start:end]
        for forbidden in ("memcmp", "guards_ok", "sha256", "reference"):
            self.assertNotIn(forbidden, timed)


class Owner(unittest.TestCase):
    def test_state_machine(self):
        with tempfile.TemporaryDirectory(prefix=".spdk-owner-", dir=HERE) as tmp:
            binary = Path(tmp) / "test_owner"
            built = subprocess.run([*CC, "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
                                    str(HERE / "test_owner.c"), "-o", str(binary)],
                                   capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertRegex(run.stdout, r"^PASS (\d+)/\1 owner checks$")


@unittest.skipUnless(os.environ.get("SPDK_INCLUDE_DIR"),
                     "SPDK_INCLUDE_DIR (official include/ at the pinned release) not given")
class OfficialHeaders(unittest.TestCase):
    def test_native_body_parses_against_official_headers(self):
        include = Path(os.environ["SPDK_INCLUDE_DIR"])
        self.assertTrue((include / "spdk/nvme.h").is_file())
        result = subprocess.run([*CC, "-std=gnu11", "-fsyntax-only", "-Wall", "-Wextra", "-Werror",
                                 "-DXDEV_EXT_SPDK_NATIVE", "-I" + str(include), str(SOURCE)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class Build(unittest.TestCase):
    def setUp(self):
        self.build = load("build")

    def test_pinned_official_release(self):
        self.assertEqual(self.build.SPDK_URL, "https://github.com/spdk/spdk")
        self.assertEqual(self.build.SPDK_TAG, "v25.05.1")
        self.assertEqual(self.build.SPDK_COMMIT, "44b23be7c35469bc0aba4b942c08c935125e2315")
        self.assertEqual(self.build.SPDK_SUBMODULES, ("dpdk", "isa-l", "isa-l-crypto"))

    def test_fetch_and_configure_commands(self):
        src = Path("/private/build/spdk")
        clone = self.build.clone_command(src)
        self.assertEqual(clone[:2], ["git", "clone"])
        for arg in ("--depth", "1", "--branch", "v25.05.1", "https://github.com/spdk/spdk"):
            self.assertIn(arg, clone)
        self.assertEqual(clone[-1], str(src))
        sub = self.build.submodule_command(src)
        self.assertEqual(sub[:4], ["git", "-C", str(src), "submodule"])
        self.assertEqual(sub[-3:], ["dpdk", "isa-l", "isa-l-crypto"])
        configure = self.build.configure_command(src)
        self.assertEqual(configure[0], str(src / "configure"))
        for flag in ("--disable-tests", "--disable-unit-tests", "--disable-examples",
                     "--disable-apps", "--without-shared", "--without-nvme-cuse", "--without-fuse"):
            self.assertIn(flag, configure)
        everything = " ".join(clone + sub + configure + self.build.make_command(src, 4))
        for forbidden in ("pkgdep", "setup.sh", "sudo", "install"):
            self.assertNotIn(forbidden, everything)

    def test_link_command_follows_official_pkg_config_recipe(self):
        root = Path("/private/build/spdk")
        command = self.build.native_command(["cc"], root, Path("/out/bin"),
                                            "-lspdk_nvme -lspdk_env_dpdk -lrte_eal",
                                            "-lnuma -luuid")
        text = " ".join(command)
        self.assertIn("-DXDEV_EXT_SPDK_NATIVE", command)
        self.assertIn("-I" + str(root / "include"), command)
        self.assertRegex(text, r"-Wl,--whole-archive -Wl,-Bstatic -lspdk_nvme -lspdk_env_dpdk "
                               r"-lrte_eal -Wl,-Bdynamic -Wl,--no-whole-archive -lnuma -luuid")
        self.assertIn("-pthread", command)

    def run_build(self, *args, env=None):
        return subprocess.run([sys.executable, str(HERE / "build.py"), *args],
                              capture_output=True, text=True, env=env, timeout=60)

    def test_build_dir_inside_repository_refused(self):
        target = HERE / ".spdk-build-must-not-exist"
        p = self.run_build("--fetch-sdk", "--build-dir", str(target))
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertFalse(target.exists())
        self.assertEqual(p.stdout, "")

    def test_shared_or_relative_build_dir_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp) / "shared"
            shared.mkdir(mode=0o755)
            shared.chmod(0o755)
            p = self.run_build("--fetch-sdk", "--build-dir", str(shared))
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertEqual(list(shared.iterdir()), [])
        p = self.run_build("--fetch-sdk", "--build-dir", "relative/dir")
        self.assertEqual(p.returncode, 2, p.stderr)

    def test_missing_tools_refused_before_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "bin"
            empty.mkdir()
            target = Path(tmp) / "private"
            env = dict(os.environ, PATH=str(empty))
            p = self.run_build("--fetch-sdk", "--build-dir", str(target), env=env)
            self.assertEqual(p.returncode, 4, p.stderr)
            self.assertRegex(p.stderr, r"git|make|pkg-config")
            self.assertFalse(target.exists())

    def test_sdk_without_headers_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self.run_build("--output", str(Path(tmp) / "bin"), "--spdk-root", tmp)
            self.assertEqual(p.returncode, 4, p.stderr)
            self.assertIn("include/spdk/env.h", p.stderr)
            self.assertFalse((Path(tmp) / "bin").exists())

    @unittest.skipUnless(os.environ.get("SPDK_INCLUDE_DIR"),
                         "SPDK_INCLUDE_DIR (official include/ at the pinned release) not given")
    def test_official_checkout_without_build_refused(self):
        # The supplied official tree may already be built. Isolate a headers-only
        # view so this refusal test does not depend on external build progress.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "headers-only"
            root.mkdir()
            (root / "include").symlink_to(Path(os.environ["SPDK_INCLUDE_DIR"]))
            p = self.run_build("--output", str(Path(tmp) / "bin"), "--spdk-root", str(root))
            self.assertEqual(p.returncode, 4, p.stderr)
            self.assertIn("pkg-config", p.stderr)
            self.assertFalse((Path(tmp) / "bin").exists())

    def test_print_commands_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "private"
            p = self.run_build("--print-commands", "--build-dir", str(target))
            self.assertEqual(p.returncode, 0, p.stderr)
            plan = json.loads(p.stdout)
            self.assertEqual(plan["spdk_tag"], "v25.05.1")
            self.assertEqual(plan["spdk_commit"], "44b23be7c35469bc0aba4b942c08c935125e2315")
            self.assertFalse(target.exists())

    def test_first_fetch_supplies_configure_dependencies_and_records_their_heads(self):
        # Model only the external build tools. The real CLI must fetch every
        # configure dependency even with --without-crypto, then read each HEAD
        # for its receipt. No network, SDK build or device is involved.
        pins = {"dpdk": "cf36799c473a686fa14fde9af97f917a2125d3d5",
                "isa-l": "6f420b14a1e3e091bc9d15f508a54f82c007483c",
                "isa-l-crypto": "9b7a2b842c9f4e54b8dc1c82899e5a5520c53301"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tools = root / "tools"
            tools.mkdir()
            log = root / "argv.jsonl"
            tool = tools / "tool"
            tool.write_text("#!" + sys.executable + "\n" + r'''
import json
import os
from pathlib import Path
import sys

name, args = Path(sys.argv[0]).name, sys.argv[1:]
pins = json.loads(os.environ["SDK_TEST_PINS"])
with open(os.environ["SDK_TEST_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\n")
if name == "git":
    if args[0] == "clone":
        src = Path(args[-1])
        (src / "include/spdk").mkdir(parents=True)
        for header in ("env.h", "nvme.h", "stdinc.h"):
            (src / "include/spdk" / header).touch()
        (src / "configure").symlink_to(Path(__file__).resolve())
    elif args[0] == "-C":
        src = Path(args[1])
        if args[2:] == ["rev-parse", "HEAD"]:
            if not src.is_dir():
                sys.exit(1)
            print(pins.get(src.name, "44b23be7c35469bc0aba4b942c08c935125e2315"))
        elif args[2:7] == ["submodule", "update", "--init", "--depth", "1"]:
            for module in args[7:]:
                (src / module).mkdir(exist_ok=True)
                (src / module / ".git").touch()
        else:
            sys.exit(1)
    else:
        sys.exit(1)
elif name == "configure":
    for module in pins:
        if not (Path.cwd() / module).is_dir():
            sys.exit("configure requires " + module + " even with --without-crypto")
    pc = Path.cwd() / "build/lib/pkgconfig/spdk_nvme.pc"
    pc.parent.mkdir(parents=True)
    pc.touch()
elif name == "cc":
    Path(args[args.index("-o") + 1]).write_bytes(b"native link contract")
elif name not in ("make", "pkg-config"):
    sys.exit(1)
''')
            tool.chmod(0o700)
            for name in ("git", "make", "pkg-config", "cc"):
                (tools / name).symlink_to(tool)
            env = dict(os.environ, PATH=str(tools), CC="cc", SDK_TEST_LOG=str(log),
                       SDK_TEST_PINS=json.dumps(pins))
            target = root / "sdk"
            p = self.run_build("--fetch-sdk", "--build-dir", str(target), env=env)
            self.assertEqual(p.returncode, 0, p.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertIn(["git", "-C", str(target / "spdk"), "submodule", "update",
                           "--init", "--depth", "1", *pins], calls)
            receipt = json.loads(p.stdout)
            self.assertEqual(receipt.get("spdk_submodules"), pins)
            for module in pins:
                self.assertIn(["git", "-C", str(target / "spdk" / module),
                               "rev-parse", "HEAD"], calls)
            # An externally built tree may lack a module checkout. Git would
            # then walk up to the parent SPDK repository: do not mislabel it.
            (target / "spdk/isa-l/.git").unlink()
            p = self.run_build("--spdk-root", str(target / "spdk"),
                               "--output", str(root / "relinked"), env=env)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout)["spdk_submodules"], dict(pins, **{"isa-l": None}))

    def test_offline_fixture_still_builds(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self.run_build("--output", str(Path(tmp) / "offline"))
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue((Path(tmp) / "offline").is_file())


class Admission(unittest.TestCase):
    """native_prerequisites() against a fabricated sysfs/procfs tree."""

    def setUp(self):
        self.run = load("run")
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sys, self.proc, self.dev = (self.root / x for x in ("sys", "proc", "dev"))
        self.bdf = "0000:01:00.0"
        self.fn = self.sys / "bus/pci/devices" / self.bdf
        self.fn.mkdir(parents=True)
        (self.fn / "class").write_text("0x010802\n")
        drivers = self.sys / "bus/pci/drivers"
        for name in ("nvme", "vfio-pci"):
            (drivers / name).mkdir(parents=True)
        groups = self.sys / "kernel/iommu_groups/7"
        groups.mkdir(parents=True)
        (self.fn / "iommu_group").symlink_to(groups)
        (self.dev / "vfio").mkdir(parents=True)
        (self.dev / "vfio/7").write_text("")
        pages = self.sys / "kernel/mm/hugepages/hugepages-2048kB"
        pages.mkdir(parents=True)
        (pages / "free_hugepages").write_text("512\n")
        self.proc.mkdir()
        (self.proc / "mounts").write_text("hugetlbfs /dev/hugepages hugetlbfs rw 0 0\n")

    def tearDown(self):
        self.tmp.cleanup()

    def bind(self, driver):
        link = self.fn / "driver"
        if link.is_symlink():
            link.unlink()
        if driver:
            link.symlink_to(self.sys / "bus/pci/drivers" / driver)

    def check(self, bdf=None):
        return self.run.native_prerequisites(bdf or self.bdf, sysfs=self.sys, proc=self.proc,
                                             dev=self.dev)

    def test_userspace_bound_nvme_with_hugepages_admitted(self):
        self.bind("vfio-pci")
        self.assertIsNone(self.check())

    def test_absent_function_refused(self):
        self.bind("vfio-pci")
        self.assertRegex(self.check("0000:02:00.0"), "not present")

    def test_kernel_bound_or_unbound_refused_without_rebinding(self):
        for driver in ("nvme", None):
            with self.subTest(driver=driver):
                self.bind(driver)
                self.assertRegex(self.check(), "userspace driver")
                self.assertEqual((self.fn / "driver").is_symlink(), driver is not None)

    def test_not_nvme_class_refused(self):
        self.bind("vfio-pci")
        (self.fn / "class").write_text("0x020000\n")
        self.assertRegex(self.check(), "not an NVMe")

    def test_no_free_hugepages_refused(self):
        self.bind("vfio-pci")
        (self.sys / "kernel/mm/hugepages/hugepages-2048kB/free_hugepages").write_text("0\n")
        self.assertRegex(self.check(), "hugepage")

    def test_no_hugetlbfs_mount_refused(self):
        self.bind("vfio-pci")
        (self.proc / "mounts").write_text("proc /proc proc rw 0 0\n")
        self.assertRegex(self.check(), "hugetlbfs")

    def test_missing_vfio_group_refused(self):
        self.bind("vfio-pci")
        (self.dev / "vfio/7").unlink()
        self.assertRegex(self.check(), "vfio")


class NativeRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix=".spdk-native-", dir=HERE)
        self.root = Path(self.tmp.name)
        self.reference = self.root / "reference.bin"
        self.reference.write_bytes(bytes(16384))
        self.capture = self.root / "capture.bin"
        self.args = ["--traddr", "0000:01:00.0", "--nsid", "7", "--sector-size", "512",
                     "--namespace-lbas", "4096", "--start-lba", "101", "--window-lbas", "32",
                     "--block-bytes", "1024", "--reference", str(self.reference),
                     "--capture", str(self.capture), "--ack-isolated-read-only"]

    def tearDown(self):
        self.tmp.cleanup()

    def invoke(self, *extra):
        return subprocess.run([sys.executable, str(HERE / "run.py"), "--mode", "native-correctness",
                               *self.args, *extra], capture_output=True, text=True, timeout=30)

    def test_headers_without_built_libraries_refused(self):
        sdk = self.root / "sdk"
        (sdk / "include/spdk").mkdir(parents=True)
        p = self.invoke("--spdk-root", str(sdk))
        self.assertEqual(p.returncode, 4, p.stderr)
        self.assertEqual(p.stdout, "")
        self.assertFalse(self.capture.exists())

    def test_host_fixture_binary_refuses_native_modes(self):
        binary = self.root / "pipeline"
        built = subprocess.run([sys.executable, str(HERE / "build.py"), "--output", str(binary)],
                               capture_output=True, text=True)
        self.assertEqual(built.returncode, 0, built.stderr)
        fd = os.open(self.reference, os.O_RDONLY)
        try:
            fields = ["native-correctness", "0000:01:00.0", "7", "512", "4096", "101", "32",
                      "1024", "8", "2", "0", "1000", str(fd), str(self.capture), "1048576",
                      "1048576", "", "0" * 64]
            p = subprocess.run([str(binary), *fields], capture_output=True, text=True,
                               pass_fds=(fd,), timeout=20)
        finally:
            os.close(fd)
        self.assertEqual(p.returncode, 4, p.stderr)
        self.assertEqual(p.stdout, "")
        self.assertRegex(p.stderr, "XDEV_EXT_SPDK_NATIVE")
        self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
