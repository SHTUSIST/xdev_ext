#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the actual nv-xdev_ext-ce-backend.c against host stubs (G1, G2, G3, G12).

The production file is copied byte for byte into a private build directory and
compiled with ordinary user-space stubs for kernel services and the
RM/nv-p2p boundary.  Four builds cover the two completion variants (event,
NV_XDEV_EXT_CE_POLL_COMPLETION) and the two address variants (DMA-API IOVA,
NV_XDEV_EXT_CE_PHYS_ADDR).  No GPU, IOMMU, pin, MMIO or transfer exists here;
cases check correctness, teardown and error paths only.
"""
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex  # noqa: E402

BACKEND = "kernel-open/nvidia/nv-xdev_ext-ce-backend.c"
NVP2P_H = "kernel-open/nvidia/nv-p2p.h"
MECH_H = ex.REPO / "kernel/include/linux/xdev_ext_mech.h"
FIXTURE = ex.HERE / "nv_xdev_ext_ce_backend_harness.c"
STUB_HEADERS = ("os-interface.h", "nv-linux.h", "nv-lock.h", "nv-p2p.h")
LINUX_STUBS = ("xdev_ext_mech.h", "hrtimer.h", "dma-mapping.h", "scatterlist.h",
               "spinlock.h", "workqueue.h", "atomic.h", "timer.h", "slab.h", "mm.h",
               "jiffies.h", "mutex.h", "kernel.h", "module.h",
               "bug.h", "minmax.h", "ktime.h", "iommu.h", "device.h", "sched.h",
               "compiler.h", "wait.h", "interrupt.h", "bitops.h", "string.h",
               "overflow.h", "rcupdate.h", "list.h", "vmalloc.h", "gfp.h",
               "printk.h", "export.h", "irqflags.h", "preempt.h", "smp.h", "delay.h",
               "dma-direction.h", "llist.h", "completion.h", "lockdep.h")
VARIANTS = {
    "event+iova": (),
    "poll+iova": ("NV_XDEV_EXT_CE_POLL_COMPLETION",),
    "event+phys": ("NV_XDEV_EXT_CE_PHYS_ADDR",),
    "poll+phys": ("NV_XDEV_EXT_CE_POLL_COMPLETION", "NV_XDEV_EXT_CE_PHYS_ADDR"),
}


def contract_switches():
    header = ex.read(NVP2P_H)
    event = 1 if re.search(r"\bnv_p2p_ce_event_fn\b", header) else 0
    unbind = 1 if re.search(r"NV_STATUS\s+NV_API_CALL\s+nv_p2p_vidmem_unbind\s*\(",
                            header) else 0
    return event, unbind


def types_header():
    text = MECH_H.read_text()
    parts = ["/* Generated from kernel/include/linux/xdev_ext_mech.h, exact bytes. */",
             "struct xdev_ext_ce_cookie;",
             "enum xdev_ext_mech_dir { XDEV_EXT_MECH_DIR_TO_DEVICE = 1,"
             " XDEV_EXT_MECH_DIR_FROM_DEVICE = 2 };",
             "enum xdev_ext_ce_outcome { XDEV_EXT_CE_OK = 0,"
             " XDEV_EXT_CE_PRE_SUBMIT_FAILED = 1, XDEV_EXT_CE_AMBIGUOUS = 2 };",
             "#define XDEV_EXT_CE_F_COMPLETION_POINT (1U << 0)",
             "#define XDEV_EXT_CE_F_BARRIER (1U << 1)"]
    for name in ("xdev_ext_ce_region", "xdev_ext_ce_xfer", "xdev_ext_ce_backend_ops"):
        parts.append(ex.struct(text, name))
    return "\n".join(parts) + "\n"


class BackendHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ex.Build(".ce-backend-harness-")
        source = ex.read(BACKEND)
        cls.build.write("nv-xdev_ext-ce-backend-actual.c", source)
        for name in STUB_HEADERS:
            cls.build.write(name, "/* provided by the host harness */\n")
        for name in LINUX_STUBS:
            cls.build.write("linux/" + name, "/* provided by the host harness */\n")
        cls.build.write("nv_xdev_ext_ce_backend_types.h", types_header())
        event, unbind = contract_switches()
        xfer = ex.struct(MECH_H.read_text(), "xdev_ext_ce_xfer")
        owners = int(bool(re.search(r"\bowner\b", xfer) and re.search(r"\bgeneration\b", xfer)))
        print(f"actual {BACKEND} sha256={ex.sha(source)} event_api={event} "
              f"unbind_status={unbind}")
        cls.binaries = {}
        cls.compile_errors = {}
        for cc in ex.compilers():
            for variant, defines in VARIANTS.items():
                out = f"backend-{Path(cc).name}-{variant.replace('+', '-')}"
                result, command = cls.build.compile(
                    FIXTURE, out,
                    defines=("XDEV_EXT_ENABLE_GPU_CE_DMA", "CONFIG_XDEV_EXT_MECH_CE",
                             f"HARNESS_EVENT_API={event}",
                             f"HARNESS_OWNER_API={owners}",
                             f"HARNESS_UNBIND_STATUS={unbind}") + defines,
                    extra=("-I", str(ex.GPU / "kernel-open/nvidia")),
                    compiler=cc, threads=True)
                key = (Path(cc).name, variant)
                if result.returncode:
                    cls.compile_errors[key] = " ".join(command) + "\n" + result.stderr[:3000]
                else:
                    cls.binaries[key] = out

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def run_cases(self, cases, variants=VARIANTS):
        for cc in ex.compilers():
            for variant in variants:
                key = (Path(cc).name, variant)
                with self.subTest(compiler=key[0], variant=variant):
                    if key in self.compile_errors:
                        self.fail("harness did not compile:\n" + self.compile_errors[key])
                    for case in cases:
                        with self.subTest(case=case):
                            result = self.build.run(self.binaries[key], case, timeout=120)
                            self.assertEqual(
                                result.returncode, 0,
                                f"{variant} {case}\n{result.stdout[-3000:]}\n"
                                f"{result.stderr[-3000:]}")

    # G1 + exactly-once in both completion variants
    def test_g1_completion_exactly_once(self):
        self.run_cases(("complete-once", "complete-partial", "token-zero",
                        "ambiguous-submit", "pre-submit-failure", "timeout"))

    def test_g1_event_raised_before_submit_returns(self):
        self.run_cases(("complete-in-submit",), ("event+iova", "event+phys"))

    def test_g1_g3_late_duplicate_and_impossible_events(self):
        self.run_cases(("event-regress", "event-impossible"), ("event+iova", "event+phys"))

    def test_g1_bounded_race_submit_versus_completion(self):
        self.run_cases(("race",))

    # G2 DMA-API mapping, IOVA selection, unmap ordering
    def test_g2_bind_maps_once_and_passes_iovas(self):
        self.run_cases(("bind-unbind-clean", "iova-bind", "iova-segments"))

    def test_g2_mapping_failures_unwind(self):
        self.run_cases(("iova-map-fail", "iova-rm-bind-fail"), ("event+iova", "poll+iova"))

    def test_g2_phys_variant_keeps_identity_gate(self):
        self.run_cases(("phys-identity",), ("event+phys", "poll+phys"))

    def test_g2_g3_unmap_after_last_gpu_reference(self):
        self.run_cases(("unbind-pending", "unbind-order", "unbind-rm-fail"))

    # Window/cookie identity only; these are NOT per-frame generation tests.
    def test_window_and_cookie_conflicts_rejected_before_submission(self):
        self.run_cases(("owner-mismatch", "owner-busy"))

    def test_g3_per_frame_owner_generation_and_ticket(self):
        self.run_cases(("frame-owner-reject", "frame-generation-reject",
                        "frame-generation-late", "frame-ticket-duplicate"))

    def test_g3_dma_sync_before_device_read_and_cpu_publish(self):
        self.run_cases(("sync",), ("event+iova", "poll+iova"))

    # G12 composed at the backend: failed window unbind keeps the owner
    def test_g12_failed_window_unbind_retains_owner(self):
        self.run_cases(("region-unbind-fail",))


if __name__ == "__main__":
    unittest.main(verbosity=2)
