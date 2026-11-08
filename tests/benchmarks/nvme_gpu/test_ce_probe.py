#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host regressions for the real CUDA-VMM -> CE acceptance probe.

Requirement: PASS requires every frame of the one group published (two for
the small cases, 32 for the 2 MiB large cases), exactly one completed command
per active stage, no residual/error counters, a drained STOP_REPORT, and exact
host/GPU contents including guards. A simulator can never establish this PASS.
The large cases report how many physically adjacent runs their host frames
form, counted from /proc/self/pagemap entries.

These tests call production decision helpers with hand-authored observations;
they do not emulate DMA or infer device correctness from a host-only run.
Validation helpers use the C convention: zero accepts, nonzero rejects.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

for _parent in Path(__file__).resolve().parents:
    if (_parent / "tools/layout.py").is_file():
        sys.path.insert(0, str(_parent / "tools"))
        break
else:
    raise RuntimeError("owned project layout is unavailable")
from layout import canonical_root, materialize_view

ROOT = canonical_root(Path(__file__))
HERE = ROOT / "tests/benchmarks/nvme_gpu"
SESSION = 0x123456789ABCDEF
ACTIVE, STOPPED = 1, 4

FIXTURE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/xdev_ext_policy.h>
#include "ce_vmm_probe_check.h"

#define SESSION UINT64_C(0x123456789abcdef)

static const struct xdev_ext_mech_stats one_stage = {
    .session_id = SESSION, .batches_done = 1, .published = 2,
    .submitted = {1, 0, 0, 0}, .completed = {1, 0, 0, 0},
    .state = XDEV_EXT_MECH_SESSION_ACTIVE,
};
static const struct xdev_ext_mech_stats two_stages = {
    .session_id = SESSION, .batches_done = 1, .published = 2,
    .submitted = {1, 1, 0, 0}, .completed = {1, 1, 0, 0},
    .state = XDEV_EXT_MECH_SESSION_ACTIVE,
};

/* Two payloads with different contents and surrounding poison/guard bytes.
 * Different total lengths catch accidentally using one buffer's size twice. */
static const unsigned char host_expected[32] = {
    0xa1,0xa1,0xa1,0xa1, 0x10,0x11,0x12,0x13,
    0x14,0x15,0x16,0x17, 0xa2,0xa2,0xa2,0xa2,
    0xb1,0xb1,0xb1,0xb1, 0x20,0x21,0x22,0x23,
    0x24,0x25,0x26,0x27, 0xb2,0xb2,0xb2,0xb2,
};
static const unsigned char gpu_expected[40] = {
    0xc1,0xc1,0xc1,0xc1, 0xc1,0xc1,0xc1,0xc1,
    0x30,0x31,0x32,0x33, 0x34,0x35,0x36,0x37,
    0xc2,0xc2,0xc2,0xc2, 0xc2,0xc2,0xc2,0xc2,
    0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47,
    0xd1,0xd1,0xd1,0xd1, 0xd1,0xd1,0xd1,0xd1,
};

static int change_stats(struct xdev_ext_mech_stats *s, const char *field,
                        uint64_t value, unsigned index)
{
#define CHANGE(name) if (!strcmp(field, #name)) { s->name = value; return 1; }
    CHANGE(session_id)
    CHANGE(batches_done)
    CHANGE(batches_abort)
    CHANGE(rejects)
    CHANGE(recycled)
    CHANGE(held)
    CHANGE(sequestered)
    CHANGE(timeouts)
    CHANGE(inflight)
    CHANGE(native_publish)
    CHANGE(protocol_err)
    CHANGE(published)
    CHANGE(last_err)
    CHANGE(state)
#undef CHANGE
    if (!strcmp(field, "submitted")) {
        if (index >= XDEV_EXT_MECH_MAX_STAGES) return 0;
        s->submitted[index] = value;
        return 1;
    }
    if (!strcmp(field, "completed")) {
        if (index >= XDEV_EXT_MECH_MAX_STAGES) return 0;
        s->completed[index] = value;
        return 1;
    }
    return !strcmp(field, "none");
}

static int memory_case(const char *mutation, unsigned index)
{
    unsigned char host[sizeof(host_expected)], gpu[sizeof(gpu_expected)];
    const unsigned char *hp = host, *gp = gpu;
    const unsigned char *he = host_expected, *ge = gpu_expected;
    size_t hn = sizeof(host), gn = sizeof(gpu);

    memcpy(host, host_expected, sizeof(host));
    memcpy(gpu, gpu_expected, sizeof(gpu));
    if (!strcmp(mutation, "host")) {
        if (index >= sizeof(host)) return 97;
        host[index] ^= 0x80;
    } else if (!strcmp(mutation, "gpu")) {
        if (index >= sizeof(gpu)) return 97;
        gpu[index] ^= 0x80;
    } else if (!strcmp(mutation, "noop-host")) {
        memset(host + 4, 0xee, 8);
        memset(host + 20, 0xee, 8);
    } else if (!strcmp(mutation, "noop-gpu")) {
        memset(gpu + 8, 0xee, 8);
        memset(gpu + 24, 0xee, 8);
    } else if (!strcmp(mutation, "swap-host-frames")) {
        memcpy(host + 4, host_expected + 20, 8);
        memcpy(host + 20, host_expected + 4, 8);
    } else if (!strcmp(mutation, "swap-gpu-frames")) {
        memcpy(gpu + 8, gpu_expected + 24, 8);
        memcpy(gpu + 24, gpu_expected + 8, 8);
    } else if (!strcmp(mutation, "null-host")) hp = NULL;
    else if (!strcmp(mutation, "null-host-expected")) he = NULL;
    else if (!strcmp(mutation, "null-gpu")) gp = NULL;
    else if (!strcmp(mutation, "null-gpu-expected")) ge = NULL;
    else if (!strcmp(mutation, "zero-host")) hn = 0;
    else if (!strcmp(mutation, "zero-gpu")) gn = 0;
    else if (strcmp(mutation, "none")) return 97;
    printf("%d\n", cvp_check_memory(hp, he, hn, gp, ge, gn));
    return 0;
}

static int runs_case(int argc, char **argv)
{
    uint64_t entry[64];
    int i;

    if (argc - 2 > 64) return 97;
    for (i = 2; i < argc; i++)
        entry[i - 2] = strtoull(argv[i], NULL, 0);
    printf("%u\n", cvp_phys_runs(argc > 2 ? entry : NULL, (size_t)(argc - 2)));
    return 0;
}

int main(int argc, char **argv)
{
    struct xdev_ext_mech_stats s;
    struct xdev_ext_mech_stop_report report;
    uint64_t session = SESSION, value;
    unsigned stages, index, frames;
    uint32_t state;
    const char *field;

    if (argc == 4 && !strcmp(argv[1], "memory"))
        return memory_case(argv[2], (unsigned)strtoul(argv[3], NULL, 0));
    if (argc >= 2 && !strcmp(argv[1], "runs"))
        return runs_case(argc, argv);
    if (argc != 7 && argc != 8) return 97;
    stages = (unsigned)strtoul(argv[2], NULL, 0);
    field = argv[3];
    value = strtoull(argv[4], NULL, 0);
    index = (unsigned)strtoul(argv[5], NULL, 0);
    state = (uint32_t)strtoul(argv[6], NULL, 0);
    frames = argc == 8 ? (unsigned)strtoul(argv[7], NULL, 0) : 2;
    s = stages == 1 ? one_stage : two_stages;
    s.state = state;
    s.published = frames;

    if (!strcmp(argv[1], "stats")) {
        if (!strcmp(field, "expected-session")) session = value;
        else if (!change_stats(&s, field, value, index)) return 97;
        printf("%d\n", cvp_check_stats(&s, session, stages, state, frames));
        return 0;
    }
    if (strcmp(argv[1], "stop")) return 97;
    memset(&report, 0, sizeof(report));
    report.size = sizeof(report);
    report.version = XDEV_EXT_MECH_STOP_REPORT_VERSION;
    report.session_id = SESSION;
    s.state = XDEV_EXT_MECH_SESSION_STOPPED;
    report.stats = s;
    if (!strcmp(field, "report-size")) report.size = value;
    else if (!strcmp(field, "report-size-short")) report.size--;
    else if (!strcmp(field, "report-size-long")) report.size++;
    else if (!strcmp(field, "report-version")) report.version = value;
    else if (!strcmp(field, "report-session")) report.session_id = value;
    else if (!strcmp(field, "expected-session")) session = value;
    else if (!change_stats(&report.stats, field, value, index)) return 97;
    printf("%d\n", cvp_check_stop(&report, session, stages, frames));
    return 0;
}
'''


def compile_c(source, output, *extra):
    result = subprocess.run(
        ["gcc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
         str(source), *map(str, extra), "-o", str(output)],
        capture_output=True, text=True, timeout=30)
    return None if result.returncode == 0 else result.stdout + result.stderr


class DecisionChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="ce-probe-check-", dir=build)
        cls.addClassCleanup(cls.temp.cleanup)
        work = Path(cls.temp.name)
        cls.binary = work / "check"
        header = HERE / "ce_vmm_probe_check.h"
        cls.build_failure = None
        if not header.is_file():
            cls.build_failure = (
                "feature missing: ce_vmm_probe_check.h must expose the real "
                "stats, full-memory and STOP_REPORT acceptance checks")
            return
        source = work / "fixture.c"
        source.write_text(FIXTURE)
        cls.build_failure = compile_c(
            source, cls.binary, "-I", ROOT / "src/core/include/uapi",
            "-I", HERE, "-fsanitize=undefined",
            "-fno-sanitize-recover=undefined")

    def setUp(self):
        if (self.build_failure and
                self._testMethodName != "test_acceptance_checks_are_available_and_compile"):
            self.skipTest("acceptance helper unavailable; see compile regression")

    def test_acceptance_checks_are_available_and_compile(self):
        self.assertIsNone(self.build_failure, self.build_failure)

    def decision(self, mode, stages=2, field="none", value=0, index=0,
                 state=ACTIVE, frames=None):
        if self.build_failure:
            self.skipTest("acceptance helper unavailable; see compile regression")
        command = ([str(self.binary), "memory", field, str(index)] if mode == "memory"
                   else [str(self.binary), mode, str(stages), field, str(value),
                         str(index), str(state)] +
                   ([] if frames is None else [str(frames)]))
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0,
                         "host fixture crashed or rejected its input: " + result.stderr)
        self.assertRegex(result.stdout, r"^-?\d+\n$")
        return int(result.stdout)

    def test_valid_one_and_two_stage_observations_are_accepted(self):
        for stages in (1, 2):
            for state in (ACTIVE, STOPPED):
                with self.subTest(stages=stages, state=state):
                    self.assertEqual(self.decision("stats", stages, state=state), 0)

    def test_stats_requires_nonzero_matching_session(self):
        for field, value in (("session_id", 0), ("session_id", SESSION + 1),
                             ("expected-session", 0), ("expected-session", SESSION + 1)):
            with self.subTest(field=field, value=value):
                self.assertNotEqual(self.decision("stats", field=field, value=value), 0)

    def test_stats_rejects_missing_and_extra_work(self):
        for stages in (1, 2):
            for field, values in (("batches_done", (0, 2)), ("published", (0, 1, 3))):
                for value in values:
                    with self.subTest(stages=stages, field=field, value=value):
                        self.assertNotEqual(self.decision("stats", stages, field, value), 0)
            for index in range(4):
                for field in ("submitted", "completed"):
                    for value in ((0, 2) if index < stages else (1,)):
                        with self.subTest(stages=stages, field=field, index=index, value=value):
                            self.assertNotEqual(
                                self.decision("stats", stages, field, value, index), 0)

    def test_stats_rejects_every_error_or_retained_work_counter(self):
        for field in ("batches_abort", "rejects", "recycled", "held", "sequestered",
                      "timeouts", "inflight", "native_publish", "protocol_err", "last_err"):
            for stages in (1, 2):
                with self.subTest(stages=stages, field=field):
                    self.assertNotEqual(self.decision("stats", stages, field, 1), 0)
        self.assertNotEqual(self.decision("stats", field="last_err", value=-5), 0)

    def test_stats_rejects_wrong_state_and_unsupported_stage_count(self):
        for expected in (ACTIVE, STOPPED):
            for actual in (0, 1, 2, 3, 4, 5, 99):
                if actual == expected:
                    continue
                with self.subTest(expected=expected, actual=actual):
                    self.assertNotEqual(
                        self.decision("stats", field="state", value=actual, state=expected), 0)
        for stages in (0, 3, 4, 4294967295):
            with self.subTest(stages=stages):
                self.assertNotEqual(self.decision("stats", stages), 0)
        for state in (0, 2, 3, 5, 99):
            with self.subTest(requested_state=state):
                self.assertNotEqual(self.decision("stats", state=state), 0)

    def test_large_group_requires_every_frame_published(self):
        for stages in (1, 2):
            for state in (ACTIVE, STOPPED):
                with self.subTest(stages=stages, state=state):
                    self.assertEqual(self.decision("stats", stages, state=state, frames=32), 0)
            with self.subTest(stages=stages, report="stop"):
                self.assertEqual(self.decision("stop", stages, frames=32), 0)
            for value in (0, 2, 31, 33):
                with self.subTest(stages=stages, published=value):
                    self.assertNotEqual(
                        self.decision("stats", stages, "published", value, frames=32), 0)
                    self.assertNotEqual(
                        self.decision("stop", stages, "published", value, frames=32), 0)

    def test_frame_count_must_fit_one_group(self):
        for frames in (0, 33):
            with self.subTest(frames=frames):
                self.assertNotEqual(self.decision("stats", frames=frames), 0)
                self.assertNotEqual(self.decision("stop", frames=frames), 0)

    def runs(self, *entries):
        if self.build_failure:
            self.skipTest("acceptance helper unavailable; see compile regression")
        result = subprocess.run([str(self.binary), "runs", *map(hex, entries)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"^\d+\n$")
        return int(result.stdout)

    def test_phys_runs_counts_breaks_between_adjacent_frames(self):
        present = 1 << 63
        def page(pfn, flags=0):
            return present | flags | pfn
        self.assertEqual(self.runs(page(0x100)), 1)
        self.assertEqual(self.runs(*[page(0x200 + i) for i in range(32)]), 1)
        self.assertEqual(self.runs(page(0x100), page(0x101), page(0x400), page(0x401)), 2)
        # Descending or repeated frames are not adjacent.
        self.assertEqual(self.runs(page(0x101), page(0x100)), 2)
        self.assertEqual(self.runs(page(0x100), page(0x100)), 2)
        self.assertEqual(self.runs(*[page(0x1000 + 2 * i) for i in range(8)]), 8)
        # Soft-dirty, exclusive and file/shared flag bits are not frame bits.
        self.assertEqual(self.runs(page(0x100, 1 << 55), page(0x101, 1 << 56),
                                   page(0x102, 1 << 61)), 1)

    def test_phys_runs_unknown_when_a_page_is_absent_or_its_frame_hidden(self):
        present = 1 << 63
        self.assertEqual(self.runs(), 0)
        self.assertEqual(self.runs(present | 0x100, 0x101), 0)
        self.assertEqual(self.runs(present | 0x100, present), 0)

    def test_memory_accepts_exact_bytes_for_both_buffers(self):
        self.assertEqual(self.decision("memory"), 0)

    def test_memory_rejects_each_payload_and_guard_byte_corruption(self):
        for field, length in (("host", 32), ("gpu", 40)):
            for index in range(length):
                with self.subTest(buffer=field, byte=index):
                    self.assertNotEqual(self.decision("memory", field=field, index=index), 0)

    def test_memory_rejects_noop_poison_and_wrong_frame_destinations(self):
        for field in ("noop-host", "noop-gpu", "swap-host-frames", "swap-gpu-frames"):
            with self.subTest(mutation=field):
                self.assertNotEqual(self.decision("memory", field=field), 0)

    def test_memory_rejects_missing_and_empty_buffers(self):
        for field in ("null-host", "null-host-expected", "null-gpu", "null-gpu-expected",
                      "zero-host", "zero-gpu"):
            with self.subTest(mutation=field):
                self.assertNotEqual(self.decision("memory", field=field), 0)

    def test_stop_accepts_drained_final_report(self):
        for stages in (1, 2):
            with self.subTest(stages=stages):
                self.assertEqual(self.decision("stop", stages), 0)

    def test_stop_requires_compatible_envelope_and_matching_session(self):
        for field, value in (
                ("report-size", 0), ("report-size-short", 0), ("report-size-long", 0),
                ("report-version", 0), ("report-version", 2),
                ("report-session", 0), ("report-session", SESSION + 1),
                ("expected-session", 0), ("expected-session", SESSION + 1),
                ("session_id", 0), ("session_id", SESSION + 1)):
            with self.subTest(field=field, value=value):
                self.assertNotEqual(self.decision("stop", field=field, value=value), 0)

    def test_stop_rechecks_terminal_stats_and_all_stage_counters(self):
        mutations = [(field, 1, 0) for field in
                     ("batches_abort", "rejects", "recycled", "held", "sequestered",
                      "timeouts", "inflight", "native_publish", "protocol_err", "last_err")]
        mutations += [("batches_done", 0, 0), ("batches_done", 2, 0),
                      ("published", 0, 0), ("published", 1, 0), ("published", 3, 0)]
        mutations += [("state", state, 0) for state in (0, 1, 2, 3, 5, 99)]
        for stages in (1, 2):
            cases = mutations + [
                (field, value, index)
                for index in range(4) for field in ("submitted", "completed")
                for value in ((0, 2) if index < stages else (1,))]
            for field, value, index in cases:
                with self.subTest(stages=stages, field=field, value=value, index=index):
                    self.assertNotEqual(self.decision("stop", stages, field, value, index), 0)
        for stages in (0, 3, 4, 4294967295):
            with self.subTest(stages=stages):
                self.assertNotEqual(self.decision("stop", stages), 0)


class RealProbeCommandLine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="ce-probe-cli-", dir=build)
        cls.addClassCleanup(cls.temp.cleanup)
        work = Path(cls.temp.name)
        # Includes remain exactly those of the full production binary.
        view = materialize_view(ROOT, work / "view")
        cls.binary = work / "ce-vmm-probe"
        cls.build_failure = compile_c(
            view.root / "tests/eval/nvme_gpu/ce_vmm_probe.c", cls.binary,
            view.root / "kernel/tools/xdev_ext_gpu_identity.c", "-ldl")

    def run_probe(self, *args):
        self.assertIsNone(self.build_failure, "actual full probe build failed: " + str(self.build_failure))
        return subprocess.run([str(self.binary), *args], capture_output=True,
                              text=True, timeout=10)

    def test_help_succeeds_without_gpu_or_kernel_setup(self):
        result = self.run_probe("--help")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for option in ("--case", "--ce-dev", "--timeout-ms", "--kprobe-profile",
                       "large-huge", "large-4k"):
            self.assertIn(option, result.stdout + result.stderr)

    def test_unknown_case_is_rejected_as_usage_error(self):
        result = self.run_probe("--case", "bogus")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotRegex(result.stdout + result.stderr, r"\bPASS\b")

    def test_simulator_cannot_satisfy_real_vmm_acceptance(self):
        for case in ("multi", "large-huge", "large-4k"):
            with self.subTest(case=case):
                result = self.run_probe("--ce-dev", "/dev/xdev_ext_ce_sim", "--case", case)
                self.assertIn(result.returncode, (2, 4), result.stdout + result.stderr)
                self.assertNotRegex(result.stdout + result.stderr, r"\bPASS\b")

# These wrappers decide whether the caller may explicitly release CUDA objects.
# Only the kernel control boundary is replaced; the actual wrappers execute.
CONTROL_FIXTURE = r'''
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/xdev_ext_policy.h>
#include "ce_vmm_probe_check.h"
#define CVP_FRAMES 2U
#define SESSION UINT64_C(0x123456789abcdef)
struct es_run { int ring, efd; __u64 session; };
static const char *scenario;
static unsigned creates, stops, notifies, bad_calls, stats_prints;
static struct xdev_ext_mech_stats observed;
static void es_print_stats(const struct xdev_ext_mech_stats *s)
{ observed = *s; stats_prints++; }
static int xdev_ext_mech_ctl_notify_request(struct xdev_ext_mech_notify_arm *arm,
                                           __u64 session, __u64 groups)
{
    *arm = (struct xdev_ext_mech_notify_arm){
        .session_id = session, .batches_target = groups};
    return 0;
}
static int es_mech(int ring, __u32 op, __u64 arg)
{
    if (ring != 17) bad_calls++;
    if (op == XDEV_EXT_MECH_OP_CREATE_REPORT) {
        struct xdev_ext_mech_create_with_report *q = (void *)(uintptr_t)arg;
        creates++;
        if (!strcmp(scenario, "create-undelivered")) return -EFAULT;
        q->size = sizeof(*q); q->version = XDEV_EXT_MECH_CREATE_REPORT_VERSION;
        q->create.session_id = SESSION;
        q->report = (struct xdev_ext_mech_create_report){
            .size = sizeof(q->report), .version = XDEV_EXT_MECH_CREATE_REPORT_VERSION,
            .result = 0, .cleanup = XDEV_EXT_MECH_CREATE_CLEANUP_NONE,
            .session_id = SESSION};
        if (!strcmp(scenario, "create-retained")) {
            q->create.session_id = q->report.session_id = 0;
            q->report.result = -EBUSY; q->report.rollback_errno = -ETIMEDOUT;
            q->report.cleanup = XDEV_EXT_MECH_CREATE_CLEANUP_RETAINED;
        } else if (!strcmp(scenario, "create-bad-outer-size")) q->size--;
        else if (!strcmp(scenario, "create-bad-outer-version")) q->version++;
        else if (!strcmp(scenario, "create-bad-report-size")) q->report.size--;
        else if (!strcmp(scenario, "create-bad-report-version")) q->report.version++;
        else if (!strcmp(scenario, "create-session-mismatch")) q->report.session_id++;
        else if (!strcmp(scenario, "create-session-zero")) q->create.session_id = q->report.session_id = 0;
        return !strcmp(scenario, "create-error-with-valid-report") ? -EFAULT : 0;
    }
    if (op == XDEV_EXT_MECH_OP_NOTIFY_ARM) {
        const struct xdev_ext_mech_notify_arm *a = (void *)(uintptr_t)arg;
        notifies++;
        if (a->session_id != SESSION || a->batches_target != 1) bad_calls++;
        return 0;
    }
    if (op == XDEV_EXT_MECH_OP_STOP_REPORT) {
        struct xdev_ext_mech_stop_report *q = (void *)(uintptr_t)arg;
        stops++;
        if (!strcmp(scenario, "stop-undelivered")) return -EFAULT;
        *q = (struct xdev_ext_mech_stop_report){
            .size = sizeof(*q), .version = XDEV_EXT_MECH_STOP_REPORT_VERSION,
            .session_id = SESSION, .stats = {
                .session_id = SESSION, .batches_done = 1, .published = 2,
                .submitted = {1, 1, 0, 0}, .completed = {1, 1, 0, 0},
                .state = XDEV_EXT_MECH_SESSION_STOPPED}};
        if (!strcmp(scenario, "stop-bad-size")) q->size--;
        else if (!strcmp(scenario, "stop-bad-version")) q->version++;
        else if (!strcmp(scenario, "stop-session-mismatch")) q->session_id++;
        else if (!strcmp(scenario, "stop-stats-session-mismatch")) q->stats.session_id++;
        else if (!strcmp(scenario, "stop-active")) q->stats.state = XDEV_EXT_MECH_SESSION_ACTIVE;
        else if (!strcmp(scenario, "stop-inflight")) q->stats.inflight = 1;
        else if (!strcmp(scenario, "stop-sequestered")) q->stats.sequestered = 1;
        else if (!strcmp(scenario, "stop-zero-completed")) q->stats.completed[1] = 0;
        else if (!strcmp(scenario, "stop-extra-completed")) q->stats.completed[1] = 2;
        else if (!strcmp(scenario, "stop-extra-batch")) q->stats.batches_done = 2;
        else if (!strcmp(scenario, "stop-one-published")) q->stats.published = 1;
        return !strcmp(scenario, "stop-error-with-valid-report") ? -EFAULT : 0;
    }
    bad_calls++;
    return -EINVAL;
}
'''
CONTROL_MAIN = r'''
int main(int argc, char **argv)
{
    struct es_run r = {.ring = 17, .efd = 18};
    struct xdev_ext_mech_create c = {.abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2};
    bool released;
    int rc;
    if (argc != 2 && argc != 3) return 97;
    scenario = argv[1];
    if (!strncmp(scenario, "create-", 7)) {
        released = true;
        rc = cvp_create(&r, &c, &released);
    } else {
        released = false; r.session = SESSION;
        rc = cvp_stop(&r, 2, CVP_FRAMES, argc == 2 || atoi(argv[2]) != 0, &released);
    }
    printf("{\"rc\":%d,\"released\":%d,\"session\":%llu,"
           "\"creates\":%u,\"stops\":%u,\"notifies\":%u,\"bad_calls\":%u,"
           "\"stats_prints\":%u,\"observed_done\":%llu,\"observed_published\":%llu,"
           "\"observed_completed\":%llu,\"observed_state\":%u}\n",
           rc, released, (unsigned long long)r.session, creates, stops, notifies, bad_calls,
           stats_prints, (unsigned long long)observed.batches_done,
           (unsigned long long)observed.published, (unsigned long long)observed.completed[1],
           observed.state);
    return 0;
}
'''


class ControlUncertainty(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "tests/support/benchmarks"))
        from ce_vmm_contract import function
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="ce-probe-control-", dir=build)
        cls.addClassCleanup(cls.temp.cleanup)
        work = Path(cls.temp.name)
        # Extraction compiles unchanged production bytes without replacing their decisions.
        actual = (HERE / "ce_vmm_probe.c").read_text()
        source = work / "control.c"
        source.write_text(CONTROL_FIXTURE + "\n" + function(actual, "cvp_create") +
                          "\n" + function(actual, "cvp_stop") + "\n" + CONTROL_MAIN)
        cls.binary = work / "control"
        cls.build_failure = compile_c(source, cls.binary, "-I", ROOT / "src/core/include/uapi",
                                      "-I", HERE, "-fno-diagnostics-show-caret",
                                      "-fsanitize=undefined", "-fno-sanitize-recover=undefined")

    def control(self, scenario, complete=True):
        import json
        self.assertIsNone(self.build_failure, self.build_failure)
        result = subprocess.run([str(self.binary), scenario, str(int(complete))],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        outcome = json.loads(result.stdout.splitlines()[-1])
        self.assertEqual(outcome["bad_calls"], 0, outcome)
        self.assertEqual((outcome["creates"], outcome["stops"]),
                         (1, 0) if scenario.startswith("create-") else (0, 1), outcome)
        return outcome

    def test_create_accepts_session_then_arms_notification_once(self):
        result = self.control("create-ok")
        self.assertEqual((result["rc"], result["released"], result["session"], result["notifies"]),
                         (0, 0, SESSION, 1), result)

    def test_create_uncertainty_never_accepts_session_or_authorizes_cuda_cleanup(self):
        for scenario in ("create-undelivered", "create-error-with-valid-report",
                         "create-retained", "create-bad-outer-size",
                         "create-bad-outer-version", "create-bad-report-size",
                         "create-bad-report-version", "create-session-mismatch", "create-session-zero"):
            with self.subTest(scenario=scenario):
                result = self.control(scenario)
                self.assertNotEqual(result["rc"], 0, result)
                self.assertEqual((result["released"], result["session"], result["notifies"]), (0, 0, 0), result)

    def test_stop_requires_delivered_valid_report_and_no_live_work_for_cleanup(self):
        for complete in (False, True):
            for scenario in ("stop-undelivered", "stop-error-with-valid-report", "stop-bad-size",
                             "stop-bad-version", "stop-session-mismatch", "stop-stats-session-mismatch",
                             "stop-active", "stop-inflight", "stop-sequestered"):
                with self.subTest(scenario=scenario, complete=complete):
                    result = self.control(scenario, complete)
                    self.assertNotEqual(result["rc"], 0, result)
                    self.assertEqual((result["released"], result["notifies"]), (0, 0), result)

    def test_stop_retains_exact_terminal_observation_and_authorizes_cleanup(self):
        result = self.control("stop-ok")
        self.assertEqual((result["rc"], result["released"], result["notifies"]), (0, 1, 0), result)
        self.assertEqual((result["stats_prints"], result["observed_done"], result["observed_published"],
                          result["observed_completed"], result["observed_state"]), (1, 1, 2, 1, STOPPED), result)

    def test_successful_stop_syscall_with_wrong_counts_cannot_pass_acceptance(self):
        for scenario in ("stop-zero-completed", "stop-extra-completed", "stop-extra-batch", "stop-one-published"):
            with self.subTest(scenario=scenario):
                result = self.control(scenario)
                self.assertNotEqual(result["rc"], 0, result)


# Exit 4 means the environment cannot run the probe. Once CREATE has accepted a
# session the device path is the thing under test, so any later error must be a
# failure that no SKIP-tolerant harness can file as unsupported.
EXIT_FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
enum { XG_EXIT_PASS = 0, XG_EXIT_FAIL = 1, XG_EXIT_USAGE = 2, XG_EXIT_UNAVAILABLE = 4 };
'''
EXIT_MAIN = r'''
int main(int argc, char **argv)
{
    if (argc != 3) return 97;
    printf("%d\n", cvp_exit_code(atoi(argv[1]), atoi(argv[2]) != 0));
    return 0;
}
'''
CAPABILITY_ERRNOS = {"ENODEV": 19, "ENOENT": 2, "ENOSYS": 38, "EOPNOTSUPP": 95,
                     "EPERM": 1, "EACCES": 13}


class ExitClassification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "tests/support/benchmarks"))
        from ce_vmm_contract import function
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="ce-probe-exit-", dir=build)
        cls.addClassCleanup(cls.temp.cleanup)
        work = Path(cls.temp.name)
        actual = (HERE / "ce_vmm_probe.c").read_text()
        source = work / "exit.c"
        try:
            source.write_text(EXIT_FIXTURE + function(actual, "cvp_capability") + "\n" +
                              function(actual, "cvp_exit_code") + "\n" + EXIT_MAIN)
        except AssertionError as error:
            cls.build_failure = str(error)
            return
        cls.binary = work / "exit"
        cls.build_failure = compile_c(source, cls.binary)

    def code(self, ret, created):
        self.assertIsNone(self.build_failure, self.build_failure)
        result = subprocess.run([str(self.binary), str(ret), str(int(created))],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return int(result.stdout)

    def test_capability_errors_before_create_are_unavailable(self):
        for name, value in CAPABILITY_ERRNOS.items():
            with self.subTest(errno=name):
                self.assertEqual(self.code(-value, False), 4)
        self.assertEqual(self.code(-5, False), 1)  # EIO

    def test_any_error_after_create_is_failure_not_unavailable(self):
        for name, value in {**CAPABILITY_ERRNOS, "EIO": 5, "ETIMEDOUT": 110,
                            "ESHUTDOWN": 108, "EPROTO": 71}.items():
            with self.subTest(errno=name):
                self.assertEqual(self.code(-value, True), 1)

    def test_exit_codes_pass_through(self):
        for created in (False, True):
            for value in (0, 1, 2, 4):
                with self.subTest(created=created, value=value):
                    self.assertEqual(self.code(value, created), value)


# large-4k turns transparent huge pages off for its pool.  A kernel built
# without them rejects MADV_NOHUGEPAGE with EINVAL; that pool is already made
# of 4 KiB pages, so only other errors may stop the case.
THP_FIXTURE = r'''
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MADV_NOHUGEPAGE 15
static int madvise_result, madvise_errno, madvise_calls, madvise_advice;
static size_t madvise_len;
static int madvise(void *p, size_t n, int advice)
{
    (void)p;
    madvise_calls++;
    madvise_len = n;
    madvise_advice = advice;
    errno = madvise_errno;
    return madvise_result;
}
'''
THP_MAIN = r'''
int main(int argc, char **argv)
{
    char page[8192];
    int ret;
    if (argc != 3) return 97;
    madvise_result = atoi(argv[1]);
    madvise_errno = atoi(argv[2]);
    ret = cvp_no_thp(page, sizeof(page));
    printf("%d %d %zu %d\n", ret, madvise_calls, madvise_len, madvise_advice);
    return 0;
}
'''


class TransparentHugePagesOff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "tests/support/benchmarks"))
        from ce_vmm_contract import function
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="ce-probe-thp-", dir=build)
        cls.addClassCleanup(cls.temp.cleanup)
        work = Path(cls.temp.name)
        actual = (HERE / "ce_vmm_probe.c").read_text()
        source = work / "thp.c"
        try:
            source.write_text(THP_FIXTURE + function(actual, "cvp_no_thp") + "\n" + THP_MAIN)
        except AssertionError as error:
            cls.build_failure = str(error)
            return
        cls.binary = work / "thp"
        cls.build_failure = compile_c(source, cls.binary)

    def outcome(self, result, error):
        self.assertIsNone(self.build_failure, self.build_failure)
        run = subprocess.run([str(self.binary), str(result), str(error)],
                             capture_output=True, text=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stderr)
        ret, calls, length, advice = map(int, run.stdout.split())
        self.assertEqual((calls, length, advice), (1, 8192, 15))
        return ret

    def test_success_and_kernel_without_thp_continue(self):
        self.assertEqual(self.outcome(0, 0), 0)
        self.assertEqual(self.outcome(-1, 22), 0)  # EINVAL

    def test_other_errors_stop_the_case(self):
        for error in (12, 1, 14):  # ENOMEM, EPERM, EFAULT
            with self.subTest(errno=error):
                self.assertEqual(self.outcome(-1, error), -error)


if __name__ == "__main__":
    unittest.main()
