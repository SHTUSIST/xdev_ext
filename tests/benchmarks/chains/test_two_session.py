#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual untimed coordinator/main, with syscall/device boundary fixtures.

No benchmark, GPU, storage or network is run. This is not a kernel custody
proof: actual shared-life two-session cases still need the existing guest.
Missing actual coordinator is an explicit feature RED, never a compile error.
"""
from pathlib import Path
import re
import sys
import unittest

for _parent in Path(__file__).resolve().parents:
    if (_parent / "tools/layout.py").is_file():
        sys.path.insert(0, str(_parent / "tools"))
        break
else:
    raise RuntimeError("owned project layout is unavailable")
from layout import canonical_root
ROOT = canonical_root(Path(__file__))
HERE = ROOT / "tests/benchmarks/chains"
sys.path.insert(0, str(ROOT / "tests/support/benchmarks"))
from ce_vmm_contract import COMMON, Compiled, braced, structure


def function(source, name, optional=False):
    """Preserve actual bytes, including existing split return-type lines."""
    match = re.search(r"(?m)^(?:static\s+)?(?:inline\s+)?[\w *]+\s*\b" +
                      re.escape(name) + r"\s*\([^;{}]*\)\s*\{", source)
    if match is None:
        if optional:
            return ""
        raise AssertionError("missing actual function " + name)
    return source[match.start():braced(source, source.index("{", match.start()))]


def base():
    spec = (HERE / "chain_spec.h").read_text()
    ctl = (ROOT / "src/cli/xdev_ext_mech_ctl_core.h").read_text()
    bench = (HERE / "chain_bench.h").read_text()
    session = (HERE / "chain_session.c").read_text()
    text = COMMON.replace("#define XDEV_EXT_MECH_MAX_FRAMES 32U", "")
    text += r'''
#include <limits.h>
#include <stdarg.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
'''
    for header in ("io_uring.h", "xdev_ext_mech.h", "xdev_ext_policy.h"):
        text += '#include "' + str(ROOT / "src/core/include/uapi/linux" / header) + '"\n'
    for name in ("xdev_ext_mech_ctl_hex", "xdev_ext_mech_ctl_parse_mac",
                 "xdev_ext_mech_ctl_parse_u64", "xdev_ext_mech_ctl_parse_set"):
        text += function(ctl, name) + "\n"
    pure = spec[:spec.index("/* --- validation")]
    pure = pure.replace('#include "chain_json.h"', '#include "' + str(HERE / "chain_json.h") + '"')
    pure = pure.replace('#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"', "")
    text += pure + "\n#endif\n"
    check = (HERE / "chain_check.h").read_text()
    text += re.search(r"(?m)^#define\s+CHAIN_MAX_COPY_SOURCES[^\n]*", check).group() + "\n"
    for path, names in (
        (ROOT / "tests/support/benchmarks/cpu_timer.h", ("cpu_timer_row", "cpu_timer")),
        (HERE / "chain_timing.h", ("chain_sustained",)),
        (HERE / "chain_bench.h", ("chain_result",)),
    ):
        source = path.read_text()
        for name in names:
            text += structure(source, name) + "\n"
    text += re.search(r"enum\s*\{\s*CB_PASS[^;]+;", bench).group() + "\n"
    text += function((HERE / "chain_bench.c").read_text(), "cb_fail") + "\n"
    return text, session, ctl


def actual_helpers(text, source, ctl):
    cuda = (ROOT / "src/cli/xdev_ext_mech_cuda.h").read_text()
    for name in ("xdev_ext_mech_cuda_mem_prop", "xdev_ext_mech_cuda_access", "xdev_ext_mech_cuda"):
        text += structure(cuda, name) + "\n"
    text += "#define XDEV_EXT_GPU_PCI_BDF_SIZE 32\n"
    text += structure(source, "cs_ce") + "\n" + structure(source, "cs_plans") + "\n"
    spec = (HERE / "chain_spec.h").read_text()
    core = (ROOT / "src/core/io_uring/xdev_ext_mech_core.h").read_text()
    notify = (ROOT / "src/core/io_uring/xdev_ext_mech_notify.h").read_text()
    text += "#define check_add_overflow __builtin_add_overflow\n"
    text += function(core, "xdev_ext_mech_layout_frames") + "\n"
    text += function(core, "xdev_ext_mech_layout_span") + "\n"
    text += structure(spec, "chain_iou_plan") + "\n"
    for name in ("chain_iou_layout", "chain_nvme_window_ok", "chain_stage_uapi"):
        text += function(spec, name) + "\n"
    text += function(notify, "xdev_ext_mech_notify_validate") + "\n"
    for name in ("xdev_ext_mech_ctl_notify_request", "xdev_ext_mech_ctl_notify_result",
                 "xdev_ext_mech_ctl_errname"):
        text += function(ctl, name) + "\n"
    text += '#include "' + str(HERE / "chain_oracle.h") + '"\n'
    text += "#define CS_PRISTINE 0xa6\n"
    return text


def coordinator(frames_per_group=1):
    text, source, ctl = base()
    actual = function(source, "chain_run_two_session_correctness", optional=True)
    if not actual:
        return None
    text = actual_helpers(text, source, ctl)
    assert frames_per_group in (1, 2)
    text += f"#define FIXTURE_FRAMES_PER_GROUP {frames_per_group}U\n"
    text += "#define FIXTURE_GROUP_BYTES (FIXTURE_FRAMES_PER_GROUP * 4096U)\n"
    # Extend only the boundary fixture. Keep production coordinator bytes intact.
    # Its transport entry points call this forward declaration, while the old
    # fixture body is the passthrough implementation used by the fault wrapper.
    fixture = (HERE / "two_session_boundary_fixture.c.in").read_text()
    # Parameterize fixture geometry only: each group occupies one or two
    # contiguous 4 KiB frames. CE reverses group slots, preserving frame order
    # inside each group. Exact source matches make boundary-fixture drift fail.
    for old, replacement in (
        ("reference[6*4096]", "reference[6*FIXTURE_GROUP_BYTES]"),
        ("e->create.layout.group_bytes!=4096", "e->create.layout.group_bytes!=FIXTURE_GROUP_BYTES"),
        ("e->create.st[0].arg1!=48", "e->create.st[0].arg1!=6*FIXTURE_GROUP_BYTES/512"),
        ("e->create.st[0].arg1!=depth*4096", "e->create.st[0].arg1!=depth*FIXTURE_GROUP_BYTES"),
        ("st->nr_user_frames!=st->nr_batches", "st->nr_user_frames!=st->nr_batches*FIXTURE_FRAMES_PER_GROUP"),
        ("reference+(s->first-1+k)*4096", "reference+(s->first-1)*FIXTURE_GROUP_BYTES+k*4096"),
        ("gpu+(s->q-1-k)*4096", "gpu+(s->q-1-k/FIXTURE_FRAMES_PER_GROUP)*FIXTURE_GROUP_BYTES+(k%FIXTURE_FRAMES_PER_GROUP)*4096"),
        ("gpu[(s->q-1)*4096+1023]", "gpu[(s->q-1)*FIXTURE_GROUP_BYTES+1023]"),
        ("memcpy(gpu+(s->q-1)*4096,reference+5*4096,4096)",
         "memcpy(gpu+(s->q-1)*FIXTURE_GROUP_BYTES,reference+5*FIXTURE_GROUP_BYTES,FIXTURE_GROUP_BYTES)"),
    ):
        assert fixture.count(old) == 1, old
        fixture = fixture.replace(old, replacement, 1)
    old = "static int fixture_register(int fd,unsigned opcode,void *arg)"
    assert fixture.count(old) == 1
    text += "static int fixture_register(int fd,unsigned opcode,void *arg);\n"
    text += fixture.replace(old, old.replace("fixture_register(", "fixture_register_base("), 1)
    text += (HERE / "two_session_fault_boundary.c.in").read_text()
    # Keep the real raw transport and CREATE_REPORT validation intact.
    text += function(source, "cs_mech") + "\n"
    lib = (ROOT / "src/lib/xdev_ext_session.c").read_text()
    text += function(lib, "create_report_validate") + "\n"
    text += function(lib, "xdev_ext_create_report_read") + "\n"
    text += function(source, "cs_ce_oracle") + "\n"
    # New local helpers are implementation, not fixture code. Preserve order.
    for match in re.finditer(r"(?m)^struct\s+(cs_two_\w+)\s*\{", source):
        text += structure(source, match.group(1)) + "\n"
    names = []
    for match in re.finditer(r"(?m)^static\s+(?:inline\s+)?[\w *]+\b(cs_two_\w+)\s*\([^;{}]*\)\s*\{", source):
        if match.group(1) not in names:
            names.append(match.group(1))
            text += function(source, match.group(1)) + "\n"
    text += actual + "\n" + COORDINATOR_MAIN
    return Compiled(text)


COORDINATOR_MAIN = r'''
int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    scenario=argv[1]; depth=strtoul(argv[2],NULL,0);
    struct chain_spec s={0}; struct chain_result r={0};
    strcpy(s.chain,"nvme-gpu"); s.arm=CH_SESSION; s.mode=CH_CORRECTNESS;
    s.load=CH_LOAD_CLOSED; s.start_per=CH_START_BATCH; s.plan=CH_PLAN_BPF;
    s.group_bytes=FIXTURE_GROUP_BYTES; s.frame_size=4096; s.depth=depth; s.burst=1;
    s.batches=6; s.timeout_ms=1000; s.ce_vmm=true; s.ce_len=depth*FIXTURE_GROUP_BYTES;
    s.oracle=CH_ORACLE_CE; s.nr_stages=2;
    strcpy(s.reference,"fixture-reference"); strcpy(s.ce_dev,"/dev/nvidia0");
    s.st[0].cls=CH_NVME; s.st[0].dir=CH_FROM;
    strcpy(s.st[0].dev,"/dev/ng_fixture"); s.st[0].slba=2048; s.st[0].nlb=6*FIXTURE_GROUP_BYTES/512;
    s.st[1].cls=CH_CE; s.st[1].dir=CH_TO;
    for (unsigned g=0;g<6;g++) for (unsigned b=0;b<FIXTURE_GROUP_BYTES;b++)
        reference[g*FIXTURE_GROUP_BYTES+b]=b<8?(unsigned char)((uint64_t)g>>(8*b)):
            (unsigned char)((g+1)*17+b*29+(b>>8));
    memset(gpu,CS_PRISTINE,sizeof(gpu));
    int ret=chain_run_two_session_correctness(&s,&r);
    printf("{\"rc\":%d,\"status\":%d,\"rings\":%u,\"umems\":%u,\"creates\":%u,"
           "\"nstarts\":%u,\"cstarts\":%u,\"nwaits\":%u,\"cwaits\":%u,\"nstop\":%u,\"cstop\":%u,"
           "\"ring_closes\":%u,\"unmaps\":%u,\"cuda_closes\":%u,\"plan_closes\":%u,"
           "\"reads\":%u,\"violations\":%u,\"bad_cleanup\":%u,"
           "\"done_n\":%llu,\"done_c\":%llu,\"published_n\":%llu,\"published_c\":%llu,"
           "\"frame_checks\":%u,\"oracle_detail\":%lld,\"oracle_bytes\":%llu}\n",
           ret,r.status,rings,umems,creates,sides[0].starts,sides[1].starts,
           sides[0].waits,sides[1].waits,
           sides[0].stops,sides[1].stops,ring_closes,unmaps,cuda_closes,plan_closes,
           gpu_reads,violations,bad_cleanup,(unsigned long long)sides[0].done,
           (unsigned long long)sides[1].done,(unsigned long long)sides[0].published,
           (unsigned long long)sides[1].published,frame_checks,(long long)r.oracle_detail,
           (unsigned long long)r.oracle_bytes);
    return 0;
}
'''


CLI_BOUNDARIES = r'''
static const char *cli_case;
static unsigned normal_calls, staged_calls, two_calls, plans, runtimes, timers, emitted, fd_checks, order_bad;
static char printed[8192];
int fixture_printf(const char *fmt, ...)
{
    va_list ap; va_start(ap,fmt); size_t n=strlen(printed);
    int ret=vsnprintf(printed+n,sizeof(printed)-n,fmt,ap); va_end(ap);
    if (strstr(printed,"TWO_SESSION_QUALIFICATION=PASS") &&
        (!fd_checks || !strcmp(cli_case,"fd-fail"))) order_bad++;
    return ret;
}
char *cb_slurp(const char *path, size_t *len)
{ (void)path; *len=2; return strdup("{}"); }
int fixture_parse(const char *text,size_t len,struct chain_spec *s,struct chain_err *e)
{
    (void)text; (void)len; (void)e; memset(s,0,sizeof(*s));
    strcpy(s->chain,"nvme-gpu"); strcpy(s->ce_dev,"/dev/nvidia0");
    s->arm=!strcmp(cli_case,"staged")?CH_STAGED:!strcmp(cli_case,"user")?CH_USER_CONTINUATION:CH_SESSION;
    s->mode=!strcmp(cli_case,"timing")?CH_TIMING:CH_CORRECTNESS;
    s->load=CH_LOAD_CLOSED; s->nr_stages=2; s->st[0].cls=CH_NVME; s->st[1].cls=CH_CE;
    s->st[0].dir=CH_FROM; s->st[1].dir=CH_TO;
    s->batches=6; s->depth=2; s->group_bytes=4096; return 0;
}
int fixture_validate(const struct chain_spec *s,struct chain_err *e)
{ (void)s; (void)e; return 0; }
const char *cb_status(int status) { return status?"fail":"pass"; }
void cb_json_str(FILE *f,const char *s) { (void)f; (void)s; }
void cb_plan(const struct chain_spec *s) { (void)s; plans++; }
void cb_emit(FILE *f,const struct chain_spec *s,const struct chain_result *r)
{ (void)f; (void)s; (void)r; emitted++; }
int es_ce_runtime_begin(const char *dev,int *before)
{ (void)dev; if(two_calls) order_bad++; runtimes++; *before=3; return !strcmp(cli_case,"runtime-fail")?4:0; }
int eval_fd_count(void) { return 3; }
int eval_fd_check(int before) { (void)before; fd_checks++; return !strcmp(cli_case,"fd-fail"); }
int cpu_timer_init(struct cpu_timer *t,const char *clock,size_t n)
{ (void)t; (void)clock; (void)n; timers++; return 0; }
int cpu_timer_publish(struct cpu_timer *t) { (void)t; return 0; }
void cpu_timer_destroy(struct cpu_timer *t) { (void)t; }
bool chain_env_virtual(const char *root,char *why,size_t len)
{ (void)root; (void)why; (void)len; return false; }
const char *chain_undeclared_copy(const struct chain_spec *s,const char *const *v,unsigned n)
{ (void)s; (void)v; (void)n; return NULL; }
int chain_run_session(const struct chain_spec *s,struct chain_result *r)
{ (void)s; (void)r; normal_calls++; return 0; }
int chain_run_staged(const struct chain_spec *s,struct chain_result *r)
{ (void)s; (void)r; staged_calls++; return 0; }
int chain_run_two_session_correctness(const struct chain_spec *s,struct chain_result *r)
{
    (void)s; if(runtimes!=1) order_bad++; two_calls++;
    if (!strcmp(cli_case,"run-fail")) return cb_fail(r,CB_FAIL,"fixture run failure");
    return 0;
}
#define printf fixture_printf
#define chain_parse fixture_parse
#define chain_validate fixture_validate
'''


def cli():
    text, _, _ = base()
    actual = function((HERE / "chain_bench.c").read_text(), "main")
    actual = re.sub(r"\bmain\s*\(", "actual_main(", actual, count=1)
    wrapper = r'''
#undef printf
int main(int argc,char **argv)
{
    if (argc != 3) return 2;
    cli_case=argv[2];
    char *args[]={"chain_bench",argv[1],"fixture-spec",NULL};
    int ret=actual_main(3,args);
    printf("{\"rc\":%d,\"normal\":%u,\"staged\":%u,\"two\":%u,\"plans\":%u,"
           "\"runtime\":%u,\"timers\":%u,\"emitted\":%u,\"fd_checks\":%u,"
           "\"qual_pass\":%d,\"qual_fail\":%d,\"order_bad\":%u}\n",
           ret,normal_calls,staged_calls,two_calls,plans,runtimes,timers,emitted,fd_checks,
           strstr(printed,"TWO_SESSION_QUALIFICATION=PASS")!=NULL,
           strstr(printed,"TWO_SESSION_QUALIFICATION=FAIL")!=NULL,order_bad);
    return 0;
}
'''
    return Compiled(text + CLI_BOUNDARIES + actual + wrapper)


class TwoSessionCoordinator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual=coordinator()
        if cls.actual is not None:
            cls.addClassCleanup(cls.actual.close)

    def run_case(self, case="ok", depth=2):
        self.assertIsNotNone(self.actual,
                             "missing actual chain_run_two_session_correctness: feature RED")
        return self.actual.run(case,depth)

    def test_single_owner_two_validated_report_ids_and_exact_nonrecycle_frame_handoff(self):
        for depth in (1,2,3):
            with self.subTest(depth=depth):
                r=self.run_case(depth=depth)
                self.assertEqual((r["rc"],r["status"],r["violations"],r["bad_cleanup"]),(0,0,0,0))
                self.assertEqual((r["rings"],r["umems"],r["creates"]),(1,1,2))
                self.assertEqual((r["done_n"],r["done_c"]),(6,6))
                self.assertEqual((r["nstarts"],r["cstarts"]),((6+depth-1)//depth,)*2)
                self.assertEqual((r["nwaits"],r["cwaits"]),(r["nstarts"],r["cstarts"]),
                                 "each side must wait on its CREATE eventfd for every accepted START")
                self.assertGreaterEqual(r["reads"],(6+depth-1)//depth)
                self.assertGreaterEqual(r["oracle_bytes"],6*4096)
                self.assertEqual((r["nstop"],r["cstop"],r["ring_closes"],r["unmaps"],
                                  r["cuda_closes"],r["plan_closes"]),(1,1,1,1,1,1))

    def test_n_event_without_full_success_and_published_barrier_never_lends_to_ce(self):
        for case in ("n-published-short","n-done-short","n-inflight","n-error","n-abort","n-sequester"):
            with self.subTest(case=case):
                r=self.run_case(case)
                self.assertNotEqual(r["rc"] or r["status"],0)
                self.assertEqual(r["cstarts"],0)
                self.assertEqual(r["violations"],0)

    def assert_failed_handoff(self, side, suffix):
        r = self.run_case(f"{side}-{suffix}")
        self.assertNotEqual(r["rc"] or r["status"], 0, r)
        self.assertEqual((r["nstarts"], r["cstarts"]),
                         (1, 0) if side == "n" else (1, 1),
                         "an unproven completion must stop before any next-session handoff")
        self.assertEqual(r["violations"], 0, r)
        return r

    def test_ce_event_without_full_success_and_publish_barrier_never_reuses_nvme_frames(self):
        for suffix in ("published-short", "done-short", "inflight", "error", "abort", "sequester"):
            with self.subTest(suffix=suffix):
                self.assert_failed_handoff("c", suffix)

    def test_session_state_cannot_be_substituted_by_successful_cumulative_counts(self):
        for side in ("n", "c"):
            for suffix in ("state-error", "state-stopping", "state-zombie", "state-invalid"):
                with self.subTest(side=side, suffix=suffix):
                    self.assert_failed_handoff(side, suffix)

    def test_completion_observation_must_match_exact_window_and_native_drain(self):
        for side in ("n", "c"):
            for suffix in ("published-excess", "done-excess", "native-incomplete", "native-excess",
                           "submitted-excess", "wrong-session"):
                with self.subTest(side=side, suffix=suffix):
                    self.assert_failed_handoff(side, suffix)

    def test_error_and_recycling_counters_disqualify_nonrecycling_handoff(self):
        for side in ("n", "c"):
            for suffix in ("protocol-error", "timeouts", "recycled"):
                with self.subTest(side=side, suffix=suffix):
                    self.assert_failed_handoff(side, suffix)

    def test_uncertain_ce_start_never_recycles_or_releases_shared_owner(self):
        r = self.assert_failed_handoff("c", "start-uncertain")
        self.assertEqual((r["ring_closes"], r["unmaps"], r["cuda_closes"], r["bad_cleanup"]),
                         (0, 0, 0, 0), "ambiguous CE acceptance may still read shared pages")

    def test_late_completion_during_stop_does_not_restart_failed_qualification(self):
        for side in ("n", "c"):
            with self.subTest(side=side):
                r = self.assert_failed_handoff(side, "start-uncertain-late")
                self.assertEqual((r["nstop"], r["cstop"], r["bad_cleanup"]), (1, 1, 0))
                # Successful synchronous STOP_REPORT permits cleanup. Retaining
                # after ambiguous START delivery is also safe; qualification
                # must still fail and must not begin the next window.
                self.assertIn((r["ring_closes"], r["unmaps"], r["cuda_closes"]),
                              ((0, 0, 0), (1, 1, 1)))

    def test_uncertain_stop_of_either_side_retains_shared_owner(self):
        for side in ("n", "c"):
            for suffix in ("stop-unknown", "stop-delivery-uncertain"):
                with self.subTest(side=side, suffix=suffix):
                    r = self.run_case(f"{side}-{suffix}")
                    self.assertNotEqual(r["rc"] or r["status"], 0, r)
                    self.assertEqual((r["nstop"], r["cstop"]), (1, 1))
                    self.assertEqual((r["ring_closes"], r["unmaps"], r["cuda_closes"], r["bad_cleanup"]),
                                     (0, 0, 0, 0), "STOP errors grant no cleanup permission")

    def test_malformed_successful_stop_report_cannot_authorize_shared_owner_release(self):
        for side in ("n", "c"):
            for suffix in ("stop-wrong-session", "stop-wrong-stats-session",
                           "stop-wrong-transport-session", "stop-state-active", "stop-inflight",
                           "stop-sequester", "stop-version-invalid", "stop-size-short",
                           "stop-transport-version-invalid", "stop-transport-size-short"):
                with self.subTest(side=side, suffix=suffix):
                    r = self.run_case(f"{side}-{suffix}")
                    self.assertNotEqual(r["rc"] or r["status"], 0, r)
                    self.assertEqual((r["ring_closes"], r["unmaps"], r["cuda_closes"]), (0, 0, 0),
                                     "contradictory release evidence must not free the common DMA backing")

    def test_retained_or_uncertain_second_create_preserves_shared_owner(self):
        for case in ("create-retained","create-uncertain"):
            with self.subTest(case=case):
                r=self.run_case(case)
                self.assertNotEqual(r["rc"] or r["status"],0)
                self.assertEqual((r["nstarts"],r["cstarts"]),(0,0))
                self.assertEqual((r["ring_closes"],r["unmaps"],r["cuda_closes"]),(0,0,0))
                self.assertEqual(r["violations"],0)

    def test_uncertain_start_never_hands_frames_to_next_session(self):
        r=self.run_case("start-uncertain")
        self.assertNotEqual(r["rc"] or r["status"],0)
        self.assertEqual(r["cstarts"],0)
        self.assertEqual(r["violations"],0)
        self.assertEqual((r["ring_closes"],r["unmaps"],r["cuda_closes"],r["bad_cleanup"]),
                         (0,0,0,0), "uncertain accepted START retains the shared owner")

    def test_unknown_ce_stop_retains_ring_umem_cuda_and_reports_failure(self):
        r=self.run_case("stop-unknown")
        self.assertNotEqual(r["rc"] or r["status"],0)
        self.assertEqual((r["nstop"],r["cstop"]),(1,1))
        self.assertEqual((r["ring_closes"],r["unmaps"],r["cuda_closes"]),(0,0,0))
        self.assertEqual(r["bad_cleanup"],0)

    def test_first_window_last_version_middle_byte_corruption_cannot_hide_in_final_ring(self):
        for depth in (1,2,3):
            with self.subTest(depth=depth):
                r=self.run_case("corrupt-first-window",depth)
                self.assertNotEqual(r["rc"] or r["status"],0)
                self.assertEqual((r["nstarts"],r["cstarts"]),(1,1),
                                 "the corrupt window must fail before a later window can overwrite it")

    def test_each_window_requires_every_current_version_not_merely_valid_old_or_final_slot(self):
        for depth in (2,3):
            with self.subTest(depth=depth):
                r=self.run_case("stale-first-window",depth)
                self.assertNotEqual(r["rc"] or r["status"],0,
                                    "a valid different input version cannot replace a required current output")
                self.assertEqual((r["nstarts"],r["cstarts"]),(1,1))


class TwoFrameCoordinator(unittest.TestCase):
    """Fixed independent schedule: [frames 0..7], then [frames 0..3]."""
    @classmethod
    def setUpClass(cls):
        cls.actual = coordinator(frames_per_group=2)
        if cls.actual is not None:
            cls.addClassCleanup(cls.actual.close)

    def run_case(self, case="ok"):
        self.assertIsNotNone(self.actual,
                             "missing actual chain_run_two_session_correctness: feature RED")
        return self.actual.run(case, 4)

    def test_two_frames_per_batch_exact_publication_and_short_final_window(self):
        r = self.run_case()
        self.assertEqual((r["rc"], r["status"], r["violations"], r["bad_cleanup"]), (0, 0, 0, 0))
        self.assertEqual((r["rings"], r["umems"], r["creates"]), (1, 1, 2))
        self.assertEqual((r["nstarts"], r["cstarts"], r["nwaits"], r["cwaits"]), (2, 2, 2, 2))
        self.assertEqual((r["done_n"], r["done_c"]), (6, 6))
        self.assertEqual((r["published_n"], r["published_c"]), (12, 12),
                         "publication counts frames; each successful batch returns two")
        self.assertEqual(r["frame_checks"], 24,
                         "both sides must use indices 0..7 then 0..3 exactly")
        # Both windows check all four GPU slots, including valid old slots
        # left by the short final window: this is checked data, not DMA bytes.
        self.assertEqual((r["reads"], r["oracle_detail"], r["oracle_bytes"]), (2, 0, 8*8192))
        self.assertEqual((r["nstop"], r["cstop"], r["ring_closes"], r["unmaps"],
                          r["cuda_closes"], r["plan_closes"]), (1, 1, 1, 1, 1, 1))

    def test_last_byte_of_second_frame_must_fail_before_another_window(self):
        r = self.run_case("two-frame-corrupt-tail")
        self.assertNotEqual(r["rc"] or r["status"], 0)
        self.assertEqual((r["nstarts"], r["cstarts"], r["reads"]), (1, 1, 1))
        self.assertEqual((r["done_n"], r["done_c"], r["published_n"], r["published_c"]), (4, 4, 8, 8))
        self.assertEqual((r["frame_checks"], r["violations"], r["bad_cleanup"]), (16, 0, 0))
        self.assertEqual(r["oracle_detail"], 4,
                         "full-byte oracle must reject slot 3 despite its valid group header and first frame")

    def test_one_unpublished_frame_prevents_handoff_even_when_all_batches_are_done(self):
        for side, starts in (("n", (1, 0)), ("c", (1, 1))):
            with self.subTest(side=side):
                r = self.run_case(f"{side}-published-short")
                self.assertNotEqual(r["rc"] or r["status"], 0)
                self.assertEqual((r["nstarts"], r["cstarts"]), starts)
                self.assertEqual(r["reads"], 0, "the byte oracle also waits for every published frame")
                self.assertEqual((r["violations"], r["bad_cleanup"]), (0, 0))


class ActualCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual=cli()
        cls.addClassCleanup(cls.actual.close)

    def test_new_cli_executes_only_untimed_qualification_after_runtime_and_final_fd_check(self):
        r=self.actual.run("--two-session-correctness","ok")
        self.assertEqual((r["rc"],r["two"],r["normal"],r["staged"]),(0,1,0,0))
        self.assertEqual((r["runtime"],r["fd_checks"],r["timers"],r["emitted"],r["qual_pass"]),(1,1,0,0,1))
        self.assertEqual(r["order_bad"],0)

    def test_original_check_spec_staged_user_and_invalid_cli_keep_dispatch(self):
        for option,case,expected in (("--check","ok",(0,0,0,1)),
                                     ("--spec","ok",(1,0,0,0)),
                                     ("--spec","staged",(0,1,0,0)),
                                     ("--spec","user",(1,0,0,0))):
            with self.subTest(option=option,case=case):
                r=self.actual.run(option,case)
                self.assertEqual(r["rc"],0)
                self.assertEqual((r["normal"],r["staged"],r["two"],r["plans"]),expected)
                self.assertEqual(r["emitted"],0 if option=="--check" else 1)
        self.assertEqual(self.actual.run("--other","ok")["rc"],2)

    def test_timing_and_wrong_arms_are_refused_before_any_runtime_or_coordinator(self):
        for case in ("timing","staged","user"):
            with self.subTest(case=case):
                r=self.actual.run("--two-session-correctness",case)
                self.assertNotEqual(r["rc"],0)
                self.assertEqual((r["runtime"],r["two"],r["timers"],r["qual_pass"]),(0,0,0,0))

    def test_runtime_failure_fd_leak_and_run_failure_never_print_qualification_pass(self):
        for case in ("runtime-fail","fd-fail","run-fail"):
            with self.subTest(case=case):
                r=self.actual.run("--two-session-correctness",case)
                self.assertNotEqual(r["rc"],0)
                self.assertEqual((r["qual_pass"],r["emitted"]),(0,0))


if __name__ == "__main__":
    unittest.main()
