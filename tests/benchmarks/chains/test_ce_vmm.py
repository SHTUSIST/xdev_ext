#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Qualify actual chains CE parsing/allocation/access, without a device run.

Requirements: explicit VMM on the existing session/USER arms, one export on
every opened CE stage fd, and runtime initialization before the owned-FD
scope. CUDA/identity/attach and byte-copy boundaries are fixtures. The parser,
new allocation helper, existing access function and es_ce_attach are actual C
source bytes. Missing allocation helper is an explicit feature RED.
"""
import json
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
from ce_vmm_contract import COMMON, Compiled, function, structure


def pure_parser():
    """Actual parser, no source-view/build/kernel-header dependency.

    Only the broad legacy ctl include is replaced by the actual pure MAC/set
    parser dependency closure and actual peer type. No parser decision is replaced.
    Validation/layout/oracle algorithms are outside this fixture's scope.
    """
    source = (HERE / "chain_spec.h").read_text()
    ctl = (ROOT / "src/cli/xdev_ext_mech_ctl_core.h").read_text()
    uapi = (ROOT / "src/core/include/uapi/linux/xdev_ext_mech.h").read_text()
    limit = re.search(r"(?m)^#define\s+XDEV_EXT_MECH_MAX_STAGES\s+\d+", uapi)
    if limit is None:
        raise AssertionError("missing actual stage-count limit")
    prelude = COMMON + limit.group() + "\n" + structure(uapi, "xdev_ext_mech_peer") + "\n"
    prelude += function(ctl, "xdev_ext_mech_ctl_hex") + "\n"
    prelude += function(ctl, "xdev_ext_mech_ctl_parse_mac") + "\n"
    prelude += function(ctl, "xdev_ext_mech_ctl_parse_u64") + "\n"
    prelude += function(ctl, "xdev_ext_mech_ctl_parse_set") + "\n"
    parser = source[:source.index("/* --- validation")]
    parser = parser.replace('#include "chain_json.h"',
                            '#include "' + str(HERE / "chain_json.h") + '"')
    parser = parser.replace('#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"', "")
    return prelude + parser + "\n#endif\n", source


def make_parser():
    actual, source = pure_parser()
    vmm = "s.ce_vmm" if re.search(r"\bce_vmm\b", structure(source, "chain_spec")) else "0"
    main = r'''
int main(int argc, char **argv)
{
    struct chain_spec s;
    struct chain_err e = {{0}};
    if (argc != 2) return 2;
    int ret = chain_parse(argv[1], strlen(argv[1]), &s, &e);
    printf("{\"rc\":%d,\"native\":%d,\"vmm\":%d,\"stages\":%u}\n",
           ret, s.ce_native, @VMM@, s.nr_stages);
    return 0;
}
'''.replace("@VMM@", vmm)
    return Compiled(actual + main)


BOUNDARIES = r'''
#define XDEV_EXT_GPU_PCI_BDF_SIZE 32
#define XDEV_EXT_GPU_IDENTITY_ANY_MINOR (-1)
static unsigned native_calls, vmm_calls, attached, attach_bad, identities;
static unsigned fail_attach, mismatch, fill_calls, read_calls, fd_reads, fd_writes;
static uint64_t copy_va;
static size_t copy_len;
int xdev_ext_gpu_identity_from_opened(int fd, const char *dev, int minor, char *bdf)
{
    (void)dev; (void)minor; identities++;
    strcpy(bdf, mismatch && fd == 103 ? "0000:02:00.0" : "0000:01:00.0");
    return 0;
}
int xdev_ext_mech_cuda_open(struct xdev_ext_mech_cuda *cuda, const char *bdf, uint64_t len)
{
    (void)bdf; native_calls++; cuda->lib=(void *)1;
    cuda->va=0x100000; cuda->vmm_bytes=len; return 0;
}
int xdev_ext_mech_cuda_open_vmm(struct xdev_ext_mech_cuda *cuda, const char *bdf, uint64_t len)
{
    (void)bdf; vmm_calls++; cuda->lib=(void *)1; cuda->va=0x200000;
    cuda->vmm=1; cuda->exported=1; cuda->export_fd=55;
    cuda->vmm_bytes=(len+65535)/65536*65536; return 0;
}
int xdev_ext_nv_ce_attach_memory(int fd, struct xdev_ext_nv_ce_attach_memory *a)
{
    attached++;
    /* CE stages are deliberately sparse: USER/NVMe descriptors must not attach. */
    if (fd != (attached == 1 ? 101 : 103) || a->mem_fd != 55 ||
        a->gpu_va != 0x200000 || a->size != 65536 || a->flags || a->reserved)
        attach_bad++;
    if (attached == fail_attach) { a->status=0x51; errno=EIO; return -1; }
    a->status=0; return 0;
}
int chain_cuda_fill(const char *bdf, uint64_t va, const void *buf, size_t len)
{
    (void)bdf; (void)buf; fill_calls++; copy_va=va; copy_len=len; return 0;
}
int chain_cuda_readback(const char *bdf, uint64_t va, void *buf, size_t len)
{
    (void)bdf; (void)buf; read_calls++; copy_va=va; copy_len=len; return 0;
}
ssize_t fixture_pread(int fd, void *buf, size_t len, off_t off)
{ (void)fd; (void)buf; fd_reads++; copy_va=off; copy_len=len; return len; }
ssize_t fixture_pwrite(int fd, const void *buf, size_t len, off_t off)
{ (void)fd; (void)buf; fd_writes++; copy_va=off; copy_len=len; return len; }
#define pread fixture_pread
#define pwrite fixture_pwrite
'''


def make_ce(allocation):
    source = (HERE / "chain_session.c").read_text()
    alloc = function(source, "cs_ce_open_alloc", optional=True)
    if allocation and not alloc:
        return None
    actual, spec = pure_parser()
    cuda = (ROOT / "src/cli/xdev_ext_mech_cuda.h").read_text()
    ioctl = (ROOT / "src/cli/include/xdev_ext_nv_p2p_ioctl.h").read_text()
    shared = (ROOT / "tests/benchmarks/nvme_gpu/eval_session.h").read_text()
    for name in ("xdev_ext_mech_cuda_mem_prop", "xdev_ext_mech_cuda_access", "xdev_ext_mech_cuda"):
        actual += structure(cuda, name) + "\n"
    actual += structure(ioctl, "xdev_ext_nv_ce_attach_memory") + "\n"
    actual += BOUNDARIES + structure(source, "cs_ce") + "\n"
    actual += function(shared, "es_ce_is_sim") + "\n" + function(shared, "es_ce_attach") + "\n"
    actual += (alloc if allocation else function(source, "cs_ce_access")) + "\n"
    vmm = "s.ce_vmm = mode == 2;" if re.search(r"\bce_vmm\b", structure(spec, "chain_spec")) else ""
    main = r'''
int main(int argc, char **argv)
{
    struct chain_spec s = {0};
    struct cs_ce ce = {0};
    if (argc != 5) return 2;
    unsigned mode=strtoul(argv[1],NULL,0), stages=strtoul(argv[2],NULL,0);
    fail_attach=strtoul(argv[3],NULL,0); mismatch=strtoul(argv[4],NULL,0);
    s.ce_native=mode == 1; @VMM@
    strcpy(s.ce_dev, mode == 3 ? "/dev/xdev_ext_ce_sim" : "/dev/nvidia0");
    s.ce_va=4096; s.ce_len=8192; s.nr_stages=stages == 1 ? 2 : 4;
    for (unsigned i=0;i<XDEV_EXT_MECH_MAX_STAGES;i++) ce.fd[i]=-1;
    s.st[0].cls=CH_NVME; s.st[1].cls=CH_CE; ce.fd[1]=101;
    if (stages == 2) { s.st[2].cls=CH_USER; s.st[3].cls=CH_CE; ce.fd[3]=103; }
    strcpy(ce.bdf,"0000:01:00.0"); ce.va=s.ce_va;
    @CALL@
    printf("{\"rc\":%d,\"native\":%u,\"vmm\":%u,\"attach\":%u,"
           "\"attach_bad\":%u,\"identity\":%u,\"va\":%llu,"
           "\"fill\":%u,\"read\":%u,\"fd_reads\":%u,\"fd_writes\":%u,"
           "\"copy_va\":%llu,\"copy_len\":%zu}\n",
           rc,native_calls,vmm_calls,attached,attach_bad,identities,
           (unsigned long long)ce.va,fill_calls,read_calls,fd_reads,fd_writes,
           (unsigned long long)copy_va,copy_len);
    return 0;
}
'''.replace("@VMM@", vmm)
    call = "int rc=cs_ce_open_alloc(&s,&ce);" if allocation else r'''
    unsigned char bytes[17]={0};
    int rc=cs_ce_access(&s,&ce,23,bytes,sizeof(bytes),true);
    if (!rc) rc=cs_ce_access(&s,&ce,23,bytes,sizeof(bytes),false);
'''
    return Compiled(actual + main.replace("@CALL@", call))


class AllocationParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = make_parser()
        cls.addClassCleanup(cls.actual.close)

    def parse(self, alloc, user=False):
        stages = [{"class": "nvme", "dir": "from", "dev": "/dev/ng0n1", "slba": 2048, "nlb": 64}]
        if user:
            stages.append({"class": "user", "dir": "to"})
        stages.append({"class": "ce", "dir": "to"})
        spec = {"schema": "xdev-chain-spec-v1", "chain": "nvme-gpu",
                "arm": "user-continuation" if user else "session", "mode": "correctness",
                "group_bytes": 4096, "batches": 2, "depth": 2,
                "ce": {"dev": "/dev/nvidia0", "len": 8192, "alloc": alloc}, "stages": stages}
        return self.actual.run(json.dumps(spec))

    def test_existing_session_and_user_arm_explicitly_accept_vmm(self):
        for user in (False, True):
            with self.subTest(user=user):
                result = self.parse("vmm", user)
                self.assertEqual(result["rc"], 0, "actual parser rejects requested VMM qualification")
                self.assertEqual((result["native"], result["vmm"], result["stages"]),
                                 (0, 1, 3 if user else 2))

    def test_given_native_and_invalid_allocation_keep_existing_meaning(self):
        for mode, native in (("given", 0), ("native", 1)):
            with self.subTest(mode=mode):
                result = self.parse(mode)
                self.assertEqual((result["rc"], result["native"], result["vmm"]), (0, native, 0))
        self.assertNotEqual(self.parse("automatic")["rc"], 0)


class AllocationAndAccess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alloc = make_ce(True)
        cls.access = make_ce(False)
        for actual in (cls.alloc, cls.access):
            if actual is not None:
                cls.addClassCleanup(actual.close)

    def allocate(self, mode=2, stages=2, fail_attach=0, mismatch=0):
        self.assertIsNotNone(self.alloc, "missing actual cs_ce_open_alloc: old-source feature RED")
        return self.alloc.run(mode, stages, fail_attach, mismatch)

    def test_each_sparse_ce_fd_uses_one_shared_vmm_export(self):
        for stages in (1, 2):
            with self.subTest(stages=stages):
                result = self.allocate(stages=stages)
                self.assertEqual((result["rc"], result["native"], result["vmm"], result["va"]),
                                 (0, 0, 1, 0x200000))
                self.assertEqual((result["identity"], result["attach"], result["attach_bad"]),
                                 (stages, stages, 0))

    def test_native_and_given_do_not_acquire_vmm_or_attach_exports(self):
        native = self.allocate(mode=1)
        self.assertEqual((native["rc"], native["native"], native["vmm"], native["attach"], native["va"]),
                         (0, 1, 0, 0, 0x100000))
        for mode in (0, 3):
            with self.subTest(mode=mode):
                result = self.allocate(mode=mode)
                self.assertEqual((result["rc"], result["native"], result["vmm"], result["attach"],
                                  result["identity"], result["va"]), (0, 0, 0, 0, 0, 4096))

    def test_mismatched_ce_identity_fails_before_vmm_allocation_or_attach(self):
        result = self.allocate(mismatch=1)
        self.assertNotEqual(result["rc"], 0)
        self.assertEqual((result["identity"], result["native"], result["vmm"], result["attach"]), (2, 0, 0, 0))

    def test_second_attach_failure_cannot_report_qualified_success(self):
        result = self.allocate(fail_attach=2)
        self.assertNotEqual(result["rc"], 0)
        self.assertEqual((result["vmm"], result["attach"], result["attach_bad"]), (1, 2, 0))

    def test_vmm_and_native_access_use_cuda_with_exact_window_offset(self):
        for mode in (1, 2):
            with self.subTest(mode=mode):
                result = self.access.run(mode, 2, 0, 0)
                self.assertEqual((result["rc"], result["fill"], result["read"], result["fd_reads"],
                                  result["fd_writes"], result["copy_va"], result["copy_len"]),
                                 (0, 1, 1, 0, 0, 4096 + 23, 17))

    def test_given_and_sim_access_keep_original_fd_route(self):
        for mode in (0, 3):
            with self.subTest(mode=mode):
                result = self.access.run(mode, 2, 0, 0)
                self.assertEqual((result["rc"], result["fill"], result["read"], result["fd_reads"],
                                  result["fd_writes"], result["copy_va"], result["copy_len"]),
                                 (0, 0, 0, 1, 1, 4096 + 23, 17))


class ActualSourcePlacement(unittest.TestCase):
    def test_runtime_baseline_follows_valid_parse_and_check_before_owned_resources(self):
        main = function((HERE / "chain_bench.c").read_text(), "main")
        call = re.search(r"es_ce_runtime_begin\s*\(\s*spec\.ce_dev\s*,\s*&fd_before\s*\)", main)
        self.assertIsNotNone(call, "actual chains main lacks runtime initialization before owned FD scope")
        before, after = main[:call.start()], main[call.end():]
        self.assertLess(before.index("chain_validate("), before.index("if (check)"))
        self.assertIn("return CB_PASS;", before[before.index("if (check)"):])
        self.assertNotIn("eval_fd_count(", before, "no pre-cuInit baseline may hide the owned FD boundary")
        self.assertRegex(before, r"if\s*\(spec\.arm\s*!=\s*CH_STAGED\s*&&\s*chain_has\(&spec,\s*CH_CE\)\)\s*\{[^{}]*$")
        timer = main.index("cpu_timer_init(")
        run = main.index("chain_run_session(")
        self.assertLess(call.start(), timer)
        self.assertLess(call.start(), run)
        self.assertRegex(main[call.end():timer], r"if\s*\(ret\)\s*(?:\{[^{}]*?)?return\s+ret\s*;")
        self.assertIn("eval_fd_check(fd_before)", after)
        self.assertLess(after.index("eval_fd_check(fd_before)"), after.index("cb_emit(stdout"))
        session = function((HERE / "chain_session.c").read_text(), "chain_run_session")
        self.assertNotIn("es_ce_runtime_begin(", session,
                         "initialization must not move after plans/ring/pool/stage acquisition")

    def test_allocation_is_before_create_and_safe_cleanup_covers_vmm(self):
        run = function((HERE / "chain_session.c").read_text(), "chain_run_session")
        call = re.search(r"cs_ce_open_alloc\s*\(\s*s\s*,\s*&ce\s*\)", run)
        self.assertIsNotNone(call, "actual session must use the tested allocation/attach helper")
        self.assertLess(call.start(), run.index("XDEV_EXT_MECH_OP_CREATE"))
        close = run.index("xdev_ext_mech_cuda_close(&ce.cuda)")
        unsafe = run.index("if (unsafe)")
        self.assertLess(unsafe, close)
        self.assertIn("return r->status;", run[unsafe:close])
        self.assertRegex(run[max(0, close - 100):close],
                         r"if\s*\(\(s->ce_native\s*\|\|\s*s->ce_vmm\)\s*&&\s*$")
        self.assertIn('"gpu-vmm-allocation"', run,
                      "qualified VMM must not be reported as the given-window path")


if __name__ == "__main__":
    unittest.main()
