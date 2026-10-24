#!/usr/bin/env python3
"""Execute unmodified RM fence functions with a tiny host hardware fixture.

No driver build or GPU is required. --revision allows the same behavior tests
to demonstrate the old callback-token truncation and pre-wrap wait bugs.
Only OS/hardware dependencies are simulated; fence arithmetic and callback
selection come verbatim from the requested production tree/revision.
"""
import argparse
import pathlib
import re
import subprocess
import tempfile

CE = "src/nvidia/src/kernel/gpu/mem_mgr/ce_utils.c"
CHANNEL = "src/nvidia/src/kernel/gpu/mem_mgr/channel_utils.c"
P2P = "src/nvidia/src/kernel/mem_mgr/p2p_umem.c"
CALLBACK = "src/nvidia/generated/g_ce_utils_nvoc.h"


def function(source, name):
    pattern = rf"(?m)^(?:static\s+)?(?:void|NvU64|NV_STATUS)\s+{re.escape(name)}\s*\("
    match = re.search(pattern, source)
    if not match:
        raise ValueError(f"production function missing: {name}")
    start = source.index("{", match.end())
    # Ignore comments and quoted strings when matching C braces.
    tokens = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    depth = 0
    for token in tokens.finditer(source, start):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():token.end()]
    raise ValueError(f"unterminated production function: {name}")


PRELUDE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
typedef uint32_t NvU32;
typedef int32_t NvS32;
typedef uint64_t NvU64;
typedef int NvBool;
typedef int NV_STATUS;
#define NV_OK 0
#define NV_ERR_INVALID_STATE 1
#define NV_ERR_TIMEOUT 2
#define NV_ERR_INVALID_ARGUMENT 3
#define NV_ERR_NO_MEMORY 4
#define NV_ERR_BUSY_RETRY 5
#define NV_TRUE 1
#define NV_FALSE 0
#define NV_U64_MAX UINT64_MAX
#define NV_U32_MAX UINT32_MAX
#define NV_S32_MAX INT32_MAX
#define NV_ASSERT assert
#define NV_ASSERT_OR_RETURN(c, e) do { if (!(c)) return (e); } while (0)
#define NV_PRINTF(...) ((void)0)
#define GPU_TIMEOUT_DEFAULT 0
#define GPU_TIMEOUT_FLAGS_BYPASS_THREAD_STATE 0
typedef struct { int gpuInstance; } OBJGPU;
typedef struct {
    OBJGPU *pGpu;
    NvU32 samples[8];
    unsigned int nr_samples, reads;
} OBJCHANNEL;
static NvU32 read_sema(OBJCHANNEL *c) {
    unsigned int i = c->reads++;
    return c->samples[i < c->nr_samples ? i : c->nr_samples - 1];
}
#define READ_CHANNEL_PAYLOAD_SEMA(c) read_sema(c)
typedef struct { unsigned int checks; } RMTIMEOUT;
static void gpuSetTimeout(OBJGPU *g, int t, RMTIMEOUT *r, int f) {
    (void)g; (void)t; (void)f; r->checks = 0;
}
static NV_STATUS gpuCheckTimeout(OBJGPU *g, RMTIMEOUT *r) {
    (void)g; return ++r->checks >= 4 ? NV_ERR_TIMEOUT : NV_OK;
}
static int rmDeviceGpuLockIsOwner(int n) { (void)n; return 0; }
#define GPU_GET_KERNEL_FIFO(g) (g)
static int kfifoIsLiteModeEnabled_HAL(OBJGPU *g, OBJGPU *f) { (void)g; (void)f; return 0; }
static void channelServiceScrubberInterrupts(OBJCHANNEL *c) { (void)c; }
static void osSchedule(void) {}
typedef void (*ChannelCompletionCallback)(void *);
typedef struct { void *prev, *next; } ListNode;
'''

LISTS = r'''
typedef struct { CeUtilsCallback *head, *tail; } CeUtilsCallbackList;
typedef struct {
    OBJCHANNEL *pChannel;
    NvU64 lastSubmittedPayload, lastCompletedPayload;
    NvBool bCompletionCallbackEnabled;
    void *pCallbackLock;
    CeUtilsCallbackList completionCallbacks;
} CeUtils;
typedef struct {
    NvU32 payload;
    ChannelCompletionCallback pCompletionCallback;
    void *pCompletionCallbackArg;
} CHANNEL_PB_INFO;
static void listInitIntrusive(CeUtilsCallbackList *l) { l->head = l->tail = NULL; }
static CeUtilsCallback *listHead(CeUtilsCallbackList *l) { return l->head; }
static void listAppendExisting(CeUtilsCallbackList *l, CeUtilsCallback *n) {
    n->listNode.prev = l->tail; n->listNode.next = NULL;
    if (l->tail) l->tail->listNode.next = n; else l->head = n;
    l->tail = n;
}
static void listRemove(CeUtilsCallbackList *l, CeUtilsCallback *n) {
    CeUtilsCallback *p = n->listNode.prev, *q = n->listNode.next;
    if (p) p->listNode.next = q; else l->head = q;
    if (q) q->listNode.prev = p; else l->tail = p;
}
static void listDestroy(CeUtilsCallbackList *l) { assert(!l->head); }
static void portSyncSpinlockAcquire(void *l) { (void)l; }
static void portSyncSpinlockRelease(void *l) { (void)l; }
static void *portMemAllocNonPaged(size_t n) { return calloc(1, n); }
static void portMemFree(void *p) { free(p); }
'''

P2P_FIXTURE = r'''
typedef struct { int unused; } MEMORY_DESCRIPTOR;
typedef struct { OBJGPU *pGpu; NvU64 offset, length; } P2P_UMEM_BINDING;
typedef struct {
    P2P_UMEM_BINDING *pBinding;
    CeUtils *pCeUtils;
    MEMORY_DESCRIPTOR *pHostMemDesc;
    NvU64 bytes;
    NvBool poisoned;
    void (*event)(void *, NvU64);
    void *eventArg;
} P2P_UMEM_CE_HOST;
typedef struct { NvU64 umemOffset, gpuOffset, size; } P2P_UMEM_XFER;
typedef struct {
    MEMORY_DESCRIPTOR *pSrcMemDesc, *pDstMemDesc;
    NvU64 srcOffset, dstOffset, length, submittedWorkId;
    NvU32 flags;
    ChannelCompletionCallback pCompletionCallback;
    void *pCompletionCallbackArg;
} CEUTILS_MEMCOPY_PARAMS;
#define P2P_UMEM_MAX_XFERS 1024
#define NV0050_CTRL_MEMCOPY_FLAGS_ASYNC 1
static unsigned int pushes;
static NV_STATUS _p2pXdevExtCeValid(P2P_UMEM_CE_HOST *h) { (void)h; return NV_OK; }
static NV_STATUS RmP2PUmemVidmemResolve(P2P_UMEM_BINDING *b, OBJGPU *g,
    MEMORY_DESCRIPTOR **md) {
    static MEMORY_DESCRIPTOR fixture_md;
    (void)b; (void)g; *md = &fixture_md; return NV_OK;
}
static int nvP2PVidmemXferOffset(NvU64 base, NvU64 len, NvU64 off,
    NvU64 size, NvU64 *out) {
    if (off > len || size > len - off) return 0;
    *out = base + off; return 1;
}
static NV_STATUS ceutilsMemcopy(CeUtils *c, CEUTILS_MEMCOPY_PARAMS *p) {
    ++pushes; p->submittedWorkId = ++c->lastSubmittedPayload; return NV_OK;
}
'''

HARNESS = r'''
static unsigned int failures, checks;
static void check(int ok, const char *name) {
    ++checks;
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++failures;
}
static OBJGPU gpu;
static void sample(OBJCHANNEL *c, NvU32 low) {
    c->samples[0] = low; c->nr_samples = 1; c->reads = 0;
}
static void test_progress(void) {
    OBJCHANNEL channel = { .pGpu = &gpu };
    CeUtils c = { .pChannel = &channel, .lastCompletedPayload = 0xfffffffeULL,
                  .lastSubmittedPayload = 0x100000001ULL };
    sample(&channel, 0xffffffffU);
    check(ceutilsUpdateProgress_IMPL(&c) == 0xffffffffULL,
          "real progress: ffffffff does not complete token 100000001");
    sample(&channel, 0);
    check(ceutilsUpdateProgress_IMPL(&c) == 0x100000000ULL,
          "real progress: zero extends through wrap and still lags token");
    sample(&channel, 1);
    check(ceutilsUpdateProgress_IMPL(&c) == 0x100000001ULL,
          "real progress: one completes full 64-bit token");
    check(ceutilsUpdateProgress_IMPL(&c) == 0x100000001ULL,
          "real progress: unchanged semaphore does not add an epoch");
    c.lastCompletedPayload = 0x500000001ULL;
    c.lastSubmittedPayload = 0x500000002ULL;
    check(ceutilsUpdateProgress_IMPL(&c) == 0x500000001ULL,
          "real progress: same low value retains fifth epoch");
    sample(&channel, 2);
    check(ceutilsUpdateProgress_IMPL(&c) == 0x500000002ULL,
          "real progress: high epoch completion remains 64 bit");
}
static void wait_case(NvU64 target, NvU32 low, int expected, const char *name) {
    OBJCHANNEL c = { .pGpu = &gpu };
    sample(&c, low);
    check(channelWaitForFinishPayload(&c, target) == expected, name);
}
static void test_wait(void) {
    wait_case(0x100000001ULL, 0xffffffffU, NV_ERR_TIMEOUT,
        "real wait: pre-wrap ffffffff cannot complete post-wrap one");
    wait_case(0x100000001ULL, 0, NV_ERR_TIMEOUT,
        "real wait: wrapped zero cannot complete post-wrap one");
    wait_case(0x100000001ULL, 1, NV_OK,
        "real wait: low one completes target 100000001");
    wait_case(0x500000001ULL, 1, NV_OK,
        "real wait: identical low bits complete within fifth epoch");
    wait_case(0x100000000ULL, 0xffffffffU, NV_ERR_TIMEOUT,
        "real wait: ffffffff cannot complete target 100000000");
    wait_case(0xffffffffULL, 0, NV_OK,
        "real wait: wrapped zero has passed target ffffffff");
    wait_case(0x180000000ULL, 1, NV_ERR_TIMEOUT,
        "real wait: maximum permitted forward distance still waits");
    OBJCHANNEL c = { .pGpu = &gpu, .samples = {0xffffffffU, 0, 1}, .nr_samples = 3 };
    int result = channelWaitForFinishPayload(&c, 0x100000001ULL);
    check(result == NV_OK && c.reads == 3,
        "real wait: consumes ffffffff then zero before completing on one");
}
static void count_callback(void *arg) { ++*(unsigned int *)arg; }
static void test_callbacks(void) {
    OBJCHANNEL channel = { .pGpu = &gpu };
    CeUtils c = { .pChannel = &channel, .lastCompletedPayload = 0xfffffffeULL,
        .lastSubmittedPayload = 0x100000001ULL, .bCompletionCallbackEnabled = 1 };
    unsigned int calls = 0;
    CHANNEL_PB_INFO pb = { .payload = 1, .pCompletionCallback = count_callback,
                          .pCompletionCallbackArg = &calls };
    check(_ceutilsInsertCallback(&c, &pb) == NV_OK,
        "real callback insertion accepts post-wrap token");
    check(listHead(&c.completionCallbacks)->payload == 0x100000001ULL,
        "real callback entry saves full token rather than low PB payload");
    sample(&channel, 0xffffffffU);
    _ceutilsProcessCompletionCallbacks(&c);
    check(calls == 0, "real callback: pre-wrap completion must not fire post-wrap token");
    sample(&channel, 0);
    _ceutilsProcessCompletionCallbacks(&c);
    check(calls == 0, "real callback: wrapped zero still must not fire token one");
    sample(&channel, 1);
    _ceutilsProcessCompletionCallbacks(&c);
    check(calls == 1 && listHead(&c.completionCallbacks) == NULL,
        "real callback: exact full completion fires once and removes entry");
    _ceutilsProcessCompletionCallbacks(&c);
    check(calls == 1, "real callback: repeated completion cannot fire twice");
    c.lastSubmittedPayload = 0x500000001ULL;
    c.lastCompletedPayload = 0x500000000ULL;
    _ceutilsInsertCallback(&c, &pb);
    check(listHead(&c.completionCallbacks)->payload == 0x500000001ULL,
        "real callback: same low token in fifth epoch retains distinct high bits");
    sample(&channel, 0);
    _ceutilsProcessCompletionCallbacks(&c);
    check(calls == 1, "real callback: fifth-epoch token cannot fire one behind");
    sample(&channel, 1);
    _ceutilsProcessCompletionCallbacks(&c);
    check(calls == 2, "real callback: fifth-epoch exact completion fires");
}
'''

GUARD_HARNESS = r'''
static void guard_case(NvU64 submitted, NvU64 completed, NvU32 n,
    int expected, const char *name) {
    CeUtils c = { .lastSubmittedPayload = submitted, .lastCompletedPayload = completed };
    P2P_UMEM_BINDING binding = { .pGpu = &gpu, .length = 4096 };
    P2P_UMEM_CE_HOST host = { .pBinding = &binding, .pCeUtils = &c, .bytes = 4096 };
    P2P_UMEM_XFER x[2] = {{ .size = 8 }, { .size = 8 }};
    NvBool issued = 99;
    NvU64 token = 99;
    pushes = 0;
    NV_STATUS result = RmP2PUmemCeAsyncSubmit(&host, x, n, 0, &issued, &token);
    check(result == expected && (expected == NV_OK ?
          (pushes == n && issued && token == submitted + n) :
          (pushes == 0 && !issued && token == 0)), name);
}
static void test_guard(void) {
    guard_case(0x100000000ULL + INT32_MAX - 1, 0x100000000ULL, 1, NV_OK,
        "real submit: outstanding may reach 2^31-1, full token preserved");
    guard_case(0x100000000ULL + INT32_MAX, 0x100000000ULL, 1, NV_ERR_BUSY_RETRY,
        "real submit: rejects reaching half-lap before any hardware push");
    guard_case(0x100000000ULL + INT32_MAX - 1, 0x100000000ULL, 2, NV_ERR_BUSY_RETRY,
        "real submit: entire plan budget rejects crossing half-lap");
    guard_case(0x500000001ULL, 0x400000001ULL, 1, NV_ERR_BUSY_RETRY,
        "real submit: same low bits in different epochs cannot hide full-lap backlog");
    guard_case(UINT64_MAX, UINT64_MAX - 1, 1, NV_ERR_INVALID_STATE,
        "real submit: 64-bit token overflow rejected before push");
    guard_case(0xffffffffULL, 0xfffffffeULL, 2, NV_OK,
        "real submit: post-wrap full token returned without truncation");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent)
    parser.add_argument("--revision", help="git revision; default reads worktree, falling back to HEAD for sparse files")
    parser.add_argument("--allow-missing-submit", action="store_true",
                        help="historical baseline only: skip the async submit function when absent")
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()

    def read(path):
        local = args.repo / path
        if args.revision is None and local.exists():
            return local.read_text()
        git_root = subprocess.check_output(["git", "-C", str(args.repo),
                                            "rev-parse", "--show-toplevel"], text=True).rstrip("\n")
        prefix = subprocess.check_output(["git", "-C", str(args.repo),
                                          "rev-parse", "--show-prefix"], text=True).rstrip("\n")
        return subprocess.check_output(["git", "-C", git_root, "show",
                                        f"{args.revision or 'HEAD'}:{prefix}{path}"], text=True)

    ce, channel, p2p = read(CE), read(CHANNEL), read(P2P)
    callback = re.search(r"typedef struct\s*\{[^{}]*\}\s*CeUtilsCallback;", read(CALLBACK))
    if not callback:
        raise ValueError("production CeUtilsCallback definition missing")
    progress = function(ce, "ceutilsUpdateProgress_IMPL")
    sources = [PRELUDE, callback.group(), LISTS, progress,
               "#define ceutilsUpdateProgress ceutilsUpdateProgress_IMPL\n",
               function(ce, "_ceutilsProcessCompletionCallbacks"),
               function(ce, "_ceutilsInsertCallback"),
               function(channel, "channelWaitForFinishPayload")]
    has_submit = bool(re.search(r"NV_STATUS\s+RmP2PUmemCeAsyncSubmit\s*\(", p2p))
    if not has_submit and not args.allow_missing_submit:
        raise ValueError("production async submit missing; use --allow-missing-submit only for historical RED")
    if has_submit:
        # Include the real event helper referenced by the newly callback-capable submit.
        sources.append(P2P_FIXTURE)
        if re.search(r"static void\s+_p2pXdevExtCeEvent\s*\(", p2p):
            sources.append(function(p2p, "_p2pXdevExtCeEvent"))
        sources.append(function(p2p, "RmP2PUmemCeAsyncSubmit"))
    sources.append(HARNESS)
    if has_submit:
        sources.append(GUARD_HARNESS)
    sources.append("int main(void) { test_progress(); test_wait(); test_callbacks();" +
                   ("test_guard();" if has_submit else
                    'puts("SKIP: async submit guard absent in this historical revision");') +
                   'printf("checks=%u failures=%u\\n", checks, failures); return failures ? 1 : 0; }\n')
    head = subprocess.check_output(["git", "-C", str(args.repo), "rev-parse",
                                   args.revision or "HEAD"], text=True).strip()
    print(f"production={args.repo} revision={args.revision or 'WORKTREE'} HEAD={head}", flush=True)
    with tempfile.TemporaryDirectory(prefix="xdev_ext-ce-fence-") as tmp:
        source = pathlib.Path(tmp) / "fence.c"
        exe = pathlib.Path(tmp) / "fence"
        source.write_text("\n\n".join(sources))
        subprocess.run([args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-O2", str(source), "-o", str(exe)], check=True)
        return subprocess.run([str(exe)]).returncode


if __name__ == "__main__":
    raise SystemExit(main())
