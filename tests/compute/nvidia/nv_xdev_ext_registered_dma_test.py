#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute the actual registered ioctl DMA owner with only RM/policy boundaries stubbed."""
from pathlib import Path
import os
import re
import subprocess
import sys
import unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex

FIXTURE = r'''
#include "nv_xdev_ext_host_env.h"
struct page; struct mm_struct; struct sg_table; struct device { int id; };
struct list_head { void *next, *prev; };
struct nv_p2p_vidmem_binding { int live; };
typedef struct nv_p2p_vidmem_binding nv_p2p_vidmem_binding_t;
typedef struct { int unused; } nvidia_stack_t;
struct nv_xdev_ext_gpu_binding { int unused; };
typedef uint32_t nv_xdev_ext_gpu_u32;
typedef int32_t nv_xdev_ext_gpu_s32;
typedef uint64_t nv_xdev_ext_gpu_u64;
typedef struct { NvU64 umemOffset, gpuOffset, size; } nv_p2p_umem_xfer_t;
#include "types.h"
#include "nv-xdev_ext-ce-classify.h"
#define NVRM_P2P_PAGESIZE_BIG_64K 65536
#define NV_DBG_ERRORS 1
#define nv_printf(...) ((void)0)
#define DMA_BIDIRECTIONAL 0
static struct {
    NV_STATUS bind, submit, release;
    int residual, issued, stack_fail, binds, runs, unbinds, dev_sync, cpu_sync;
} S;
static nv_p2p_vidmem_binding_t gpu = { 1 };
static nvidia_stack_t stack;
static const int nv_xdev_ext_gpu_policy_ops;
static int nv_kmem_cache_alloc_stack(nvidia_stack_t **sp)
{ if (S.stack_fail) return -1; *sp = &stack; return 0; }
static void nv_kmem_cache_free_stack(nvidia_stack_t *sp) { (void)sp; }
static NV_STATUS nv_p2p_vidmem_bind(const NvU8 *uuid, NvU64 va, NvU64 length,
    nv_p2p_vidmem_binding_t **out, NvU32 *seg
#if HAVE_RESIDUAL
    , nv_p2p_vidmem_binding_t **residual
#endif
)
{
    (void)uuid; (void)va; (void)length; (void)seg; S.binds++;
    *out = S.bind == NV_OK ? &gpu : NULL;
#if HAVE_RESIDUAL
    *residual = S.residual ? &gpu : NULL;
#endif
    return S.bind;
}
static NV_STATUS nv_p2p_vidmem_unbind(nv_p2p_vidmem_binding_t *b)
{ (void)b; S.unbinds++; return S.release; }
static void dma_sync_sgtable_for_device(struct device *d, struct sg_table *s, int dir)
{ (void)d; (void)s; (void)dir; S.dev_sync++; }
static void dma_sync_sgtable_for_cpu(struct device *d, struct sg_table *s, int dir)
{ (void)d; (void)s; (void)dir; S.cpu_sync++; }
static NV_STATUS nv_xdev_ext_gpu_run(const struct nv_xdev_ext_gpu_request *r,
    const void *ops, struct nv_xdev_ext_gpu_rm_call *call, NV_STATUS a, NV_STATUS b,
    struct nv_xdev_ext_gpu_outcome *out)
{
    (void)r; (void)ops; (void)a; (void)b; (void)out; S.runs++;
    call->hwSubmitted = S.issued;
    return S.submit;
}
static void nv_xdev_ext_gpu_report_policy_errors(const struct nv_xdev_ext_gpu_outcome *out)
{ (void)out; }
#include "actual.inc"
int main(int argc, char **argv)
{
    struct device dev = { 1 };
    NvU64 addresses[2] = { 0xa0000000, 0xa0001000 };
    nv_p2p_umem_buffer_t b = { .bufferType = NV_P2P_BUFFER_TYPE_HOST_REGION,
        .size = 8192, .pageCount = 2, .pageSize = 4096, .physAddrs = addresses,
        .dmaDev = &dev, .dmaSgt = (void *)1 };
    nv_p2p_xdev_ext_identity_t id = { 1, 2, 3, 4, 5 };
    NvU8 uuid[16] = {1}; NvBool ambiguous = NV_FALSE; NV_STATUS status;
    const char *c = argc == 2 ? argv[1] : "";
    S.issued = 1;
    if (!strcmp(c, "bind-residual")) { S.bind = NV_ERR_INVALID_STATE; S.residual = 1; }
    if (!strcmp(c, "unbind-failure")) S.release = NV_ERR_INVALID_STATE;
    if (!strcmp(c, "stack-and-unbind-failure")) { S.stack_fail = 1; S.release = NV_ERR_INVALID_STATE; }
    if (!strcmp(c, "ambiguous")) S.submit = NV_ERR_INVALID_STATE;
    if (!strcmp(c, "pre-submit")) { S.submit = NV_ERR_NO_MEMORY; S.issued = 0; }
    status = nv_registered_region_dma_xfer(&b, 65536, 0, 4096, 1, uuid, &id, &ambiguous);
    if (!strcmp(c, "success")) {
        CHECK(status == NV_OK && !ambiguous && S.runs == 1 && S.unbinds == 1, "successful ioctl");
        CHECK(S.dev_sync == 1 && S.cpu_sync == 1, "streaming ownership synchronization missing");
    } else if (!strcmp(c, "pre-submit")) {
        CHECK(status != NV_OK && !ambiguous && S.unbinds == 1 && !b.vidmemResidual,
              "safe pre-submit refusal leaked owner");
    } else {
        CHECK(status != NV_OK && ambiguous && b.vidmemResidual == &gpu,
              "failed ioctl cleanup lost live binding or failed to quarantine backing");
        if (!strcmp(c, "bind-residual")) CHECK(S.runs == 0, "bind failure reached copy");
        if (!strcmp(c, "ambiguous")) CHECK(S.unbinds == 0 && S.cpu_sync == 0, "unknown DMA ownership released");
        CHECK(nv_registered_region_dma_xfer(&b, 65536, 0, 4096, 1, uuid, &id, &ambiguous) != NV_OK,
              "quarantined registration accepted another transfer");
    }
    return env_report(c);
}
'''

class RegisteredDma(unittest.TestCase):
    def test_actual_ioctl_owner(self):
        build = ex.Build('.registered-owner-')
        try:
            p2p = ex.read('kernel-open/nvidia/nv-p2p.c')
            policy = ex.read('kernel-open/nvidia/nv-xdev_ext-gpu-policy.h')
            header = ex.read('kernel-open/nvidia/nv-p2p.h')
            source = p2p
            revision = os.environ.get('XDEV_EXT_REGISTERED_RED_REVISION')
            if revision:
                import sys
                for parent in Path(__file__).resolve().parents:
                    if (parent / 'tools/layout.py').is_file():
                        sys.path.insert(0, str(parent / 'tools'))
                        from layout import read_native
                        source = read_native(ex.GPU, 'nvidia', 'kernel-open/nvidia/nv-p2p.c', revision).decode()
                        break
                else:
                    source = subprocess.check_output(['git', '-C', str(ex.REPO), 'show',
                        revision + ':gpu/kernel-open/nvidia/nv-p2p.c'], text=True)
            body = ex.function(source, 'nv_registered_region_dma_xfer')
            enum = re.search(r'typedef enum\s*\{[^}]*\}\s*nv_p2p_buffer_type_t;', p2p, re.S).group()
            build.write('types.h', '\n'.join([enum,
                ex.typedef_struct(p2p, 'nv_p2p_umem_buffer_t'),
                ex.struct(p2p, 'nv_xdev_ext_gpu_rm_call'),
                ex.struct(policy, 'nv_xdev_ext_gpu_request'),
                ex.struct(policy, 'nv_xdev_ext_gpu_outcome'),
                ex.typedef_struct(header, 'nv_p2p_xdev_ext_identity_t')]))
            build.write('actual.inc', body)
            fixture = build.write('fixture.c', FIXTURE)
            for cc in ex.compilers():
                name = 'registered-' + Path(cc).name
                r, cmd = build.compile(fixture, name, compiler=cc,
                    defines=('HAVE_RESIDUAL=' + str(int('&residual' in body)),),
                    extra=('-I', str(ex.HERE), '-I', str(ex.GPU / 'kernel-open/nvidia')))
                self.assertEqual(r.returncode, 0, 'compile:\n' + r.stderr)
                for case in ('success', 'pre-submit', 'bind-residual', 'unbind-failure',
                             'stack-and-unbind-failure', 'ambiguous'):
                    with self.subTest(cc=cc, case=case):
                        result = build.run(name, case)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        finally:
            build.cleanup()

if __name__ == '__main__':
    unittest.main(verbosity=2)
