#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual RM bind/map/unbind bodies with an instrumented host boundary, no DMA."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def body(text, name, optional=False):
    match = re.search(r'(?m)^(?:static )?(?:NV_STATUS|NvBool|void)\s*\n?' + name + r'\s*\(', text)
    if match is None:
        if optional:
            return ''
        raise ValueError('missing actual function: ' + name)
    start = text.index('{', match.end())
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]', text[start:], re.S):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth:
                return text[match.start():start + token.end()]
    raise ValueError('unclosed actual function: ' + name)


PRE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint64_t NvU64; typedef uint32_t NvU32; typedef int NvBool, NV_STATUS;
typedef NvU64 RmPhysAddr;
#define NV_TRUE 1
#define NV_FALSE 0
#define NV_OK 0
#define NV_ERR_INVALID_ARGUMENT 1
#define NV_ERR_NO_MEMORY 2
#define NV_ERR_NOT_SUPPORTED 3
#define NV_ERR_INVALID_STATE 4
#define NV_ERR_BUSY_RETRY 5
#define NV_U64_MAX UINT64_MAX
#define NV_U32_MAX UINT32_MAX
#define RM_PAGE_SIZE 4096ULL
#define RM_PAGE_SIZE_64K 65536ULL
#define RM_PAGE_SIZE_2M 2097152U
#define ADDR_SYSMEM 1
#define NV_MEMORY_CACHED 1
#define MEMDESC_FLAGS_NONE 0
#define AT_GPU 1
#define KMIGMGR_SWIZZID_INVALID 0xffffffffU
#define DRF_DEF(a,b,c,d) 0U
#define FLD_SET_DRF(a,b,c,d,f) (f)
#define NV_MIN(a,b) ((a)<(b)?(a):(b))
#define NV_MAX(a,b) ((a)>(b)?(a):(b))
#define NV_IS_ALIGNED64(x,a) (((x)&((a)-1))==0)
#define IS_VIRTUAL(g) 0
#define IS_MIG_IN_USE(g) 0
#define IsTURINGorBetter(g) 1
#define PDB_PROP_GPU_IS_LOST 1
#define LEVEL_ERROR 0
#define NV_PRINTF(...) do {} while(0)
typedef struct OBJGPU OBJGPU;
struct OBJGPU { NvBool bIsSOC; NvBool (*getProperty)(OBJGPU *, int); };
typedef struct { NvBool bCePhysicalVidmemAccessNotSupported; } MemoryManager;
static MemoryManager manager;
#define GPU_GET_MEMORY_MANAGER(g) (&manager)
#define GPU_GET_DMA(g) (g)
typedef struct { NvU64 base; } OBJVASPACE;
static OBJVASPACE vas;
typedef struct { int unused; } VAS_ALLOC_FLAGS;
typedef struct { OBJGPU *pGpu; } P2P_UMEM_VIDMEM_BINDING;
typedef void (*P2P_UMEM_CE_EVENT)(void *,NvU64);
typedef struct { unsigned flags; } NV0050_ALLOCATION_PARAMETERS;
typedef struct { NvU64 Size, pageSize, base; NvBool contiguous; NvU64 *pages; } MEMORY_DESCRIPTOR;
typedef struct { void *pbCpuVA,*pControlGPFifo,*pTokenFromNotifier,*pRsClient; NvBool bUseDoorbellRegister; unsigned deviceId,hVASpaceId; } OBJCHANNEL;
typedef struct { OBJCHANNEL *pChannel; NvU64 lastSubmittedPayload; } CeUtils;
static unsigned maps, reserves, frees, deletes, descs, failures, checks;
static unsigned fail_map, fail_free, active_va, freed_while_live;
static NvU64 reserved_bytes;
static NvU64 map_va[2048],map_dma[2048],map_size[2048],map_page[2048];
static void *portMemAllocNonPaged(size_t n) { return malloc(n); }
static void portMemFree(void *p) { free(p); }
#define portMemSet memset
static NV_STATUS memdescCreate(MEMORY_DESCRIPTOR **out,OBJGPU *g,NvU64 bytes,NvU64 align,NvBool contig,int space,int cache,unsigned flags) {
 (void)g;(void)align;(void)space;(void)cache;(void)flags;
 *out=calloc(1,sizeof(**out));if(!*out)return NV_ERR_NO_MEMORY;
 (*out)->Size=bytes;(*out)->contiguous=contig;descs++;return NV_OK;
}
static void memdescFillPages(MEMORY_DESCRIPTOR *m,NvU64 off,RmPhysAddr *pages,NvU32 n,NvU32 pageSize) {
 (void)off;m->pages=malloc(n*sizeof(*pages));memcpy(m->pages,pages,n*sizeof(*pages));m->base=pages[0];m->pageSize=pageSize;
}
static void memdescDescribe(MEMORY_DESCRIPTOR *m,int space,NvU64 base,NvU64 bytes) {(void)space;m->base=base;m->Size=bytes;}
static void memdescSetPageSize(MEMORY_DESCRIPTOR *m,int at,NvU64 size) {(void)at;m->pageSize=size;}
static void memdescDestroy(MEMORY_DESCRIPTOR *m) {if(m){if(active_va&&!deletes)freed_while_live++;descs--;free(m->pages);free(m);}}
static NV_STATUS make_ce(CeUtils **out) { *out=calloc(1,sizeof(**out));(*out)->pChannel=calloc(1,sizeof(OBJCHANNEL));(*out)->pChannel->pbCpuVA=(void*)1;(*out)->pChannel->pControlGPFifo=(void*)1;return 0; }
#define objCreate(out,parent,cls,g,arg,p) ((void)(parent),(void)(g),(void)(p),make_ce(out))
static void objDelete(CeUtils *ce) {deletes++;active_va=0;free(ce->pChannel);free(ce);}
static NV_STATUS vaspaceGetByHandleOrDeviceDefault(void *client,unsigned device,unsigned handle,OBJVASPACE **out) {(void)client;(void)device;(void)handle;*out=&vas;return 0;}
static NvU64 vaspaceGetVaStart(OBJVASPACE *v) {(void)v;return 4096;}
static NvU64 vaspaceGetVaLimit(OBJVASPACE *v) {(void)v;return 1ULL<<48;}
static NV_STATUS vaspaceAlloc(OBJVASPACE *v,NvU64 size,NvU64 align,NvU64 lo,NvU64 hi,NvU64 mask,VAS_ALLOC_FLAGS flags,NvU64 *out) {
 (void)v;(void)align;(void)lo;(void)hi;(void)flags;reserves++;
 /* The real RM locks page-table levels for the whole reservation. */
 if((mask & RM_PAGE_SIZE_2M) && (size & (RM_PAGE_SIZE_2M-1)))return NV_ERR_INVALID_ARGUMENT;
 reserved_bytes=size;active_va=1;*out=0x8000000000ULL;return 0;
}
static NV_STATUS vaspaceFree(OBJVASPACE *v,NvU64 base) {(void)v;(void)base;frees++;if(fail_free)return NV_ERR_INVALID_STATE;active_va=0;return 0;}
static NV_STATUS dmaAllocMapping_HAL(OBJGPU *g,void *dma,OBJVASPACE *v,MEMORY_DESCRIPTOR *m,NvU64 *addr,NvU32 flags,NvU32 flags2,void *info,NvU32 swizz) {
 (void)g;(void)dma;(void)v;(void)flags;(void)flags2;(void)info;(void)swizz;
 if(maps>=2048 || *addr<0x8000000000ULL || *addr-0x8000000000ULL>reserved_bytes || m->Size>reserved_bytes-(*addr-0x8000000000ULL))return NV_ERR_INVALID_ARGUMENT;
 map_va[maps]=*addr;map_dma[maps]=m->base;map_size[maps]=m->Size;map_page[maps]=m->pageSize;maps++;
 return fail_map==maps?NV_ERR_INVALID_STATE:NV_OK;
}
'''

POST = r'''
static P2P_UMEM_CE_HOST *g_pXdevExtCeHosts;
static NV_STATUS RmP2PUmemCeProgress(void *ptr,NvU64 *watermark) {
 P2P_UMEM_CE_HOST *h=ptr;if(h->poisoned)return NV_ERR_INVALID_STATE;
 *watermark=0;return NV_OK;
}
'''
MAIN = r'''
static NvBool property(OBJGPU *g,int p) {(void)g;(void)p;return 0;}
static OBJGPU gpu={0,property};
static P2P_UMEM_VIDMEM_BINDING binding={&gpu};
static void expect(int ok,const char *what) {checks++;if(!ok){failures++;fprintf(stderr,"FAIL %s\n",what);}}
static void reset(void) {maps=reserves=frees=deletes=fail_map=fail_free=0;}
static void *bind(NvU64 *pages,unsigned n) {
 void *h=NULL;int rc=RmP2PUmemCeHostBind(&binding,pages,n,4096,(NvU64)n*4096,NULL,NULL,&h);
 expect(rc==0&&h,"bind succeeds");return h;
}
int main(void) {
 NvU64 pages[1025];void *ptr;unsigned i;
 reset();for(i=0;i<8;i++)pages[i]=0x9000000000ULL+i*8192ULL;
 ptr=bind(pages,8);expect(maps==8&&reserves==1,"fragmented pool gets one VA reservation and one map per DMA run");
 for(i=0;i<maps;i++){expect(map_dma[i]==pages[i],"already translated DMA address passed unchanged");expect(map_size[i]==4096,"reservation padding has no data mapping");expect(map_va[i]==0x8000000000ULL+i*4096,"mapping preserves logical host offsets");}
 if(ptr){P2P_UMEM_CE_HOST *h=ptr;h->pCeUtils->lastSubmittedPayload=1;
  expect(RmP2PUmemCeHostUnbind(h)==NV_ERR_BUSY_RETRY&&frees==0&&deletes==0,"pending work retains all mappings");
  h->pCeUtils->lastSubmittedPayload=0;h->poisoned=1;
  expect(RmP2PUmemCeHostUnbind(h)==NV_ERR_INVALID_STATE&&frees==0,"UNKNOWN retains mappings");h->poisoned=0;
  expect(RmP2PUmemCeHostUnbind(h)==0&&frees==1&&descs==0,"drained host frees mapping before descriptors");}
 reset();for(i=0;i<1024;i++)pages[i]=0x10000000ULL+(i/512)*0x800000ULL+(i%512)*4096ULL;
 ptr=bind(pages,1024);expect(maps==0&&reserves==0,"all 2MiB DMA runs preserve physical path");if(ptr)expect(RmP2PUmemCeHostUnbind(ptr)==0,"physical teardown");
 reset();for(i=0;i<1025;i++)pages[i]=i<512?0x10000000ULL+i*4096ULL:i<1024?0x20000000ULL+(i-512)*4096ULL:0x30000000ULL;
 ptr=bind(pages,1025);expect(maps==3&&map_page[0]==2097152&&map_page[1]==2097152&&map_page[2]==4096,"mixed runs retain 2MiB PTE eligibility");if(ptr)expect(RmP2PUmemCeHostUnbind(ptr)==0,"mixed teardown");
 reset();for(i=0;i<8;i++)pages[i]=0x9000000000ULL+i*8192ULL;fail_map=2;ptr=NULL;
 int rc=RmP2PUmemCeHostBind(&binding,pages,8,4096,32768,NULL,NULL,&ptr);
 expect(rc!=0&&ptr==NULL&&descs==0&&active_va==0,"partial bind mapping failure releases isolated channel and descriptors");
 reset();{
  unsigned n=1048578;NvU64 *big=malloc((size_t)n*sizeof(*big));expect(big!=NULL,"large-address fixture array allocated");
  if(big){for(i=0;i<n-1;i++)big[i]=0x100000000ULL+(NvU64)i*4096;big[n-1]=0x400000000ULL;
   ptr=bind(big,n);expect(reserved_bytes>UINT32_MAX&&maps==2,"reservation rounding preserves bits above4GiB");
   if(ptr){expect(RmP2PUmemCeHostUnbind(ptr)==0&&descs==0,"large-address pool teardown");}
   free(big);}
 }
 reset();ptr=bind(pages,8);if(ptr){unsigned before=descs;fail_free=1;
  expect(RmP2PUmemCeHostUnbind(ptr)!=0&&descs==before&&deletes==0,"failed VA free keeps host channel and descriptors");
  expect(((P2P_UMEM_CE_HOST*)ptr)->poisoned,"failed VA free quarantines host");}
 expect(!freed_while_live,"no descriptor destroyed while mapping remains live");
 printf("HOST_VA checks=%u failures=%u\n",checks,failures);return failures?1:0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default='gcc')
    args = parser.parse_args()
    source = args.source.read_text()
    host = re.search(r'typedef struct P2P_UMEM_CE_HOST\s*\{.*?\}\s*P2P_UMEM_CE_HOST;', source, re.S)
    if host is None:
        raise ValueError('missing actual host ownership struct')
    helpers = ''.join(body(source, n, True) for n in ('_p2pXdevExtCeUsesHostVa', '_p2pXdevExtCeMapHost', '_p2pXdevExtCeDestroyHostRuns'))
    args.output.mkdir(parents=True, exist_ok=True)
    c = args.output / 'host-va.c'; binary = args.output / 'host-va'
    c.write_text(PRE + host.group() + POST + helpers + body(source, 'RmP2PUmemCeHostBind') + body(source, 'RmP2PUmemCeHostUnbind') + MAIN)
    command = [args.cc, '-std=gnu11', '-O0', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-fsanitize=undefined', '-fno-sanitize-recover=undefined', str(c), '-o', str(binary)]
    built = subprocess.run(command, text=True, capture_output=True)
    (args.output / 'compile.log').write_text(built.stdout + built.stderr)
    if built.returncode:
        print(built.stdout + built.stderr);return 2
    run = subprocess.run([str(binary)], text=True, capture_output=True)
    (args.output / 'run.log').write_text(run.stdout + run.stderr)
    print(run.stdout + run.stderr, end='')
    return run.returncode


if __name__ == '__main__':
    raise SystemExit(main())
