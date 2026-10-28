#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual device-memory pool: any power-of-two frame size, several frames per batch.

Requirement P1 (pool side): xdev_ext_peer_mech_pool_bind() accepts every frame
size xdev_ext_mech_peer_layout_check() accepts and groups of several frames;
xdev_ext_peer_pool_alloc(nr) returns nr frames, preferring the lowest run of
consecutive frames (so one NVMe command can cover a DMA-contiguous span), then
the lowest free frames, and rolls back completely on -ENOSPC. The production
pool functions are extracted and compiled with the same adapters as
../xdev_ext_mech/peer_graph/independent_pool.py; no payload backing exists.
"""
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE.parent / "xdev_ext_mech/peer_graph/independent_pool.py"))
KERNEL = BASE["KERNEL"]

MAIN = r'''
static void reset(void){alloc_calls=fail_alloc=claim_calls=claim_error=put_calls=0;allocation_len=8*65536ULL;allocation_gen=19;assert(authority.refs==1);}
static int failures;
#define CHECK(c, text) do { if (!(c)) { printf("not ok - %s (line %d)\n", text, __LINE__); failures++; } else printf("ok - %s\n", text); } while (0)
struct racer {struct xdev_ext_mech_pool *p;struct xdev_ext_mech_frame f[2];int result;};
static void *take_two(void *arg){struct racer *r=arg;r->result=xdev_ext_peer_pool_alloc(r->p,r->f,2);return NULL;}
static int bind(struct xdev_ext_mech_pool *p,u32 frame,u32 hdr,u32 seg,u32 group,u64 len)
{
 struct file original={1};struct xdev_ext_mech_layout l={.frame_size=frame,.hdr_room=hdr,.seg_len=seg,.group_bytes=group};
 reset();allocation_len=len;memset(p,0,sizeof(*p));return xdev_ext_peer_mech_pool_bind(p,&original,&l);
}
static void set_free(struct xdev_ext_mech_pool *p,const char *map)
{for(u32 i=0;i<p->nr_frames;i++)p->state[i]=map[i]=='.'?XDEV_EXT_MECH_F_K_FREE:XDEV_EXT_MECH_F_HELD;}
static bool states(struct xdev_ext_mech_pool *p,const char *map)
{for(u32 i=0;i<p->nr_frames;i++)if((p->state[i]==XDEV_EXT_MECH_F_K_FREE)!=(map[i]=='.'))return false;return true;}
int main(void)
{
 struct xdev_ext_mech_pool p;struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES+1];int ret;
 ret=bind(&p,4096,0,4096,4*4096,8*4096);
 CHECK(!ret&&p.frame_size==4096&&p.nr_frames==8,"4 KiB GPU frames, four frames per group bind");
 if(!ret)p.ops->release(&p);
 ret=bind(&p,2u<<20,0,2u<<20,4u<<20,4ull<<20);
 CHECK(!ret&&p.frame_size==(2u<<20)&&p.nr_frames==2,"2 MiB GPU frames bind");
 if(!ret)p.ops->release(&p);
 ret=bind(&p,65536,0,65536,16*65536,16*65536ULL);
 CHECK(!ret&&p.nr_frames==16,"a 1 MiB group of sixteen 64 KiB frames binds");
 if(!ret)p.ops->release(&p);
 ret=bind(&p,12288,0,4096,4096,12*4096);CHECK(ret==-EOPNOTSUPP&&!claim_calls,"non-power-of-two frame refused before claiming the allocation");
 ret=bind(&p,2048,0,2048,2048,8*2048);CHECK(ret==-EOPNOTSUPP&&!claim_calls,"frame below 4 KiB refused");
 ret=bind(&p,4u<<20,0,4096,4096,8ull<<20);CHECK(ret==-EOPNOTSUPP&&!claim_calls,"frame above 2 MiB refused");
 ret=bind(&p,65536,16,4096,4096,8*65536ULL);CHECK(ret==-EOPNOTSUPP&&!claim_calls,"CPU header room refused");
 ret=bind(&p,4096,0,4096,4096,3*4096+1);CHECK(ret==-EINVAL&&put_calls==1,"allocation not a multiple of the frame size refused and released");

 /* Allocation rules are independent of geometry: fall back to a layout 75b51c2 binds. */
 ret=bind(&p,4096,0,4096,4*4096,8*4096);
 if(ret)ret=bind(&p,65536,0,4096,4096,8*65536ULL);
 if(ret){printf("not ok - no GPU pool binds (%d); allocation cases skipped\n",ret);return 1;}
 ret=xdev_ext_peer_pool_alloc(&p,f,4);
 CHECK(!ret&&f[0].index==0&&f[1].index==1&&f[2].index==2&&f[3].index==3&&states(&p,"####...."),"alloc(4) on a fresh pool takes frames 0..3 in order");
 ret=xdev_ext_peer_pool_alloc(&p,f,4);
 CHECK(!ret&&f[0].index==4&&f[3].index==7&&states(&p,"########"),"second alloc(4) takes 4..7");
 CHECK(xdev_ext_peer_pool_alloc(&p,f,1)==-ENOSPC,"full pool refuses");
 set_free(&p,"#.#.....");ret=xdev_ext_peer_pool_alloc(&p,f,2);
 CHECK(!ret&&f[0].index==3&&f[1].index==4&&states(&p,"#.###..."),"the lowest consecutive run wins over scattered lower frames");
 set_free(&p,"#.#.#.##");ret=xdev_ext_peer_pool_alloc(&p,f,2);
 CHECK(!ret&&f[0].index==1&&f[1].index==3&&states(&p,"#####.##"),"without a run, the lowest free frames in ascending order");
 set_free(&p,"#.#.#.##");ret=xdev_ext_peer_pool_alloc(&p,f,4);
 CHECK(ret==-ENOSPC&&states(&p,"#.#.#.##"),"too few free frames: -ENOSPC and every taken frame returned");
 CHECK(xdev_ext_peer_pool_alloc(&p,f,0)==-EINVAL,"zero frames refused");
 set_free(&p,"........");CHECK(xdev_ext_peer_pool_alloc(&p,f,XDEV_EXT_MECH_MAX_FRAMES+1)==-EINVAL&&states(&p,"........"),"more than XDEV_EXT_MECH_MAX_FRAMES refused");
 for(int i=0;i<4;i++){ret=xdev_ext_peer_pool_alloc(&p,f,2);if(ret)break;if(!xdev_ext_peer_pool_resolve(&p,&f[0])&&!xdev_ext_peer_pool_resolve(&p,&f[1]))CHECK(f[1].umem_addr==f[0].umem_addr+p.frame_size&&!f[0].kaddr,"a two-frame batch resolves to adjacent allocation offsets");}
 set_free(&p,"........");
 {pthread_t t[4];struct racer r[4];unsigned mask=0;bool ok=true;memset(r,0,sizeof(r));
  for(int i=0;i<4;i++){r[i].p=&p;pthread_create(&t[i],NULL,take_two,&r[i]);}
  for(int i=0;i<4;i++){pthread_join(t[i],NULL);if(r[i].result){ok=false;continue;}for(int k=0;k<2;k++){if(mask&(1U<<r[i].f[k].index))ok=false;mask|=1U<<r[i].f[k].index;}}
  CHECK(ok&&mask==255,"four concurrent alloc(2) calls get disjoint frames covering the pool");}
 p.ops->release(&p);
 if(failures){printf("# %d pool frame checks failed\n",failures);return 1;}
 puts("ok 1 - GPU pool binds any supported frame size and allocates multi-frame batches with run preference and rollback");
 return 0;
}
'''


def main():
    contract = (KERNEL / "include/linux/xdev_ext_mech.h").read_text()
    pool = (KERNEL / "io_uring/xdev_ext_mech_peer_pool.c").read_text()
    pool = pool[pool.index("struct xdev_ext_peer_mech_pool {"):]
    support = "".join(BASE["struct"](contract, name) for name in
                      ("xdev_ext_mech_frame", "xdev_ext_mech_pool_ops", "xdev_ext_mech_pool")) + BASE["GLUE"]
    with tempfile.TemporaryDirectory(prefix="peer-pool-frames-") as tmp:
        source = Path(tmp) / "actual.c"
        binary = Path(tmp) / "actual"
        # The pool may use the shared PEER geometry rule from the step header.
        source.write_text(BASE["SHIM"] + '#include "io_uring/xdev_ext_mech_step.h"\n' + support + pool + MAIN)
        compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                                   "-fsanitize=undefined", "-pthread", "-I" + str(KERNEL), str(source), "-o", str(binary)],
                                  capture_output=True, text=True)
        if compiled.returncode:
            print(compiled.stderr, file=sys.stderr)
            raise SystemExit("not ok - production GPU pool does not compile under the pool adapters")
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        print(result.stdout, end="")
        if result.returncode:
            print(result.stderr, end="", file=sys.stderr)
            raise SystemExit(1)


if __name__ == "__main__":
    main()
