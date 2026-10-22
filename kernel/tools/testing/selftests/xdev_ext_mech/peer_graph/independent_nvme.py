#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual GPU NVMe graph submit: admitted offsets and native ownership result.

No bio, payload storage, device emulator, provider or physical DMA is created.
The private native peer_rw boundary records its immutable request and outcome.
"""
from pathlib import Path
import subprocess
import tempfile

KERNEL = Path(__file__).resolve().parents[5]
SHIM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "include/linux/nvme_xdev_ext_passthru.h"
#include "include/uapi/linux/xdev_ext_peer.h"
typedef uint8_t u8;typedef uint32_t u32;typedef uint64_t u64;
struct file {int unused;};static struct file authority;
struct nvme_ns;
struct ctrl_ops {int(*peer_rw)(struct nvme_ns*,const struct xdev_ext_peer_nvme_rw*,struct file*,bool*);};
struct ctrl {const struct ctrl_ops *ops;};struct nvme_ns {struct ctrl *ctrl;};
struct nvme_xdev_ext_mech_stage {struct nvme_ns *ns;bool write;};
struct xdev_ext_mech_pool {u32 kind,frame_size,nr_frames;};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;};
struct xdev_ext_mech_stage {void *priv;struct xdev_ext_mech_session *s;};
struct xdev_ext_mech_frame {void *kaddr;u64 umem_addr;u32 index,data_off,data_len;};
struct xdev_ext_mech_batch {void *priv;struct xdev_ext_mech_frame f;u32 nr,bytes;u64 ticket;};
static int calls,completions,sequesters,last_status,native_result;static bool native_accepted;
static struct xdev_ext_peer_nvme_rw observed;
static int native(struct nvme_ns *ns,const struct xdev_ext_peer_nvme_rw *u,struct file *f,bool *accepted)
{assert(ns&&f==&authority&&accepted);calls++;observed=*u;*accepted=native_accepted;return native_result;}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b){return b->priv;}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return &s->pool;}
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b){return b->nr;}
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 pos,struct xdev_ext_mech_frame *f){if(pos||!b->nr)return -EINVAL;*f=b->f;return 0;}
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b){return b->bytes;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b){return b->ticket;}
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p){assert(p->kind==3);return 87;}
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p){assert(p->kind==3);return &authority;}
static void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch *b,u64 ticket,int status){assert(ticket==b->ticket&&!completions&&!sequesters);completions++;last_status=status;}
static void xdev_ext_mech_batch_sequester(struct xdev_ext_mech_batch *b,u64 ticket,int status){assert(ticket==b->ticket&&!completions&&!sequesters);sequesters++;last_status=status;}
'''
MAIN = r'''
int main(void)
{
 const struct ctrl_ops ops={native};struct ctrl ctrl={&ops};struct nvme_ns ns={&ctrl};
 struct nvme_xdev_ext_mech_stage private={&ns,false};struct xdev_ext_mech_session s={.pool={3,65536,4}};
 struct xdev_ext_mech_stage st={&private,&s};struct nvme_xdev_ext_mech_batch bp={};
 struct xdev_ext_mech_batch b={.priv=&bp,.f={.umem_addr=65536,.index=1,.data_off=512,.data_len=1024},.nr=1,.bytes=1024,.ticket=11};
 bp.sqe[40]=0x21;bp.sqe[41]=0x43;bp.sqe[42]=0x65;bp.sqe[43]=0x87;bp.sqe[44]=0x34;bp.sqe[45]=0x12;
 native_accepted=true;assert(!nvme_xdev_ext_peer_submit(&st,&b)&&calls==1&&completions==1&&!sequesters&&!last_status);
 assert(observed.allocation_fd==-1&&!observed.flags&&!observed.reserved&&observed.generation==87&&observed.offset==65536+512&&observed.bytes==1024&&observed.slba==0x123487654321ULL);
 assert(!bp.bio&&!bp.slot&&!bp.bounce&&!bp.nr_bounce);
 puts("ok 1 - actual NVMe GPU submit forwards only admitted allocation offsets, generation, length and little-endian SLBA, without a host bio");
 for(int c=0;c<7;c++){
  struct xdev_ext_mech_batch invalid=b;calls=completions=sequesters=0;
  switch(c){case 0:invalid.nr=0;break;case 1:invalid.nr=2;break;case 2:invalid.f.kaddr=(void*)1;break;case 3:invalid.f.data_len=0;break;case 4:invalid.f.umem_addr++;break;case 5:invalid.f.data_off=65537;break;case 6:invalid.bytes++;break;}
  assert(nvme_xdev_ext_peer_submit(&st,&invalid)<0&&!calls&&!completions&&!sequesters);
 }
 puts("ok 2 - actual NVMe GPU submit rejects CPU-backed, malformed or mismatched spans before any native request");
 calls=completions=sequesters=0;native_accepted=false;native_result=-EAGAIN;
 assert(nvme_xdev_ext_peer_submit(&st,&b)==-EAGAIN&&calls==1&&!completions&&!sequesters);
 calls=0;native_result=0;assert(nvme_xdev_ext_peer_submit(&st,&b)==-EPROTO&&calls==1&&!completions&&!sequesters);
 puts("ok 3 - actual NVMe GPU submit exposes preaccept backpressure and rejects zero-without-native-acceptance");
 for(int c=0;c<3;c++){
  const int status[]={-EIO,-EINTR,0x182};calls=completions=sequesters=0;native_accepted=true;native_result=status[c];
  assert(!nvme_xdev_ext_peer_submit(&st,&b)&&calls==1&&!completions&&sequesters==1&&last_status==status[c]);
  assert(bp.cqe.status==(status[c]>0?status[c]:0)&&bp.cqe.err==(status[c]<0?status[c]:0));
 }
 calls=completions=sequesters=0;native_result=0;private.write=true;
 assert(!nvme_xdev_ext_peer_submit(&st,&b)&&calls==1&&completions==1&&!sequesters&&observed.flags==XDEV_EXT_PEER_NVME_F_WRITE);
 puts("ok 4 - actual accepted NVMe errors never resubmit and sequester for errno/cancel/controller status; read and write directions remain explicit");
 return 0;
}
'''


def execute(code, structs, directory, name):
    source = directory / (name + ".c")
    binary = directory / name
    source.write_text(SHIM + structs + code + MAIN)
    compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-I" + str(KERNEL), str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return subprocess.run([str(binary)], capture_output=True, text=True)


def main():
    source = (KERNEL / "drivers/nvme/host/xdev_ext_mech_nvme.c").read_text()
    start = source.index("struct nvme_xdev_ext_mech_batch {")
    structs = source[start:source.index("\n};", start) + 3]
    start = source.index("static int nvme_xdev_ext_peer_submit(")
    code = source[start:source.index("\nstatic int nvme_xdev_ext_class_submit(", start)]
    mutations = [
        ("preaccept reported as accepted", code.replace("if (!accepted) return ret ? ret : -EPROTO;", "if (!accepted && false) return ret ? ret : -EPROTO;")),
        ("accepted error releases as ordinary completion", code.replace("if (ret) xdev_ext_mech_batch_sequester", "if (ret && false) xdev_ext_mech_batch_sequester")),
        ("GPU subspan offset omitted", code.replace("u.offset = f.umem_addr + f.data_off;", "u.offset = f.umem_addr;")),
        ("native write direction reversed", code.replace("u.flags = p->write ? XDEV_EXT_PEER_NVME_F_WRITE : 0;", "u.flags = p->write ? 0 : XDEV_EXT_PEER_NVME_F_WRITE;")),
    ]
    with tempfile.TemporaryDirectory(prefix="independent-peer-nvme-graph-") as tmp:
        directory = Path(tmp)
        result = execute(code, structs, directory, "actual")
        print(result.stdout, end="")
        assert result.returncode == 0, result.stderr
        for i, (name, changed) in enumerate(mutations):
            assert changed != code, name
            result = execute(changed, structs, directory, "mutation" + str(i))
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
