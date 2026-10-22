#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run actual NVIDIA peer adapter functions against ownership-aware API stubs.

The stubs follow this checkout's NVIDIA590 nv-p2p.c: successful persistent put
destroys the page table, DMA unmap destroys its mapping, free_* APIs are no-ops.
This is host control/lifetime evidence, never physical DMA evidence.
"""
from pathlib import Path
import os
import subprocess
import tempfile

KERNEL = Path(__file__).resolve().parents[4]
GPU = Path(os.environ.get("XDEV_EXT_GPU_SOURCE", str(KERNEL.parent / "gpu")))
SHIM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
typedef uint64_t u64; typedef uint8_t NvU8; typedef int nvidia_stack_t;
#define NVIDIA_P2P_GPU_UUID_LEN 16
#define NVIDIA_P2P_FLAGS_DEFAULT 0
#define NVIDIA_P2P_PAGE_SIZE_64KB 1
#define NVIDIA_P2P_PAGE_SIZE_128KB 2
#define NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE(p) ((p)->version==1)
#define NVIDIA_P2P_DMA_MAPPING_VERSION_COMPATIBLE(p) ((p)->version==1)
#define NV_DBG_ERRORS 0
#define GFP_KERNEL 0
#define THIS_MODULE NULL
#define WARN_ON(x) assert(!(x))
struct file_operations { int unused; };
struct inode { bool control; };
typedef struct { int unused; } nv_linux_state_t;
typedef struct { nv_linux_state_t *nvptr; int open_rc; } nv_linux_file_private_t;
struct file { struct inode inode; nv_linux_file_private_t *private_data; };
#define NV_GET_LINUX_FILE_PRIVATE(f) ((f)->private_data)
#define NV_FILE_INODE(f) (&(f)->inode)
#define NV_STATE_PTR(x) (x)
struct pci_dev { int id; };
struct nvidia_p2p_page_table { int version; NvU8 *gpu_uuid; };
struct nvidia_p2p_dma_mapping { int version,page_size_type; uint32_t entries; u64 *dma_addresses; };
struct xdev_ext_peer_dma { void *private;const u64 *addresses;uint32_t entries;uint8_t page_shift; };
struct xdev_ext_peer_provider_ops { void *owner;const struct file_operations *fops;int (*pin)(struct file*,u64,u64,void**);int (*unpin)(void*);int (*map)(void*,struct pci_dev*,struct xdev_ext_peer_dma*);int (*unmap)(void*,struct pci_dev*,struct xdev_ext_peer_dma*); };
static int allocations,frees,pm_depth,nv_system_pm_lock,stacks,module_refs;
static int wait_error,lock_error,stack_error,get_error,put_error,map_error,unmap_error;
static int gets,put_calls,maps,unmaps,live_pages,live_mapping;
static bool no_uuid;
static NvU8 gpu_uuid[16]={1}, page_uuid[16]={1}; static u64 addresses[2]={0x900000,0xb00000};
static struct nvidia_p2p_page_table pages={1,page_uuid};
static struct nvidia_p2p_dma_mapping mapping={1,1,2,addresses};
static struct pci_dev *mapped_peer;
static void *kzalloc(size_t n,int flags) { (void)flags;allocations++;return calloc(1,n); }
static void kfree(void *p) { if(p){frees++;free(p);} }
static bool nv_is_control_device(struct inode *i){return i->control;}
static int nv_wait_open_complete_interruptible(nv_linux_file_private_t *f){assert(f);return wait_error;}
static int nv_down_read_interruptible(int *l){assert(l==&nv_system_pm_lock);if(lock_error)return lock_error;pm_depth++;return 0;}
static void down_read(int *l){assert(l==&nv_system_pm_lock);pm_depth++;}
static void up_read(int *l){assert(l==&nv_system_pm_lock && pm_depth>0);pm_depth--;}
static int nv_kmem_cache_alloc_stack(nvidia_stack_t **s){if(stack_error)return stack_error;stacks++;*s=(void*)1;return 0;}
static void nv_kmem_cache_free_stack(nvidia_stack_t *s){assert(s && stacks>0);stacks--;}
static const NvU8 *rm_get_gpu_uuid_raw(nvidia_stack_t *s,nv_linux_state_t *n){assert(s && n && pm_depth);return no_uuid?NULL:gpu_uuid;}
static int nvidia_p2p_get_pages_persistent(u64 va,u64 len,struct nvidia_p2p_page_table **p,unsigned flags)
{assert(pm_depth && va==0x200000 && len==131072 && !flags);gets++;if(get_error)return get_error;assert(!live_pages);live_pages++;*p=&pages;return 0;}
static int nvidia_p2p_put_pages_persistent(u64 va,struct nvidia_p2p_page_table *p,unsigned flags)
{assert(pm_depth && va==0x200000 && p==&pages && !flags && live_pages && !live_mapping);put_calls++;if(put_error)return put_error;live_pages--;return 0;}
static int nvidia_p2p_dma_map_pages(struct pci_dev *p,struct nvidia_p2p_page_table *pt,struct nvidia_p2p_dma_mapping **m)
{assert(pm_depth && p && pt==&pages && live_pages && !live_mapping);maps++;if(map_error)return map_error;mapped_peer=p;live_mapping++;*m=&mapping;return 0;}
static int nvidia_p2p_dma_unmap_pages(struct pci_dev *p,struct nvidia_p2p_page_table *pt,void *m)
{assert(pm_depth && p==mapped_peer && pt==&pages && m==&mapping && live_mapping && live_pages);unmaps++;if(unmap_error)return unmap_error;live_mapping--;return 0;}
static void __module_get(void *module){(void)module;module_refs++;}
static void nv_printf(int lvl,const char *message,...){(void)lvl;(void)message;}
static int xdev_ext_peer_provider_register(const struct xdev_ext_peer_provider_ops *o){assert(o->pin && o->fops);return 0;}
static int xdev_ext_peer_provider_unregister(const struct xdev_ext_peer_provider_ops *o){assert(o->pin && o->fops);return 0;}
'''
MAIN = r'''
int main(void)
{
 nv_linux_state_t nvl={};nv_linux_file_private_t private={&nvl,0};struct file f={{false},&private};
 const struct file_operations fops={};struct pci_dev peer={7};struct xdev_ext_peer_dma dma={};void *a=NULL;int before;
 nv_xdev_ext_peer_init(&fops);nv_xdev_ext_peer_exit();
 assert(nv_xdev_ext_peer_pin(&f,0x200001,131072,&a)==-EINVAL && !gets);
 f.inode.control=true;assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==-EINVAL && !gets);f.inode.control=false;
 wait_error=-EINTR;assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==-EINTR && !gets);wait_error=0;
 private.open_rc=-1;assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==-ENODEV);private.open_rc=0;
 lock_error=-EINTR;assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==-EINTR && allocations==frees);lock_error=0;
 stack_error=-ENOMEM;assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==-ENOMEM && allocations==frees && !pm_depth);stack_error=0;
 no_uuid=true;assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==-ENODEV && !gets && !stacks);no_uuid=false;
 puts("ok 1 - real NVIDIA adapter rejects wrong device/alignment/open state and unwinds lock/stack failures");
 assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==0 && a && live_pages==1 && !pm_depth && !stacks);
 assert(nv_xdev_ext_peer_map(a,&peer,&dma)==0 && dma.private==&mapping && dma.addresses==addresses && dma.entries==2 && dma.page_shift==16);
 assert(live_mapping==1 && mapped_peer==&peer && !pm_depth);
 assert(nv_xdev_ext_peer_unmap(a,&peer,&dma)==0 && !live_mapping && live_pages==1);
 assert(nv_xdev_ext_peer_unpin(a)==0 && !live_pages && allocations==frees && !pm_depth);
 puts("ok 2 - real NVIDIA adapter pins persistent pages, maps exact PCI device and unmaps before releasing persistent pages");
 page_uuid[0]=2;a=NULL;
 assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==-EXDEV && !a && !live_pages && allocations==frees);
 page_uuid[0]=1;get_error=-EIO;
 assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==-EIO && !live_pages && allocations==frees);get_error=0;
 assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==0);before=frees;
 map_error=-EIO;assert(nv_xdev_ext_peer_map(a,&peer,&dma)==-EIO && !live_mapping);map_error=0;
 assert(nv_xdev_ext_peer_map(a,&peer,&dma)==0);unmap_error=-EIO;
 assert(nv_xdev_ext_peer_unmap(a,&peer,&dma)==-EIO && live_mapping && live_pages && frees==before);
 unmap_error=0;assert(nv_xdev_ext_peer_unmap(a,&peer,&dma)==0);
 put_error=-EIO;assert(nv_xdev_ext_peer_unpin(a)==-EIO && live_pages && frees==before);put_error=0;
 assert(nv_xdev_ext_peer_unpin(a)==0 && !live_pages && allocations==frees);
 puts("ok 3 - real NVIDIA adapter enforces GPU UUID and retains private handles on native unmap/unpin failure");
 assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==0);
 mapping.page_size_type=NVIDIA_P2P_PAGE_SIZE_128KB;assert(nv_xdev_ext_peer_map(a,&peer,&dma)==0 && dma.page_shift==17);
 assert(nv_xdev_ext_peer_unmap(a,&peer,&dma)==0);mapping.version=2;
 assert(nv_xdev_ext_peer_map(a,&peer,&dma)==0 && dma.page_shift==0 && dma.private==&mapping);
 assert(nv_xdev_ext_peer_unmap(a,&peer,&dma)==0 && nv_xdev_ext_peer_unpin(a)==0);
 puts("ok 4 - real NVIDIA adapter preserves malformed native mapping for common cleanup and supports both NVIDIA page sizes");
 page_uuid[0]=2;put_error=-EIO;a=NULL;before=frees;
 assert(nv_xdev_ext_peer_pin(&f,0x200000,131072,&a)==-EXDEV && !a && live_pages && frees==before && module_refs==1);
 assert(!pm_depth && !stacks);
 puts("ok 5 - real NVIDIA adapter retains persistent allocation and module if mismatched GPU cleanup itself fails");
 return 0;
}
'''


def execute(code, directory, name):
    source = directory / (name + ".c")
    source.write_text(SHIM + code + MAIN)
    binary = directory / name
    compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return subprocess.run([str(binary)], capture_output=True, text=True)


def main():
    source = (GPU / "kernel-open/nvidia/nv-xdev_ext-peer.c").read_text()
    code = source[source.index("struct nv_xdev_ext_peer_allocation {"):]
    mutations = [
        ("GPU identity bypass", code.replace("memcmp(uuid, a->pages->gpu_uuid, NVIDIA_P2P_GPU_UUID_LEN)", "(memcmp(uuid, a->pages->gpu_uuid, NVIDIA_P2P_GPU_UUID_LEN) && false)")),
        ("failed unpin frees handle", code.replace("if (!rc) kfree(a);", "kfree(a);")),
        ("wrong peer DMA page size", code.replace("out->page_shift = 17", "out->page_shift = 16")),
        ("failed GPU mismatch put drops module", code.replace("__module_get(THIS_MODULE);", "if (false) __module_get(THIS_MODULE);")),
    ]
    with tempfile.TemporaryDirectory(prefix="independent-gpu-peer-") as tmp:
        directory = Path(tmp)
        result = execute(code, directory, "actual")
        print(result.stdout, end="")
        assert result.returncode == 0, result.stderr
        for i, (name, changed) in enumerate(mutations):
            assert changed != code, name
            result = execute(changed, directory, "mutation" + str(i))
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
