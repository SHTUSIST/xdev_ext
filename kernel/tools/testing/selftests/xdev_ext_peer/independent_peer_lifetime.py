#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent execution of real peer core + allocation-fd lifetime code.

Host software adapters prove reference/bounds/cleanup behavior, not DMA. Every
mutation must compile and fail an assertion in the unchanged behavior oracle.
Run directly; no dependency on the original peer selftest assertions.
"""
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[3]


def actual_fd_code():
    source = (KERNEL / "io_uring/xdev_ext_peer_fd.c").read_text()
    return source[source.index("struct xdev_ext_peer_fd {"):source.index("static long xdev_ext_peer_ctl_ioctl(")]


SHIM = (HERE / "xdev_ext_peer_test_shim.h").read_text()
SHIM = SHIM.replace("struct file_operations { int unused; };", """
struct inode { int unused; };
struct file;
struct file_operations { void *owner; int (*release)(struct inode *, struct file *); };
""")
SHIM = SHIM.replace("struct file { const struct file_operations *f_op; int refs; };", "struct file { const struct file_operations *f_op; int refs; void *private_data; };")
SHIM = SHIM.replace("static inline void fput(struct file *f) { f->refs--; }", "static inline void fput(struct file *f) { assert(f->refs > 0); if (!--f->refs && f->f_op->release) f->f_op->release(NULL,f); }")
SHIM = "#include <assert.h>\n#include <stdio.h>\n#include <string.h>\n" + SHIM + "\ntypedef uint16_t u16;\n"
SHIM += r'''
#define THIS_MODULE NULL
#define list_for_each_entry_safe(p,n,h,m) for (p=container_of((h)->next,__typeof__(*p),m), n=container_of(p->m.next,__typeof__(*p),m); &p->m!=(h); p=n,n=container_of(n->m.next,__typeof__(*n),m))
#define O_RDWR 2
#define CAP_SYS_RAWIO 17
#define ERR_PTR(n) ((void *)(intptr_t)(n))
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096)
#define PTR_ERR(p) ((int)(intptr_t)(p))
static bool rawio=true;
static bool capable(int cap) { (void)cap; return rawio; }
static struct file *anon_inode_getfile(const char *name, const struct file_operations *ops, void *private, int flags)
{ (void)name; (void)flags; struct file *f=calloc(1,sizeof(*f)); assert(f); f->f_op=ops; f->refs=1; f->private_data=private; return f; }
static struct file *fd_table[16];
static struct file *fget(int fd) { struct file *f=fd>=0 && fd<16?fd_table[fd]:NULL; if(f)get_file(f); return f; }
'''

MAIN = r'''
static struct module provider_module;
static const struct file_operations gpu_fops = {};
static const struct file_operations wrong_fops = {};
static int pins, unpins, maps, unmaps, pin_error, unpin_error, map_error, unmap_error;
static int geometry;
static u64 addresses[2] = {0x100000,0x400000};
static int provider_pin(struct file *f, u64 va, u64 len, void **out)
{ (void)f; (void)va; (void)len; pins++; *out=addresses; return pin_error; }
static int provider_unpin(void *a) { assert(a==addresses); unpins++; return unpin_error; }
static int provider_map(void *a, struct pci_dev *p, struct xdev_ext_peer_dma *out)
{ assert(a==addresses); assert(p); maps++; out->addresses=addresses; out->entries=geometry?0:2; out->page_shift=16; return map_error; }
static int provider_unmap(void *a, struct pci_dev *p, struct xdev_ext_peer_dma *out)
{ assert(a==addresses); assert(p); assert(out->addresses==addresses); unmaps++; return unmap_error; }
static struct xdev_ext_peer_provider_ops ops={.owner=&provider_module,.fops=&gpu_fops,.pin=provider_pin,.unpin=provider_unpin,.map=provider_map,.unmap=provider_unmap};
static struct file gpu={.f_op=&gpu_fops,.refs=1};
static struct xdev_ext_peer_region *region(void)
{ struct xdev_ext_peer_region *r=NULL; assert(xdev_ext_peer_pin(&gpu,0x100000,131072,&r)==0); assert(r); return r; }
static struct file allocation(struct xdev_ext_peer_region *r)
{ struct xdev_ext_peer_fd *p=calloc(1,sizeof(*p)); assert(p); mutex_init(&p->lock); INIT_LIST_HEAD(&p->maps); p->region=r; return (struct file){.f_op=&xdev_ext_peer_allocation_fops,.refs=1,.private_data=p}; }
static void reset_counts(void) { pins=unpins=maps=unmaps=0; pin_error=unpin_error=map_error=unmap_error=geometry=0; }
int main(void)
{
 struct xdev_ext_peer_region *r; struct xdev_ext_peer_mapping *m; struct pci_dev peer={0};
 struct xdev_ext_peer_fd_lease h={}; struct xdev_ext_peer_lease a={}, b={}, copied;
 struct file f, wrong={.f_op=&wrong_fops,.refs=1}; u64 gen; int old;
 assert(xdev_ext_peer_provider_register(&ops)==0);
 assert(xdev_ext_peer_provider_register(&ops)==-EEXIST);
 pin_error=-EIO; r=(void*)1;
 assert(xdev_ext_peer_pin(&gpu,0,65536,&r)==-EIO && !r);
 assert(provider_module.refs==0 && gpu.refs==1);
 reset_counts(); r=region(); gen=xdev_ext_peer_generation(r);
 assert(gen && gpu.refs==2 && provider_module.refs==1);
 assert(xdev_ext_peer_provider_unregister(&ops)==-EBUSY);
 assert(xdev_ext_peer_map(r,&peer,DMA_TO_DEVICE,&m)==0 && peer.refs==1);
 assert(xdev_ext_peer_acquire(m,gen,65536-512,1024,DMA_TO_DEVICE,&a)==-ERANGE);
 assert(xdev_ext_peer_acquire(m,gen,131072,512,DMA_TO_DEVICE,&a)==-ERANGE);
 assert(xdev_ext_peer_acquire(m,gen-1,0,512,DMA_TO_DEVICE,&a)==-ESTALE);
 assert(xdev_ext_peer_acquire(m,gen,0,512,DMA_FROM_DEVICE,&a)==-EACCES);
 assert(xdev_ext_peer_acquire(m,gen,65536+32,512,DMA_TO_DEVICE,&a)==0 && a.dma_address==0x400020);
 copied=a; assert(xdev_ext_peer_release(&copied,copied.ticket,true)==-ESTALE);
 assert(xdev_ext_peer_release(&a,a.ticket+1,true)==-ESTALE);
 assert(xdev_ext_peer_unmap(m)==-EBUSY && !unmaps);
 assert(xdev_ext_peer_acquire(m,gen,0,512,DMA_TO_DEVICE,&a)==-EBUSY);
 assert(xdev_ext_peer_release(&a,a.ticket,true)==0);
 assert(xdev_ext_peer_unmap(m)==0 && unmaps==1 && peer.refs==0);
 assert(xdev_ext_peer_unpin(r)==0 && provider_module.refs==0 && gpu.refs==1);
 puts("ok 1 - real core: exact geometry, stale generations, lease identity, direction, busy unregister and refs");

 reset_counts(); r=region(); f=allocation(r); gen=xdev_ext_peer_generation(r); fd_table[3]=&f;
 assert(xdev_ext_peer_fd_acquire(15,&peer,gen,0,512,DMA_TO_DEVICE,&h)==-EBADF);
 fd_table[4]=&wrong;
 assert(xdev_ext_peer_fd_acquire(4,&peer,gen,0,512,DMA_TO_DEVICE,&h)==-EINVAL && wrong.refs==1);
 assert(xdev_ext_peer_fd_acquire(3,&peer,gen,0,512,DMA_TO_DEVICE,&h)==0 && f.refs==2);
 assert(maps==1 && peer.refs==1);
 /* Closing/reusing fd number cannot change request's held allocation. */
 fd_table[3]=&wrong; fput(&f); assert(f.refs==1 && !unmaps && !unpins);
 assert(xdev_ext_peer_fd_acquire(3,&peer,gen,0,512,DMA_TO_DEVICE,&(struct xdev_ext_peer_fd_lease){})==-EINVAL);
 xdev_ext_peer_fd_release(&h,true);
 assert(!h.file && f.refs==0 && unmaps==1 && unpins==1 && !peer.refs && !provider_module.refs);
 puts("ok 2 - real fd: bad type, close/reuse, held file keeps mapping and allocation until last lease");

 reset_counts(); r=region(); f=allocation(r); gen=xdev_ext_peer_generation(r);
 assert(xdev_ext_peer_file_acquire(&f,&peer,gen,0,512,DMA_TO_DEVICE,&h)==0);
 xdev_ext_peer_fd_release(&h,true);
 assert(xdev_ext_peer_file_acquire(&f,&peer,gen,65536,512,DMA_FROM_DEVICE,&h)==0);
 assert(maps==1 && h.lease.dma_address==0x400000);
 xdev_ext_peer_fd_release(&h,true); fput(&f);
 assert(unmaps==1 && unpins==1 && !peer.refs && !provider_module.refs);
 puts("ok 3 - real fd: cached bidirectional map composes both directions with exactly one native map/unmap");

 reset_counts(); r=region(); f=allocation(r); gen=xdev_ext_peer_generation(r);
 assert(xdev_ext_peer_file_acquire(&f,&peer,gen,0,512,DMA_TO_DEVICE,&h)==0);
 xdev_ext_peer_fd_release(&h,false); fput(&f);
 assert(!unmaps && !unpins && peer.refs==1 && provider_module.refs==1 && gpu.refs==2);
 assert(xdev_ext_peer_provider_unregister(&ops)==-EBUSY);
 puts("ok 4 - real fd: uncertain completion permanently retains GPU/PCI/module allocation, prevents unregister");

 reset_counts(); r=region(); geometry=1; unmap_error=-EIO; old=provider_module.refs;
 m=(void*)1; assert(xdev_ext_peer_map(r,&peer,DMA_TO_DEVICE,&m)==-EPROTO && !m);
 assert(unmaps==1 && xdev_ext_peer_unpin(r)==-EIO && provider_module.refs==old);
 assert(peer.refs==2 && gpu.refs==3);
 puts("ok 5 - real core: malformed provider geometry and failed native cleanup quarantine every reference");

 reset_counts(); r=region(); assert(xdev_ext_peer_map(r,&peer,DMA_TO_DEVICE,&m)==0);
 gen=xdev_ext_peer_generation(r); xdev_ext_peer_invalidate(r);
 assert(xdev_ext_peer_acquire(m,gen,0,512,DMA_TO_DEVICE,&b)==-ESTALE);
 unmap_error=-EIO; assert(xdev_ext_peer_unmap(m)==-EIO);
 assert(xdev_ext_peer_unpin(r)==-EIO && peer.refs==3);
 reset_counts(); r=region(); unpin_error=-EIO; old=provider_module.refs;
 assert(xdev_ext_peer_unpin(r)==-EIO && provider_module.refs==old);
 assert(xdev_ext_peer_unpin(r)==-EIO && unpins==1);
 puts("ok 6 - real core: explicit invalidation, unmap and unpin failures cannot free or retry retained resources");
 return 0;
}
'''


def run(core, fd, directory, name):
    source = directory / (name + ".c")
    source.write_text(SHIM + "\n#define XDEV_EXT_PEER_HOST_TEST\n#include \"" + str(KERNEL / "include/linux/xdev_ext_peer.h") + "\"\n" + core + fd + MAIN)
    binary = directory / name
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-pthread", str(source), "-o", str(binary)], check=True, capture_output=True, text=True)
    return subprocess.run([str(binary)], capture_output=True, text=True)


def main():
    core_source = (KERNEL / "io_uring/xdev_ext_peer.c").read_text()
    core = core_source[core_source.index("struct xdev_ext_peer_provider {"):]
    fd = actual_fd_code()
    mutations = [
        ("generation bypass", core.replace("generation != r->generation", "(generation && false)"), fd),
        ("cross GPU page span", core.replace("len > page_size - (offset & (page_size - 1))", "page_size == 0"), fd),
        ("uncertain completion cleanup", core.replace("if (!quiesced) r->invalid = r->quarantined = true;", "(void)quiesced;"), fd),
        ("fd type confusion", core, fd.replace("} else return -EINVAL;", "} else return -EBADF;")),
        ("module pin removed", core.replace("try_module_get(p->ops->owner)", "true"), fd),
    ]
    with tempfile.TemporaryDirectory(prefix="independent-peer-life-") as tmp:
        directory = Path(tmp)
        result = run(core, fd, directory, "actual")
        print(result.stdout, end="")
        if result.returncode:
            print(result.stderr, end="")
            raise SystemExit(result.returncode)
        for i, (name, changed_core, changed_fd) in enumerate(mutations):
            assert (changed_core, changed_fd) != (core, fd), name
            result = run(changed_core, changed_fd, directory, "mutation" + str(i))
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
