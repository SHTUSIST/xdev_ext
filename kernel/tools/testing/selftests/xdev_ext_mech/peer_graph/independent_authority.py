#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute real peer registry, leases and allocation authority under contention.

Assertions independently cover both directions of claim exclusion, original
fd lifetime, claim rollback, generation, and permanently unknown ownership.
The provider is a software boundary adapter, not physical DMA evidence.
"""
from pathlib import Path
import subprocess
import tempfile

KERNEL = Path(__file__).resolve().parents[5]
RAW_SHIM = KERNEL / "tools/testing/selftests/xdev_ext_peer/xdev_ext_peer_test_shim.h"
SHIM = RAW_SHIM.read_text()
SHIM = "#include <assert.h>\n#include <stdio.h>\n#include <string.h>\n" + SHIM
SHIM = SHIM.replace("struct file_operations { int unused; };", "struct inode { int unused; }; struct file; struct file_operations { void *owner; int (*release)(struct inode *,struct file *); };")
SHIM = SHIM.replace("struct file { const struct file_operations *f_op; int refs; };", "struct file { const struct file_operations *f_op; int refs; void *private_data; };")
SHIM = SHIM.replace("static inline void get_file(struct file *f) { f->refs++; }", "static inline void get_file(struct file *f) { __atomic_add_fetch(&f->refs,1,__ATOMIC_SEQ_CST); }")
SHIM = SHIM.replace("static inline void fput(struct file *f) { f->refs--; }", "static inline void fput(struct file *f) { int old=__atomic_fetch_sub(&f->refs,1,__ATOMIC_SEQ_CST);assert(old>0);if(old==1 && f->f_op->release)f->f_op->release(NULL,f); }")
SHIM += r'''
typedef uint16_t u16;
#define THIS_MODULE NULL
#define CAP_SYS_RAWIO 17
#define O_RDWR 2
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((intptr_t)(p))
#define list_for_each_entry_safe(p,n,h,m) for(p=container_of((h)->next,__typeof__(*p),m),n=container_of(p->m.next,__typeof__(*p),m);&p->m!=(h);p=n,n=container_of(n->m.next,__typeof__(*n),m))
static bool rawio=true;
static int anon_error;
static bool capable(int cap){assert(cap==CAP_SYS_RAWIO);return rawio;}
static struct file *anon_inode_getfile(const char *name,const struct file_operations *ops,void *private,int flags)
{struct file *f;(void)name;assert(flags==O_RDWR);if(anon_error)return ERR_PTR(anon_error);f=calloc(1,sizeof(*f));assert(f);*f=(struct file){ops,1,private};return f;}
static struct file *slots[16];
static struct file *fget(int fd){struct file *f=fd>=0 && fd<16?slots[fd]:NULL;if(f)get_file(f);return f;}
'''
MAIN = r'''
static const struct file_operations gpu_ops={},wrong_ops={};
static struct module module;
static u64 addresses[4]={0x100000,0x300000,0x500000,0x700000};
static int maps,unmaps,unpins;
static int pin(struct file *f,u64 va,u64 len,void **out){assert(f && va==0 && len==262144);*out=addresses;return 0;}
static int unpin(void *a){assert(a==addresses);unpins++;return 0;}
static int map(void *a,struct pci_dev *pci,struct xdev_ext_peer_dma *d){assert(a==addresses && pci);maps++;*d=(struct xdev_ext_peer_dma){.addresses=addresses,.entries=4,.page_shift=16};return 0;}
static int unmap(void *a,struct pci_dev *pci,struct xdev_ext_peer_dma *d){assert(a==addresses && pci && d->addresses==addresses);unmaps++;return 0;}
static const struct xdev_ext_peer_provider_ops provider={.owner=&module,.fops=&gpu_ops,.pin=pin,.unpin=unpin,.map=map,.unmap=unmap};
static struct file gpu={.f_op=&gpu_ops,.refs=1};
static struct file *allocation(void)
{struct xdev_ext_peer_fd *p=calloc(1,sizeof(*p));struct file *f=calloc(1,sizeof(*f));assert(p&&f);mutex_init(&p->lock);INIT_LIST_HEAD(&p->maps);assert(!xdev_ext_peer_pin(&gpu,0,262144,&p->region));*f=(struct file){&xdev_ext_peer_allocation_fops,1,p};return f;}
static pthread_barrier_t start_gate;
struct contestant{struct file *f,*authority;struct pci_dev *pci;u64 gen,len,claim_generation;struct xdev_ext_peer_fd_lease lease;int result;};
static void *claim_racer(void *arg){struct contestant *c=arg;pthread_barrier_wait(&start_gate);c->authority=xdev_ext_peer_file_claim(c->f,&c->len,&c->claim_generation);return NULL;}
static void *lease_racer(void *arg){struct contestant *c=arg;pthread_barrier_wait(&start_gate);c->result=xdev_ext_peer_file_acquire(c->f,c->pci,c->gen,0,512,DMA_TO_DEVICE,&c->lease);return NULL;}
int main(void)
{
 struct file *f,*a,*again,wrong={.f_op=&wrong_ops,.refs=1};struct pci_dev pci={};
 struct xdev_ext_peer_fd_lease h={};u64 len=0,gen=0,query_gen=0;int before;
 assert(!xdev_ext_peer_provider_register(&provider));f=allocation();
 rawio=false;a=xdev_ext_peer_file_claim(f,&len,&gen);assert(IS_ERR(a)&&PTR_ERR(a)==-EPERM&&f->refs==1);rawio=true;
 a=xdev_ext_peer_file_claim(&wrong,&len,&gen);assert(IS_ERR(a)&&PTR_ERR(a)==-EINVAL&&wrong.refs==1);
 a=xdev_ext_peer_file_claim(f,NULL,&gen);assert(IS_ERR(a)&&PTR_ERR(a)==-EINVAL);
 anon_error=-ENFILE;a=xdev_ext_peer_file_claim(f,&len,&gen);assert(IS_ERR(a)&&PTR_ERR(a)==-ENFILE&&f->refs==1&&!((struct xdev_ext_peer_fd*)f->private_data)->claimed);anon_error=0;
 puts("ok 1 - actual authority checks capability/type/output pointers and rolls back failed anonymous-file creation");
 gen=xdev_ext_peer_generation(((struct xdev_ext_peer_fd*)f->private_data)->region);
 assert(!xdev_ext_peer_file_acquire(f,&pci,gen,0,512,DMA_FROM_DEVICE,&h));
 a=xdev_ext_peer_file_claim(f,&len,&query_gen);assert(IS_ERR(a)&&PTR_ERR(a)==-EBUSY);
 xdev_ext_peer_fd_release(&h,true);
 a=xdev_ext_peer_file_claim(f,&len,&query_gen);assert(!IS_ERR(a)&&len==262144&&query_gen==gen&&f->refs==2);
 again=xdev_ext_peer_file_claim(f,&len,&query_gen);assert(IS_ERR(again)&&PTR_ERR(again)==-EBUSY);
 again=xdev_ext_peer_file_claim(a,&len,&query_gen);assert(IS_ERR(again)&&PTR_ERR(again)==-EINVAL);
 assert(xdev_ext_peer_file_info(f,&len,&query_gen)==-EINVAL);
 assert(!xdev_ext_peer_file_info(a,&len,&query_gen)&&len==262144&&query_gen==gen);
 slots[3]=f;assert(xdev_ext_peer_fd_acquire(3,&pci,gen,0,512,DMA_TO_DEVICE,&h)==-EBUSY);
 assert(xdev_ext_peer_file_acquire(f,&pci,gen,0,512,DMA_TO_DEVICE,&h)==-EBUSY);
 puts("ok 2 - actual authority excludes active ordinary leases, duplicate claims and every alias of the original fd");
 assert(xdev_ext_peer_file_acquire(a,&pci,gen+1,0,512,DMA_TO_DEVICE,&h)==-ESTALE);
 assert(xdev_ext_peer_file_acquire(a,&pci,gen,65536-256,512,DMA_TO_DEVICE,&h)==-ERANGE);
 assert(!xdev_ext_peer_file_acquire(a,&pci,gen,65536,512,DMA_TO_DEVICE,&h)&&h.lease.dma_address==0x300000);
 before=unpins;fput(a);assert(a->refs==1 && f->refs==2 && unpins==before);
 xdev_ext_peer_fd_release(&h,true);assert(!a->refs && f->refs==1 && !((struct xdev_ext_peer_fd*)f->private_data)->claimed);
 assert(!xdev_ext_peer_file_acquire(f,&pci,gen,0,512,DMA_FROM_DEVICE,&h));xdev_ext_peer_fd_release(&h,true);
 assert(maps==1);fput(f);assert(unpins==before+1&&!pci.refs&&!module.refs&&gpu.refs==1);
 puts("ok 3 - actual authority holds original fd through native lease, preserves exact generation/bounds, normal close restores ordinary authority");
 for(int round=0;round<64;round++){
  pthread_t t1,t2;struct contestant c={.pci=&pci};f=allocation();c.f=f;c.gen=xdev_ext_peer_generation(((struct xdev_ext_peer_fd*)f->private_data)->region);
  assert(!pthread_barrier_init(&start_gate,NULL,2));assert(!pthread_create(&t1,NULL,claim_racer,&c));assert(!pthread_create(&t2,NULL,lease_racer,&c));
  assert(!pthread_join(t1,NULL)&&!pthread_join(t2,NULL));assert(!pthread_barrier_destroy(&start_gate));
  assert((!IS_ERR(c.authority)) != (c.result==0));
  if(IS_ERR(c.authority)){assert(PTR_ERR(c.authority)==-EBUSY);xdev_ext_peer_fd_release(&c.lease,true);}
  else{assert(c.result==-EBUSY);fput(c.authority);}
  fput(f);assert(!module.refs&&!pci.refs&&gpu.refs==1);
 }
 puts("ok 4 - actual authority versus ordinary acquisition race has exactly one winner in 64 real pthread interleavings");
 f=allocation();a=xdev_ext_peer_file_claim(f,&len,&gen);assert(!IS_ERR(a));
 assert(!xdev_ext_peer_file_acquire(a,&pci,gen,0,512,DMA_TO_DEVICE,&h));before=unpins;
 xdev_ext_peer_fd_release(&h,false);assert(xdev_ext_peer_file_info(a,&len,&query_gen)==-ESTALE);fput(a);
 assert(f->refs==2&&((struct xdev_ext_peer_fd*)f->private_data)->claimed&&unpins==before&&module.refs==1&&pci.refs==1);
 assert(xdev_ext_peer_file_acquire(f,&pci,gen,0,512,DMA_TO_DEVICE,&h)==-EBUSY);
 again=xdev_ext_peer_file_claim(f,&len,&query_gen);assert(IS_ERR(again)&&PTR_ERR(again)==-EBUSY);
 fput(f);assert(f->refs==1&&unpins==before&&module.refs==1&&pci.refs==1&&gpu.refs==2);
 assert(xdev_ext_peer_provider_unregister(&provider)==-EBUSY);
 puts("ok 5 - actual unknown ownership permanently retains claim/original fd/provider/PCI and rejects both reuse paths");
 return 0;
}
'''


def execute(core, fd, directory, name):
    source = directory / (name + ".c")
    binary = directory / name
    source.write_text(SHIM + '\n#define XDEV_EXT_PEER_HOST_TEST\n#include "' + str(KERNEL / "include/linux/xdev_ext_peer.h") + '"\n' + core + fd + MAIN)
    compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-pthread", str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)


def main():
    source = (KERNEL / "io_uring/xdev_ext_peer.c").read_text()
    core = source[source.index("struct xdev_ext_peer_provider {"):]
    source = (KERNEL / "io_uring/xdev_ext_peer_fd.c").read_text()
    fd = source[source.index("struct xdev_ext_peer_fd {"):source.index("static long xdev_ext_peer_ctl_ioctl(")]
    mutations = [
        ("ordinary ioctl bypasses claim", core, fd.replace("if (p->claimed != a)", "if (p->claimed != a && false)")),
        ("claim ignores active native owner", core.replace("if (m->active)", "if (m->active && false)"), fd),
        ("claim ignores capability", core, fd.replace("if (!capable(CAP_SYS_RAWIO))", "if (!capable(CAP_SYS_RAWIO) && false)")),
        ("unknown claim released", core, fd.replace("if (xdev_ext_peer_info(p->region, &len, &generation, true))", "if (xdev_ext_peer_info(p->region, &len, &generation, true) && false)")),
        ("claim loses original file reference", core, fd.replace("p->claimed = a; get_file(file);", "p->claimed = a;")),
    ]
    with tempfile.TemporaryDirectory(prefix="independent-peer-authority-") as tmp:
        directory = Path(tmp)
        result = execute(core, fd, directory, "actual")
        print(result.stdout, end="")
        assert result.returncode == 0, result.stderr
        for i, (name, changed_core, changed_fd) in enumerate(mutations):
            assert (changed_core, changed_fd) != (core, fd), name
            result = execute(changed_core, changed_fd, directory, "mutation" + str(i))
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
