#!/usr/bin/env python3
"""Run real fixture open/mmap and kernel remap_vmalloc_range flag/bounds logic."""
import pathlib,re,subprocess,tempfile,unittest
HERE=pathlib.Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'mm/vmalloc.c').is_file())
def fn(text,name):
    m=re.search(r'^(?:static )?[^;{}]*\b'+name+r'\([^;{}]*\)\n\{\n.*?^\}',text,re.M|re.S)
    if not m:raise AssertionError('missing function '+name)
    return m[0]
class Mapping(unittest.TestCase):
 def test_real_vmalloc_guard(self):
  vm=(ROOT/'mm/vmalloc.c').read_text();sim=(HERE/'xdev_ext_dma_provider_sim.c').read_text()
  code=r'''
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096UL
#define PAGE_ALIGN(x) (((x)+PAGE_SIZE-1)&~(PAGE_SIZE-1))
#define PAGE_ALIGNED(x) (!((uintptr_t)(x)&(PAGE_SIZE-1)))
#define VM_USERMAP 1
#define VM_DMA_COHERENT 2
#define VM_DONTEXPAND 4
#define VM_DONTDUMP 8
#define GFP_KERNEL 0
#define DMA_FIXTURE_MAP_BYTES (8U*1024U*1024U)
#define check_add_overflow(a,b,c) __builtin_add_overflow(a,b,c)
#define check_shl_overflow(a,b,c) ((*(c)=(a)<<(b)),((*(c)>>(b))!=(a)))
#define kzalloc(n,g) calloc(1,n)
#define kfree(p) free(p)
#define vfree(p) free(p)
#define mutex_init(p) (*(p)=0)
struct vm_struct { void *addr;unsigned long size,flags; };
struct vm_area_struct { unsigned long vm_start,vm_end,vm_pgoff,flags; };
struct page { int unused; };
struct inode { int unused; };
struct file { void *private_data; };
struct sim_device { void *window;int lock; };
static struct vm_struct allocation;static unsigned inserted;
static void *allocate(unsigned long size,unsigned long flags) {
 void *p=NULL;if(posix_memalign(&p,PAGE_SIZE,size))return NULL;
 memset(p,0,size);allocation=(struct vm_struct){.addr=p,.size=size,.flags=flags};return p;
}
static void *vzalloc(unsigned long bytes) { return allocate(bytes,0); }
static void *vmalloc_user(unsigned long bytes) { return allocate(bytes,VM_USERMAP); }
static struct vm_struct *find_vm_area(void *p) { return p==allocation.addr?&allocation:NULL; }
static unsigned long get_vm_area_size(struct vm_struct *p) { return p->size; }
static struct page *vmalloc_to_page(void *p) { return (struct page *)p; }
static int vm_insert_page(struct vm_area_struct *v,unsigned long at,struct page *p) {
 assert(at>=v->vm_start && at<v->vm_end && p);inserted++;return 0;
}
static void vm_flags_set(struct vm_area_struct *v,unsigned flags) {v->flags|=flags;}
/* REAL_FUNCTIONS */
int main(void) {
 struct file f={0};struct inode i={0};
 struct vm_area_struct v={.vm_start=0x100000,.vm_end=0x100000+DMA_FIXTURE_MAP_BYTES};
 assert(!sim_open(&i,&f));
 int ret=sim_mmap(&f,&v);
 if(ret) { fprintf(stderr,"FAIL actual remap_vmalloc_range rejected fixture allocation: %d flags=%lu\n",ret,allocation.flags);return 1; }
 assert(inserted==DMA_FIXTURE_MAP_BYTES/PAGE_SIZE);
 for(unsigned n=0;n<DMA_FIXTURE_MAP_BYTES;n++)assert(!((unsigned char *)allocation.addr)[n]);
 v.vm_pgoff=1;assert(sim_mmap(&f,&v)==-EINVAL);v.vm_pgoff=0;
 v.vm_end-=PAGE_SIZE;assert(sim_mmap(&f,&v)==-EINVAL);v.vm_end+=PAGE_SIZE;
 assert(!sim_release(&i,&f));
 void *bare=vzalloc(DMA_FIXTURE_MAP_BYTES);assert(bare);
 assert(remap_vmalloc_range(&v,bare,0)==-EINVAL);free(bare);
 puts("PASS real fixture open/mmap and kernel VM_USERMAP rejection, zeroed map, exact bounds");return 0;
}
'''
  funcs=[fn(vm,n) for n in ('remap_vmalloc_range_partial','remap_vmalloc_range')]
  funcs += [fn(sim,n) for n in ('sim_open','sim_release','sim_mmap')]
  code=code.replace('/* REAL_FUNCTIONS */','\n\n'.join(funcs))
  with tempfile.TemporaryDirectory(prefix='xdev-ext-mmap-') as tmp:
   c=pathlib.Path(tmp)/'t.c';c.write_text(code);exe=pathlib.Path(tmp)/'t'
   p=subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter',str(c),'-o',str(exe)],capture_output=True,text=True)
   self.assertEqual(p.returncode,0,p.stderr)
   p=subprocess.run([str(exe)],capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stderr);print(p.stdout.strip())
if __name__=='__main__':unittest.main(verbosity=2)
