// SPDX-License-Identifier: GPL-2.0-only
/* NVMe lease lifecycle OS-boundary harness; production bodies are injected. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
typedef uint64_t u64;typedef uint32_t u32;typedef uint8_t u8;typedef uint64_t atomic64_t;
#define U32_MAX UINT32_MAX
#define GFP_KERNEL 0
struct mutex {int held;};struct list_head {struct list_head *next,*prev;};
struct pci_dev {int id;};struct file_operations {int id;};
struct file {const struct file_operations *f_op;void *private_data;int refs;};
static u64 hops,locks,file_puts,file_gets,accesses;
static void mutex_lock(struct mutex*m){assert(!m->held);m->held=1;locks++;}
static void mutex_unlock(struct mutex*m){assert(m->held);m->held=0;}
static u64 atomic64_inc_return(atomic64_t*a){return ++*a;}
static void get_file(struct file*f){assert(f->refs>0);f->refs++;file_gets++;}
static void fput(struct file*f){assert(f->refs>1);f->refs--;file_puts++;}
static void *kzalloc(size_t n,int g){(void)n;(void)g;abort();}
static void kfree(void*p){(void)p;abort();}
#define list_for_each_entry(p,h,m) for(p=(void*)(h)->next;&p->m!=(h);p=(void*)p->m.next)
static void list_add_tail(struct list_head*n,struct list_head*h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
/* PRODUCTION_TYPES */
static atomic64_t xdev_ext_peer_serial;
static const struct file_operations xdev_ext_peer_allocation_fops={1},xdev_ext_peer_authority_fops={2};
static int xdev_ext_peer_map(struct xdev_ext_peer_region*r,struct pci_dev*p,enum dma_data_direction d,struct xdev_ext_peer_mapping**m){(void)r;(void)p;(void)d;(void)m;abort();}
/* PRODUCTION_FUNCTIONS */
static int allow(void*p,enum dma_data_direction d){struct xdev_ext_peer_region*r=p;assert(r->lock.held);assert(d==DMA_TO_DEVICE);accesses++;return 0;}
static struct xdev_ext_peer_fd_lease handles[1024];
static u64 addresses[1024];
static unsigned checks,failures;
#define CHECK(c) do{checks++;if(!(c)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#c);failures++;}}while(0)
static void scenario(unsigned n,unsigned depth,int reverse,int authority){
 memset(handles,0,sizeof(handles));hops=locks=file_puts=file_gets=accesses=0;
 struct xdev_ext_peer_provider_ops ops={.may_access=allow};
 struct xdev_ext_peer_region r={.ops=&ops,.len=sizeof(addresses)/sizeof(addresses[0])*4096ULL,.generation=73};r.allocation=&r;
 struct pci_dev pci={1};struct xdev_ext_peer_mapping m={.region=&r,.peer=&pci,.direction=DMA_BIDIRECTIONAL,.dma={.addresses=addresses,.entries=1024,.page_shift=12}};
 struct xdev_ext_peer_fd p={.region=&r};p.maps.next=p.maps.prev=&p.maps;
 struct xdev_ext_peer_fd_map map={.peer=&pci,.mapping=&m};list_add_tail(&map.node,&p.maps);
 struct xdev_ext_peer_authority a={.parent=&p};
 p.claimed=authority?&a:NULL;
 struct file f={.f_op=authority?&xdev_ext_peer_authority_fops:&xdev_ext_peer_allocation_fops,.private_data=authority?(void*)&a:(void*)&p,.refs=1};
 for(unsigned i=0;i<n*depth;i++){addresses[i]=0x100000000ULL+i*4096;CHECK(!xdev_ext_peer_file_acquire(&f,&pci,73,i*4096ULL,4096,DMA_TO_DEVICE,&handles[i]));}
 CHECK(m.active==n*depth);CHECK(file_gets==n*depth&&f.refs==(int)(1+n*depth));
 u64 first=0;
 for(unsigned b=0;b<depth;b++){
  u64 before=hops;
  if(reverse){for(unsigned i=n;i--;)xdev_ext_peer_fd_release(&handles[b*n+i],true);}
  else xdev_ext_stor_leases_retire(&handles[b*n],n,true);
  if(!b)first=hops-before;
  CHECK(m.active==n*(depth-b-1));CHECK(f.refs==(int)(1+n*(depth-b-1)));
  for(unsigned i=0;i<n*(b+1);i++)CHECK(!handles[i].file&&!handles[i].lease.mapping&&!handles[i].lease.next&&!handles[i].lease.len&&!handles[i].lease.dma_address);
  for(unsigned i=n*(b+1);i<n*depth;i++)CHECK(handles[i].file==&f&&handles[i].lease.mapping==&m);
 }
 CHECK(!m.leases&&!m.active);CHECK(f.refs==1&&file_puts==file_gets&&accesses==file_gets);CHECK(!r.lock.held&&!p.lock.held&&!r.invalid&&!r.quarantined);
#ifdef COUNTED_LEASE
 u64 expected=reverse?(depth==1?0:(u64)n*n):((u64)n*depth)*((u64)n*depth-1)/2;
 /* Characterized regression ceiling, not a linear-scaling claim. */
 CHECK(hops<=expected);CHECK(first<=(reverse?(depth==1?0:(u64)n*n):(u64)n*n*(depth-1)+(u64)n*(n-1)/2));
 printf("LEASE authority=%d n=%u active_batches=%u retire=%s hops=%llu first_batch_hops=%llu file_gets=%llu file_puts=%llu active=%u refs=%d\n",authority,n,depth,reverse?"reverse_control":"production_forward",(unsigned long long)hops,(unsigned long long)first,(unsigned long long)file_gets,(unsigned long long)file_puts,m.active,f.refs);
#else
 (void)first;
#endif
 /* Stale-ticket refusal must retain actual acquired fields and fd reference. */
 CHECK(!xdev_ext_peer_file_acquire(&f,&pci,73,0,4096,DMA_TO_DEVICE,&handles[0]));
 CHECK(xdev_ext_peer_release(&handles[0].lease,handles[0].lease.ticket+1,true)==-ESTALE);
 CHECK(m.active==1&&f.refs==2&&handles[0].file==&f&&handles[0].lease.mapping==&m);
 xdev_ext_peer_fd_release(&handles[0],true);u64 oldputs=file_puts;xdev_ext_peer_fd_release(&handles[0],true);CHECK(file_puts==oldputs&&!m.active&&f.refs==1);
}
int main(void){unsigned sizes[]={1,8,64,256,512};for(unsigned k=0;k<5;k++)for(unsigned depth=1;depth<=2;depth++)for(int reverse=0;reverse<=1;reverse++)for(int authority=0;authority<=1;authority++)scenario(sizes[k],depth,reverse,authority);
 printf("LEASE_CONTRACT checks=%u failures=%u\n",checks,failures);return failures?1:0;}
