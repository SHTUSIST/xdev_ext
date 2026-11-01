/* SPDX-License-Identifier: GPL-2.0 */
/* Expectations derive from frozen NET29-2 prose, never an existing test oracle. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "xdev_ext_mech_core.h"
#include "xdev_ext_peer_net_core.h"
#include "xdev_ext_netfam_core.h"
#define EQ(a,b) do { long long va=(long long)(a),vb=(long long)(b); if(va!=vb) { fprintf(stderr,"ASSERT %s:%d %s=%lld expected %s=%lld\n",__FILE__,__LINE__,#a,va,#b,vb); abort(); } } while(0)
static unsigned callback_log[128],callback_nr;
static void log_call(unsigned value) { assert(callback_nr<128); callback_log[callback_nr++]=value; }
/* Trace actual generic dispatch; callbacks below call original adapters and do
 * not implement coverage/range/entry logic. Input context remains read-only. */
static struct {
 unsigned calls; const struct xdev_ext_mech_frame_info *f; __u32 nf,n,max;
 xdev_ext_net_span_fn span; xdev_ext_net_entry_fn entry; const void *ctx;
} family;
static void forward_span(const void *ctx,__u32 i,struct xdev_ext_net_span *out) { log_call(100+i); family.span(family.ctx,i,out); }
static int forward_entry(const void *ctx,__u32 i) { log_call(200+i); return family.entry(family.ctx,i); }
static inline int observed_cover(const struct xdev_ext_mech_frame_info *f,__u32 nf,__u32 n,__u32 max,xdev_ext_net_span_fn span,xdev_ext_net_entry_fn entry,const void *ctx) {
 family.calls++; family.f=f;family.nf=nf;family.n=n;family.max=max;family.span=span;family.entry=entry;family.ctx=ctx;
 return xdev_ext_net_cover_check(f,nf,n,max,span?forward_span:NULL,entry?forward_entry:NULL,ctx);
}
#define xdev_ext_net_cover_check(...) observed_cover(__VA_ARGS__)
#include "xdev_ext_mech_net_core.h"
#undef xdev_ext_net_cover_check

struct generic_input { struct xdev_ext_mech_frame_info f[33]; struct xdev_ext_net_span s[40]; int result[40]; unsigned char unused[7]; };
static void span_cb(const void *ctx,__u32 i,struct xdev_ext_net_span *out) { const struct generic_input *c=ctx; log_call(100+i); *out=c->s[i]; }
static int entry_cb(const void *ctx,__u32 i) { const struct generic_input *c=ctx;log_call(200+i);return c->result[i]; }
static void expect_trace(const unsigned *want,size_t count) { EQ(callback_nr,count);for(size_t i=0;i<count;i++)EQ(callback_log[i],want[i]); }
static void generic(struct generic_input *g,__u32 nf,__u32 n,__u32 max,bool with_entry,int wanted,const unsigned *trace,size_t trace_n) {
 unsigned char before[sizeof(*g)]; memcpy(before,g,sizeof(*g));callback_nr=0;
 EQ(xdev_ext_net_cover_check(g->f,nf,n,max,span_cb,with_entry?entry_cb:NULL,g),wanted);
 assert(!memcmp(g,before,sizeof(*g)));expect_trace(trace,trace_n);
}
static void init_generic(struct generic_input *g) {
 memset(g,0xa5,sizeof(*g)); memset(g->result,0,sizeof(g->result));
 g->f[0]=(struct xdev_ext_mech_frame_info){.data_off=16,.data_len=128};
 g->f[1]=(struct xdev_ext_mech_frame_info){.data_off=32,.data_len=64};
 g->s[0]=(struct xdev_ext_net_span){.frame_off=16,.len=64};
 g->s[1]=(struct xdev_ext_net_span){.frame_off=80,.len=64};
 g->s[2]=(struct xdev_ext_net_span){.frame_pos=1,.frame_off=32,.len=64};
}
static void generic_vectors(void) {
 struct generic_input g;init_generic(&g);callback_nr=0;
 EQ(xdev_ext_net_cover_check(NULL,1,1,16,span_cb,entry_cb,&g),-EINVAL);
 EQ(xdev_ext_net_cover_check(g.f,1,1,16,NULL,entry_cb,&g),-EINVAL);EQ(callback_nr,0);
 generic(&g,0,1,16,true,-EINVAL,NULL,0);generic(&g,33,1,16,true,-EINVAL,NULL,0);generic(&g,1,0,16,true,-EINVAL,NULL,0);generic(&g,1,17,16,true,-EINVAL,NULL,0);
 const unsigned all[]={100,200,101,201,102,202};generic(&g,2,3,16,true,0,all,6);
 const unsigned spans[]={100,101,102};generic(&g,2,3,16,false,0,spans,3);
 const unsigned first[]={100,200};generic(&g,2,1,16,true,-EMSGSIZE,first,2);
 /* A range error must suppress simultaneous entry error and later callbacks. */
 g.s[0].frame_off=17;g.result[0]=-EILSEQ;const unsigned s0[]={100};generic(&g,2,3,16,true,-ERANGE,s0,1);
 g.s[0].frame_off=16;generic(&g,2,3,16,true,-EILSEQ,first,2);g.result[0]=7;generic(&g,2,3,16,true,7,first,2);
 init_generic(&g);g.s[1].frame_pos=1;g.s[1].frame_off=32;g.s[1].bad=1;
 const unsigned early[]={100,200,101};generic(&g,2,2,16,true,-EINVAL,early,3);g.s[1].bad=0;generic(&g,2,2,16,true,-EMSGSIZE,early,3);
 init_generic(&g);g.s[2].frame_pos=0;generic(&g,2,3,16,true,-ERANGE,(unsigned[]){100,200,101,201,102},5);
 init_generic(&g);g.s[0].frame_pos=2;generic(&g,2,1,16,true,-EINVAL,s0,1);
 /* completed frame -> move forward -> backward is EINVAL, not range. */
 g.s[0]=(struct xdev_ext_net_span){.frame_off=16,.len=128};g.s[1]=(struct xdev_ext_net_span){.frame_pos=1,.frame_off=32,.len=64};g.s[2]=(struct xdev_ext_net_span){.frame_pos=0,.frame_off=144,.len=0};generic(&g,2,3,16,true,-EINVAL,(unsigned[]){100,200,101,201,102},5);
 init_generic(&g);g.f[0].data_off=UINT32_MAX-15;g.f[0].data_len=32;g.s[0]=(struct xdev_ext_net_span){.frame_off=UINT32_MAX-15,.len=16};g.s[1]=(struct xdev_ext_net_span){.frame_off=0,.len=16};generic(&g,1,2,16,true,-ERANGE,early,3);
 g.s[0].len=32;generic(&g,1,1,16,true,0,first,2);
 /* Zero span is allowed in generic; NET's entry separately refuses zero payload. */
 init_generic(&g);g.f[0].data_len=0;g.s[0].len=0;generic(&g,1,1,16,true,0,first,2);generic(&g,1,1,16,false,0,s0,1);
 for(__u32 i=0;i<32;i++) { g.f[i]=(struct xdev_ext_mech_frame_info){.data_off=i,.data_len=1};g.s[i]=(struct xdev_ext_net_span){.frame_pos=i,.frame_off=i,.len=1}; }
 unsigned many[64];for(unsigned i=0;i<32;i++){many[2*i]=100+i;many[2*i+1]=200+i;}generic(&g,17,17,32,true,0,many,34);generic(&g,32,32,32,true,0,many,64);generic(&g,33,32,32,true,-EINVAL,NULL,0);
 puts("generic literals: pointer/count guards, callback order/status, priority pairs,64-bit offsets,zero spans,32/33 frames");
}
static void info_init(struct xdev_ext_net_mech_info *i,struct xdev_ext_net_send_desc d[40]) {
 memset(i,0xa5,sizeof(*i));memset(d,0xa5,40*sizeof(*d));
 i->nr_frames=1;i->mtu=1500;i->f[0].data_off=16;i->f[0].data_len=128;
 d[0]=(struct xdev_ext_net_send_desc){.frame_off=16,.len=128,.header_len=14};
 /* Header bytes deliberately arbitrary, including bytes beyond header_len. */
 memset(d[0].header,0x9d,sizeof(d[0].header));
}
static void wrapper(struct xdev_ext_net_mech_info *i,struct xdev_ext_net_send_desc d[40],__u32 n,int wanted) {
 unsigned char before_i[sizeof(*i)],before_d[40*sizeof(*d)];memcpy(before_i,i,sizeof(*i));memcpy(before_d,d,40*sizeof(*d));
 memset(&family,0,sizeof(family));callback_nr=0;EQ(xdev_ext_net_plan_check(i,d,n),wanted);
 assert(!memcmp(i,before_i,sizeof(*i)));assert(!memcmp(d,before_d,40*sizeof(*d)));
#ifdef TEST_SHARED
 EQ(family.calls,1);assert(family.f==i->f);EQ(family.nf,i->nr_frames);EQ(family.n,n);EQ(family.max,16);assert(family.span==xdev_ext_net_plan_span);assert(family.entry==xdev_ext_net_plan_entry);
#endif
}
static void wrapper_vectors(void) {
 struct xdev_ext_net_mech_info i;struct xdev_ext_net_send_desc d[40];info_init(&i,d);
 callback_nr=0;memset(&family,0,sizeof(family));EQ(xdev_ext_net_plan_check(NULL,d,1),-EINVAL);EQ(xdev_ext_net_plan_check(&i,NULL,1),-EINVAL);EQ(callback_nr,0);EQ(family.calls,0);
 wrapper(&i,d,1,0);wrapper(&i,d,0,-EINVAL);wrapper(&i,d,17,-EINVAL);i.nr_frames=0;wrapper(&i,d,1,-EINVAL);i.nr_frames=33;wrapper(&i,d,1,-EINVAL);i.nr_frames=32;wrapper(&i,d,1,-EMSGSIZE);
 info_init(&i,d);i.f[0].data_len=16*64;for(unsigned k=0;k<17;k++) { d[k]=(struct xdev_ext_net_send_desc){.frame_off=16+k*64,.len=64,.header_len=14};memset(d[k].header,k+17,128); }wrapper(&i,d,16,0);wrapper(&i,d,17,-EINVAL);wrapper(&i,d,15,-EMSGSIZE);
 info_init(&i,d);i.nr_frames=2;i.f[1]=(struct xdev_ext_mech_frame_info){.data_off=32,.data_len=64};d[0].len=64;d[1]=(struct xdev_ext_net_send_desc){.frame_off=80,.len=64,.header_len=14};d[2]=(struct xdev_ext_net_send_desc){.frame_pos=1,.frame_off=32,.len=64,.header_len=14};wrapper(&i,d,3,0);wrapper(&i,d,2,-EMSGSIZE);
 d[1].frame_pos=1;d[1].frame_off=32;d[1].flags=1;wrapper(&i,d,2,-EINVAL);d[1].flags=0;wrapper(&i,d,2,-EMSGSIZE);d[1].reserved=0x80000000;wrapper(&i,d,2,-EINVAL);
 info_init(&i,d);d[0].frame_off=17;d[0].header_len=1;wrapper(&i,d,1,-ERANGE);d[0].frame_off=16;wrapper(&i,d,1,-EINVAL);
 info_init(&i,d);i.mtu=0;d[0].frame_off=17;wrapper(&i,d,1,-ERANGE);d[0].frame_off=16;wrapper(&i,d,1,-EMSGSIZE);
 info_init(&i,d);for(unsigned bit=0;bit<32;bit++){d[0].flags=1U<<bit;wrapper(&i,d,1,-EINVAL);d[0].flags=0;d[0].reserved=1U<<bit;wrapper(&i,d,1,-EINVAL);d[0].reserved=0;}
 info_init(&i,d);i.f[0].data_off=UINT32_MAX-15;i.f[0].data_len=128;d[0].frame_off=UINT32_MAX-15;wrapper(&i,d,1,0);
 /* Full valid Ethernet pieces cross u32 offset boundary without wrapping. */
 i.f[0].data_off=UINT32_MAX-63;i.f[0].data_len=128;d[0].frame_off=UINT32_MAX-63;d[0].len=64;d[1]=(struct xdev_ext_net_send_desc){.frame_off=0,.len=64,.header_len=14};wrapper(&i,d,2,-ERANGE);
 info_init(&i,d);i.f[0].data_len=0;d[0].len=0;wrapper(&i,d,1,-EINVAL);
 puts("NET wrapper literals:16/17 descriptors,32/33 frames,split coverage,flags/reserved,priority,high offset,input/header bytes");
}
/* One-entry independent expected predicate, using length arithmetic and no
 * production helper. This bounded domain has a single exact-coverage span. */
static int one_expected(__u32 off,__u32 actual_off,__u32 data_len,__u32 len,__u32 header,__u32 mtu,__u32 bad) {
 if(bad)return -EINVAL;
 if((__u64)off!=actual_off || len>data_len)return -ERANGE;
 if(header<14||header>128||!len||(len<60&&header+len<60))return -EINVAL;
 if(mtu>65535||(__u64)header+len>(__u64)mtu+14)return -EMSGSIZE;
 return len==data_len?0:-EMSGSIZE;
}
static void independent_vectors(void) {
 const __u32 headers[]={0,13,14,59,60,128,129};const __u32 lengths[]={0,1,45,46,59,60,64,128,129};const __u32 mtus[]={0,46,60,114,1500,65535,65536};unsigned count=0;
 struct xdev_ext_net_mech_info i;struct xdev_ext_net_send_desc d[40];
 for(unsigned h=0;h<7;h++)for(unsigned l=0;l<9;l++)for(unsigned m=0;m<7;m++)for(unsigned gap=0;gap<2;gap++)for(unsigned bad=0;bad<2;bad++) {
  info_init(&i,d);i.mtu=mtus[m];d[0].header_len=headers[h];d[0].len=lengths[l];d[0].frame_off=16+gap;d[0].reserved=bad;
  wrapper(&i,d,1,one_expected(16,16+gap,128,lengths[l],headers[h],mtus[m],bad));count++;
 }
 printf("independent header/interval oracle: %u exhaustive vectors\n",count);
}
static __u32 seed=0x91d3a507;
static __u32 random32(void){seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;return seed;}
static void randomized_splits(void) {
 struct xdev_ext_net_mech_info i;struct xdev_ext_net_send_desc d[40];
 for(unsigned trial=0;trial<1024;trial++) {
  info_init(&i,d);unsigned n=1+random32()%16;i.f[0].data_len=0;unsigned off=16;
  for(unsigned k=0;k<n;k++){unsigned len=60+random32()%128;d[k]=(struct xdev_ext_net_send_desc){.frame_off=off,.len=len,.header_len=14};memset(d[k].header,(int)(random32()&255),128);off+=len;i.f[0].data_len+=len;}
  wrapper(&i,d,n,0);unsigned bad=random32()%n;d[bad].frame_off++;wrapper(&i,d,n,-ERANGE);
 }
 puts("independent randomized splits:1024 exact plans +1024 offset-gap refusals");
}
#ifdef TEST_SHARED
static void adapter_vectors(void) {
 struct xdev_ext_net_mech_info i;struct xdev_ext_net_send_desc d[40];info_init(&i,d);d[0].flags=0x80000000;d[0].reserved=5;
 struct xdev_ext_net_plan_ctx c={.info=&i,.d=d};struct xdev_ext_net_span out;
 unsigned char before_i[sizeof(i)],before_d[sizeof(d)],before_c[sizeof(c)];memcpy(before_i,&i,sizeof(i));memcpy(before_d,d,sizeof(d));memcpy(before_c,&c,sizeof(c));
 xdev_ext_net_plan_span(&c,0,&out);EQ(out.frame_pos,0);EQ(out.frame_off,16);EQ(out.len,128);EQ(out.bad,0x80000005);
 /* Entry's flags argument is literal0, even when descriptor flags are nonzero. */
 EQ(xdev_ext_net_plan_entry(&c,0),0);i.mtu=0;EQ(xdev_ext_net_plan_entry(&c,0),-EMSGSIZE);d[0].header_len=13;EQ(xdev_ext_net_plan_entry(&c,0),-EINVAL);
 i.mtu=1500;d[0].header_len=14;assert(!memcmp(&i,before_i,sizeof(i)));assert(!memcmp(d,before_d,sizeof(d)));assert(!memcmp(&c,before_c,sizeof(c)));
 puts("frozen adapters:field-wise span,bad flags|reserved,literal entry flags0,untranslated errno,input preservation");
}
#endif
static void wiring(void) {
#ifdef TEST_WIRING
 struct xdev_ext_net_mech_info i;struct xdev_ext_net_send_desc d[40];info_init(&i,d);wrapper(&i,d,1,0);EQ(family.calls,1);expect_trace((unsigned[]){100,200},2);
 puts("shared-consumer gate:actual NET wrapper calls real family exact-cover once");
#endif
}
int main(void) {
 setvbuf(stdout,NULL,_IONBF,0);generic_vectors();wrapper_vectors();independent_vectors();randomized_splits();
#ifdef TEST_SHARED
 adapter_vectors();
#endif
 wiring();puts("PASS: NET29-2 actual-header contract cohort");return 0;
}
