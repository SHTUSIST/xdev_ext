/* SPDX-License-Identifier: GPL-2.0 */
/* Literal expected outcomes come from frozen ASSERTIONS.md, not a helper. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#ifdef DMA_SCOPE_LEGACY_ADAPTER
#include "contract.h"
#include XDEV_LEGACY_HEADER
#include "legacy_adapter.h"
#else
#include XDEV_SCOPE_HEADER
#endif
static const char provider_a,scope_s,scope_t;
#ifndef DMA_SCOPE_LEGACY_ADAPTER
static const char provider_b;
#endif
#define A (&provider_a)
#define B (&provider_b)
#define S ((const struct xdev_ext_dma_scope *)&scope_s)
#define T ((const struct xdev_ext_dma_scope *)&scope_t)
#define L(p,start,len) {p,XDEV_EXT_DMA_SCOPE_LEGACY,NULL,start,len}
#define K(p,scope,start,len) {p,XDEV_EXT_DMA_SCOPE_KNOWN,scope,start,len}
#define U(p) {p,XDEV_EXT_DMA_SCOPE_UNKNOWN,NULL,0,0}
struct literal {
 const char *name;struct xdev_ext_dma_scope_key a,b;bool overlap,serial;
};
#ifndef DMA_SCOPE_LEGACY_ADAPTER
static const struct literal cases[]={
 {"different ops remain independent",L(A,100,20),L(B,100,20),false,false},
 {"different ops win over invalid metadata",{A,99,NULL,0,0},K(B,NULL,UINT64_MAX,2),false,false},
 {"legacy same base cooperates",L(A,100,20),L(A,100,10),true,false},
 {"legacy shifted overlap serializes",L(A,100,20),L(A,119,1),true,true},
 {"legacy touching ranges are disjoint",L(A,100,20),L(A,120,1),false,false},
 {"legacy disjoint ranges are independent",L(A,100,20),L(A,500,1),false,false},
 {"known same canonical base cooperates",K(A,S,100,20),K(A,S,100,30),true,false},
 {"known zero canonical base is valid",K(A,S,0,20),K(A,S,0,10),true,false},
 {"known zero canonical base keeps distinct scopes independent",K(A,S,0,20),K(A,T,0,20),false,false},
 {"known zero-based touching ranges are disjoint",K(A,S,0,20),K(A,S,20,10),false,false},
 {"known shifted canonical aliases serialize",K(A,S,500,20),K(A,S,510,20),true,true},
 {"known touching canonical ranges are independent",K(A,S,100,20),K(A,S,120,1),false,false},
 {"known disjoint canonical ranges are independent",K(A,S,100,20),K(A,S,500,20),false,false},
 {"distinct proven scopes share equal numeric windows",K(A,S,100,20),K(A,T,100,20),false,false},
 {"distinct proven scopes remain independent with unequal ranges",K(A,S,100,20),K(A,T,500,20),false,false},
 {"unknown versus unknown is ops-wide",U(A),U(A),true,true},
 {"unknown versus known is ops-wide",U(A),K(A,S,500,20),true,true},
 {"unknown versus legacy is ops-wide",U(A),L(A,500,20),true,true},
 {"legacy versus known is ops-wide",L(A,100,20),K(A,S,500,20),true,true},
 {"unknown across ops remains independent",U(A),U(B),false,false},
 {"invalid known null scope is conservative",K(A,NULL,100,20),K(A,T,500,20),true,true},
 {"invalid known zero length defeats distinct scope",K(A,S,100,0),K(A,T,500,20),true,true},
 {"invalid known overflow defeats distinct scope",K(A,S,UINT64_MAX,2),K(A,T,500,20),true,true},
 {"invalid legacy zero length is conservative",L(A,100,0),L(A,500,20),true,true},
 {"invalid legacy same base cannot authorize cooperation",L(A,100,0),L(A,100,20),true,true},
 {"invalid legacy overflow is conservative",L(A,UINT64_MAX,2),L(A,500,20),true,true},
 {"invalid legacy scope identity is conservative",{A,XDEV_EXT_DMA_SCOPE_LEGACY,S,100,20},L(A,500,20),true,true},
 {"invalid unknown identity is conservative",{A,XDEV_EXT_DMA_SCOPE_UNKNOWN,S,0,0},K(A,T,500,20),true,true},
 {"invalid unknown start is conservative",{A,XDEV_EXT_DMA_SCOPE_UNKNOWN,NULL,100,0},K(A,S,500,20),true,true},
 {"invalid unknown length is conservative",{A,XDEV_EXT_DMA_SCOPE_UNKNOWN,NULL,0,20},K(A,S,500,20),true,true},
 {"unknown kind is conservative",{A,99,NULL,100,20},L(A,500,20),true,true},
 {"valid maximum end is not overflow",K(A,S,UINT64_MAX-7,7),K(A,S,0,1),false,false},
 {"known touching maximum-end interval is disjoint",K(A,S,UINT64_MAX-7,7),K(A,S,UINT64_MAX-8,1),false,false},
 {"legacy valid maximum end remains comparable",L(A,UINT64_MAX-7,7),L(A,0,1),false,false},
 {"invalid kind cannot authorize same-base cooperation",{A,99,NULL,100,20},L(A,100,20),true,true},
 {"invalid known cannot authorize same-base cooperation",K(A,S,100,0),K(A,S,100,20),true,true},
 {"mixed same-base remains serial",L(A,100,20),K(A,S,100,20),true,true},
};
#else
/* Root-admitted RED scope: unchanged same-provider numeric legacy controls,
 * plus exactly the new independent-scope capability absent from baseline. */
static const struct literal cases[]={
 {"legacy same base cooperates",L(A,100,20),L(A,100,10),true,false},
 {"legacy shifted overlap serializes",L(A,100,20),L(A,119,1),true,true},
 {"legacy touching ranges are disjoint",L(A,100,20),L(A,120,1),false,false},
 {"legacy disjoint ranges are independent",L(A,100,20),L(A,500,1),false,false},
 {"distinct proven scopes share equal numeric windows",K(A,S,100,20),K(A,T,100,20),false,false},
};
#endif
int main(void)
{
 unsigned int i,reverse,failures=0,checks=0;
 for(i=0;i<sizeof(cases)/sizeof(cases[0]);i++)for(reverse=0;reverse<2;reverse++) {
  const struct xdev_ext_dma_scope_key *a=reverse?&cases[i].b:&cases[i].a;
  const struct xdev_ext_dma_scope_key *b=reverse?&cases[i].a:&cases[i].b;
  bool overlap=xdev_ext_dma_scope_overlap(a,b);
  checks++;if(overlap!=cases[i].overlap)failures++;
  printf("%s overlap %s reverse=%u got=%u want=%u\n",overlap==cases[i].overlap?"ok":"not ok",cases[i].name,reverse,overlap,cases[i].overlap);
#ifndef DMA_SCOPE_LEGACY_ADAPTER
  {bool serial=xdev_ext_dma_scope_serial(a,b);checks++;if(serial!=cases[i].serial)failures++;
   printf("%s serial %s reverse=%u got=%u want=%u\n",serial==cases[i].serial?"ok":"not ok",cases[i].name,reverse,serial,cases[i].serial);}
#endif
 }
#ifdef DMA_SCOPE_LEGACY_ADAPTER
 printf("BOUNDARY legacy adapter executes real old overlap only; no pure serial result claimed\n");
#endif
 printf("RESULT checks=%u failures=%u\n",checks,failures);return failures?1:0;
}
