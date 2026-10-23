/* SPDX-License-Identifier: GPL-2.0 */
/* Actual baseline allocation/history helpers; no device, syscall workload or clock. */
#define _GNU_SOURCE
#include <stdio.h>
#include "hft_runtime.h"
#define CHECK(c) do{if(!(c)){fprintf(stderr,"line %u\n",__LINE__);return 1;}}while(0)
int main(void)
{
 struct hft_config c={.payload=512,.depth=2,.burst=4,.bursts=1,.measured=1};
 struct hft_actor a={.c=&c};struct hft_buffer b;
 CHECK(!hft_history_setup(&a)&&!hft_allocate(&b,0,512)&&b.bytes==4096);
 b.allocation[0]=0x11;b.allocation[4095]=0x22;
 CHECK(!hft_history_commit(&a,&b,0));CHECK(a.history[0].raw_prefix[0]==0x11&&a.history[0].raw_tail[3071]==0x22);
 b.allocation[0]=0xa5;b.allocation[4095]=0x5a;
 CHECK(!hft_history_commit(&a,&b,2));CHECK(a.history[0].raw_prefix[0]==0x11&&a.history[2].raw_prefix[0]==0xa5);
 CHECK(hft_history_commit(&a,&b,2)<0); /* a committed generation cannot be overwritten */
 b.life.index=1;b.life.phase=HFT_WAIT_RELEASE;CHECK(hft_history_commit(&a,&b,3)<0&&!a.history[3].committed);
 b.life.phase=HFT_FREE;CHECK(!hft_history_commit(&a,&b,3));
 CHECK(a.history[3].raw_tail[3071]==0x5a);free(a.history);free(b.allocation);
 /* Correctness mode still admits 4096-byte payloads: the frame must hold
  * headroom, payload and a nonempty suffix guard, never a negative tail. */
 for(unsigned payload=512;payload<=4096;payload*=2) {
  CHECK(!hft_allocate(&b,0,payload)&&b.bytes>=512+payload+32&&b.bytes%4096==0);
  CHECK(hft_buffer_ok(&b,payload));b.allocation[b.bytes-1]^=1;CHECK(!hft_buffer_ok(&b,payload));
  free(b.allocation);
 }
 puts("actual baseline history: full frame/earlier corruption/reuse/duplicate/late NOTIF PASS");return 0;
}
