/* SPDX-License-Identifier: GPL-2.0 */
/* OS-only boundary; engine.h contains the actual simulator copy functions. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;
#define check_add_overflow(a,b,p) __builtin_add_overflow(a,b,p)
#define XDEV_EXT_MECH_DIR_TO_DEVICE 1
#define SIM_FAIL_SKIP_H2D 3
#define SIM_FAIL_SKIP_D2H 4
struct xdev_ext_ce_sim_host { void *vaddr; u64 bytes; };
struct xdev_ext_ce_xfer { u64 host_byte_off, gpu_off; u32 len; };
struct xdev_ext_ce_sim_req {
 void *window; u64 window_len; struct xdev_ext_ce_sim_host *host;
 u64 bytes; u32 dir, n; int mode; bool poison_after_h2d;
 struct xdev_ext_ce_xfer x[3];
};
#include "engine.h"
static unsigned checks, failures;
#define CHECK(c,msg) do {checks++;if(!(c)){failures++;fprintf(stderr,"D2H_ASSERT %s\n",msg);}}while(0)
#define HOST_BYTES (3*4096)
#define DEVICE_BYTES (8192+128)
static void roundtrip(bool poison, int mode)
{
 u8 host[HOST_BYTES], original[HOST_BYTES], device[DEVICE_BYTES];
 u8 expected_host[HOST_BYTES], expected_device[DEVICE_BYTES];
 struct xdev_ext_ce_sim_host h={host,sizeof(host)};
 struct xdev_ext_ce_sim_req r={.window=device,.window_len=sizeof(device),.host=&h,
  .dir=XDEV_EXT_MECH_DIR_TO_DEVICE,.n=3,.mode=mode,.poison_after_h2d=poison,
  .x={{256,32,3000},{4352,3032,3000},{8448,6032,2192}}};
 for(u32 i=0;i<HOST_BYTES;i++)original[i]=(u8)(i*37U+(i/4096)*13U+0x5a);
 memcpy(host,original,sizeof(host));memcpy(expected_host,original,sizeof(host));
 memset(device,0xc3,sizeof(device));memset(expected_device,0xc3,sizeof(device));
 /* Expected offsets and lengths are fixed independently of the request list. */
 if(mode!=SIM_FAIL_SKIP_H2D){
  memcpy(expected_device+32,original+256,3000);
  memcpy(expected_device+3032,original+4352,3000);
  memcpy(expected_device+6032,original+8448,2192);
 }
 if(poison){
  for(u32 i=256;i<3256;i++)expected_host[i]^=0xff;
  for(u32 i=4352;i<7352;i++)expected_host[i]^=0xff;
  for(u32 i=8448;i<10640;i++)expected_host[i]^=0xff;
 }
 CHECK(!xdev_ext_ce_sim_copy(&r),"valid H2D refused");
 CHECK(r.bytes==8192,"H2D nominal byte count changed");
 CHECK(!memcmp(host,expected_host,sizeof(host)),"H2D safe-point poison or Host guard incorrect");
 CHECK(!memcmp(device,expected_device,sizeof(device)),"H2D data or device guard incorrect");
 r.dir=2;r.bytes=0;
 /* Expected D2H payload is whatever is in the independent device source. */
 if(mode!=SIM_FAIL_SKIP_D2H){
  memcpy(expected_host+256,expected_device+32,3000);
  memcpy(expected_host+4352,expected_device+3032,3000);
  memcpy(expected_host+8448,expected_device+6032,2192);
 }
 CHECK(!xdev_ext_ce_sim_copy(&r),"valid D2H refused");
 CHECK(r.bytes==8192,"D2H nominal byte count changed");
 CHECK(!memcmp(host,expected_host,sizeof(host)),"D2H data or Host guard incorrect");
 CHECK(!memcmp(device,expected_device,sizeof(device)),"D2H changed its source or guards");
 if(mode==0)CHECK(!memcmp(host,original,sizeof(host)),"correct roundtrip did not restore Host");
 if(mode==SIM_FAIL_SKIP_D2H)CHECK((memcmp(host,original,sizeof(host))!=0)==poison,
      "skip D2H observability does not match diagnostic mode");
}
static void invalid_tail(unsigned kind, unsigned dir)
{
 u8 host[HOST_BYTES], before[HOST_BYTES], device[DEVICE_BYTES], device_before[DEVICE_BYTES];
 struct xdev_ext_ce_sim_host h={host,sizeof(host)};
 struct xdev_ext_ce_sim_req r={.window=device,.window_len=sizeof(device),.host=&h,
  .dir=dir,.n=2,.poison_after_h2d=true,
  .x={{256,32,3000},{4352,3032,3000}}};
 memset(host,0x5a,sizeof(host));memcpy(before,host,sizeof(host));
 memset(device,0xc3,sizeof(device));memcpy(device_before,device,sizeof(device));
 switch(kind){
 case 0:r.x[1].host_byte_off=HOST_BYTES-1;break;
 case 1:r.x[1].gpu_off=DEVICE_BYTES-1;break;
 case 2:r.x[1].host_byte_off=UINT64_MAX-1;break;
 case 3:r.x[1].gpu_off=UINT64_MAX-1;break;
 }
 CHECK(xdev_ext_ce_sim_copy(&r)==-EFAULT,"invalid last range accepted");
 CHECK(!r.bytes,"invalid last range accounted a copied prefix");
 CHECK(!memcmp(host,before,sizeof(host)),"invalid last range changed Host prefix");
 CHECK(!memcmp(device,device_before,sizeof(device)),"invalid last range changed device prefix");
}
int main(void)
{
 for(unsigned poison=0;poison<2;poison++){
  roundtrip(poison,0);roundtrip(poison,SIM_FAIL_SKIP_H2D);roundtrip(poison,SIM_FAIL_SKIP_D2H);
 }
 for(unsigned kind=0;kind<4;kind++){
  invalid_tail(kind,1);invalid_tail(kind,2);
 }
 if(failures){fprintf(stderr,"FAIL %u/%u assertions\n",failures,checks);return 1;}
 printf("PASS %u assertions; 6 roundtrips, 8 invalid-tail cases\n",checks);return 0;
}
