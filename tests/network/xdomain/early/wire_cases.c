/* SPDX-License-Identifier: GPL-2.0 */
/* Independent literal wire oracle for frozen early CTS contract. */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#include "io_uring/xdomain/xdev_ext_xdomain_core.h"
#include "io_uring/xdomain/xdev_ext_xdomain_early.h"
_Static_assert(sizeof(struct xdev_ext_xdomain_proto_info)==256,"v1 facts retain256");
_Static_assert(sizeof(struct xdev_ext_xdomain_proto_verdict)==64,"v1/v2 verdict retains64");
_Static_assert(sizeof(struct xdev_ext_xdomain_proto_info_v2)==320,"new facts exactly320");
_Static_assert(offsetof(struct xdev_ext_xdomain_proto_info_v2,base)==0,"v1 base at0");
_Static_assert(offsetof(struct xdev_ext_xdomain_proto_info_v2,tx_bind)==256,"tx bind at256");
_Static_assert(offsetof(struct xdev_ext_xdomain_proto_info_v2,pair_deadline_ns)==280,"deadline at280");
_Static_assert(offsetof(struct xdev_ext_xdomain_proto_info_v2,shape_total)==288,"shape at288");
_Static_assert(offsetof(struct xdev_ext_xdomain_proto_info_v2,mode)==304,"mode at304");
_Static_assert(XDEV_EXT_XDOMAIN_F_EARLY==2,"public class optin bit1");
static unsigned checks,failures;
#define EXPECT(c,why) do{checks++;if(!(c)){failures++;fprintf(stderr,"EARLY_WIRE_ASSERT %s line%d\n",why,__LINE__);}}while(0)
static __u32 crc(__u32 v,const void *data,size_t len)
{const __u8 *p=data;while(len--){v^=*p++;for(unsigned b=0;b<8;b++)v=(v>>1)^((v&1)?0x82f63b78U:0);}return v;}
static void put(__u8 *p,__u64 v,unsigned n){for(unsigned i=0;i<n;i++)p[i]=v>>(8*i);}
static void repair(__u8 *p){put(p+124,~crc(~0U,p,124),4);}
static void literal(__u8 b[129],unsigned type)
{
 memset(b,0,129);memcpy(b,"NXD2",4);b[4]=2;b[5]=type;b[6]=1;
 put(b+8,0x0102030405060708ULL,8);put(b+16,0x1112131415161718ULL,8);put(b+24,0x2122232425262728ULL,8);
 if(type!=7)put(b+32,0x3132333435363738ULL,8);
 if(type==7||type==8||type==9||type==2){put(b+72,9216,4);put(b+76,3,2);put(b+80,8192,4);}
 if(type<=6){put(b+40,1,8);if(type==2||type==3||type==4)put(b+48,4,8);}
 if(type==2){put(b+64,0x8182838485868788ULL,8);for(unsigned i=0;i<8;i++)b[96+i]=0x81+i;}
 if(type==5)put(b+78,5,2);
 repair(b);
}
static int decode(__u8 b[129],unsigned len)
{struct xdev_ext_xd_msg_v2 out;memset(&out,0xa5,sizeof(out));return xdev_ext_xd_msg_v2_decode(b,len,crc,&out);}
int main(void)
{
 __u8 b[129],bad[129],encoded[128];struct xdev_ext_xd_msg_v2 msg;unsigned count=0;
 EXPECT(~crc(~0U,"123456789",9)==0xe3069283U,"independent CRC32C standard vector");
 EXPECT(xdev_ext_xd_early_shape(9216,8192,&count)==0&&count==3,"short tail exact3 native elements");
 EXPECT(xdev_ext_xd_early_shape(16384,8192,&count)==0&&count==4,"two full frames exact4 elements");
 EXPECT(xdev_ext_xd_early_shape(32*8192,8192,&count)==0&&count==64,"64 native elements boundary");
 EXPECT(xdev_ext_xd_early_shape(32*8192+4096,8192,&count)<0,"65 native elements rejected");
 EXPECT(xdev_ext_xd_early_shape(0,8192,&count)<0&&xdev_ext_xd_early_shape(8192,0,&count)<0,"zero geometry rejected");
 for(unsigned type=2;type<=9;type++){
  literal(b,type);memset(&msg,0,sizeof(msg));
  EXPECT(xdev_ext_xd_msg_v2_decode(b,128,crc,&msg)==0,"every documented type literal decodes");
  EXPECT(xdev_ext_xd_msg_v2_encode(encoded,&msg,crc)==0&&!memcmp(encoded,b,128),"encode exact independent little endian vector");
  EXPECT(xdev_ext_xd_msg_v2_for_us(&msg,0x1112131415161718ULL,0x0102030405060708ULL,2)==0,"current incarnation and channel route");
  EXPECT(xdev_ext_xd_msg_v2_for_us(&msg,0x1112131415161719ULL,0x0102030405060708ULL,2)<0,"old destination incarnation rejected");
  for(unsigned len=0;len<128;len++)EXPECT(decode(b,len)<0,"all short lengths rejected");
  EXPECT(decode(b,129)<0,"oversized v2 wire rejected");
  for(unsigned bit=0;bit<1024;bit++){memcpy(bad,b,129);bad[bit/8]^=1U<<(bit%8);EXPECT(decode(bad,128)<0,"every single bit corruption rejected");}
  const unsigned reserved[]={7,84,85,86,87,88,89,90,91,92,93,94,95,120,121,122,123};
  for(unsigned i=0;i<sizeof(reserved)/sizeof(reserved[0]);i++){memcpy(bad,b,129);bad[reserved[i]]=1;repair(bad);EXPECT(decode(bad,128)<0,"reserved flags rejected after valid CRC");}
  const unsigned common[]={8,16,24};
  for(unsigned i=0;i<3;i++){memcpy(bad,b,129);memset(bad+common[i],0,8);repair(bad);EXPECT(decode(bad,128)<0,"zero incarnation or TX binding rejected");}
  memcpy(bad,b,129);bad[0]^=1;repair(bad);EXPECT(decode(bad,128)<0,"wrong magic rejected with valid CRC");
  memcpy(bad,b,129);bad[6]=255;repair(bad);EXPECT(decode(bad,128)<0,"invalid channel255 rejected with valid CRC");
  memcpy(bad,b,129);bad[5]=1;repair(bad);EXPECT(decode(bad,128)<0,"v2 RTS type1 rejected");
  memcpy(bad,b,129);bad[4]=1;repair(bad);EXPECT(decode(bad,128)<0,"v1 cannot enter v2 codec");
  if(type==7){memcpy(bad,b,129);bad[32]=1;repair(bad);EXPECT(decode(bad,128)<0,"HELLO forbids RX bind");}
  else{memcpy(bad,b,129);memset(bad+32,0,8);repair(bad);EXPECT(decode(bad,128)<0,"nonHELLO requires RX bind");}
  const unsigned offs[]={40,48,56,64,72,76,78,80,96};
  for(unsigned i=0;i<9;i++){
   unsigned off=offs[i];int allowed=0;
   if(type==7||type==8||type==9)allowed=off==72||off==76||off==80;
   else if(type==2)allowed=off!=78;
   else if(type==3||type==4)allowed=off==40||off==48;
   else if(type==5)allowed=off==40||off==48||off==78;
   else if(type==6)allowed=off==40;
   if(allowed)continue;
   memcpy(bad,b,129);bad[off]=1;repair(bad);EXPECT(decode(bad,128)<0,"per type scalar whitelist checked independently");
  }
 }
 literal(b,2);memset(b+64,0,8);memset(b+96,0,24);repair(b);EXPECT(decode(b,128)==0,"key0 and sequence0 legal for CTS");
 literal(b,2);b[103]^=1;repair(b);EXPECT(decode(b,128)<0,"CTS BE key tag mismatch rejected");
 literal(b,2);b[119]=1;repair(b);EXPECT(decode(b,128)<0,"CTS trailing sixteen zero enforced");
 literal(b,2);put(b+48,1,8);repair(b);EXPECT(decode(b,128)<0,"group below cumulative credit bound");
 literal(b,2);put(b+76,4,2);repair(b);EXPECT(decode(b,128)<0,"short tail rejects upperbound count");
 literal(b,5);put(b+78,4096,2);repair(b);EXPECT(decode(b,128)<0,"FAIL status above4095 rejected");
 for(unsigned type=3;type<=5;type++){
  literal(b,type);put(b+40,5,8);put(b+48,1,8);repair(b);
  EXPECT(decode(b,128)==0,"ACK HELD FAIL permit checked prior credit below own group");
  put(b+48,5,8);repair(b);EXPECT(decode(b,128)==0,"ACK HELD FAIL permit cumulative bound equal own group");
 }
 printf("EARLY_WIRE_ASSERTIONS %u failures=%u\n",checks,failures);return failures?1:0;
}
