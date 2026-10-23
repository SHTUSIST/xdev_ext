/* SPDX-License-Identifier: GPL-2.0 */
/* New benchmark policy; production NXP2 correctness remains independent. */
#ifndef HFT_BENCHMARK_POLICY_H
#define HFT_BENCHMARK_POLICY_H
#include <stdint.h>
#include <string.h>
static inline void hftb_be32(unsigned char *p,uint32_t v)
{p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static inline int hftb_encode_header(unsigned char *dst,uint64_t session,uint32_t generation,uint32_t payload_len)
{
 if(!dst||!session||!generation||(payload_len!=512&&payload_len!=1024))return -1;
 memset(dst,0,40);hftb_be32(dst,0x48465431U);dst[4]=1;dst[5]=40;dst[6]=2;
 hftb_be32(dst+8,(uint32_t)(session>>32));hftb_be32(dst+12,(uint32_t)session);
 hftb_be32(dst+16,generation);dst[23]=1;hftb_be32(dst+24,payload_len);hftb_be32(dst+32,payload_len);return 0;
}
/* Setup-only network template. The provider still performs its mandatory
 * validation and IPv4 checksum finishing on every native transmit. */
static inline int hftb_setup_template(unsigned char *p,const unsigned char *local_mac,const unsigned char *peer_mac,uint32_t local_ip,uint32_t peer_ip,uint16_t local_port,uint16_t peer_port,unsigned payload)
{
 if(!p||(payload!=512&&payload!=1024))return -1;
 memset(p,0,42);memcpy(p,peer_mac,6);memcpy(p+6,local_mac,6);p[12]=8;
 p[14]=0x45;p[22]=64;p[23]=17;
 unsigned length=20+8+40+payload;p[16]=(unsigned char)(length>>8);p[17]=(unsigned char)length;
 memcpy(p+26,&local_ip,4);memcpy(p+30,&peer_ip,4);memcpy(p+34,&local_port,2);memcpy(p+36,&peer_port,2);
 length-=20;p[38]=(unsigned char)(length>>8);p[39]=(unsigned char)length;
 unsigned sum=0;for(unsigned i=14;i<34;i+=2)sum+=(unsigned)p[i]*256+p[i+1];
 while(sum>>16)sum=(sum&65535)+(sum>>16);
 sum=(~sum)&65535;p[24]=(unsigned char)(sum>>8);p[25]=(unsigned char)sum;return 0;
}
#endif
