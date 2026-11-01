/* SPDX-License-Identifier: GPL-2.0 */
/* Execute production-generated BPF instructions. This is an ISA interpreter
 * at the BPF helper boundary, not another implementation of packet matching. */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contract_api.h"

#define PKT 0x100000ULL
#define CTX 0x200000ULL
#define STK 0x300000ULL
#define FLOW 0x400000ULL
#define XSK 0x410000ULL
#define MAP 0x500000ULL
#define XSK_FD 101
#define FLOW_FD 102
static unsigned char packet[128], stack_bytes[512], stack_written[512];
static struct xdp_md context;
static struct xdev_ext_xsk_shared_flow flow;
static uint32_t xsk_value;
static size_t packet_length;
static int flow_present,xsk_present,vm_bad;
static struct bpf_insn program[XDEV_EXT_XSK_SHARED_MAX_INSNS];
static size_t program_count;
static uint64_t registers[11];
static int failures;
static void check(int ok,const char *name)
{ printf("%s - %s\n",ok?"ok":"not ok",name); failures+=!ok; }
static void *memory(uint64_t a,size_t n,int write)
{
 if(a>=STK && a+n<=STK+512) {
  size_t i,o=(size_t)(a-STK);
  for(i=0;i<n;i++) {
   if(write) stack_written[o+i]=1;
   else if(!stack_written[o+i]) vm_bad=1;
  }
  return stack_bytes+o;
 }
 if(!write && a>=PKT && a+n<=PKT+packet_length)return packet+(a-PKT);
 if(!write && a>=CTX && a+n<=CTX+sizeof(context))return (char *)&context+(a-CTX);
 if(!write && a>=FLOW && a+n<=FLOW+sizeof(flow))return (char *)&flow+(a-FLOW);
 if(!write && a>=XSK && a+n<=XSK+sizeof(xsk_value))return (char *)&xsk_value+(a-XSK);
 vm_bad=1;return NULL;
}
static uint64_t load(uint64_t addr,size_t bytes)
{ uint64_t n=0;void *p=memory(addr,bytes,0);if(p)memcpy(&n,p,bytes);return n; }
static void store(uint64_t addr,uint64_t value,size_t bytes)
{ void *p=memory(addr,bytes,1);if(p)memcpy(p,&value,bytes); }
static uint64_t helper(int id)
{
 uint64_t map=registers[1],key=registers[2];
 if(id==BPF_FUNC_map_lookup_elem) {
  if(map==MAP+FLOW_FD) {
   struct xdev_ext_xsk_shared_key k;
   void *p=memory(key,sizeof(k),0);
   if(!p)return 0;
   memcpy(&k,p,sizeof(k));
   if(flow_present && k.dst_ipv4==0xc6336402U && k.payload_magic==0x11223344U &&
      k.dst_port==9000 && k.reserved==0)return FLOW;
   return 0;
  }
  if(map==MAP+XSK_FD)return load(key,4)==flow.queue_id && xsk_present?XSK:0;
 }
 if(id==BPF_FUNC_redirect_map && map==MAP+XSK_FD) {
  if(registers[2]==flow.queue_id && xsk_present)return XDP_REDIRECT;
  return registers[3]&3U;
 }
 vm_bad=1;return 0;
}
static int execute(void)
{
 size_t pc=0,steps=0;
 memset(registers,0,sizeof(registers));memset(stack_written,0,sizeof(stack_written));
 memset(stack_bytes,0,sizeof(stack_bytes));vm_bad=0;
 registers[1]=CTX;registers[10]=STK+512;
 while(pc<program_count && steps++<10000 && !vm_bad) {
  struct bpf_insn i=program[pc++];
  uint64_t *dst=&registers[i.dst_reg],src=(i.code&BPF_X)?registers[i.src_reg]:(uint64_t)(int64_t)i.imm;
  unsigned int cls=BPF_CLASS(i.code),op=BPF_OP(i.code),size=BPF_SIZE(i.code);
  size_t bytes=size==BPF_DW?8:size==BPF_W?4:size==BPF_H?2:1;
  if(i.dst_reg>10 || i.src_reg>10){vm_bad=1;break;}
  if(cls==BPF_LD && i.code==(BPF_LD|BPF_DW|BPF_IMM)) {
   if(pc>=program_count){vm_bad=1;break;}
   *dst=(uint32_t)i.imm|((uint64_t)(uint32_t)program[pc++].imm<<32);
   if(i.src_reg==BPF_PSEUDO_MAP_FD)*dst=MAP+(uint32_t)i.imm;
   continue;
  }
  if(cls==BPF_LDX && BPF_MODE(i.code)==BPF_MEM){*dst=load(registers[i.src_reg]+i.off,bytes);continue;}
  if(cls==BPF_STX && BPF_MODE(i.code)==BPF_MEM){store(*dst+i.off,registers[i.src_reg],bytes);continue;}
  if(cls==BPF_ST && BPF_MODE(i.code)==BPF_MEM){store(*dst+i.off,(uint64_t)(int64_t)i.imm,bytes);continue;}
  if(cls==BPF_ALU || cls==BPF_ALU64) {
   int is32=cls==BPF_ALU;
   if(is32 && op!=BPF_END){*dst=(uint32_t)*dst;src=(uint32_t)src;}
   switch(op) {
   case BPF_ADD:*dst+=src;break;case BPF_SUB:*dst-=src;break;
   case BPF_MUL:*dst*=src;break;case BPF_DIV:if(!src)vm_bad=1;else *dst/=src;break;
   case BPF_AND:*dst&=src;break;case BPF_OR:*dst|=src;break;case BPF_XOR:*dst^=src;break;
   case BPF_LSH:*dst<<=src&(is32?31:63);break;case BPF_RSH:*dst>>=src&(is32?31:63);break;
   case BPF_ARSH:*dst=is32?(uint32_t)((int32_t)*dst>>(src&31)):(uint64_t)((int64_t)*dst>>(src&63));break;
   case BPF_NEG:*dst=-*dst;break;case BPF_MOV:*dst=src;break;
   case BPF_MOD:if(!src)vm_bad=1;else *dst%=src;break;
   case BPF_END:
    if((i.code&BPF_TO_BE)==BPF_TO_BE) {
     if(i.imm==16)*dst=__builtin_bswap16((uint16_t)*dst);
     else if(i.imm==32)*dst=__builtin_bswap32((uint32_t)*dst);
     else if(i.imm==64)*dst=__builtin_bswap64(*dst);else vm_bad=1;
    } else if(i.imm==16)*dst=(uint16_t)*dst;else if(i.imm==32)*dst=(uint32_t)*dst;
    break;
   default:vm_bad=1;
   }
   if(is32 && op!=BPF_END)*dst=(uint32_t)*dst;
   continue;
  }
  if(cls==BPF_JMP || cls==BPF_JMP32) {
   uint64_t a=*dst,b=src;int take=0;
   if(cls==BPF_JMP32){a=(uint32_t)a;b=(uint32_t)b;}
   switch(op) {
   case BPF_EXIT:return vm_bad?-1:(int)registers[0];
   case BPF_CALL:registers[0]=helper(i.imm);continue;
   case BPF_JA:take=1;break;case BPF_JEQ:take=a==b;break;case BPF_JNE:take=a!=b;break;
   case BPF_JGT:take=a>b;break;case BPF_JGE:take=a>=b;break;case BPF_JLT:take=a<b;break;case BPF_JLE:take=a<=b;break;
   case BPF_JSET:take=!!(a&b);break;
   case BPF_JSGT:take=cls==BPF_JMP32?(int32_t)a>(int32_t)b:(int64_t)a>(int64_t)b;break;
   case BPF_JSGE:take=cls==BPF_JMP32?(int32_t)a>=(int32_t)b:(int64_t)a>=(int64_t)b;break;
   case BPF_JSLT:take=cls==BPF_JMP32?(int32_t)a<(int32_t)b:(int64_t)a<(int64_t)b;break;
   case BPF_JSLE:take=cls==BPF_JMP32?(int32_t)a<=(int32_t)b:(int64_t)a<=(int64_t)b;break;
   default:vm_bad=1;
   }
   if(take){int64_t next=(int64_t)pc+i.off;if(next<0 || next>=(int64_t)program_count)vm_bad=1;else pc=(size_t)next;}
   continue;
  }
  vm_bad=1;
 }
 return -1;
}
static void reset(void)
{
 static const unsigned char valid[]={
  0x02,0,0,0,0,1, 0x02,0,0,0,0,2, 0x08,0x00,
  0x45,0,0,32, 0,1,0,0, 64,17,0,0, 192,0,2,1, 198,51,100,2,
  0x30,0x39,0x23,0x28, 0,12,0,0, 0x11,0x22,0x33,0x44
 };
 memset(packet,0,sizeof(packet));memcpy(packet,valid,sizeof(valid));packet_length=sizeof(valid);
 context=(struct xdp_md){.data=PKT,.data_end=PKT+sizeof(valid),.ingress_ifindex=7,.rx_queue_index=3};
 flow=(struct xdev_ext_xsk_shared_flow){.queue_id=3,.flags=XDEV_EXT_XSK_FILTER_F_DST_IPV4|XDEV_EXT_XSK_FILTER_F_DST_PORT|XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC};
 flow_present=1;xsk_present=1;xsk_value=99;
}
static void expect(int want,const char *name)
{ int got=execute();if(got!=want)printf("  got=%d want=%d vm_bad=%d\n",got,want,vm_bad);check(got==want,name); }
int main(void)
{
 int ret;unsigned int n;
 ret=xdev_ext_xsk_shared_build_program(XSK_FD,FLOW_FD,program,256,&program_count);
 check(ret==0 && program_count>0 && program_count<=256,"production builder emits bounded dispatcher instructions");
 if(ret || !program_count || program_count>256)return 2;
 reset();expect(XDP_REDIRECT,"matching UDP tuple and payload magic redirects to admitted queue");
 reset();packet[45]^=1;expect(XDP_PASS,"wrong payload magic remains ordinary traffic");
 reset();packet[33]^=1;expect(XDP_PASS,"another destination IP remains ordinary traffic");
 reset();packet[37]^=1;expect(XDP_PASS,"another destination port remains ordinary traffic");
 reset();flow_present=0;expect(XDP_PASS,"missing flow remains ordinary traffic");
 reset();xsk_present=0;expect(XDP_PASS,"missing XSK entry never redirects or drops traffic");
 reset();context.rx_queue_index=2;expect(XDP_PASS,"flow cannot redirect from a different hardware RX queue");
 reset();flow.queue_id=4;expect(XDP_PASS,"flow recorded on another queue is not consumed here");
 reset();packet[12]=0x81;packet[13]=0;expect(XDP_PASS,"tagged Ethernet is not admitted");
 reset();packet[14]=0x46;expect(XDP_PASS,"IPv4 options are not admitted");
 reset();packet[14]=0x65;expect(XDP_PASS,"IPv6 or wrong IP version is not admitted");
 reset();packet[23]=6;expect(XDP_PASS,"TCP is not admitted as UDP");
 reset();packet[20]=0x20;expect(XDP_PASS,"IPv4 more-fragments flag is rejected");
 reset();packet[20]=0x40;expect(XDP_REDIRECT,"IPv4 don't-fragment flag remains a valid nonfragmented packet");
 reset();packet[21]=1;expect(XDP_PASS,"nonzero IPv4 fragment offset is rejected");
 reset();packet[17]=31;expect(XDP_PASS,"IPv4 total length cannot disagree with UDP length");
 reset();packet[17]=33;expect(XDP_PASS,"IPv4 total length cannot extend beyond received bytes");
 reset();packet[39]=11;expect(XDP_PASS,"UDP length must include the four-byte magic");
 reset();packet[39]=13;expect(XDP_PASS,"UDP length cannot extend beyond IP length");
 for(n=0;n<46;n++){reset();packet_length=n;context.data_end=PKT+n;expect(XDP_PASS,"every truncation before complete magic passes safely");}
 reset();flow.flags|=XDEV_EXT_XSK_FILTER_F_SRC_IPV4;flow.src_ipv4=0xc0000201;expect(XDP_REDIRECT,"optional matching source IPv4 is accepted");
 reset();flow.flags|=XDEV_EXT_XSK_FILTER_F_SRC_IPV4;flow.src_ipv4=0xc0000202;expect(XDP_PASS,"optional nonmatching source IPv4 passes");
 reset();flow.flags|=XDEV_EXT_XSK_FILTER_F_SRC_PORT;flow.src_port=12345;expect(XDP_REDIRECT,"optional matching source port is accepted");
 reset();flow.flags|=XDEV_EXT_XSK_FILTER_F_SRC_PORT;flow.src_port=12346;expect(XDP_PASS,"optional nonmatching source port passes");
 reset();flow.flags|=XDEV_EXT_XSK_FILTER_F_DST_MAC;memcpy(flow.dst_mac,packet,6);expect(XDP_REDIRECT,"optional matching destination MAC is accepted");
 reset();flow.flags|=XDEV_EXT_XSK_FILTER_F_DST_MAC;memset(flow.dst_mac,0xff,6);expect(XDP_PASS,"optional nonmatching destination MAC passes");
 reset();flow.flags|=XDEV_EXT_XSK_FILTER_F_MAX_LEN;flow.max_len=46;expect(XDP_REDIRECT,"frame exactly at maximum length is accepted");
 reset();flow.flags|=XDEV_EXT_XSK_FILTER_F_MAX_LEN;flow.max_len=45;expect(XDP_PASS,"frame above maximum length passes");
 reset();packet_length=60;context.data_end=PKT+60;expect(XDP_REDIRECT,"Ethernet padding beyond coherent IP and UDP lengths is accepted");
 printf("RESULT failures=%d\n",failures);return failures?1:0;
}
