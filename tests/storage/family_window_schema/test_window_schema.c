/* SPDX-License-Identifier: GPL-2.0 */
/* Independent oracle: storage-window-schema-v1 sections4/5, not old tests. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "nvme_xdev_ext_passthru.h"
#ifdef SW_SCHEMA_NEW
#include "xdev_ext_desc_schema.h"
#endif

static unsigned checks,failures;
static char label[128];
static void eq(const char *what, long long got, long long want)
{
 checks++;
 if(got!=want) {failures++;fprintf(stderr,"FAIL %s %s got=%lld want=%lld\n",label,what,got,want);}
}
#define EQ(what,got,want) eq(what,(long long)(got),(long long)(want))
struct bind_vector {__u64 cap,shift,start,count,group;int want;};
struct validate_vector {__u64 cap,shift,start,count,slba,nlb,data,write,opcode,bad_dw,bad_bit,control,allow;int want;};
struct admit_vector {__u64 cap,shift,start,count,slba,nlb,data;int want;};
#include "vectors.inc"

static void dw_put(__u8 sqe[64],unsigned dw,__u32 value)
{
 unsigned i;for(i=0;i<4;i++)sqe[4*dw+i]=value>>(8*i);
}
static void sqe_make(__u8 sqe[64],unsigned opcode,__u64 slba,__u64 nlb,unsigned control)
{
 memset(sqe,0,64);sqe[0]=opcode;
 dw_put(sqe,10,(__u32)slba);dw_put(sqe,11,(__u32)(slba>>32));
 dw_put(sqe,12,(__u32)(nlb-1)|((__u32)control<<16));
}
static struct nvme_xdev_ext_identity identity(__u64 cap,unsigned shift)
{
 struct nvme_xdev_ext_identity id={.nsid=7,.lba_shift=shift,.namespace_ready=1,.capacity_lbas=cap};return id;
}
static struct nvme_xdev_ext_mech_bounds bounds(__u64 cap,unsigned shift,__u64 start,__u64 count,unsigned data,unsigned write,unsigned allow)
{
 struct nvme_xdev_ext_mech_bounds b={.window_slba=start,.window_nlb=count,.capacity_lbas=cap,.data_len=data,.control_allow=allow,.lba_shift=shift,.write=write};return b;
}
static void decoded_check(const struct nvme_xdev_ext_decoded *out,int ret,__u64 slba,__u64 nlb,unsigned shift,unsigned write)
{
 struct nvme_xdev_ext_decoded zero={0};
 if(ret) {EQ("decoded-zero-after-valid-pointers",memcmp(out,&zero,sizeof(zero)),0);return;}
 EQ("decoded-slba",out->slba,slba);EQ("decoded-nlb",out->nlb,nlb);
 EQ("decoded-byte-offset",out->byte_offset,slba<<shift);EQ("decoded-byte-length",out->byte_length,nlb<<shift);
 EQ("decoded-write",out->write,write);EQ("decoded-reserved-zero",memcmp(out->reserved,zero.reserved,sizeof(out->reserved)),0);
}
static void validate_case(const char *name,__u64 cap,unsigned shift,__u64 start,__u64 count,__u64 slba,unsigned nlb,unsigned data,unsigned write,unsigned opcode,unsigned bad_dw,unsigned bad_bit,unsigned control,unsigned allow,int want)
{
 __u8 sqe[64];struct nvme_xdev_ext_decoded out;
 struct nvme_xdev_ext_mech_bounds b=bounds(cap,shift,start,count,data,write,allow);
 snprintf(label,sizeof(label),"%s",name);sqe_make(sqe,opcode,slba,nlb,control);
 if(bad_dw<16)sqe[bad_dw*4+bad_bit/8]|=1U<<(bad_bit%8);
 memset(&out,0xa5,sizeof(out));int ret=nvme_xdev_ext_mech_validate(sqe,&b,&out);
 EQ("NVMe-validate-errno",ret,want);
 /* Expected shifts are used only on contract-success cases. No arithmetic
  * from production is used to determine the expected errno. */
 decoded_check(&out,want,slba,nlb,shift,write);
}
#define V(name,shift,slba,nlb,data,opcode,bad_dw,bad_bit,want) validate_case(name,1000,shift,100,8,slba,nlb,data,0,opcode,bad_dw,bad_bit,0,0,want)
static void legacy_golden(void)
{
 static const struct bind_vector cases[]={
  {1000,9,100,8,4096,0},{1000,9,992,8,4096,0},
  {1000,9,993,8,4096,-ERANGE},{1000,9,100,0,4096,-EINVAL},
  {1000,9,100,8,513,-EMSGSIZE},{1000,9,100,8,8192,-ERANGE},
  {1000,8,100,8,0,-EINVAL},{1000,32,100,8,0,-EOVERFLOW},
  {1000,9,100,0,513,-EMSGSIZE},{1000,9,100,8,0,-EINVAL},
  {UINT64_MAX,9,UINT64_MAX-7,8,4096,-ERANGE},
  {UINT64_MAX,9,UINT64_MAX-8,8,4096,0},
  {100000,9,0,100000,33554432,0},{100000,9,0,100000,33554944,-EMSGSIZE},
 };
 size_t i;
 for(i=0;i<sizeof(cases)/sizeof(*cases);i++) {
  const struct bind_vector *v=&cases[i];struct nvme_xdev_ext_identity id=identity(v->cap,v->shift);
  snprintf(label,sizeof(label),"bind-golden[%zu]",i);
  EQ("NVMe-bind-errno",nvme_xdev_ext_mech_bind_check(&id,0,v->start,v->count,v->group),v->want);
 }
 V("read-literal",9,100,8,4096,2,16,0,0);
 validate_case("write-literal",1000,9,100,8,100,8,4096,1,1,16,0,0,0,0);
 V("before-window",9,99,8,4096,2,16,0,-ERANGE);
 V("past-window",9,107,2,1024,2,16,0,-ERANGE);
 V("wrong-data-length",9,100,8,512,2,16,0,-EMSGSIZE);
 V("cdw2-forbidden",9,100,8,4096,2,2,0,-EPERM);
 V("DW14-forbidden",9,100,8,4096,2,14,7,-EPERM);
 V("opcode-before-schema",9,100,8,4096,1,2,0,-EOPNOTSUPP);
 V("shift-before-opcode-schema",8,100,8,4096,1,2,0,-EINVAL);
 V("shift-overflow-before-opcode",32,100,8,4096,1,2,0,-EOVERFLOW);
 V("schema-before-window",9,99,8,4096,2,2,0,-EPERM);
 V("window-before-zero-length",9,99,8,0,2,16,0,-ERANGE);
 V("window-before-length-mismatch",9,107,2,1,2,16,0,-ERANGE);
 validate_case("window-before-SLBA-shift-overflow",UINT64_MAX,9,100,8,UINT64_MAX,1,512,0,2,16,0,0,0,-ERANGE);
 validate_case("SLBA-shift-overflow",UINT64_MAX,9,UINT64_C(36028797018963968),8,UINT64_C(36028797018963968),1,512,0,2,16,0,0,0,-EOVERFLOW);
 validate_case("capacity-last",100,9,100,8,100,1,512,0,2,16,0,0,0,-ERANGE);
 validate_case("length-before-capacity",100,9,100,8,100,1,1,0,2,16,0,0,0,-EMSGSIZE);
 validate_case("bytes-above-U32",UINT64_MAX,31,0,65536,0,2,UINT_MAX,0,2,16,0,0,0,-EMSGSIZE);
 validate_case("data-zero-before-byte-limit",UINT64_MAX,31,0,65536,0,2,0,0,2,16,0,0,0,-EINVAL);
 struct nvme_xdev_ext_decoded out,sentinel;struct nvme_xdev_ext_mech_bounds b=bounds(1000,9,100,8,4096,0,0);__u8 sqe[64];
 sqe_make(sqe,2,100,8,0);memset(&sentinel,0xa5,sizeof(sentinel));out=sentinel;
 snprintf(label,sizeof(label),"NULL-pointer-output-timing");
 EQ("NULL-sqe",nvme_xdev_ext_mech_validate(NULL,&b,&out),-EINVAL);EQ("NULL-sqe-unchanged",memcmp(&out,&sentinel,sizeof(out)),0);
 EQ("NULL-bounds",nvme_xdev_ext_mech_validate(sqe,NULL,&out),-EINVAL);EQ("NULL-bounds-unchanged",memcmp(&out,&sentinel,sizeof(out)),0);
 EQ("NULL-output",nvme_xdev_ext_mech_validate(sqe,&b,NULL),-EINVAL);
}
static void legacy_bits(void)
{
 unsigned dw,bit;
 for(dw=0;dw<16;dw++)for(bit=0;bit<32;bit++) {
  bool forbidden=(dw==0&&bit>=8)||(dw>=1&&dw<=9)||(dw==12&&bit>=16)||(dw>=13);
  if(forbidden) {char name[80];snprintf(name,sizeof(name),"NVMe-forbidden-DW%u-bit%u",dw,bit);V(name,9,100,8,4096,2,dw,bit,-EPERM);}
 }
 for(bit=0;bit<16;bit++) {
  char name[80];snprintf(name,sizeof(name),"control-allowed-bit%u",bit);
  validate_case(name,1000,9,100,8,100,8,4096,0,2,16,0,1U<<bit,1U<<bit,0);
  snprintf(name,sizeof(name),"control-unallowed-neighbor%u",bit);
  validate_case(name,1000,9,100,8,100,8,4096,0,2,16,0,1U<<bit,1U<<((bit+1)%16),-EPERM);
  snprintf(name,sizeof(name),"control-no-other-DW-grant%u",bit);
  validate_case(name,1000,9,100,8,100,8,4096,0,2,14,bit,1U<<bit,0xffff,-EPERM);
 }
}
static void legacy_random(void)
{
 size_t i;
 for(i=0;i<sizeof(random_bind)/sizeof(*random_bind);i++) {
  const struct bind_vector *v=&random_bind[i];struct nvme_xdev_ext_identity id=identity(v->cap,v->shift);
  snprintf(label,sizeof(label),"bind-random[%zu]",i);
  EQ("bind-errno",nvme_xdev_ext_mech_bind_check(&id,0,v->start,v->count,v->group),v->want);
 }
 for(i=0;i<sizeof(random_validate)/sizeof(*random_validate);i++) {
  const struct validate_vector *v=&random_validate[i];char name[64];snprintf(name,sizeof(name),"validate-random[%zu]",i);
  validate_case(name,v->cap,v->shift,v->start,v->count,v->slba,v->nlb,v->data,v->write,v->opcode,v->bad_dw,v->bad_bit,v->control,v->allow,v->want);
 }
}
#ifdef SW_SCHEMA_NEW
static void typed_bind(void)
{
 size_t i;struct xdev_ext_stor_window sentinel;memset(&sentinel,0xa5,sizeof(sentinel));
 for(i=0;i<sizeof(random_bind)/sizeof(*random_bind);i++) {
  const struct bind_vector *v=&random_bind[i];struct xdev_ext_stor_window out=sentinel;
  snprintf(label,sizeof(label),"typed-bind[%zu]",i);
  EQ("errno",xdev_ext_stor_window_bind(&out,v->cap,v->shift,true,v->start,v->count,v->group),v->want);
  if(v->want) EQ("atomic-failure-no-output",memcmp(&out,&sentinel,sizeof(out)),0);
  else {EQ("capacity",out.capacity_lbas,v->cap);EQ("slba",out.slba,v->start);EQ("nlb",out.nlb,v->count);EQ("shift",out.lba_shift,v->shift);EQ("write",out.write,1);}
 }
 snprintf(label,sizeof(label),"typed-bind-NULL");
 EQ("NULL-out-before-invalid-shift",xdev_ext_stor_window_bind(NULL,0,32,false,0,0,0),-EINVAL);
}
static void typed_admit_case(const char *name,__u64 cap,unsigned shift,__u64 start,__u64 count,__u64 slba,__u64 nlb,unsigned data,int want)
{
 struct xdev_ext_stor_window w={.slba=start,.nlb=count,.capacity_lbas=cap,.lba_shift=shift,.write=1},old=w;
 struct xdev_ext_stor_rw out,zero={0};memset(&out,0xa5,sizeof(out));snprintf(label,sizeof(label),"%s",name);
 EQ("errno",xdev_ext_stor_window_admit(&w,slba,nlb,data,&out),want);
 EQ("window-immutable",memcmp(&w,&old,sizeof(w)),0);
 if(want)EQ("valid-pointer-clears-out",memcmp(&out,&zero,sizeof(out)),0);
 else {EQ("slba",out.slba,slba);EQ("nlb",out.nlb,nlb);EQ("byte-offset",out.byte_offset,slba<<shift);EQ("byte-length",out.byte_length,nlb<<shift);EQ("write",out.write,1);}
}
static void typed_admit(void)
{
 size_t i;
 typed_admit_case("typed-golden",1000,9,100,8,100,8,4096,0);
 typed_admit_case("typed-before-window",1000,9,100,8,99,1,512,-ERANGE);
 typed_admit_case("typed-count-zero",1000,9,100,8,99,0,0,-EINVAL);
 typed_admit_case("typed-NLB-overflow-before-zero-data",UINT64_MAX,9,0,UINT64_MAX,0,UINT64_C(36028797018963968),0,-EOVERFLOW);
 typed_admit_case("typed-window-before-NLB-overflow",1000,9,100,8,99,UINT64_C(36028797018963968),0,-ERANGE);
 typed_admit_case("typed-NLB-limit-after-data-zero",UINT64_MAX,31,0,UINT64_MAX,0,2,0,-EINVAL);
 typed_admit_case("typed-window-before-SLBA-overflow",UINT64_MAX,9,100,8,UINT64_MAX,1,512,-ERANGE);
 for(i=0;i<sizeof(random_admit)/sizeof(*random_admit);i++) {
  const struct admit_vector *v=&random_admit[i];char name[64];snprintf(name,sizeof(name),"typed-admit-random[%zu]",i);
  typed_admit_case(name,v->cap,v->shift,v->start,v->count,v->slba,v->nlb,v->data,v->want);
 }
 struct xdev_ext_stor_rw out,old;struct xdev_ext_stor_window w={.slba=100,.nlb=8,.capacity_lbas=1000,.lba_shift=9};
 memset(&old,0xa5,sizeof(old));out=old;snprintf(label,sizeof(label),"typed-admit-NULL");
 EQ("NULL-window",xdev_ext_stor_window_admit(NULL,100,1,512,&out),-EINVAL);EQ("no-pointer-clear",memcmp(&out,&old,sizeof(out)),0);
 EQ("NULL-out",xdev_ext_stor_window_admit(&w,100,1,512,NULL),-EINVAL);
}
static void schema(void)
{
 const struct xdev_ext_desc_schema16 nvme={.writable={0xff,0,0,0,0,0,0,0,0,0,0xffffffff,0xffffffff,0xffff,0,0,0}};
 unsigned dw,bit;__u8 sqe[64];
 for(dw=0;dw<16;dw++)for(bit=0;bit<32;bit++) {
  sqe_make(sqe,2,100,8,0);sqe[dw*4+bit/8]|=1U<<(bit%8);
  bool allowed=(dw==0&&bit<8)||dw==10||dw==11||(dw==12&&bit<16);
  /* Setting the already-present opcode bit preserves exact opcode. */
  int want=dw==0&&bit<8&&bit!=1?-EOPNOTSUPP:allowed?0:-EPERM;
  snprintf(label,sizeof(label),"schema-DW%u-bit%u",dw,bit);
  EQ("mask-errno",xdev_ext_desc_schema16_check(sqe,&nvme,2),want);
 }
 sqe_make(sqe,2,100,8,0);sqe[56]=0x80;
 struct xdev_ext_desc_schema16 extra=nvme;extra.writable[14]=0x80;
 snprintf(label,sizeof(label),"schema-declaration-variation");
 EQ("NVMe-mask-rejects-DW14",xdev_ext_desc_schema16_check(sqe,&nvme,2),-EPERM);
 EQ("trusted-mask-allows-DW14",xdev_ext_desc_schema16_check(sqe,&extra,2),0);
 sqe[56]=0x40;EQ("neighbor-still-rejected",xdev_ext_desc_schema16_check(sqe,&extra,2),-EPERM);
 sqe[0]=1;EQ("opcode-before-forbidden",xdev_ext_desc_schema16_check(sqe,&extra,2),-EOPNOTSUPP);
 extra.writable[0]=UINT_MAX;sqe_make(sqe,3,100,8,0);
 EQ("opcode-is-exact-not-mask",xdev_ext_desc_schema16_check(sqe,&extra,2),-EOPNOTSUPP);
 sqe_make(sqe,2,100,8,0);extra.writable[0]=0;EQ("opcode-still-subject-to-schema",xdev_ext_desc_schema16_check(sqe,&extra,2),-EPERM);
 EQ("NULL-sqe",xdev_ext_desc_schema16_check(NULL,&nvme,2),-EINVAL);EQ("NULL-schema",xdev_ext_desc_schema16_check(sqe,NULL,2),-EINVAL);
}
#endif
int main(void)
{
 legacy_golden();legacy_bits();legacy_random();
#ifdef SW_SCHEMA_NEW
 typed_bind();typed_admit();schema();
#endif
 printf("storage_window_schema assertions=%u failures=%u\n",checks,failures);return failures?1:0;
}
