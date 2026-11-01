#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Check actual masks/helper instructions/protocol; no namespaces or BPF loads."""
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'source-layout.json').is_file())
source = (HERE / 'token_guest.c').read_text()
start = source.index('  int sent=send_fd(sv[0],mnt);')
end = source.index('\n }\n puts("PASS token-native', start)
tail = source[start:end]
delegate_start = source.index('static int delegate(')
delegate_end = source.index('\nint main(', delegate_start)
delegate_source = source[delegate_start:delegate_end]
fixture = r'''
#include <stdarg.h>
#define main token_guest_entry_unused
#include "TOKEN_SOURCE"
#undef main
/* Intercept only privileged fsconfig/fsmount calls; execute actual delegate(). */
static __u64 delegated[4];
static unsigned delegation_calls;
static const char *delegate_keys[]={"delegate_cmds","delegate_maps","delegate_progs","delegate_attachs"};
static long capture_delegate_syscall(long nr,...)
{
 va_list args; long result=-1;
 va_start(args,nr);
 if (nr==__NR_fsconfig) {
  int fs=va_arg(args,int),command=va_arg(args,int);
  const char *key=va_arg(args,const char *);
  const char *value=va_arg(args,const char *);
  int aux=va_arg(args,int);
  if (fs==17 && aux==0 && command==FSCONFIG_SET_STRING && delegation_calls<4 &&
      key && !strcmp(key,delegate_keys[delegation_calls]) && value) {
   char *end;
   delegated[delegation_calls++]=strtoull(value,&end,0);
   if (*value && !*end) result=0;
  } else if (fs==17 && command==FSCONFIG_CMD_CREATE && !key && !value && !aux && delegation_calls==4) {
   delegation_calls++; result=0;
  }
 } else if (nr==__NR_fsmount) {
  int fs=va_arg(args,int),flags=va_arg(args,int),attrs=va_arg(args,int);
  if (fs==17 && !flags && !attrs && delegation_calls==5) {
   delegation_calls++; result=23;
  }
 }
 va_end(args);
 if(result<0) errno=EINVAL;
 return result;
}
#define syscall capture_delegate_syscall
#define delegate captured_delegate
ACTUAL_DELEGATE
#undef delegate
#undef syscall
static bool allows_load(unsigned prog,unsigned attach)
{
 return (delegated[0]&BIT(BPF_PROG_LOAD)) && (delegated[2]&BIT(prog)) && (delegated[3]&BIT(attach));
}
static int test_delegate(void)
{
 const char *cases[]={"positive","no-command","no-map","no-prog","no-attach"};
 for (unsigned i=0;i<5;i++) {
  bool no_command=i==1,no_map=i==2,no_prog=i==3,no_attach=i==4;
  memset(delegated,0,sizeof(delegated)); delegation_calls=0;
  REQUIRE(captured_delegate(17,cases[i])==23 && delegation_calls==6,"materialize one bpffs with all four delegate masks");
  REQUIRE(allows_load(BPF_PROG_TYPE_SOCKET_FILTER,0)==!no_command,"libbpf SOCKET_FILTER/0 probe must not mask target permission negatives");
  for (unsigned callback=2;callback<=4;callback++)
   REQUIRE(allows_load(BPF_PROG_TYPE_STRUCT_OPS,callback)==!(no_command||no_prog||no_attach),"callback program permission matches targeted negative");
  REQUIRE(!!(delegated[1]&BIT(BPF_MAP_TYPE_STRUCT_OPS))==!no_map,"STRUCT_OPS map permission matches targeted negative");
  REQUIRE(delegated[0]==(BIT(BPF_MAP_CREATE)|BIT(BPF_BTF_LOAD)|(no_command?0:BIT(BPF_PROG_LOAD))),"delegate only required commands");
  REQUIRE(delegated[1]==(BIT(BPF_MAP_TYPE_ARRAY)|(no_map?0:BIT(BPF_MAP_TYPE_STRUCT_OPS))),"delegate only required maps");
  REQUIRE(delegated[2]==(BIT(BPF_PROG_TYPE_SOCKET_FILTER)|(no_prog?0:BIT(BPF_PROG_TYPE_STRUCT_OPS))),"delegate only required program types");
  REQUIRE(delegated[3]==(BIT(0)|(no_attach?0:(BIT(2)|BIT(3)|BIT(4)))),"delegate only probe and callback attach values");
  printf("ok - actual delegation %s matches prerequisite and target authority\n",cases[i]);
 }
 return 0;
}
static int test_helper(const char *file)
{
 LIBBPF_OPTS(bpf_object_open_opts,opts,.bpf_token_path="");
 struct bpf_object *obj=bpf_object__open_file(file,&opts);
 struct bpf_program *prog;
 struct bpf_insn *copy,*before;
 const struct bpf_insn *insns;
 size_t count,index=0,found=0;
 REQUIRE(obj,"open real bad-helper ELF without kernel loading");
 prog=bpf_object__find_program_by_name(obj,"token_prepare");
 REQUIRE(prog,"bad-helper token_prepare exists");
 count=bpf_program__insn_cnt(prog);
 REQUIRE(count>1 && count<4096,"real bad-helper instruction bounds");
 insns=bpf_program__insns(prog);
 for(size_t i=0;i<count;i++) if(insns[i].imm==113) { index=i; found++; }
 REQUIRE(found==1,"original fixture has exactly one helper113");
 copy=calloc(4097,sizeof(*copy)); before=calloc(4097,sizeof(*before));
 REQUIRE(copy && before,"instruction fixture allocation");
 memcpy(copy,insns,count*sizeof(*copy));
 REQUIRE(!forbidden_helper_original(obj,&found) && found==index,"actual original validator finds exact helper113");
 REQUIRE(!forbidden_helper_restore(obj,index),"unchanged113 prepared call accepted");
 /* Independent relocation marker: only helper immediate may be changed. */
 copy[count-1].off=7;
 for(unsigned from=4;from<=113;from+=109) {
  copy[index].imm=from; memcpy(before,copy,count*sizeof(*before));
  REQUIRE(!bpf_program__set_insns(prog,copy,count),"set prepared instruction fixture");
  REQUIRE(!forbidden_helper_restore(obj,index),"actual restore accepts only113 or sanitized4");
  insns=bpf_program__insns(prog);
  REQUIRE(insns[index].imm==113,"restore submits exact intended helper113");
  before[index].imm=113;
  REQUIRE(!memcmp(insns,before,count*sizeof(*before)),"restore preserves all prepared instruction bytes except intended immediate");
 }
 copy[count-1].off=0;
 for(unsigned kind=0;kind<7;kind++) {
  struct bpf_insn saved=copy[index]; size_t n=count;
  copy[index].imm=113;
  if(kind==0) copy[index].imm=0;
  if(kind==1) copy[count]=copy[index],n=count+1;
  if(kind==2) copy[index].code=BPF_ALU64|BPF_MOV|BPF_K;
  if(kind==3) copy[index].src_reg=1;
  if(kind==4) copy[index].dst_reg=1;
  if(kind==5) copy[index].off=1;
  if(kind==6) n=4097;
  REQUIRE(!bpf_program__set_insns(prog,copy,n),"set invalid original fixture");
  REQUIRE(forbidden_helper_original(obj,&found)==-EINVAL,"missing/duplicate/malformed/oversized original fails closed");
  copy[index]=saved;
 }
 for(unsigned kind=0;kind<6;kind++) {
  struct bpf_insn saved=copy[index]; size_t target=index;
  copy[index].imm=4;
  if(kind==0) copy[index].imm=112;
  if(kind==1) copy[index].code=BPF_ALU64|BPF_MOV|BPF_K;
  if(kind==2) copy[index].src_reg=1;
  if(kind==3) copy[index].off=1;
  if(kind==4) target=count;
  if(kind==5) copy[index].dst_reg=1;
  memcpy(before,copy,count*sizeof(*before));
  REQUIRE(!bpf_program__set_insns(prog,copy,count),"set invalid prepared fixture");
  REQUIRE(forbidden_helper_restore(obj,target)==-EINVAL,"unexpected prepared helper/shape/index fails closed");
  REQUIRE(!memcmp(bpf_program__insns(prog),before,count*sizeof(*before)),"rejected prepared input remains unchanged");
  copy[index]=saved;
 }
 REQUIRE(!bpf_program__set_insns(prog,copy,4097),"set oversized prepared fixture");
 REQUIRE(forbidden_helper_restore(obj,index)==-EINVAL,"oversized prepared array fails closed");
 REQUIRE(!bpf_program__set_insns(prog,copy,0),"set empty original fixture");
 REQUIRE(forbidden_helper_original(obj,&found)==-EINVAL && forbidden_helper_restore(obj,0)==-EINVAL,"empty arrays fail closed");
 bpf_object__close(obj); free(before); free(copy);
 puts("ok - actual helper validation/restoration preserves exact113 and prepared bytes; invalid inputs rejected");
 return 0;
}
static int actual_send_wait(pid_t pid,int sock,int mnt)
{
 int status,sv[2]={sock,-1};
 ACTUAL_TAIL
 return 0;
}
static int test_send(bool fail)
{
 int sv[2],rc,status,fd; pid_t pid;
 REQUIRE(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,sv),"probe socketpair");
 pid=fork(); REQUIRE(pid>=0,"probe fork");
 if (!pid) {
  close(sv[0]); fd=receive_fd(sv[1]);
  if(fd>=0) close(fd);
  close(sv[1]); _exit(fd<0 ? 2 : 0);
 }
 close(sv[1]);
 fd=fail ? -1 : open("/dev/null",O_RDONLY|O_CLOEXEC);
 REQUIRE(fail || fd>=0,"probe source fd");
 rc=actual_send_wait(pid,sv[0],fd);
 REQUIRE(rc==(fail ? 2 : 0),"send failure stays SETUP; success stays success");
 REQUIRE(!fail || errno==EBADF,"original SCM_RIGHTS errno retained after wait");
 errno=0;
 pid_t reaped=waitpid(pid,&status,WNOHANG);
 /* Any waitable child means the actual tail failed to reap it. */
 if (reaped!=-1 || errno!=ECHILD) {
  if (!reaped) waitpid(pid,&status,0);
  fprintf(stderr,"ASSERT: native parent must always reap child (failed-send=%d)\n",fail);
  return 1;
 }
 puts(fail ? "ok - failed SCM_RIGHTS send returns SETUP and reaps child" : "ok - successful SCM_RIGHTS send reaps child");
 return 0;
}
int main(int argc,char **argv) { REQUIRE(argc==2,"helper object argument"); int rc=test_helper(argv[1]); if(rc) return rc; rc=test_delegate(); if(rc) return rc; rc=test_send(true); return rc ? rc : test_send(false); }
'''.replace('TOKEN_SOURCE',str(HERE / 'token_guest.c')).replace('ACTUAL_TAIL',tail).replace('ACTUAL_DELEGATE',delegate_source)
include = os.environ.get('LIBBPF_INCLUDE', '/usr/include')
archive = os.environ.get('LIBBPF_A', '-lbpf')
with tempfile.TemporaryDirectory(prefix='token-protocol-') as tmp:
    path=Path(tmp); (path/'probe.c').write_text(fixture)
    subprocess.run(['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-O1','-g',
                    '-fsanitize=undefined','-I'+str(ROOT/'src/core/include/uapi'),
                    '-I'+include,str(path/'probe.c'),archive,'-lelf','-lz',
                    '-o',str(path/'probe')],check=True)
    object_dir = os.environ.get('TOKEN_OBJECT_DIR')
    if not object_dir:
        object_dir = str(path)
        subprocess.run(['make','-s','-C',str(HERE),'OUT='+str(path),
                        'KERNEL_SRC='+str(ROOT),'LIBBPF_INCLUDE='+include,
                        'LIBBPF_HELPER_INCLUDE='+os.environ.get('LIBBPF_HELPER_INCLUDE',include+'/bpf'),
                        'CLANG='+os.environ.get('CLANG','clang'),
                        str(path/'bad_helper.bpf.o')],check=True)
    subprocess.run([str(path/'probe'),str(Path(object_dir)/'bad_helper.bpf.o')],check=True,timeout=10)
