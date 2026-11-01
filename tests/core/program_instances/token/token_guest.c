// SPDX-License-Identifier: GPL-2.0
/* Guest-only upstream token delegation; no device emulator or host settings. */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <linux/mount.h>
#include <linux/xdev_ext_mech.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#define BIT(n) (1ULL<<(n))
#define REQUIRE(c,msg) do { if (!(c)) { fprintf(stderr,"ASSERT: %s errno=%d\n",msg,errno); return 1; } } while (0)
#define SETUP(c,msg) do { if (!(c)) { fprintf(stderr,"SETUP: %s errno=%d\n",msg,errno); return 2; } } while (0)
static ino_t initial_userns;
static const char *objects;
static int send_fd(int sock,int fd)
{
 char byte=0,control[CMSG_SPACE(sizeof(int))]={0};
 struct iovec io={&byte,1};
 struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
 struct cmsghdr *c=CMSG_FIRSTHDR(&msg);
 c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(sizeof(fd));
 memcpy(CMSG_DATA(c),&fd,sizeof(fd));
 return sendmsg(sock,&msg,MSG_NOSIGNAL)==1 ? 0 : -1;
}
static int receive_fd(int sock)
{
 char byte,control[CMSG_SPACE(sizeof(int))]={0}; int fd;
 struct iovec io={&byte,1};
 struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
 struct cmsghdr *c;
 if (recvmsg(sock,&msg,MSG_CMSG_CLOEXEC)!=1 || (msg.msg_flags & MSG_CTRUNC)) return -1;
 c=CMSG_FIRSTHDR(&msg);
 if (!c || c->cmsg_level!=SOL_SOCKET || c->cmsg_type!=SCM_RIGHTS || c->cmsg_len!=CMSG_LEN(sizeof(fd))) return -1;
 memcpy(&fd,CMSG_DATA(c),sizeof(fd)); return fd;
}
static int write_file(const char *path,const char *data)
{
 int fd=open(path,O_WRONLY|O_CLOEXEC|O_NOFOLLOW); ssize_t n;
 if (fd<0) return -1;
 n=write(fd,data,strlen(data)); close(fd); return n==(ssize_t)strlen(data) ? 0 : -1;
}
static int enter_userns(void)
{
 char map[80]; uid_t uid=getuid(); gid_t gid=getgid(); struct stat st;
 SETUP(!unshare(CLONE_NEWUSER),"unshare guest child user namespace");
 SETUP(!write_file("/proc/self/setgroups","deny") || errno==ENOENT,"deny setgroups");
 snprintf(map,sizeof(map),"0 %u 1",uid); SETUP(!write_file("/proc/self/uid_map",map),"uid mapping");
 snprintf(map,sizeof(map),"0 %u 1",gid); SETUP(!write_file("/proc/self/gid_map",map),"gid mapping");
 SETUP(!setgid(0) && !setuid(0),"namespace root");
 SETUP(!stat("/proc/self/ns/user",&st),"userns identity");
 REQUIRE(st.st_ino!=initial_userns,"loader must have no init user namespace capabilities");
 SETUP(!unshare(CLONE_NEWNS),"guest child mount namespace");
 return 0;
}
struct loaded { struct bpf_object *obj; struct bpf_link *link; int selected; };
/* This fixed test object has one ordinary helper CALL and no BPF subprograms. */
#define FORBIDDEN_MAX_INSNS 4096
static bool forbidden_call_shape(const struct bpf_insn *insn)
{
 return insn->code==(BPF_JMP|BPF_CALL) && !insn->src_reg &&
        !insn->dst_reg && !insn->off;
}
static int forbidden_helper_original(struct bpf_object *obj,size_t *index)
{
 struct bpf_program *prog=bpf_object__find_program_by_name(obj,"token_prepare");
 const struct bpf_insn *insns; size_t count,found=0;
 if (!prog) return -EINVAL;
 count=bpf_program__insn_cnt(prog); insns=bpf_program__insns(prog);
 if (!count || count>FORBIDDEN_MAX_INSNS || !insns) return -EINVAL;
 for (size_t i=0;i<count;i++) {
  if (insns[i].imm!=BPF_FUNC_probe_read_kernel) continue;
  if (!forbidden_call_shape(&insns[i]) || ++found!=1) return -EINVAL;
  *index=i;
 }
 return found==1 ? 0 : -EINVAL;
}
static int forbidden_helper_restore(struct bpf_object *obj,size_t index)
{
 struct bpf_program *prog=bpf_object__find_program_by_name(obj,"token_prepare");
 const struct bpf_insn *insns; struct bpf_insn *copy;
 size_t count; int before,ret;
 if (!prog) return -EINVAL;
 count=bpf_program__insn_cnt(prog); insns=bpf_program__insns(prog);
 if (!count || count>FORBIDDEN_MAX_INSNS || index>=count || !insns) return -EINVAL;
 before=insns[index].imm;
 if (!forbidden_call_shape(&insns[index]) ||
     (before!=BPF_FUNC_probe_read_kernel && before!=BPF_FUNC_probe_read)) return -EINVAL;
 /* set_insns may realloc its storage: never pass a borrowed insns alias. */
 copy=malloc(count*sizeof(*copy)); if (!copy) return -ENOMEM;
 memcpy(copy,insns,count*sizeof(*copy));
 copy[index].imm=BPF_FUNC_probe_read_kernel;
 ret=bpf_program__set_insns(prog,copy,count); free(copy);
 if (!ret) fprintf(stderr,"helper index=%zu prepared=%d restored=%d insns=%zu\n",
                   index,before,BPF_FUNC_probe_read_kernel,count);
 return ret;
}
static int object_load(const char *name,const char *token_path,struct loaded *out,char *log,size_t size)
{
 LIBBPF_OPTS(bpf_object_open_opts,opts,.bpf_token_path=token_path,.kernel_log_buf=log,.kernel_log_size=size,.kernel_log_level=1);
 char path[4096]; struct bpf_map *map; int ret;
 snprintf(path,sizeof(path),"%s/%s",objects,name);
 out->obj=bpf_object__open_file(path,&opts);
 ret=libbpf_get_error(out->obj); if (ret) { out->obj=NULL; return ret; }
 if (!strcmp(name,"bad_helper.bpf.o")) {
  size_t index=0;
  ret=forbidden_helper_original(out->obj,&index); if (ret) return ret;
  fprintf(stderr,"helper index=%zu original=%d\n",index,BPF_FUNC_probe_read_kernel);
  ret=bpf_object__prepare(out->obj); if (ret) return ret;
  /* libbpf's TRACEPOINT feature probe is outside this token's authority.
   * Undo only its known 113->4 fallback after all prepare relocations. */
  ret=forbidden_helper_restore(out->obj,index); if (ret) return ret;
 }
 ret=bpf_object__load(out->obj); if (ret) return ret;
 map=bpf_object__find_map_by_name(out->obj,"private_cpu_ops"); if (!map) return -ENOENT;
 out->link=bpf_map__attach_struct_ops(map);
 ret=libbpf_get_error(out->link); if (ret) { out->link=NULL; return ret; }
 map=bpf_object__find_map_by_name(out->obj,"selected");
 out->selected=map ? bpf_map__fd(map) : -1;
 return out->selected<0 ? -ENOENT : 0;
}
static void unload(struct loaded *p)
{ bpf_link__destroy(p->link); bpf_object__close(p->obj); memset(p,0,sizeof(*p)); }
static int create_session(int link_fd,int *ring_out)
{
 struct io_uring_params params={0};
 struct io_uring_xdev_ext_umem_reg reg={0};
 struct xdev_ext_mech_create_programs req={.size=sizeof(req),.version=XDEV_EXT_MECH_CREATE_PROGRAMS_VERSION};
 struct xdev_ext_mech_create *c=&req.request.create;
 struct io_uring_xdev_ext_mech op={.op=XDEV_EXT_MECH_OP_CREATE_PROGRAMS,.arg=(uintptr_t)&req};
 int ring,ret; void *mem;
 ring=syscall(__NR_io_uring_setup,8,&params); SETUP(ring>=0,"io_uring_setup");
 *ring_out=ring;
 mem=mmap(NULL,16384,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 SETUP(mem!=MAP_FAILED,"UMEM allocation");
 reg.addr=(uintptr_t)mem; reg.size=16384; reg.frame_size=4096;
 ret=syscall(__NR_io_uring_register,ring,IORING_REGISTER_XDEV_EXT_UMEM,&reg,1);
 SETUP(ret==0,"register real IOU_UMEM");
 for (unsigned i=0;i<XDEV_EXT_MECH_MAX_STAGES;i++) req.program_fds[i]=-1;
 req.program_fds[0]=link_fd; /* explicit PRIVATE link; never global fallback */
 req.request.size=sizeof(req.request); req.request.version=XDEV_EXT_MECH_CREATE_REPORT_VERSION;
 c->abi_version=XDEV_EXT_MECH_ABI_VERSION; c->nr_stages=1;
 c->pool_kind=XDEV_EXT_MECH_POOL_IOU_UMEM; c->pool_fd=-1;
 c->layout=(struct xdev_ext_mech_layout){4096,0,4096,4096}; c->depth=1; c->eventfd=-1;
 c->st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_CPU,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=-1,.arg0=XDEV_EXT_CPU_XFORM_CRC32C_SEAL};
 ret=syscall(__NR_io_uring_register,ring,IORING_REGISTER_XDEV_EXT_MECH,&op,1);
 if (ret || req.request.report.result) fprintf(stderr,"CREATE ret=%d result=%d phase=%u\n",ret,req.request.report.result,req.request.report.phase);
 REQUIRE(ret==0 && req.request.report.result==0 && c->session_id,"CREATE with explicit token-loaded PRIVATE link");
 return 0;
}
static int counter(struct loaded *p,__u64 expected)
{
 __u32 key=0; __u64 value=~0ULL;
 REQUIRE(!bpf_map_lookup_elem(p->selected,&key,&value) && value==expected,"selected instance PREPARE counter"); return 0;
}
static int child(int sock,const char *test)
{
 int rc,fs,mnt,ret,ring_a=-1,ring_b=-1; char path[80];
 static char log[262144]; struct loaded a={0},b={0},bad={0};
 rc=enter_userns(); if (rc) return rc;
 fs=syscall(__NR_fsopen,"bpf",0); SETUP(fs>=0,"fsopen token bpffs");
 errno=0; ret=syscall(__NR_fsconfig,fs,FSCONFIG_SET_STRING,"delegate_cmds","any",0);
 REQUIRE(ret==-1 && errno==EPERM,"child cannot self-delegate BPF");
 SETUP(!send_fd(sock,fs),"send guest userns fs context"); close(fs);
 mnt=receive_fd(sock); SETUP(mnt>=0,"receive administrator-delegated detached bpffs");
 snprintf(path,sizeof(path),"/proc/self/fd/%d",mnt);
 if (!strcmp(test,"positive")) {
  ret=object_load("private_a.bpf.o","",&bad,log,sizeof(log));
  REQUIRE(ret==-EPERM || ret==-EACCES,"no token denies struct_ops load"); unload(&bad);
 }
 memset(log,0,sizeof(log)); ret=object_load("private_a.bpf.o",path,&a,log,sizeof(log));
 if (strcmp(test,"positive")) {
  REQUIRE(ret==-EPERM || ret==-EACCES,"restricted delegation denies load with permission error");
  REQUIRE(a.obj && bpf_object__token_fd(a.obj)>=0,"negative used real created token");
  unload(&a); close(mnt); printf("PASS token=%s permission-denied\n",test); return 0;
 }
 if (ret) fprintf(stderr,"%s\n",log);
 REQUIRE(ret==0 && bpf_object__token_fd(a.obj)>=0,"token loads and attaches PRIVATE A");
 memset(log,0,sizeof(log)); ret=object_load("private_b.bpf.o",path,&b,log,sizeof(log));
 if (ret) fprintf(stderr,"%s\n",log);
 REQUIRE(ret==0 && bpf_object__token_fd(b.obj)>=0,"token loads and attaches PRIVATE B");
 REQUIRE(bpf_link__fd(a.link)!=bpf_link__fd(b.link),"independent PRIVATE links");
 if ((rc=counter(&a,0)) || (rc=counter(&b,0))) return rc;
 if ((rc=create_session(bpf_link__fd(a.link),&ring_a))) return rc;
 if ((rc=counter(&a,1)) || (rc=counter(&b,0))) return rc;
 if ((rc=create_session(bpf_link__fd(b.link),&ring_b))) return rc;
 if ((rc=counter(&a,1)) || (rc=counter(&b,2))) return rc;
 memset(log,0,sizeof(log)); ret=object_load("bad_helper.bpf.o",path,&bad,log,sizeof(log));
 REQUIRE(ret<0 && bad.obj && bpf_object__token_fd(bad.obj)>=0,"forbidden helper rejected under token");
 REQUIRE(strstr(log,"program of this type cannot use helper bpf_probe_read_kernel#113"),"exact helper whitelist verifier diagnostic");
 unload(&bad); close(ring_b); close(ring_a); unload(&b); unload(&a); close(mnt);
 puts("PASS token=positive no-init-userns-caps no-token-denied two-PRIVATE-links explicit-CREATE selected-counters helper-denied"); return 0;
}
static int delegate(int fs,const char *test)
{
 /* struct_ops expected_attach_type is the BTF member index: prepare=2,
  * build=3, complete=4 in the fixed CPU ops type (not an attach enum).
  * libbpf 1.6 first probes SOCKET_FILTER with expected_attach_type=0. */
 __u64 masks[]={BIT(BPF_MAP_CREATE)|BIT(BPF_BTF_LOAD)|BIT(BPF_PROG_LOAD),BIT(BPF_MAP_TYPE_ARRAY)|BIT(BPF_MAP_TYPE_STRUCT_OPS),BIT(BPF_PROG_TYPE_SOCKET_FILTER)|BIT(BPF_PROG_TYPE_STRUCT_OPS),BIT(0)|BIT(2)|BIT(3)|BIT(4)};
 const char *keys[]={"delegate_cmds","delegate_maps","delegate_progs","delegate_attachs"}; char value[40]; int fd;
 if (!strcmp(test,"no-command")) masks[0]&=~BIT(BPF_PROG_LOAD);
 if (!strcmp(test,"no-map")) masks[1]&=~BIT(BPF_MAP_TYPE_STRUCT_OPS);
 if (!strcmp(test,"no-prog")) masks[2]&=~BIT(BPF_PROG_TYPE_STRUCT_OPS);
 if (!strcmp(test,"no-attach")) masks[3]&=~(BIT(2)|BIT(3)|BIT(4));
 for (unsigned i=0;i<4;i++) {
  snprintf(value,sizeof(value),"0x%llx",(unsigned long long)masks[i]);
  if (syscall(__NR_fsconfig,fs,FSCONFIG_SET_STRING,keys[i],value,0)) return -1;
 }
 if (syscall(__NR_fsconfig,fs,FSCONFIG_CMD_CREATE,NULL,NULL,0)) return -1;
 fd=syscall(__NR_fsmount,fs,0,0); return fd;
}
int main(int argc,char **argv)
{
 struct stat ns; struct btf *btf; const char *tests[]={"positive","no-command","no-map","no-prog","no-attach"};
 /* Refuse implicit execution. Root invokes this only inside a prepared guest. */
 SETUP(argc==3 && !strcmp(argv[1],"--guest"),"usage: token_guest --guest OBJECT_DIR (guest only)");
 objects=argv[2]; setbuf(stdout,NULL); setbuf(stderr,NULL);
 const char *inputs[]={"private_a.bpf.o","private_b.bpf.o","bad_helper.bpf.o"};
 for (unsigned i=0;i<3;i++) {
  char path[4096]; snprintf(path,sizeof(path),"%s/%s",objects,inputs[i]);
  SETUP(!access(path,R_OK),"required BPF object");
 }
 SETUP(geteuid()==0,"guest administrator required for delegation parent");
 SETUP(!stat("/proc/self/ns/user",&ns),"initial user namespace"); initial_userns=ns.st_ino;
 btf=btf__parse("/sys/kernel/btf/vmlinux",NULL);
 SETUP(!libbpf_get_error(btf),"running kernel BTF");
 int type=btf__find_by_name_kind(btf,"xdev_ext_cpu_mech_ops",BTF_KIND_STRUCT); btf__free(btf);
 SETUP(type>0,"running kernel CPU struct_ops type");
 for (unsigned i=0;i<sizeof(tests)/sizeof(tests[0]);i++) {
  int sv[2],fs,mnt,status; pid_t pid;
  SETUP(!socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,sv),"socketpair");
  pid=fork(); SETUP(pid>=0,"fork");
  if (!pid) { close(sv[0]); int rc=child(sv[1],tests[i]); close(sv[1]); _exit(rc); }
  close(sv[1]); fs=receive_fd(sv[0]);
  if (fs<0) { close(sv[0]); waitpid(pid,&status,0); return WIFEXITED(status) && WEXITSTATUS(status) ? WEXITSTATUS(status) : 2; }
  mnt=delegate(fs,tests[i]); close(fs);
  if (mnt<0) { close(sv[0]); waitpid(pid,&status,0); fprintf(stderr,"SETUP: bpffs delegation errno=%d\n",errno); return 2; }
  int sent=send_fd(sv[0],mnt);
  int send_error=errno;
  close(mnt); close(sv[0]); /* EOF releases the child when send failed. */
  pid_t waited;
  do { waited=waitpid(pid,&status,0); } while (waited<0 && errno==EINTR);
  if (sent) {
   fprintf(stderr,"SETUP: send delegated bpffs fd errno=%d\n",send_error);
   errno=send_error;
   return 2;
  }
  SETUP(waited==pid,"wait delegated child");
  REQUIRE(WIFEXITED(status),"native child exited normally");
  if (WEXITSTATUS(status)) return WEXITSTATUS(status);
 }
 puts("PASS token-native cases=5; BPF delegation grants no device or physical address authority"); return 0;
}
