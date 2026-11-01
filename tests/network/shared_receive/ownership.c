/* SPDX-License-Identifier: GPL-2.0 */
/* Assertions derived from frozen lifecycle prose. Only OS/BPF/ethtool
 * boundaries are replaced; real manager C, files, flock and fork execute. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "contract_api.h"
#include "ownership_boundary.h"
static int failures;
static void check(int ok,const char *name)
{printf("%s - %s\n",ok?"ok":"not ok",name);fflush(stdout);failures+=!ok;}
static struct xdev_ext_xsk_shared_opts options(unsigned int queue,unsigned int port,unsigned int magic)
{
 struct xdev_ext_xsk_shared_opts o={.sz=sizeof(o),.ifname="fixture0",.queue_id=queue,
  .xdp_flags=XDP_FLAGS_DRV_MODE,.xsk_fd=fixture_borrowed(queue),
  .filter={.flags=XDEV_EXT_XSK_FILTER_F_DST_IPV4|XDEV_EXT_XSK_FILTER_F_DST_PORT|XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC,
   .dst_ipv4=0xc6336402,.dst_port=(uint16_t)port,.payload_magic=magic}};
 return o;
}
static int open_owner(unsigned int queue,unsigned int port,unsigned int magic,struct xdev_ext_xsk_shared **out)
{
 struct xdev_ext_xsk_shared_opts o=options(queue,port,magic);struct xdev_ext_xsk_shared_error error={0};
 int ret=xdev_ext_xsk_shared_open(&o,out,&error);
 printf("open q=%u netns=%u ret=%d operation=%s reason=%s\n",queue,fixture_netns,ret,error.operation,error.reason);fflush(stdout);
 return ret;
}
static int close_owner(struct xdev_ext_xsk_shared *owner)
{
 struct xdev_ext_xsk_shared_error error={0};int ret=xdev_ext_xsk_shared_close(owner,&error);
 printf("close netns=%u ret=%d operation=%s reason=%s\n",fixture_netns,ret,error.operation,error.reason);fflush(stdout);return ret;
}
static int first_owner(struct xdev_ext_xsk_shared **out)
{
 int ret=open_owner(1,9000,0x11223344,out);
 check(ret==0 && *out,"first valid owner configures one queue");
 if(ret || !*out)return -1;
 check(fixture_current_xdp()!=0,"first owner has attached a pinned dispatcher link");
 check(fixture_rule_count()==1,"first owner installs one hardware tuple rule");
 return 0;
}
static void empty(void)
{
 check(fixture_rule_count()==0,"last successful close removes the exact owned hardware rule");
 check(fixture_pin_count()==0,"last owner removes its pinned objects");
 check(fixture_current_xdp()==0,"last owner releases its own XDP attachment");
 check(fixture_unconditional_detach==0,"ownership cleanup never uses unconditional XDP attach/detach");
}
static int wait_child(pid_t pid)
{int status;if(waitpid(pid,&status,0)!=pid)return -1;return WIFEXITED(status)?WEXITSTATUS(status):-1;}
static void basic(void)
{
 struct xdev_ext_xsk_shared *a=NULL,*b=NULL;uint32_t id;
 if(first_owner(&a))return;
 id=fixture_current_xdp();
 check(open_owner(2,9001,0x11223345,&b)==0 && b,"second same-process owner joins a distinct queue and flow");
 if(!b)return;
 check(fixture_current_xdp()==id,"joining a second owner preserves the dispatcher program");
 check(fixture_rule_count()==2,"each owner has its own hardware tuple");
 check(close_owner(a)==0,"first owner can close while second remains");
 check(fixture_current_xdp()==id && fixture_pin_count()>0 && fixture_rule_count()==1,"first close preserves second owner's link, pins and hardware rule");
 check(close_owner(b)==0,"last owner can close");empty();
}
static void conflict(const char *scenario)
{
 struct xdev_ext_xsk_shared *a=NULL,*b=NULL;uint32_t id;int ret,want;
 if(first_owner(&a))return;
 id=fixture_current_xdp();
 if(!strcmp(scenario,"queue-conflict")){ret=open_owner(1,9001,0x11223345,&b);want=-EBUSY;}
 else if(!strcmp(scenario,"flow-conflict")){ret=open_owner(2,9000,0x11223344,&b);want=-EEXIST;}
 else {ret=open_owner(2,9000,0x55667788,&b);want=-EADDRINUSE;}
 check(ret==want,"queue, duplicate-flow and overlapping hardware tuples use their specified errors");
 check(b==NULL && fixture_rule_count()==1 && fixture_current_xdp()==id,"rejected join leaves current owner's hardware and link untouched");
 check(close_owner(a)==0,"original owner remains closable after rejected join");empty();
}
static void foreign_rule(void)
{
 struct xdev_ext_xsk_shared *a=NULL;struct ethtool_rx_flow_spec before,after;int ret;
 fixture_add_foreign_rule(0xc6336402,9000);fixture_get_rule(0,&before);
 ret=open_owner(1,9000,0x11223344,&a);
 check(ret==-EADDRINUSE && a==NULL,"overlapping foreign wildcard-source ntuple is rejected before insertion");
 check(fixture_get_rule(0,&after)==0 && !memcmp(&before,&after,sizeof(before)) && fixture_rule_count()==1,"foreign hardware rule is byte-for-byte preserved");
 check(fixture_current_xdp()==0 && fixture_pin_count()==0,"failed initial join leaves no private dispatcher resources");
}
static void changed_rule(void)
{
 struct xdev_ext_xsk_shared *a=NULL;struct ethtool_rx_flow_spec own,changed,after;
 if(first_owner(&a))return;
 fixture_get_rule(0,&own);changed=own;changed.ring_cookie=6;
 fixture_replace_rule(&changed);
 check(close_owner(a)==-ESTALE,"changed rule at saved location retains close with -ESTALE");
 check(fixture_get_rule(0,&after)==0 && !memcmp(&after,&changed,sizeof(after)),"failed close does not delete or rewrite changed foreign rule");
 fixture_replace_rule(&own);
 check(close_owner(a)==0,"retained close succeeds when exact owned rule is restored");empty();
}
static void foreign_link(int replace)
{
 struct xdev_ext_xsk_shared *a=NULL;int ret;
 if(replace && first_owner(&a))return;
 fixture_foreign_xdp(0x7777);
 ret=replace?close_owner(a):open_owner(1,9000,0x11223344,&a);
 check(ret==(replace?-ESTALE:-EBUSY),"foreign or replaced XDP link is refused with ownership error");
 check(fixture_current_xdp()==0x7777 && fixture_unconditional_detach==0,"foreign XDP attachment remains installed");
 if(!replace)check(a==NULL && fixture_rule_count()==0,"foreign XDP rejection does not install hardware steering");
}
static void corrupt_pin(void)
{
 struct xdev_ext_xsk_shared *a=NULL,*b=NULL;uint32_t id;
 if(first_owner(&a))return;
 id=fixture_current_xdp();fixture_corrupt_pin("meta");
 check(open_owner(2,9001,0x11223345,&b)==-ESTALE && b==NULL,"zero-ID pinned metadata fails closed when joining");
 check(fixture_current_xdp()==id && fixture_rule_count()==1,"invalid pinned metadata cannot reap an existing owner");
}
static void namespaces(void)
{
 struct xdev_ext_xsk_shared *a=NULL,*b=NULL;uint32_t first;
 fixture_netns=11;if(first_owner(&a))return;first=fixture_current_xdp();fixture_netns=12;
 check(close_owner(a)==-EXDEV,"close from another calling namespace retains ownership with -EXDEV");
 check(open_owner(1,9000,0x11223344,&b)==0 && b,"coincident ifindex, queue and flow in another namespace do not conflict");
 if(!b)return;
 check(close_owner(b)==0,"second namespace can clean only its resources");
 check(fixture_current_xdp()==0 && fixture_rule_count()==0,"second namespace has no surviving own attachment or rule");fixture_netns=11;
 check(fixture_current_xdp()==first && fixture_rule_count()==1,"second namespace cleanup preserved first namespace owner");
 check(close_owner(a)==0,"original namespace can retry retained close");empty();
}
static void multiprocess(void)
{
 struct xdev_ext_xsk_shared *a=NULL;pid_t pid;int ready[2],go[2],ret;uint32_t id;
 if(first_owner(&a))return;
 id=fixture_current_xdp();
 if(pipe(ready)||pipe(go)){check(0,"pipes created");return;}
 pid=fork();if(pid<0){check(0,"child created");return;}
 if(!pid) {
  struct xdev_ext_xsk_shared *b=NULL;char token;
  close(ready[0]);close(go[1]);ret=open_owner(2,9001,0x11223345,&b);
  if(write(ready[1],&ret,sizeof(ret))!=(ssize_t)sizeof(ret))_exit(94);
  if(read(go[0],&token,1)!=1)_exit(95);
  if(ret||!b)_exit(96);
  _exit(close_owner(b)?97:0);
 }
 close(ready[1]);close(go[0]);
 if(read(ready[0],&ret,sizeof(ret))!=(ssize_t)sizeof(ret))ret=-EIO;
 check(ret==0,"independent child process joins existing pinned dispatcher");
 check(close_owner(a)==0,"parent owner closes while child owner is alive");
 check(fixture_current_xdp()==id && fixture_rule_count()==1,"parent close preserves child's shared link and hardware tuple");
 if(write(go[1],"x",1)!=1)check(0,"child release signal delivered");
 close(go[1]);close(ready[0]);check(wait_child(pid)==0,"last child owner closes its own resources");empty();
}
static void fork_policy(void)
{
 struct xdev_ext_xsk_shared *a=NULL;pid_t pid;
 if(first_owner(&a))return;
 pid=fork();if(pid<0){check(0,"fork succeeds");return;}
 if(!pid)_exit(close_owner(a)==-ECHILD?0:1);
 check(wait_child(pid)==0,"fork child cannot operate parent's handle");
 check(fixture_rule_count()==1 && fixture_current_xdp()!=0,"fork rejection retains original parent's resources");
 check(close_owner(a)==0,"originating process can close its handle");empty();
}
static void insertion_crash(void)
{
 struct xdev_ext_xsk_shared *b=NULL;struct ethtool_rx_flow_spec before,after;pid_t pid;int ret;
 pid=fork();if(pid<0){check(0,"crash child fork succeeds");return;}
 if(!pid){struct xdev_ext_xsk_shared *a=NULL;fixture_crash_after_insert=1;ret=open_owner(1,9000,0x11223344,&a);_exit(ret?98:99);}
 check(wait_child(pid)==77,"child stops after hardware insertion side effect before receiving its allocated location");
 check(fixture_rule_count()==1 && fixture_get_rule(0,&before)==0,"unrecorded hardware insertion persists after process death");
 ret=open_owner(2,9001,0x11223345,&b);
 check(ret==-ESTALE,"next opener quarantines insertion whose location ownership cannot be proven");
 check(fixture_rule_count()==1 && fixture_get_rule(0,&after)==0 && !memcmp(&before,&after,sizeof(before)),"crash recovery never deletes unproven hardware rule");
 check(fixture_pin_count()>0,"ambiguous owner state remains available for diagnosis and recovery");
}
static void recorded_crash(int changed)
{
 struct xdev_ext_xsk_shared *b=NULL;struct ethtool_rx_flow_spec before,after;pid_t pid;int ret;
 pid=fork();if(pid<0){check(0,"recorded crash child fork succeeds");return;}
 if(!pid){struct xdev_ext_xsk_shared *a=NULL;ret=open_owner(1,9000,0x11223344,&a);_exit(ret?98:77);}
 check(wait_child(pid)==77,"child exits after full owner transaction");
 check(fixture_rule_count()==1 && fixture_get_rule(0,&before)==0,"fully recorded rule persists after owner exits");
 if(changed){before.ring_cookie=6;fixture_replace_rule(&before);}
 ret=open_owner(2,9001,0x11223345,&b);
 if(changed) {
  check(ret==-ESTALE,"departed owner's changed hardware rule is quarantined");
  check(fixture_rule_count()==1 && fixture_get_rule(0,&after)==0 && !memcmp(&before,&after,sizeof(before)),"stale owner recovery preserves changed foreign rule");
 } else {
  check(ret==0 && b,"new process recovers departed owner with recorded exact rule");
  check(fixture_rule_count()==1,"recognized crash recovery removes only prior rule before installing new rule");
  if(b)check(close_owner(b)==0,"recovered dispatcher remains normally closable");
  empty();
 }
}
int main(int argc,char **argv)
{
 const char *scenario=argc>2?argv[2]:"basic";
 if(argc<2)return 2;
 fixture_init(argv[1]);
 if(!strcmp(scenario,"basic"))basic();
 else if(strstr(scenario,"-conflict"))conflict(scenario);
 else if(!strcmp(scenario,"foreign-rule"))foreign_rule();
 else if(!strcmp(scenario,"changed-rule"))changed_rule();
 else if(!strcmp(scenario,"foreign-link"))foreign_link(0);
 else if(!strcmp(scenario,"replaced-link"))foreign_link(1);
 else if(!strcmp(scenario,"corrupt-pin"))corrupt_pin();
 else if(!strcmp(scenario,"namespaces"))namespaces();
 else if(!strcmp(scenario,"multiprocess"))multiprocess();
 else if(!strcmp(scenario,"fork-policy"))fork_policy();
 else if(!strcmp(scenario,"insertion-crash"))insertion_crash();
 else if(!strcmp(scenario,"recorded-crash"))recorded_crash(0);
 else if(!strcmp(scenario,"changed-crash-rule"))recorded_crash(1);
 else return 2;
 printf("RESULT failures=%d\n",failures);return failures?1:0;
}
