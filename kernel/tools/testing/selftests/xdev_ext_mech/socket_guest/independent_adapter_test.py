#!/usr/bin/env python3
"""Run actual socket adapter functions against a real loopback UDP peer.

The kvec/sendmsg bridge is host-only. Socket state, worker callbacks and
custody are fixtures; this does not exercise kernel file references or DMA.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[5]

def function(text, name):
    m = re.search(r'^static (?:int|void) ' + name + r'\(', text, re.M)
    if not m:
        raise AssertionError('missing actual production function '+name)
    end = text.index('{',m.start())
    depth=1
    i=end+1
    while depth:
        depth+=(text[i]=='{')-(text[i]=='}')
        i+=1
    return text[m.start():i]

PREAMBLE=r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include "io_uring/xdev_ext_mech_core.h"
typedef __u8 u8;typedef __u32 u32;typedef __u64 u64;
#define GFP_KERNEL 0
#define SEND_SHUTDOWN 2
#define TCP_ESTABLISHED 1
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define CORK 1
struct sock {int sk_family,sk_protocol,sk_shutdown,sk_state,pending,gso_size,cork;};
struct socket {struct sock *sk;int type,fd;};
#define udp_sk(x) (x)
#define udp_test_bit(bit,sk) ((void)(bit),(sk)->cork)
struct kvec {void *iov_base;size_t iov_len;};
struct xdev_ext_mech_frame {u64 umem_addr;u32 index,data_off,data_len;void *kaddr;};
struct xdev_ext_mech_batch {u32 slot,nr,bytes;u64 ticket;int status;struct xdev_ext_mech_frame f[32];};
struct xdev_ext_mech_pool {u32 nr_frames,frame_size;__u8 states[32];};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout layout;u32 depth;bool admits;};
struct xdev_ext_mech_stage {u32 direction;struct socket *file;void *priv;struct xdev_ext_mech_session *s;};
/* OS credential adapters only. The behavioral oracle below is unchanged. */
struct cred {unsigned refs;};
static struct cred caller_cred={1};
static const struct cred *active_cred=&caller_cred;
static const struct cred *get_current_cred(void){((struct cred *)active_cred)->refs++;return active_cred;}
static void put_cred(const struct cred *c){if(!c || c->refs<2)abort();((struct cred *)c)->refs--;}
static const struct cred *override_creds(const struct cred *c){const struct cred *old=active_cred;active_cred=c;return old;}
static void revert_creds(const struct cred *c){active_cred=c;}
static int allocations,frees,fail_alloc,calls,completions,complete_error,forced_result=INT32_MAX;
static u64 complete_ticket;
static void *zalloc(size_t n){if(fail_alloc && ++allocations==fail_alloc)return NULL; if(!fail_alloc)allocations++;return calloc(1,n);}
#define kzalloc(n,g) zalloc(n)
#define kvcalloc(n,z,g) zalloc((n)*(z))
static void dealloc(void *p){if(p)frees++;free(p);}
#define kfree dealloc
#define kvfree dealloc
static struct socket *sock_from_file(struct socket *f){return f;}
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s){return s->depth;}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return &s->pool;}
static struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s){return &s->layout;}
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b){return b->nr;}
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b){return b->bytes;}
static u32 xdev_ext_mech_batch_slot(struct xdev_ext_mech_batch *b){return b->slot;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b){return b->ticket;}
static int xdev_ext_mech_batch_status(struct xdev_ext_mech_batch *b){return b->status;}
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 i,struct xdev_ext_mech_frame *f){if(i>=b->nr)return -EINVAL;*f=b->f[i];return 0;}
static u32 xdev_ext_mech_pool_frame_state(struct xdev_ext_mech_pool *p,u32 i){return i<p->nr_frames?p->states[i]:XDEV_EXT_MECH_F_NR;}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s){return s->admits;}
static void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch *b,u64 ticket,int err){completions++;complete_ticket=ticket;complete_error=err;b->status=err;}
static int kernel_sendmsg(struct socket *s,struct msghdr *m,struct kvec *v,u32 nr,size_t bytes){
 struct iovec iov[32];struct msghdr out={0};calls++;
 if(forced_result!=INT32_MAX)return forced_result;
 for(u32 i=0;i<nr;i++){iov[i].iov_base=v[i].iov_base;iov[i].iov_len=v[i].iov_len;}
 out.msg_iov=iov;out.msg_iovlen=nr;
 ssize_t n=sendmsg(s->fd,&out,m->msg_flags);(void)bytes;return n<0?-errno:(int)n;
}
'''
TESTS=r'''
#define CHECK(x) do{if(!(x)){fprintf(stderr,"line=%d case=%s failed: %s errno=%d\n",__LINE__,test_case,#x,errno);return 1;}}while(0)
static const char *test_case;
struct fixture {struct sock sk;struct socket socket;struct xdev_ext_mech_stage st;struct xdev_ext_mech_session s;struct xdev_ext_mech_batch b;struct xdev_ext_socket_send_desc desc[2];unsigned char pool[2][256];};
static void initialize(struct fixture *f){
 memset(f,0,sizeof(*f));f->sk=(struct sock){.sk_family=AF_INET,.sk_protocol=IPPROTO_UDP,.sk_state=TCP_ESTABLISHED};f->socket=(struct socket){&f->sk,SOCK_DGRAM,-1};f->s.depth=8;f->s.admits=true;f->s.pool.nr_frames=2;f->s.pool.frame_size=256;
 f->s.layout=(struct xdev_ext_mech_layout){256,16,64,128};f->st=(struct xdev_ext_mech_stage){.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.file=&f->socket,.s=&f->s};
 f->b.nr=2;f->b.bytes=128;f->b.ticket=123;
 for(u32 i=0;i<2;i++){f->b.f[i]=(struct xdev_ext_mech_frame){.index=i,.data_off=16,.data_len=64,.umem_addr=i*256,.kaddr=f->pool[i]};f->desc[i]=(struct xdev_ext_socket_send_desc){.frame_pos=i,.frame_off=16,.len=64};f->s.pool.states[i]=XDEV_EXT_MECH_F_INFLIGHT;memset(f->pool[i],0xa7,256);}
 calls=completions=complete_error=allocations=frees=fail_alloc=0;forced_result=INT32_MAX;
}
static int bind_fixture(struct fixture *f){struct xdev_ext_mech_stage_uapi u={0};return xdev_ext_socket_bind(&f->st,&u);}
static int readiness(void){
 struct fixture f;initialize(&f);CHECK(xdev_ext_socket_ready(&f.socket)==0);
 f.sk.sk_family=AF_INET6;CHECK(xdev_ext_socket_ready(&f.socket)==0);f.sk.sk_family=AF_UNIX;CHECK(xdev_ext_socket_ready(&f.socket)==-EPROTONOSUPPORT);
 initialize(&f);f.socket.type=SOCK_STREAM;CHECK(xdev_ext_socket_ready(&f.socket)==-EPROTONOSUPPORT);
 initialize(&f);f.sk.sk_protocol=IPPROTO_TCP;CHECK(xdev_ext_socket_ready(&f.socket)==-EPROTONOSUPPORT);
 initialize(&f);f.socket.sk=NULL;CHECK(xdev_ext_socket_ready(&f.socket)==-EPROTONOSUPPORT);
 initialize(&f);f.sk.sk_shutdown=SEND_SHUTDOWN;CHECK(xdev_ext_socket_ready(&f.socket)==-ESHUTDOWN);
 initialize(&f);f.sk.sk_state=0;CHECK(xdev_ext_socket_ready(&f.socket)==-ENOTCONN);
 initialize(&f);f.sk.cork=1;CHECK(xdev_ext_socket_ready(&f.socket)==-EOPNOTSUPP);
 initialize(&f);f.sk.pending=1;CHECK(xdev_ext_socket_ready(&f.socket)==-EOPNOTSUPP);
 initialize(&f);f.sk.gso_size=512;CHECK(xdev_ext_socket_ready(&f.socket)==-EOPNOTSUPP);
 return 0;
}
static int binding(void){
 struct fixture f;struct xdev_ext_mech_stage_uapi u={0};initialize(&f);
 f.st.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;CHECK(xdev_ext_socket_bind(&f.st,&u)==-EINVAL);
 initialize(&f);u.flags=1;CHECK(xdev_ext_socket_bind(&f.st,&u)==-EINVAL);u.flags=0;u.arg0=1;CHECK(xdev_ext_socket_bind(&f.st,&u)==-EINVAL);u.arg0=0;u.arg1=1;CHECK(xdev_ext_socket_bind(&f.st,&u)==-EINVAL);u.arg1=0;
 f.st.file=NULL;CHECK(xdev_ext_socket_bind(&f.st,&u)==-ENOTSOCK);
 initialize(&f);fail_alloc=1;CHECK(bind_fixture(&f)==-ENOMEM);CHECK(f.st.priv==NULL&&frees==0);
 initialize(&f);fail_alloc=2;CHECK(bind_fixture(&f)==-ENOMEM);CHECK(f.st.priv==NULL&&frees==1);
 initialize(&f);CHECK(bind_fixture(&f)==0);CHECK(allocations==2);xdev_ext_socket_unbind(&f.st);CHECK(frees==2&&f.st.priv==NULL);
 return 0;
}
static int bad_spans(void){
 for(int c=0;c<16;c++){
 struct fixture f;initialize(&f);CHECK(bind_fixture(&f)==0);u32 n=2;
 if(c==0)f.b.bytes=0;if(c==1)f.b.bytes=XDEV_EXT_SOCKET_MAX_DATAGRAM+1;if(c==2)f.b.slot=8;
 if(c==3)n=0;if(c==4)n=33;if(c==5)n=1;if(c==6)f.b.f[0].kaddr=NULL;if(c==7)f.b.f[0].index=2;
 if(c==8)f.b.f[0].data_len=0;if(c==9)f.b.f[0].data_off=257;if(c==10)f.b.f[0].data_len=256;
 if(c==11)f.desc[0].flags=1;if(c==12)f.desc[1].frame_pos=0;if(c==13)f.desc[0].frame_off=0;if(c==14)f.desc[0].len=63;if(c==15)f.b.bytes=127;
 CHECK(xdev_ext_socket_validate(&f.st,&f.b,(u8 *)f.desc,n)<0);CHECK(calls==0&&completions==0);xdev_ext_socket_unbind(&f.st);
 }
 return 0;
}
static int completion_boundaries(void){
 const int results[]={-EAGAIN,-EINTR,-EIO,127,128};
 for(unsigned i=0;i<5;i++){
 struct fixture f;initialize(&f);CHECK(bind_fixture(&f)==0);CHECK(!xdev_ext_socket_validate(&f.st,&f.b,(u8 *)f.desc,2));forced_result=results[i];
 CHECK(xdev_ext_socket_submit(&f.st,&f.b)==(i==0?-EAGAIN:0));CHECK(calls==1);CHECK(completions==(i==0?0:1));
 if(i){CHECK(complete_ticket==123);CHECK(complete_error==(i==4?0:i==3?-EIO:results[i]));struct xdev_ext_socket_mech_cqe cqe;xdev_ext_socket_fill_cqe(&f.st,&f.b,&cqe);CHECK(cqe.status==complete_error&&cqe.bytes_sent==(i==4?128:0));}
 xdev_ext_socket_unbind(&f.st);
 }
 for(int c=0;c<6;c++){
 struct fixture f;initialize(&f);CHECK(bind_fixture(&f)==0);CHECK(!xdev_ext_socket_validate(&f.st,&f.b,(u8 *)f.desc,2));
 if(c==0)xdev_ext_socket_mark_dead(&f.st);if(c==1)f.s.admits=false;if(c==2)f.b.slot=8;if(c==3)f.s.pool.states[0]=XDEV_EXT_MECH_F_HELD;if(c==4)f.sk.cork=1;if(c==5)f.sk.sk_shutdown=SEND_SHUTDOWN;
 CHECK(xdev_ext_socket_submit(&f.st,&f.b)<0);CHECK(calls==0&&completions==0);xdev_ext_socket_unbind(&f.st);
 }
 return 0;
}
static int udp257(int family){
 struct fixture f;initialize(&f);int rx=socket(family,SOCK_DGRAM,0),tx=socket(family,SOCK_DGRAM,0);CHECK(rx>=0&&tx>=0);struct sockaddr_storage address={0};socklen_t alen;
 if(family==AF_INET){struct sockaddr_in *a=(void *)&address;a->sin_family=family;a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);alen=sizeof(*a);}else{struct sockaddr_in6 *a=(void *)&address;a->sin6_family=family;a->sin6_addr=in6addr_loopback;alen=sizeof(*a);}
 CHECK(bind(rx,(struct sockaddr *)&address,alen)==0);CHECK(getsockname(rx,(struct sockaddr *)&address,&alen)==0);CHECK(connect(tx,(struct sockaddr *)&address,alen)==0);
 struct timeval timeout={2,0};CHECK(!setsockopt(rx,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)));f.socket.fd=tx;f.sk.sk_family=family;CHECK(bind_fixture(&f)==0);
 unsigned char expected[128],received[129];unsigned mask=0;
 for(unsigned group=0;group<257;group++){
 uint32_t state=0x9e3779b9U^(group*0x85ebca6bU);
 for(unsigned byte=0;byte<128;byte++){state^=state<<13;state^=state>>17;state^=state<<5;expected[byte]=(unsigned char)state;f.pool[byte/64][16+byte%64]=expected[byte];}
 f.b.slot=group%8;f.b.ticket=group+1;mask|=1U<<f.b.slot;
 CHECK(!xdev_ext_socket_validate(&f.st,&f.b,(u8 *)f.desc,2));
 struct xdev_ext_socket_stage *stage=f.st.priv;CHECK(stage->request[f.b.slot].vec[0].iov_base==f.pool[0]+16&&stage->request[f.b.slot].vec[1].iov_base==f.pool[1]+16);
 CHECK(!xdev_ext_socket_submit(&f.st,&f.b));CHECK(complete_ticket==group+1&&complete_error==0);CHECK(recv(rx,received,sizeof(received),0)==128);CHECK(!memcmp(expected,received,128));
 for(unsigned frame=0;frame<2;frame++)for(unsigned byte=0;byte<256;byte++)if(byte<16||byte>=80)CHECK(f.pool[frame][byte]==0xa7);
 }
 CHECK(calls==257&&completions==257&&mask==255);CHECK(recv(rx,received,sizeof(received),MSG_DONTWAIT)<0&&(errno==EAGAIN||errno==EWOULDBLOCK));
 xdev_ext_socket_unbind(&f.st);CHECK(frees==2);close(tx);close(rx);return 0;
}
int main(int argc,char **argv){if(argc!=2)return 2;test_case=argv[1];if(!strcmp(argv[1],"readiness"))return readiness();if(!strcmp(argv[1],"binding"))return binding();if(!strcmp(argv[1],"bad_spans"))return bad_spans();if(!strcmp(argv[1],"completion_boundaries"))return completion_boundaries();if(!strcmp(argv[1],"udp4_257"))return udp257(AF_INET);if(!strcmp(argv[1],"udp6_257"))return udp257(AF_INET6);return 2;}
'''
class IndependentAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='independent-socket-')
        text=(ROOT/'io_uring/xdev_ext_mech_socket.c').read_text()
        structs=text[text.index('struct xdev_ext_socket_request {'):text.index('static int xdev_ext_socket_ready')]
        names=('ready','bind','unbind','fill_info','validate','submit','fill_cqe','mark_dead')
        code=PREAMBLE+structs+'\n'+'\n'.join(function(text,'xdev_ext_socket_'+n) for n in names)+TESTS
        cls.code=code
        source=Path(cls.tmp.name)/'adapter.c';source.write_text(code);cls.binary=Path(cls.tmp.name)/'adapter'
        r=subprocess.run([os.getenv('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-Wno-unused-function','-I',str(ROOT),str(source),'-o',str(cls.binary)],capture_output=True,text=True)
        if r.returncode:raise AssertionError(r.stdout+r.stderr)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_actual_adapter(self):
        for case in ('readiness','binding','bad_spans','completion_boundaries','udp4_257','udp6_257'):
            with self.subTest(case=case):
                r=subprocess.run([str(self.binary),case],capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stdout+r.stderr)
    def test_mutations_rejected(self):
        mutations=(
            ('d[i].flags ||','0 ||','bad_spans'),
            ('READ_ONCE(udp_sk(sk)->gso_size)','0','readiness'),
            ('if (err == -EAGAIN)\n\t\treturn err;','if (err == -EAGAIN)\n\t\terr = 0;','completion_boundaries'),
            ('(u8 *)f.kaddr + f.data_off,','(u8 *)f.kaddr + f.data_off + 1,','udp4_257'),
        )
        for number,(old,new,case) in enumerate(mutations):
            with self.subTest(mutation=number,case=case):
                self.assertEqual(self.code.count(old),1)
                source=Path(self.tmp.name)/f'mutant-{number}.c'
                binary=Path(self.tmp.name)/f'mutant-{number}'
                source.write_text(self.code.replace(old,new))
                compile_result=subprocess.run([os.getenv('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-Wno-unused-function','-I',str(ROOT),str(source),'-o',str(binary)],capture_output=True,text=True)
                self.assertEqual(compile_result.returncode,0,compile_result.stdout+compile_result.stderr)
                result=subprocess.run([str(binary),case],capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0,'unsafe production mutation escaped behavioral tests')
if __name__=='__main__':unittest.main(verbosity=2)
