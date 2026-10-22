// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include "xdev_ext_preload_core.h"
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
static long model_syscall(long nr, ...);
#define syscall model_syscall
#include "xdev_ext_preload_socket_mech.h"
#undef syscall

static void *registered;
static int sink=-1, wake=-1, starts, arms, mode, stops;
static unsigned stages;
static struct xdev_ext_mech_stats snapshot;

/* Only the unavailable custom kernel API is modelled. The production runtime
 * creates and reuses its actual frame/eventfd; sends reach an actual UDP peer.
 */
static long model_syscall(long nr, ...)
{
	va_list ap;
	long ret;
	va_start(ap,nr);
	if(nr==SYS_io_uring_setup) {
		(void)va_arg(ap,int);(void)va_arg(ap,void *);
		ret=eventfd(0,EFD_CLOEXEC);
	} else if(nr==SYS_io_uring_register) {
		(void)va_arg(ap,int);
		unsigned opcode=va_arg(ap,unsigned);
		void *arg=va_arg(ap,void *);
		(void)va_arg(ap,int);
		ret=0;
		if(opcode==IORING_REGISTER_XDEV_EXT_UMEM)registered=(void *)(uintptr_t)((struct io_uring_xdev_ext_umem_reg *)arg)->addr;
		else {
			struct io_uring_xdev_ext_mech *r=arg;
			void *p=(void *)(uintptr_t)r->arg;
			if(r->op==XDEV_EXT_MECH_OP_CREATE) {
				struct xdev_ext_mech_create *c=p;
				assert(c->depth==1 && c->layout.group_bytes==4096);
				stages=c->nr_stages;wake=c->eventfd;
				sink=dup(c->st[stages-1].fd);c->session_id=19;
				snapshot=(struct xdev_ext_mech_stats){.session_id=19,.state=XDEV_EXT_MECH_SESSION_ACTIVE};
			} else if(r->op==XDEV_EXT_MECH_OP_NOTIFY_ARM) {
				struct xdev_ext_mech_notify_arm *a=p;
				assert(a->batches_target==snapshot.batches_done+1);
				assert(a->published_target==snapshot.published+1);arms++;
			} else if(r->op==XDEV_EXT_MECH_OP_START) {
				struct xdev_ext_mech_start *s=p;
				struct xdev_ext_mech_user_span *span=(void *)(uintptr_t)s->user_frames;
				uint64_t one=1;
				assert(s->nr_batches==1 && span->index==0 && span->len && span->len<=4096);
				assert(s->flags==(XDEV_EXT_MECH_START_F_USER_FRAMES|XDEV_EXT_MECH_START_F_USER_SPANS));
				assert(send(sink,registered,span->len,MSG_NOSIGNAL)==(ssize_t)span->len);starts++;
				snapshot.batches_done++;snapshot.published++;
				for(unsigned i=0;i<stages;i++){snapshot.submitted[i]++;snapshot.completed[i]++;}
				assert(write(wake,&one,sizeof(one))==sizeof(one));
				if(mode==1){errno=EINTR;ret=-1;}
				if(mode==2)snapshot.last_err=-EIO;
			} else if(r->op==XDEV_EXT_MECH_OP_STATS) *(struct xdev_ext_mech_stats *)p=snapshot;
			else if(r->op==XDEV_EXT_MECH_OP_STOP) {
				stops++;
				if(mode==2){errno=EBUSY;ret=-1;}
				else {close(sink);sink=-1;}
			} else assert(0);
		}
	} else if(nr==SYS_getsockopt) {
		int fd=va_arg(ap,int),level=va_arg(ap,int),opt=va_arg(ap,int);
		void *out=va_arg(ap,void *);socklen_t *len=va_arg(ap,socklen_t *);
		ret=getsockopt(fd,level,opt,out,len);
	} else if(nr==SYS_getpeername) {
		int fd=va_arg(ap,int);void *addr=va_arg(ap,void *);socklen_t *len=va_arg(ap,socklen_t *);
		ret=getpeername(fd,addr,len);
	} else if(nr==SYS_close)ret=close(va_arg(ap,int));
	else if(nr==SYS_eventfd2) {int init=va_arg(ap,int),flags=va_arg(ap,int);ret=eventfd(init,flags);}
	else if(nr==SYS_read) {int fd=va_arg(ap,int);void *buf=va_arg(ap,void *);size_t len=va_arg(ap,size_t);ret=read(fd,buf,len);}
	else if(nr==SYS_process_vm_readv) {
		pid_t pid=va_arg(ap,pid_t);void *local=va_arg(ap,void *);int ln=va_arg(ap,int);
		void *remote=va_arg(ap,void *);int rn=va_arg(ap,int);int flags=va_arg(ap,int);
		ret=syscall(nr,pid,local,ln,remote,rn,flags);
	} else {assert(0);ret=-1;}
	va_end(ap);return ret;
}

static void recv_bytes(int rx,const void *payload,size_t len)
{
	unsigned char out[8192];
	assert(recv(rx,out,sizeof(out),0)==(ssize_t)len && !memcmp(out,payload,len));
}

int main(void)
{
	struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
	socklen_t alen=sizeof(addr);
	struct xdev_ext_socket_mech_config cfg={.enabled=true};
	struct xdev_ext_socket_mech_runtime m={0};
	unsigned char payload[4096];
	int rx=socket(AF_INET,SOCK_DGRAM,0),tx=socket(AF_INET,SOCK_DGRAM,0);
	assert(rx>=0 && tx>=0 && !bind(rx,(void *)&addr,sizeof(addr)) && !getsockname(rx,(void *)&addr,&alen));
	assert(!connect(tx,(void *)&addr,sizeof(addr)));
	for(unsigned i=0;i<257;i++) {
		size_t len=1+((i*37U)%4096);
		memset(payload,i,sizeof(payload));
		assert(xdev_ext_socket_mech_send(&m,&cfg,tx,payload,len,4096)==(ssize_t)len);
		recv_bytes(rx,payload,len);
	}
	assert(m.creates==1 && m.calls==257 && starts==257 && arms==257 && !stops);
	mode=1;
	assert(xdev_ext_socket_mech_send(&m,&cfg,tx,payload,17,4096)==-EINTR);
	recv_bytes(rx,payload,17);
	assert(starts==258 && stops==1 && !m.session);
	mode=2;
	assert(xdev_ext_socket_mech_send(&m,&cfg,tx,payload,19,4096)==-EIO);
	recv_bytes(rx,payload,19);
	assert(m.unknown && starts==259);
	assert(xdev_ext_socket_mech_send(&m,&cfg,tx,payload,19,4096)==-EBUSY);
	assert(starts==259 && m.creates==2);
	puts("PASS: 257 reused-session real UDP sends, actual lengths, rearm, accepted EINTR no replay, bounded unknown");
	/* Release the fixture's intentionally ambiguous resources after assertions. */
	mode=0;m.unknown=false;
	assert(!xdev_ext_socket_mech_release(&m));
	close(rx);close(tx);
	return 0;
}
