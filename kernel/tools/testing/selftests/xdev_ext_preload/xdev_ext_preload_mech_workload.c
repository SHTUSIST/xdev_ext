// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* Ordinary libc application: no xdev_ext headers, handles or control calls. */
static int campaign(unsigned nr, unsigned seed)
{
	struct sockaddr_in addr = {.sin_family=AF_INET,
		.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
	socklen_t alen=sizeof(addr);
	struct timeval timeout={.tv_sec=5};
	struct sockaddr_in local={0};
	socklen_t local_len=sizeof(local);
	unsigned char payload[4097], received[8192];
	int rx=-1, tx=-1, alias=-1, rc=1;
	unsigned i, j;
	size_t bytes=0;

	rx=socket(AF_INET,SOCK_DGRAM,0);
	if(rx<0 || setsockopt(rx,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
	   bind(rx,(void *)&addr,sizeof(addr)) || getsockname(rx,(void *)&addr,&alen))goto out;
	tx=socket(AF_INET,SOCK_DGRAM,0);
	if(tx<0 || connect(tx,(void *)&addr,sizeof(addr)) || (alias=dup(tx))<0)goto out;
	if(getsockname(tx,(void *)&local,&local_len))goto out;
	for(i=0;i<nr;i++) {
		size_t len=1+((i*37U+seed)%4096U);
		ssize_t sent;
		struct iovec iov={payload,len};
		struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
		for(j=0;j<len;j++)payload[j]=(unsigned char)(i+j*11U+seed);
		errno=EDOM;
		if(i%3==0)sent=send(alias,payload,len,MSG_NOSIGNAL);
		else if(i%3==1)sent=sendto(tx,payload,len,0,NULL,0);
		else sent=sendmsg(alias,&msg,0);
		int send_errno=errno;
		if(sent!=(ssize_t)len || send_errno!=EDOM) {
			fprintf(stderr,"XDEV_EXT_MECH_APP_FAILURE seed=%u index=%u check=send expected=%zu actual=%zd errno=%d expected_errno=%d\n",
				seed,i,len,sent,send_errno,EDOM);
			goto out;
		}
		ssize_t got=recv(rx,received,sizeof(received),0);
		if(got!=(ssize_t)len) {
			fprintf(stderr,"XDEV_EXT_MECH_APP_FAILURE seed=%u index=%u check=recv expected=%zu actual=%zd errno=%d\n",
				seed,i,len,got,errno);
			goto out;
		}
		if(memcmp(payload,received,len)) {
			for(j=0;j<len && payload[j]==received[j];j++) {}
			fprintf(stderr,"XDEV_EXT_MECH_APP_FAILURE seed=%u index=%u check=payload len=%zu offset=%u expected=%u actual=%u\n",
				seed,i,len,j,payload[j],received[j]);
			goto out;
		}
		bytes+=len;
	}
	/* Explicitly outside the first mechanism surface: still real datagrams. */
	if(send(tx,NULL,0,0)!=0 || recv(rx,received,sizeof(received),0)!=0)goto out;
	memset(payload,0xa7,sizeof(payload));
	if(send(tx,payload,sizeof(payload),0)!=(ssize_t)sizeof(payload) ||
	   recv(rx,received,sizeof(received),0)!=(ssize_t)sizeof(payload) ||
	   memcmp(payload,received,sizeof(payload)))goto out;
	if(fcntl(tx,F_SETFL,O_NONBLOCK) || send(tx,payload,7,MSG_DONTWAIT)!=7 ||
	   recv(rx,received,sizeof(received),0)!=7 || memcmp(payload,received,7))goto out;
	rc=0;
out:
	if(rc)perror("mechanism ordinary UDP app");
	if(alias>=0)close(alias);
	if(tx>=0)close(tx);
	if(rx>=0)close(rx);
	if(!rc) {
		/* A cached kernel socket reference must not keep the closed port busy. */
		int replacement=socket(AF_INET,SOCK_DGRAM,0);
		if(replacement<0 || bind(replacement,(void *)&local,local_len))rc=1;
		if(replacement>=0)close(replacement);
		if(!rc)printf("XDEV_EXT_MECH_APP=PASS calls=%u bytes=%zu fallback=3 seed=%u\n",nr,bytes,seed);
	}
	return rc;
}

static void *thread_run(void *arg)
{
	return (void *)(uintptr_t)campaign(17,(unsigned)(uintptr_t)arg);
}

int main(int argc,char **argv)
{
	pthread_t threads[2];
	void *ret;
	int status;
	pid_t child;
	unsigned i;
	if(argc!=2)return 2;
	if(campaign(257,0))return 1;
	if(!strcmp(argv[1],"base"))return 0;
	if(strcmp(argv[1],"lifecycle"))return 2;
	fflush(NULL);
	child=fork();
	if(child<0)return 1;
	if(!child)exit(campaign(13,3));
	if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status))return 1;
	for(i=0;i<2;i++)if(pthread_create(&threads[i],NULL,thread_run,(void *)(uintptr_t)(i+7)))return 1;
	for(i=0;i<2;i++)if(pthread_join(threads[i],&ret) || ret)return 1;
	/* fd numbers have been closed/reused by several independent socket pairs. */
	if(campaign(11,9))return 1;
	puts("XDEV_EXT_MECH_APP_LIFECYCLE=PASS fork=1 threads=2 fd_reuse=PASS");
	return 0;
}
