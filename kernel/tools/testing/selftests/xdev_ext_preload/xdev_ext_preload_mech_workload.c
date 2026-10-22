// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
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
		/* Neither endpoint is a reference: the send may have changed both. */
		for(j=0;j<len;j++) {
			unsigned char expected=(unsigned char)(i+j*11U+seed);
			if(payload[j]!=expected || received[j]!=expected) {
				fprintf(stderr,"XDEV_EXT_MECH_APP_FAILURE seed=%u index=%u check=payload len=%zu offset=%u expected=%u source=%u actual=%u\n",
					seed,i,len,j,expected,payload[j],received[j]);
				goto out;
			}
		}
		bytes+=len;
	}
	/* Explicitly outside the first mechanism surface: still real datagrams. */
	if(send(tx,NULL,0,0)!=0 || recv(rx,received,sizeof(received),0)!=0)goto out;
	memset(payload,0xa7,sizeof(payload));
	if(send(tx,payload,sizeof(payload),0)!=(ssize_t)sizeof(payload) ||
	   recv(rx,received,sizeof(received),0)!=(ssize_t)sizeof(payload))goto out;
	for(j=0;j<sizeof(payload);j++)
		if(payload[j]!=0xa7 || received[j]!=0xa7)goto out;
	if(fcntl(tx,F_SETFL,O_NONBLOCK) || send(tx,payload,7,MSG_DONTWAIT)!=7 ||
	   recv(rx,received,sizeof(received),0)!=7)goto out;
	for(j=0;j<7;j++)
		if(payload[j]!=0xa7 || received[j]!=0xa7)goto out;
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

#define MAX_ACTORS 32
#define MAX_ROUNDS 1024
struct actor_result {
	pid_t pid, tid;
	unsigned ready, entered, exited, calls;
	size_t bytes;
	uint64_t begin[MAX_ROUNDS], end[MAX_ROUNDS];
};
struct concurrency {
	pthread_mutex_t lock;
	pthread_cond_t condition;
	unsigned actors, rounds, generation, waiting;
	int broken;
	struct actor_result result[MAX_ACTORS];
};
struct actor_arg { struct concurrency *shared; unsigned actor; };

static uint64_t now_ns(void)
{
	struct timespec t;
	if(clock_gettime(CLOCK_MONOTONIC,&t))abort();
	return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;
}

static void break_gate(struct concurrency *s)
{
	pthread_mutex_lock(&s->lock);
	s->broken=1;
	pthread_cond_broadcast(&s->condition);
	pthread_mutex_unlock(&s->lock);
}

/* Process-shared, bounded wait: a missing/failed actor cannot silently turn
 * this campaign into a sequence of unrelated application runs. */
static int round_gate(struct concurrency *s)
{
	struct timespec until;
	unsigned generation;
	int rc;
	clock_gettime(CLOCK_MONOTONIC,&until);
	until.tv_sec+=20;
	pthread_mutex_lock(&s->lock);
	generation=s->generation;
	if(++s->waiting==s->actors) {
		s->waiting=0;s->generation++;
		pthread_cond_broadcast(&s->condition);
	} else while(!s->broken && generation==s->generation) {
		rc=pthread_cond_timedwait(&s->condition,&s->lock,&until);
		if(rc) {s->broken=1;pthread_cond_broadcast(&s->condition);}
	}
	rc=s->broken;
	pthread_mutex_unlock(&s->lock);
	return rc;
}

static int fd_count(void)
{
	DIR *directory=opendir("/proc/self/fd");
	struct dirent *entry;
	int count=0;
	if(!directory)return -1;
	while((entry=readdir(directory)))if(entry->d_name[0]!='.')count++;
	closedir(directory);
	return count;
}

static void *concurrent_actor(void *opaque)
{
	struct actor_arg *arg=opaque;
	struct concurrency *s=arg->shared;
	struct actor_result *row=&s->result[arg->actor];
	struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
	struct timeval timeout={.tv_sec=5};
	socklen_t alen=sizeof(addr);
	struct { unsigned char pre[16],data[2048],post[16]; } received;
	unsigned char payload[1023];
	const size_t lengths[]={31,257,1023};
	unsigned round,j;
	int rx=-1,tx=-1,rc=1;
	row->pid=getpid();row->tid=(pid_t)syscall(SYS_gettid);
	rx=socket(AF_INET,SOCK_DGRAM,0);
	if(rx<0 || setsockopt(rx,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
	   bind(rx,(void *)&addr,sizeof(addr)) || getsockname(rx,(void *)&addr,&alen))goto out;
	tx=socket(AF_INET,SOCK_DGRAM,0);
	if(tx<0 || connect(tx,(void *)&addr,sizeof(addr)))goto out;
	for(round=0;round<s->rounds;round++) {
		size_t len=lengths[round%3];
		ssize_t sent,got;
		int saved;
		struct iovec iov={payload,len};
		struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
		/* Actor and round are explicit bytes, avoiding modulo-256 aliases. */
		for(j=0;j<len;j++)payload[j]=(unsigned char)(arg->actor*19+round*7+j*11);
		payload[0]=(unsigned char)arg->actor;
		payload[1]=(unsigned char)round;payload[2]=(unsigned char)(round>>8);
		memset(&received,0xa5,sizeof(received));
		row->ready++;
		if(round_gate(s))goto out;
		row->entered++;
		errno=EDOM;
		/* concurrency call lock fault point */
		row->begin[round]=now_ns();
		if(round%3==0)sent=send(tx,payload,len,MSG_NOSIGNAL);
		else if(round%3==1)sent=sendto(tx,payload,len,0,NULL,0);
		else sent=sendmsg(tx,&msg,0);
		saved=errno;
		row->end[round]=now_ns();
		/* concurrency call unlock fault point */
		row->exited++;
		if(sent!=(ssize_t)len || saved!=EDOM)goto out;
		got=recv(rx,received.data,sizeof(received.data),0);
		/* concurrency receive fault point */
		if(got!=(ssize_t)len)goto out;
		for(j=0;j<len;j++) {
			unsigned char expected=(unsigned char)(arg->actor*19+round*7+j*11);
			if(j==0)expected=(unsigned char)arg->actor;
			else if(j==1)expected=(unsigned char)round;
			else if(j==2)expected=(unsigned char)(round>>8);
			if(payload[j]!=expected || received.data[j]!=expected)goto out;
		}
		for(j=0;j<sizeof(received.pre);j++)
			if(received.pre[j]!=0xa5 || received.post[j]!=0xa5)goto out;
		for(j=(unsigned)len;j<sizeof(received.data);j++)if(received.data[j]!=0xa5)goto out;
		row->calls++;row->bytes+=len;
	}
	if(recv(rx,received.data,sizeof(received.data),MSG_DONTWAIT)!=-1 ||
	   (errno!=EAGAIN && errno!=EWOULDBLOCK))goto out;
	rc=0;
out:
	if(rc) {
		fprintf(stderr,"XDEV_EXT_MECH_CONCURRENCY_FAILURE actor=%u calls=%u errno=%d\n",arg->actor,row->calls,errno);
		break_gate(s);
	}
	if(tx>=0)close(tx);
	if(rx>=0)close(rx);
	return (void *)(uintptr_t)rc;
}

static int concurrent_process(struct concurrency *s,unsigned process,unsigned threads)
{
	pthread_t tids[8];
	struct actor_arg args[8];
	unsigned i,created=0;
	int before=fd_count(),after,rc=0;
	void *result;
	if(before<0)return 1;
	for(i=0;i<threads;i++) {
		args[i]=(struct actor_arg){s,process*threads+i};
		if(pthread_create(&tids[i],NULL,concurrent_actor,&args[i])) {rc=1;break_gate(s);break;}
		created++;
	}
	for(i=0;i<created;i++)if(pthread_join(tids[i],&result) || result)rc=1;
	/* TLS destructors have STOPped and closed each actor's kernel session. */
	after=fd_count();
	if(before!=after)rc=1;
	if(!rc)dprintf(STDOUT_FILENO,"XDEV_EXT_MECH_FDS=PASS process=%u pid=%ld before=%d after=%d\n",
		process,(long)getpid(),before,after);
	return rc;
}

static int concurrency_main(unsigned threads,unsigned processes,unsigned rounds)
{
	struct concurrency *s;
	pthread_mutexattr_t ma;
	pthread_condattr_t ca;
	pid_t children[4];
	unsigned i,j,round,spawned=0,overlap=0,cross_process_overlap=0;
	int rc=0,status;
	if(!threads || threads>8 || !processes || processes>4 ||
	   threads*processes<2 || !rounds || rounds>MAX_ROUNDS)return 2;
	s=mmap(NULL,sizeof(*s),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
	if(s==MAP_FAILED)return 1;
	memset(s,0,sizeof(*s));s->actors=threads*processes;s->rounds=rounds;
	if(pthread_mutexattr_init(&ma) || pthread_mutexattr_setpshared(&ma,PTHREAD_PROCESS_SHARED) ||
	   pthread_mutex_init(&s->lock,&ma) || pthread_condattr_init(&ca) ||
	   pthread_condattr_setpshared(&ca,PTHREAD_PROCESS_SHARED) ||
	   pthread_condattr_setclock(&ca,CLOCK_MONOTONIC) || pthread_cond_init(&s->condition,&ca))return 1;
	pthread_mutexattr_destroy(&ma);pthread_condattr_destroy(&ca);
	fflush(NULL);
	if(processes==1)rc=concurrent_process(s,0,threads);
	else {
		/* Fork before creating any application session/thread. Every child
 * owns a separate mm and creates its own TLS sessions. Launch all before wait. */
		for(i=0;i<processes;i++) {
			pid_t child=fork();
			if(child<0) {rc=1;break_gate(s);break;}
			if(!child)exit(concurrent_process(s,i,threads));
			children[spawned++]=child;
		}
		for(i=0;i<spawned;i++)if(waitpid(children[i],&status,0)!=children[i] ||
			!WIFEXITED(status) || WEXITSTATUS(status))rc=1;
	}
	for(i=0;i<s->actors;i++) {
		struct actor_result *a=&s->result[i];
		if(a->ready!=rounds || a->entered!=rounds || a->exited!=rounds || a->calls!=rounds)rc=1;
		for(round=0;round<rounds;round++) {
			if(!a->begin[round] || a->end[round]<=a->begin[round])rc=1;
			for(j=i+1;j<s->actors;j++) {
				struct actor_result *b=&s->result[j];
				if(a->begin[round]<b->end[round] && b->begin[round]<a->end[round]) {
					overlap++;
					if(a->pid!=b->pid)cross_process_overlap++;
				}
			}
		}
		if(!rc)dprintf(STDOUT_FILENO,"XDEV_EXT_MECH_ACTOR=PASS actor=%u pid=%ld tid=%ld calls=%u bytes=%zu ready=%u entered=%u exited=%u full_compare=1 guards=1 extra_datagrams=0\n",
			i,(long)a->pid,(long)a->tid,a->calls,a->bytes,a->ready,a->entered,a->exited);
	}
	if(!overlap || (processes>1 && !cross_process_overlap))rc=1;
	if(!rc)dprintf(STDOUT_FILENO,"XDEV_EXT_MECH_CONCURRENCY=PASS processes=%u threads=%u actors=%u rounds=%u overlap_pairs=%u cross_process_overlap_pairs=%u per_round_gate=1 fd_leaks=0\n",
		processes,threads,s->actors,rounds,overlap,cross_process_overlap);
	else fprintf(stderr,"XDEV_EXT_MECH_CONCURRENCY_FAILURE overlap_pairs=%u cross_process_overlap_pairs=%u\n",overlap,cross_process_overlap);
	pthread_cond_destroy(&s->condition);pthread_mutex_destroy(&s->lock);munmap(s,sizeof(*s));
	return rc;
}

int main(int argc,char **argv)
{
	pthread_t threads[2];
	void *ret;
	int status;
	pid_t child;
	unsigned i;
	if(argc==5 && !strcmp(argv[1],"concurrency")) {
		unsigned values[3];char *end;
		for(i=0;i<3;i++) {
			unsigned long n=strtoul(argv[i+2],&end,10);
			if(!*argv[i+2] || *end || n>MAX_ROUNDS)return 2;
			values[i]=(unsigned)n;
		}
		return concurrency_main(values[0],values[1],values[2]);
	}
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
