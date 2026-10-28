// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>

static int mode(const char *name)
{
 const char *value=getenv("INTEGRITY_FAULT");
 return value && !strcmp(value,name);
}
static void corrupt_source(const void *p,size_t n)
{
 if(n>3 && (mode("source-and-wire") || (mode("fallback-large") && n==4097) ||
    (mode("fallback-seven") && n==7 && ((const unsigned char *)p)[0]==0xa7)))
  ((unsigned char *)p)[n/2]^=1;
}
ssize_t send(int fd,const void *p,size_t n,int flags)
{
 int saved=errno;
 ssize_t (*real)(int,const void *,size_t,int)=dlsym(RTLD_NEXT,"send");
 corrupt_source(p,n);errno=saved;return real(fd,p,n,flags);
}
ssize_t sendto(int fd,const void *p,size_t n,int flags,const struct sockaddr *a,socklen_t z)
{
 int saved=errno;
 ssize_t (*real)(int,const void *,size_t,int,const struct sockaddr *,socklen_t)=dlsym(RTLD_NEXT,"sendto");
 corrupt_source(p,n);errno=saved;return real(fd,p,n,flags,a,z);
}
ssize_t sendmsg(int fd,const struct msghdr *m,int flags)
{
 int saved=errno;
 ssize_t (*real)(int,const struct msghdr *,int)=dlsym(RTLD_NEXT,"sendmsg");
 if(m && m->msg_iovlen==1) corrupt_source(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len);
 errno=saved;return real(fd,m,flags);
}
ssize_t recv(int fd,void *p,size_t n,int flags)
{
 int saved=errno;
 ssize_t (*real)(int,void *,size_t,int)=dlsym(RTLD_NEXT,"recv");
 errno=saved;ssize_t got=real(fd,p,n,flags);
 if(got>0){
  if(mode("receive-middle")) ((unsigned char *)p)[got/2]^=1;
  if(mode("receive-last")) ((unsigned char *)p)[got-1]^=1;
  if(mode("receive-truncate")) got--;
 }
 return got;
}
