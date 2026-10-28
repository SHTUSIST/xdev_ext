// SPDX-License-Identifier: GPL-2.0
#ifndef MV_CREATE_CAPTURE_H
#define MV_CREATE_CAPTURE_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <linux/if_xdp.h>
#include "../../../kernel/include/uapi/linux/xdev_ext_mech.h"

_Static_assert(sizeof(struct xdev_ext_mech_create)==200,"update audited raw CREATE layout");
static inline int mv_blob(const char *prefix,const char *suffix,const void *data,size_t bytes)
{
    char path[4096];
    int fd, saved;
    ssize_t n;
    if (snprintf(path,sizeof(path),"%s.%s",prefix,suffix)>=(int)sizeof(path)) {
        errno=ENAMETOOLONG; return -1;
    }
    fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if (fd<0) return -1;
    n=write(fd,data,bytes); saved=errno;
    if (n!=(ssize_t)bytes || fsync(fd)) {
        if (n>=0 && n!=(ssize_t)bytes) saved=EIO;
        else if (n==(ssize_t)bytes) saved=errno;
        close(fd); errno=saved; return -1;
    }
    return close(fd);
}
static inline int mv_fd_json(FILE *f,const char *role,int fd,int comma)
{
    struct stat st;
    struct sockaddr_xdp sx={0};
    socklen_t size=sizeof(sx);
    int family=0,flags=fd>=0?fcntl(fd,F_GETFL):-1;
    if (fd>=0 && fstat(fd,&st)) return -1;
    if (fd<0) memset(&st,0,sizeof(st));
    if (fd>=0 && !getsockname(fd,(struct sockaddr *)&sx,&size))
        family=sx.sxdp_family;
    fprintf(f,"%s\"%s\":{\"fd\":%d,\"file_type\":%u,\"rdev_major\":%u,\"rdev_minor\":%u,\"inode\":%llu,\"socket_family\":%d,\"file_flags\":%d",
        comma?",":"",role,fd,(unsigned)(st.st_mode&S_IFMT),
        major(st.st_rdev),minor(st.st_rdev),(unsigned long long)st.st_ino,family,flags);
    if (family==AF_XDP)
        fprintf(f,",\"ifindex\":%u,\"queue_id\":%u,\"bind_flags\":%u,\"shared_umem_fd\":%u",
            sx.sxdp_ifindex,sx.sxdp_queue_id,sx.sxdp_flags,sx.sxdp_shared_umem_fd);
    fputc('}',f);
    return ferror(f)?-1:0;
}
static inline int mv_capture_before(const char *prefix,const struct xdev_ext_mech_create *c)
{
    char *json=NULL;
    size_t size=0;
    FILE *f;
    unsigned i;
    int ret=0;
    if (c->nr_stages>XDEV_EXT_MECH_MAX_STAGES) { errno=EINVAL; return -1; }
    if (mv_blob(prefix,"before",c,sizeof(*c))) return -1;
    f=open_memstream(&json,&size);
    if (!f) return -1;
    fputc('{',f);
    ret=mv_fd_json(f,"pool",c->pool_fd,0) || mv_fd_json(f,"eventfd",c->eventfd,1);
    for (i=0;!ret && i<c->nr_stages;i++) {
        char name[24];
        snprintf(name,sizeof(name),"stage%u",i);
        ret=mv_fd_json(f,name,c->st[i].fd,1);
    }
    fputs("}\n",f);
    if (fclose(f)) ret=-1;
    if (!ret) ret=mv_blob(prefix,"resources.json",json,size);
    free(json);
    return ret;
}
#endif
