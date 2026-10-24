// SPDX-License-Identifier: GPL-2.0
/* Host snapshot selfcheck only, no actual CREATE execution claim. */
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "mv_create_capture.h"
int main(int argc,char **argv)
{
    struct xdev_ext_mech_create c={0},readback;
    char path[4096];
    FILE *f;
    struct stat st;
    assert(argc==2);
    c.abi_version=1; c.nr_stages=2; c.depth=1; c.pool_kind=1;
    c.pool_fd=open("/dev/null",O_RDONLY); c.eventfd=-1;
    c.st[0].fd=c.pool_fd; c.st[0].class_id=3; c.st[0].direction=2;
    c.st[0].arg0=2048; c.st[0].arg1=64;
    c.st[1].fd=c.pool_fd;
    assert(c.pool_fd>=0);
    assert(!mv_capture_before(argv[1],&c));
    snprintf(path,sizeof(path),"%s.before",argv[1]);
    f=fopen(path,"rb"); assert(f);
    assert(fread(&readback,1,sizeof(readback),f)==sizeof(readback)); fclose(f);
    assert(!memcmp(&c,&readback,sizeof(c)));
    assert(!stat(path,&st) && (st.st_mode&0777)==0600);
    assert(mv_capture_before(argv[1],&c)<0); /* refuse overwrite */
    close(c.pool_fd);
    return 0;
}
