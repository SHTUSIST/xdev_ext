/* SPDX-License-Identifier: GPL-2.0 */
/* libc large-file entry points must preserve the same OS fixture behavior. */
#ifndef SHARED_RECEIVE_ABI_TRANSPORT_H
#define SHARED_RECEIVE_ABI_TRANSPORT_H
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
static inline void fixture_copy_stat64(struct stat64 *to,const struct stat *from)
{
 memset(to,0,sizeof(*to));
 to->st_dev=from->st_dev;to->st_ino=from->st_ino;to->st_nlink=from->st_nlink;
 to->st_mode=from->st_mode;to->st_uid=from->st_uid;to->st_gid=from->st_gid;
 to->st_rdev=from->st_rdev;to->st_size=from->st_size;to->st_blksize=from->st_blksize;
 to->st_blocks=from->st_blocks;to->st_atim=from->st_atim;to->st_mtim=from->st_mtim;to->st_ctim=from->st_ctim;
}
static inline void fixture_copy_statfs64(struct statfs64 *to,const struct statfs *from)
{
 size_t i;memset(to,0,sizeof(*to));
 to->f_type=from->f_type;to->f_bsize=from->f_bsize;to->f_blocks=from->f_blocks;
 to->f_bfree=from->f_bfree;to->f_bavail=from->f_bavail;to->f_files=from->f_files;
 to->f_ffree=from->f_ffree;to->f_fsid=from->f_fsid;to->f_namelen=from->f_namelen;
 to->f_frsize=from->f_frsize;to->f_flags=from->f_flags;
 for(i=0;i<sizeof(to->f_spare)/sizeof(to->f_spare[0]);i++)to->f_spare[i]=from->f_spare[i];
}
#endif
