// SPDX-License-Identifier: GPL-2.0
/* Existing ctl frontend plus observational CREATE and verifier capture.
 * Every operation still runs the existing ctl and actual libc syscall path. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include "mv_create_capture.h"

static long mv_syscall(long number,...);
static struct bpf_object *mv_open_file(const char *path,const struct bpf_object_open_opts *opts);
#define syscall mv_syscall
#define bpf_object__open_file mv_open_file
#define main mv_original_main
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl.c"
#undef main
#undef bpf_object__open_file
#undef syscall

static char *mv_verifier_buffer;
#define MV_LOG_BYTES (4U*1024U*1024U)
static struct bpf_object *mv_open_file(const char *path,const struct bpf_object_open_opts *opts)
{
    struct bpf_object_open_opts capture={.sz=sizeof(capture)};
    if (!mv_verifier_buffer)
        return bpf_object__open_file(path,opts);
    if (opts) capture=*opts;
    capture.kernel_log_buf=mv_verifier_buffer;
    capture.kernel_log_size=MV_LOG_BYTES;
    capture.kernel_log_level=1;
    return bpf_object__open_file(path,&capture);
}
static long mv_syscall(long number,...)
{
    va_list ap;
    long ret;
    va_start(ap,number);
    if (number==__NR_io_uring_setup) {
        int entries=va_arg(ap,int);
        void *params=va_arg(ap,void *);
        va_end(ap);
        return syscall(number,entries,params);
    }
    if (number==__NR_io_uring_register) {
        int ring=va_arg(ap,int);
        unsigned opcode=va_arg(ap,unsigned);
        void *arg=va_arg(ap,void *);
        int count=va_arg(ap,int),saved=0;
        const char *capture=getenv("E2_CREATE_CAPTURE");
        struct xdev_ext_mech_create *create=NULL;
        va_end(ap);
        if (capture && opcode==IORING_REGISTER_XDEV_EXT_MECH && count==1) {
            const struct io_uring_xdev_ext_mech *req=arg;
            if (req->op==XDEV_EXT_MECH_OP_CREATE) {
                create=(void *)(uintptr_t)req->arg;
                if (mv_capture_before(capture,create))
                    return -1;
            }
        }
        ret=syscall(number,ring,opcode,arg,count);
        if (ret<0) saved=errno;
        if (create) {
            char result[256];
            int size=snprintf(result,sizeof(result),
                "{\"syscall_return\":%ld,\"errno\":%d,\"session_id\":%llu}\n",
                ret,saved,(unsigned long long)create->session_id);
            if (mv_blob(capture,"after",create,sizeof(*create)) ||
                mv_blob(capture,"result.json",result,(size_t)size)) {
                errno=EIO;
                return -1;
            }
        }
        errno=saved;
        return ret;
    }
    va_end(ap);
    errno=ENOSYS;
    return -1; /* Existing ctl currently has exactly the two syscall sites. */
}
int main(int argc,char **argv)
{
    const char *verifier=getenv("E2_VERIFIER_LOG");
    int status;
    if (verifier) {
        mv_verifier_buffer=calloc(1,MV_LOG_BYTES);
        if (!mv_verifier_buffer) return 3;
    }
    status=mv_original_main(argc,argv);
    if (verifier && mv_blob(verifier,"log",mv_verifier_buffer,
                            strnlen(mv_verifier_buffer,MV_LOG_BYTES))) {
        perror("E2 actual verifier log capture"); status=3;
    }
    free(mv_verifier_buffer);
    return status;
}
