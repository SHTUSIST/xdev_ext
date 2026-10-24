// SPDX-License-Identifier: GPL-2.0
/* Existing ctl frontend plus observational CREATE and verifier capture.
 * Every operation still runs the existing ctl and actual libc syscall path. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include "mv_create_capture.h"
#include "mv_umem_guard.h"
#include "mv_policy_capture.h"

static long mv_syscall(long number,...);
static int mv_object_load(struct bpf_object *object);
static int mv_setsockopt(int fd,int level,int name,const void *value,socklen_t bytes);
static int mv_close(int fd);
static struct mv_umem_guard mv_guard;
static struct xdev_ext_mech_layout mv_guard_layout;
static uint64_t mv_guard_session;
static int mv_guard_ring=-1,mv_guard_failed,mv_guard_stopped;
static struct bpf_object *mv_open_file(const char *path,const struct bpf_object_open_opts *opts);
#define syscall mv_syscall
#define bpf_object__load mv_object_load
#define setsockopt mv_setsockopt
#define close mv_close
#define bpf_object__open_file mv_open_file
#define main mv_original_main
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl.c"
#undef main
#undef bpf_object__open_file
#undef syscall
#undef bpf_object__load
#undef setsockopt
#undef close

static int mv_object_load(struct bpf_object *object)
{
    const char *prefix=getenv("E2_POLICY_CAPTURE");
    if (prefix && mv_policy_capture(object,prefix)) return -errno;
    return bpf_object__load(object);
}
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
        ret=syscall(number,entries,params);
        if (ret>=0 && getenv("E2_UMEM_CAPTURE")) mv_guard_ring=(int)ret;
        return ret;
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
            if (ret>=0 && mv_guard.prefix) {
                mv_guard_layout=create->layout;
                mv_guard_session=create->session_id;
            }
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
static int mv_setsockopt(int fd,int level,int name,const void *value,socklen_t bytes)
{
    const char *prefix=getenv("E2_UMEM_CAPTURE");
    int ret,saved;
    if (prefix && level==SOL_XDP && name==XDP_UMEM_REG) {
        if (bytes!=sizeof(struct xdp_umem_reg) || mv_guard_begin(&mv_guard,value,prefix)) return -1;
        ret=setsockopt(fd,level,name,value,bytes); saved=ret<0?errno:0;
        mv_guard.registration_return=ret; mv_guard.registration_errno=saved;
        errno=saved; return ret;
    }
    return setsockopt(fd,level,name,value,bytes);
}
static int mv_close(int fd)
{
    if (fd==mv_guard_ring && mv_guard.prefix && mv_guard_session && !mv_guard_stopped) {
        struct io_uring_xdev_ext_mech req={.op=XDEV_EXT_MECH_OP_STOP,.arg=mv_guard_session};
        long ret=syscall(__NR_io_uring_register,fd,IORING_REGISTER_XDEV_EXT_MECH,&req,1);
        int saved=ret<0?errno:0;
        if (ret) {
            char result[256];
            int n=snprintf(result,sizeof(result),"{\"stop_syscall_return\":%ld,\"errno\":%d,\"session_id\":%llu}\n",ret,saved,(unsigned long long)mv_guard_session);
            (void)mv_blob(mv_guard.prefix,"stop-error.json",result,(size_t)n);
            fputs("E2 STOP failed; retaining registered native resources until guest termination\n",stderr);
            fflush(stderr);
            for (;;) pause();
        }
        mv_guard_stopped=1;
        if (mv_guard_finish(&mv_guard,&mv_guard_layout,mv_guard_session,ret,saved)) mv_guard_failed=1;
    }
    return close(fd);
}
int main(int argc,char **argv)
{
    const char *verifier=getenv("E2_VERIFIER_LOG");
    if (getenv("E2_UMEM_CAPTURE") && !getenv("E2_CREATE_CAPTURE")) { fputs("E2 guard capture requires actual CREATE capture\n",stderr); return 2; }
    int status;
    if (verifier) {
        mv_verifier_buffer=calloc(1,MV_LOG_BYTES);
        if (!mv_verifier_buffer) return 3;
    }
    status=mv_original_main(argc,argv);
    if (mv_guard_failed && !status) status=1;
    if (verifier && mv_blob(verifier,"log",mv_verifier_buffer,
                            strnlen(mv_verifier_buffer,MV_LOG_BYTES))) {
        perror("E2 actual verifier log capture"); status=3;
    }
    free(mv_verifier_buffer);
    return status;
}
