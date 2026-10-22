#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual atfork hooks with real descriptors from a vanished worker thread.

The child must close every inherited mechanism runtime without STOP/unregister;
all six parent descriptors must remain valid. This catches an orphan runtime
from a non-forking thread even if the child refreshes its own TLS lazily.
"""
from pathlib import Path
import subprocess
import tempfile

KERNEL = Path(__file__).resolve().parents[4]


def function(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


SHIM = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/wait.h>
static int close_count, child_admission_reset;
static long observed_syscall(long nr,...)
{
 va_list ap;int fd;va_start(ap,nr);assert(nr==SYS_close);fd=va_arg(ap,int);va_end(ap);
 close_count++;return syscall(SYS_close,fd);
}
#define syscall observed_syscall
'''
GLOBAL = r'''
/* Only the atfork registry boundary is substituted. Descriptors and VMAs are
 * real kernel objects, allocated by main and an actual second pthread.
 */
struct xdev_ext_thread_ctx {
 struct xdev_ext_socket_mech_runtime socket_mech;
 pthread_mutex_t socket_mech_lock;
 pid_t owner_pid;
 struct xdev_ext_thread_ctx *next;
};
static pthread_mutex_t xdev_ext_thread_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t xdev_ext_fd_locks=PTHREAD_MUTEX_INITIALIZER;
static struct xdev_ext_thread_ctx *xdev_ext_threads;
static void xdev_ext_preload_fd_lock_all(pthread_mutex_t *m){pthread_mutex_lock(m);}
static void xdev_ext_preload_fd_unlock_all(pthread_mutex_t *m){pthread_mutex_unlock(m);}
static void xdev_ext_admission_after_fork_child(void){child_admission_reset++;}
'''
MAIN = r'''
#undef syscall
static struct xdev_ext_thread_ctx main_context,worker_context;
static pthread_mutex_t ready_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready_condition=PTHREAD_COND_INITIALIZER;
static bool worker_ready,worker_exit;
static void runtime(struct xdev_ext_thread_ctx *c)
{
 c->owner_pid=getpid();c->socket_mech.owner=getpid();c->socket_mech.capacity=4096;
 c->socket_mech.frame=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(c->socket_mech.frame!=MAP_FAILED);
 c->socket_mech.ring=eventfd(0,EFD_CLOEXEC);c->socket_mech.event=eventfd(0,EFD_CLOEXEC);c->socket_mech.ce_fd=eventfd(0,EFD_CLOEXEC);
 assert(c->socket_mech.ring>=0 && c->socket_mech.event>=0 && c->socket_mech.ce_fd>=0);
 c->socket_mech.session=7;c->socket_mech_lock=(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
}
static void *worker(void *unused)
{
 (void)unused;runtime(&worker_context);
 pthread_mutex_lock(&ready_lock);worker_ready=true;pthread_cond_signal(&ready_condition);
 while(!worker_exit)pthread_cond_wait(&ready_condition,&ready_lock);
 pthread_mutex_unlock(&ready_lock);return NULL;
}
int main(void)
{
 pthread_t tid;pid_t child;int status,fds[6],closed=0;void *frames[2];
 runtime(&main_context);assert(!pthread_create(&tid,NULL,worker,NULL));
 pthread_mutex_lock(&ready_lock);while(!worker_ready)pthread_cond_wait(&ready_condition,&ready_lock);pthread_mutex_unlock(&ready_lock);
 main_context.next=&worker_context;xdev_ext_threads=&main_context;
 fds[0]=main_context.socket_mech.ring;fds[1]=main_context.socket_mech.event;fds[2]=main_context.socket_mech.ce_fd;
 fds[3]=worker_context.socket_mech.ring;fds[4]=worker_context.socket_mech.event;fds[5]=worker_context.socket_mech.ce_fd;
 frames[0]=main_context.socket_mech.frame;frames[1]=worker_context.socket_mech.frame;
 assert(!pthread_atfork(xdev_ext_atfork_prepare,xdev_ext_atfork_parent,xdev_ext_atfork_child));
 child=fork();assert(child>=0);
 if(!child){
  /* Exercise the existing lazy refresh too: it can only see main TLS. */
  xdev_ext_socket_mech_forget_child(&main_context.socket_mech);
  for(int i=0;i<6;i++)if(fcntl(fds[i],F_GETFD)<0 && errno==EBADF)closed++;
  if(closed!=6){fprintf(stderr,"RED: child inherited %d of 6 mechanism handles; worker runtime cannot be found from child TLS (close_count=%d)\n",6-closed,close_count);_exit(41);}
  assert(child_admission_reset==1 && close_count==6);
  for(int i=0;i<2;i++){unsigned char resident;assert(mincore(frames[i],4096,&resident)==-1 && errno==ENOMEM);}
  _exit(0);
 }
 assert(waitpid(child,&status,0)==child);
 for(int i=0;i<6;i++)assert(fcntl(fds[i],F_GETFD)>=0);
 assert(!close_count && !child_admission_reset && main_context.socket_mech.session==7 && worker_context.socket_mech.session==7);
 for(int i=0;i<2;i++){unsigned char resident;assert(!mincore(frames[i],4096,&resident));}
 pthread_mutex_lock(&ready_lock);worker_exit=true;pthread_cond_signal(&ready_condition);pthread_mutex_unlock(&ready_lock);assert(!pthread_join(tid,NULL));
 for(int i=0;i<6;i++)close(fds[i]);
 for(int i=0;i<2;i++)munmap(frames[i],4096);
 if(!WIFEXITED(status) || WEXITSTATUS(status)){fprintf(stderr,"not ok - actual atfork child must drop all inherited mechanism handles without touching parent sessions\n");return 1;}
 puts("ok - actual atfork child closes 6/6 inherited handles and 2/2 mappings; parent retains every handle/mapping/session");return 0;
}
'''


def main():
    preload = (KERNEL / "tools/io_uring_unified_preload.c").read_text()
    header = (KERNEL / "tools/xdev_ext_preload_socket_mech.h").read_text()
    runtime_start = header.index("struct xdev_ext_socket_mech_runtime {")
    runtime = header[runtime_start:header.index("\n};", runtime_start) + 3]
    hooks = "".join(function(preload, "static void " + name + "(void)") for name in ("xdev_ext_atfork_prepare", "xdev_ext_atfork_parent", "xdev_ext_atfork_child"))
    child_cleanup = function(header, "static inline void xdev_ext_socket_mech_forget_child(")
    with tempfile.TemporaryDirectory(prefix="independent-mech-fork-") as tmp:
        source = Path(tmp) / "actual.c"
        binary = Path(tmp) / "actual"
        source.write_text(SHIM + '#include "' + str(KERNEL / "include/uapi/linux/xdev_ext_mech.h") + '"\n' + runtime + child_cleanup + GLOBAL + hooks + MAIN)
        compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-pthread", str(source), "-o", str(binary)], capture_output=True, text=True)
        assert compiled.returncode == 0, compiled.stderr
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        print(result.stdout, end="")
        print(result.stderr, end="")
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
