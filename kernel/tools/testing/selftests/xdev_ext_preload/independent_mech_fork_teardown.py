#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Pause the real thread destructor after registry removal, then really fork.

This is distinct from the steady-state inheritance case: atfork cannot find a
context already removed from the registry. No payload I/O/DMA is simulated.
"""
from pathlib import Path
import argparse
import runpy
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / "independent_mech_fork_inherited.py"))
KERNEL = BASE["KERNEL"]
EXTRA = r'''
#define IORING_UNREGISTER_XDEV_EXT_UMEM 65535
static __thread int xdev_ext_in_hook;
static __thread bool destructor_thread;
static bool removed,paused,allow_finish;
static pid_t parent_pid;
static pthread_mutex_t pause_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pause_cond=PTHREAD_COND_INITIALIZER;
static void xdev_ext_report_thread_locked(struct xdev_ext_thread_ctx *t){(void)t;}
static void io_uring_queue_exit(void *ring){(void)ring;assert(0);}
static int stop_count;
static int xdev_ext_socket_mech_control(struct xdev_ext_socket_mech_runtime *m,unsigned op,uint64_t arg)
{assert(m && op==XDEV_EXT_MECH_OP_STOP && arg==7);stop_count++;return 0;}
static int watched_unlock(pthread_mutex_t *m)
{
 int ret=pthread_mutex_unlock(m);
 if(m==&xdev_ext_thread_lock && destructor_thread && removed && getpid()==parent_pid){
  pthread_mutex_lock(&pause_lock);paused=true;pthread_cond_signal(&pause_cond);
  while(!allow_finish)pthread_cond_wait(&pause_cond,&pause_lock);
  pthread_mutex_unlock(&pause_lock);
 }
 return ret;
}
#define pthread_mutex_unlock watched_unlock
'''
MAIN = r'''
#undef pthread_mutex_unlock
#undef syscall
static struct xdev_ext_thread_ctx *ctx;
static int fds[3];static void *frame;
static void *destroy(void *unused){(void)unused;destructor_thread=true;xdev_ext_thread_destroy(ctx);return NULL;}
int main(void)
{
 pthread_t tid;pid_t child;int status,closed=0;
 parent_pid=getpid();ctx=calloc(1,sizeof(*ctx));assert(ctx);
 ctx->owner_pid=parent_pid;ctx->socket_mech.owner=parent_pid;ctx->socket_mech.capacity=4096;ctx->socket_mech.session=7;
 ctx->socket_mech.frame=frame=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(frame!=MAP_FAILED);
 ctx->socket_mech.ring=fds[0]=eventfd(0,EFD_CLOEXEC);ctx->socket_mech.event=fds[1]=eventfd(0,EFD_CLOEXEC);ctx->socket_mech.ce_fd=fds[2]=eventfd(0,EFD_CLOEXEC);
 for(int i=0;i<3;i++)assert(fds[i]>=0);
 ctx->socket_mech_lock=(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;xdev_ext_threads=ctx;
 assert(!pthread_atfork(xdev_ext_atfork_prepare,xdev_ext_atfork_parent,xdev_ext_atfork_child));
 assert(!pthread_create(&tid,NULL,destroy,NULL));
 pthread_mutex_lock(&pause_lock);while(!paused)pthread_cond_wait(&pause_cond,&pause_lock);pthread_mutex_unlock(&pause_lock);
 assert(!xdev_ext_threads && removed);
 child=fork();assert(child>=0);
 if(!child){
  for(int i=0;i<3;i++)if(fcntl(fds[i],F_GETFD)<0 && errno==EBADF)closed++;
  if(closed!=3){fprintf(stderr,"RED: real destructor removed context before closing %d/3 mechanism handles; fork child registry cannot find them\n",3-closed);_exit(41);}
  assert(stop_count==1); /* Parent cleanup, never a child's STOP. */
  {unsigned char resident;assert(mincore(frame,4096,&resident)==-1 && errno==ENOMEM);}
  _exit(0);
 }
 assert(waitpid(child,&status,0)==child);
 pthread_mutex_lock(&pause_lock);allow_finish=true;pthread_cond_signal(&pause_cond);pthread_mutex_unlock(&pause_lock);assert(!pthread_join(tid,NULL));
 if(!WIFEXITED(status) || WEXITSTATUS(status)){fprintf(stderr,"not ok - actual thread destructor must retire mechanism handles before context becomes invisible to atfork\n");return 1;}
 assert(stop_count==1 && close_count==3);
 puts("ok - actual destructor closes runtime before registry removal; fork during post-removal window inherits no orphan handles");return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", help="also reproduce against a specific production preload revision")
    args = parser.parse_args()
    function = BASE["function"]
    preload = subprocess.check_output(["git", "show", args.revision + ":./tools/io_uring_unified_preload.c"], cwd=KERNEL, text=True) if args.revision else (KERNEL / "tools/io_uring_unified_preload.c").read_text()
    header = (KERNEL / "tools/xdev_ext_preload_socket_mech.h").read_text()
    runtime_start = header.index("struct xdev_ext_socket_mech_runtime {")
    runtime = header[runtime_start:header.index("\n};", runtime_start) + 3]
    globals_ = BASE["GLOBAL"].replace("pid_t owner_pid;", "pid_t owner_pid; bool quiescence_unknown,umem_registered,ring_ready; struct {int ring_fd;} ring; void *shared,*umem;")
    hooks = "".join(function(preload, "static void " + name + "(void)") for name in ("xdev_ext_atfork_prepare", "xdev_ext_atfork_parent", "xdev_ext_atfork_child"))
    remove = function(preload, "static void xdev_ext_remove_thread_locked(")
    remove = remove.replace("static void xdev_ext_remove_thread_locked(", "static void actual_remove(")
    remove += "static void xdev_ext_remove_thread_locked(struct xdev_ext_thread_ctx *t){actual_remove(t);removed=true;}\n"
    helpers = function(header, "static inline void xdev_ext_socket_mech_forget_child(") + function(header, "static inline int xdev_ext_socket_mech_release(")
    destructor = function(preload, "static void xdev_ext_thread_destroy(")
    with tempfile.TemporaryDirectory(prefix="independent-mech-fork-teardown-") as tmp:
        source = Path(tmp) / "actual.c"
        binary = Path(tmp) / "actual"
        source.write_text(BASE["SHIM"] + '#include "' + str(KERNEL / "include/uapi/linux/xdev_ext_mech.h") + '"\n' + runtime + globals_ + EXTRA + remove + helpers + hooks + destructor + MAIN)
        compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-pthread", str(source), "-o", str(binary)], capture_output=True, text=True)
        assert compiled.returncode == 0, compiled.stderr
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        print(result.stdout, end="")
        print(result.stderr, end="")
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
