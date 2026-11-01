#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual parent send/wait tail with real children, no namespaces."""
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'source-layout.json').is_file())
source = (HERE / 'token_guest.c').read_text()
start = source.index('  int sent=send_fd(sv[0],mnt);')
end = source.index('\n }\n puts("PASS token-native', start)
tail = source[start:end]
fixture = r'''
#define main token_guest_entry_unused
#include "TOKEN_SOURCE"
#undef main
static int actual_send_wait(pid_t pid,int sock,int mnt)
{
 int status,sv[2]={sock,-1};
 ACTUAL_TAIL
 return 0;
}
static int test_send(bool fail)
{
 int sv[2],rc,status,fd; pid_t pid;
 REQUIRE(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,sv),"probe socketpair");
 pid=fork(); REQUIRE(pid>=0,"probe fork");
 if (!pid) {
  close(sv[0]); fd=receive_fd(sv[1]);
  if(fd>=0) close(fd);
  close(sv[1]); _exit(fd<0 ? 2 : 0);
 }
 close(sv[1]);
 fd=fail ? -1 : open("/dev/null",O_RDONLY|O_CLOEXEC);
 REQUIRE(fail || fd>=0,"probe source fd");
 rc=actual_send_wait(pid,sv[0],fd);
 REQUIRE(rc==(fail ? 2 : 0),"send failure stays SETUP; success stays success");
 REQUIRE(!fail || errno==EBADF,"original SCM_RIGHTS errno retained after wait");
 errno=0;
 pid_t reaped=waitpid(pid,&status,WNOHANG);
 /* Any waitable child means the actual tail failed to reap it. */
 if (reaped!=-1 || errno!=ECHILD) {
  if (!reaped) waitpid(pid,&status,0);
  fprintf(stderr,"ASSERT: native parent must always reap child (failed-send=%d)\n",fail);
  return 1;
 }
 puts(fail ? "ok - failed SCM_RIGHTS send returns SETUP and reaps child" : "ok - successful SCM_RIGHTS send reaps child");
 return 0;
}
int main(void) { int rc=test_send(true); return rc ? rc : test_send(false); }
'''.replace('TOKEN_SOURCE',str(HERE / 'token_guest.c')).replace('ACTUAL_TAIL',tail)
include = os.environ.get('LIBBPF_INCLUDE', '/usr/include')
archive = os.environ.get('LIBBPF_A', '-lbpf')
with tempfile.TemporaryDirectory(prefix='token-protocol-') as tmp:
    path=Path(tmp); (path/'probe.c').write_text(fixture)
    subprocess.run(['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-O1','-g',
                    '-fsanitize=undefined','-I'+str(ROOT/'src/core/include/uapi'),
                    '-I'+include,str(path/'probe.c'),archive,'-lelf','-lz',
                    '-o',str(path/'probe')],check=True)
    subprocess.run([str(path/'probe')],check=True,timeout=10)
