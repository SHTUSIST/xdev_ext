#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual socket adapter must issue native send under bound caller credentials.

The security boundary shim records the subject seen by kernel_sendmsg, matching
the real kernel_sendmsg->sock_sendmsg->security_socket_sendmsg call chain.
This is not an end-to-end SELinux/AppArmor policy test.
"""
from pathlib import Path
import re
import subprocess
import tempfile
from adapter_test import socket_family_declarations, socket_family_reference

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[4]
CREDENTIALS = r'''
struct cred {int subject,refs;};
static struct cred user_cred={1001,1},worker_cred={0,1};
static const struct cred *active_cred=&user_cred;
static inline const struct cred *current_cred(void){return active_cred;}
static inline const struct cred *get_cred(const struct cred *c){((struct cred*)c)->refs++;return c;}
static inline const struct cred *get_current_cred(void){return get_cred(current_cred());}
static inline void put_cred(const struct cred *c){assert(c && c->refs>1);((struct cred*)c)->refs--;}
static inline const struct cred *override_creds(const struct cred *c){const struct cred *old=active_cred;active_cred=c;return old;}
static inline void revert_creds(const struct cred *c){active_cred=c;}
static int forced_result=8,observed_subject=-1,send_calls;
static int kernel_sendmsg(struct socket *s,struct msghdr *m,struct kvec *v,size_t n,size_t bytes)
{assert(s && m && v && n==1 && bytes==8);send_calls++;observed_subject=current_cred()->subject;return forced_result;}
/* Receive boundary of the same LSM chain (kernel_recvmsg->sock_recvmsg->
 * security_socket_recvmsg); needed once the adapter has a FROM_DEVICE path. */
static int recv_subject=-1,recv_calls,forced_recv_result=-EAGAIN;
static inline int kernel_recvmsg(struct socket *s,struct msghdr *m,struct kvec *v,size_t n,size_t len,int flags)
{(void)s;(void)m;(void)v;(void)n;(void)len;assert(flags&MSG_DONTWAIT);recv_calls++;recv_subject=current_cred()->subject;return forced_recv_result;}
'''
MAIN = r'''
int main(void)
{
 struct sock sk={.sk_family=AF_INET,.sk_protocol=IPPROTO_UDP,.sk_state=TCP_ESTABLISHED};
 struct socket sock={.type=SOCK_DGRAM,.fd=-1,.sk=&sk};struct file file={.sock=&sock};
 struct xdev_ext_mech_session session={.pool={.frame_size=4096,.nr_frames=1,.state={XDEV_EXT_MECH_F_INFLIGHT}},.depth=1,.admits=true};
 struct xdev_ext_mech_stage stage={.file=&file,.s=&session,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 struct xdev_ext_mech_stage_uapi u={};
 unsigned char payload[4096]={};
 struct xdev_ext_mech_batch b={.nr=1,.bytes=8,.ticket=9,.f={{.kaddr=payload,.index=0,.data_len=8}}};
 struct xdev_ext_socket_send_desc desc={.frame_pos=0,.frame_off=0,.len=8};
 struct xdev_ext_socket_mech_info info;struct xdev_ext_socket_mech_cqe cqe;
 assert(!xdev_ext_socket_bind(&stage,&u));
 assert(!xdev_ext_socket_validate(&stage,&b,(const u8*)&desc,1));
 xdev_ext_socket_fill_info(&stage,&b,&info);assert(info.nr_frames==1);
 active_cred=&worker_cred;
 assert(!xdev_ext_socket_submit(&stage,&b));
 if(observed_subject!=user_cred.subject){fprintf(stderr,"RED: kernel_sendmsg sees worker subject=%d instead of creator subject=%d\n",observed_subject,user_cred.subject);return 1;}
 assert(active_cred==&worker_cred && send_calls==1 && b.completions==1 && !b.status);
 forced_result=-EAGAIN;assert(xdev_ext_socket_submit(&stage,&b)==-EAGAIN && active_cred==&worker_cred && send_calls==2 && b.completions==1 && observed_subject==1001);
 forced_result=-EACCES;assert(!xdev_ext_socket_submit(&stage,&b) && active_cred==&worker_cred && send_calls==3 && b.completions==2 && b.status==-EACCES && observed_subject==1001);
 xdev_ext_socket_fill_cqe(&stage,&b,&cqe);assert(cqe.status==-EACCES);
 xdev_ext_socket_mark_dead(&stage);assert(xdev_ext_socket_submit(&stage,&b)==-ENODEV && send_calls==3);
 xdev_ext_socket_unbind(&stage);
 assert(user_cred.refs==1 && worker_cred.refs==1);
 puts("ok - actual socket native send uses bound creator credentials, restores worker creds on success/EAGAIN/error, releases credential ref");
 return 0;
}
'''


def main():
    shim = (HERE / "shim.h").read_text()
    shim = shim[:shim.index("static int forced_send =")]
    source = (KERNEL / "io_uring/xdev_ext_mech_socket.c").read_text()
    source = re.sub(r"^#include[^\n]*\n", "", source, flags=re.M)
    source = source[:source.index("static const struct xdev_ext_mech_class_ops")]
    with tempfile.TemporaryDirectory(prefix="independent-socket-creds-") as tmp:
        cfile = Path(tmp) / "actual.c"
        binary = Path(tmp) / "actual"
        cfile.write_text(shim + CREDENTIALS + socket_family_declarations(KERNEL) +
                        source + socket_family_reference() + MAIN)
        # -Wno-unused-function: this TX oracle does not call the receive-direction entry points.
        compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-fsanitize=undefined", "-I" + str(KERNEL), str(cfile), "-o", str(binary)], capture_output=True, text=True)
        assert compiled.returncode == 0, compiled.stderr
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        print(result.stdout, end="")
        print(result.stderr, end="")
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
