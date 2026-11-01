/* SPDX-License-Identifier: GPL-2.0 */
/* OS object adapters; production bind and command-effects policy run verbatim. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define GFP_KERNEL 0
#define kzalloc(n,f) calloc(1,n)
#define kfree free
#define cpu_to_le32(n) (n)
#define CAP_SYS_RAWIO 17
#define CAP_SYS_ADMIN 21
#define FMODE_READ 1
#define FMODE_WRITE 2
#define NVME_IOCTL_PARTITION 2
#define NVME_CMD_EFFECTS_CSUPP 1
#define NVME_CMD_EFFECTS_LBCC 2
#define NVME_CMD_EFFECTS_UUID_SEL 4
#define NVME_CMD_EFFECTS_SCOPE_MASK 8
#define nvme_cmd_write 1
#define nvme_cmd_read 2
#define nvme_cmd_vendor_start 0xc0
#define nvme_fabrics_command 0x7f
#define nvme_admin_identify 6
#define NVME_ID_CNS_NS 0
#define NVME_ID_CNS_CS_NS 1
#define NVME_ID_CNS_NS_CS_INDEP 2
#define NVME_ID_CNS_CS_CTRL 3
#define NVME_ID_CNS_CTRL 4
#define XDEV_EXT_MECH_DIR_TO_DEVICE 1
#define XDEV_EXT_MECH_DIR_FROM_DEVICE 2
#define XDEV_EXT_MECH_POOL_PEER 3
struct nvme_command {
 union {
  struct { unsigned opcode, nsid; } rw;
  struct { unsigned opcode, nsid; } common;
  struct { unsigned opcode, nsid, cns; } identify;
 };
};
struct file { unsigned f_mode; bool native_ns; };
struct nvme_ops { const char *name; bool peer_rw; };
struct nvme_ctrl { struct nvme_ops *ops; };
struct nvme_ns_head { unsigned ns_id; };
struct nvme_ns { struct nvme_ctrl *ctrl; struct nvme_ns_head *head; void *queue; };
struct xdev_ext_mech_layout { unsigned group_bytes; };
struct xdev_ext_mech_pool { unsigned kind; };
struct xdev_ext_mech_session { struct xdev_ext_mech_layout layout; struct xdev_ext_mech_pool pool; };
struct xdev_ext_mech_stage_uapi { unsigned flags; };
struct nvme_xdev_ext_mech_stage { struct nvme_ns *ns; bool write; int identity; void *head, *disk, *queue; };
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; struct file *file; unsigned direction; bool poll; unsigned arg0,arg1; void *priv; };
static struct nvme_ops ops={"pcie",true};
static struct nvme_ctrl ctrl={&ops};
static struct nvme_ns_head head={1};
static struct nvme_ns ns={&ctrl,&head,NULL};
static unsigned effects=NVME_CMD_EFFECTS_CSUPP, resources;
static bool rawio, admin;
static bool capable(int cap) { return cap==CAP_SYS_RAWIO ? rawio : admin; }
static unsigned nvme_command_effects(struct nvme_ctrl *c,struct nvme_ns *n,unsigned op)
{ assert(c==&ctrl && n==&ns); assert(op==nvme_cmd_read || op==nvme_cmd_write); return effects; }
static bool nvme_is_write(struct nvme_command *c) { return c->common.opcode==nvme_cmd_write; }
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s) { return &s->layout; }
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static struct nvme_ns *nvme_xdev_ext_class_ns(struct file *f) { return f->native_ns ? &ns : NULL; }
static bool nvme_xdev_ext_poll_capable(void *q) { (void)q; return true; }
static int nvme_xdev_ext_capture_identity(struct nvme_ns *n,int *i,void **h,void **d,void **q)
{ assert(n==&ns); *i=1; *h=&head; *d=&ns; *q=&ctrl; return 0; }
static int nvme_xdev_ext_mech_bind_check(int *i,bool write,unsigned start,unsigned len,unsigned bytes)
{ assert(*i==1); (void)write; assert(bytes==4096); return start<32 && len && len<=32-start ? 0 : -ERANGE; }
static int nvme_xdev_ext_class_resources_init(struct xdev_ext_mech_stage *st) { assert(st->priv); resources++; return 0; }
static int nvme_xdev_ext_peer_resources_init(struct xdev_ext_mech_stage *st) { assert(st->priv); return 0; }
/* PRODUCTION */
static int bind_case(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_stage_uapi *u)
{ int rc=nvme_xdev_ext_class_bind(st,u); if (!rc) { free(st->priv); st->priv=NULL; } return rc; }
int main(void)
{
 struct xdev_ext_mech_session s={.layout={4096},.pool={XDEV_EXT_MECH_POOL_PEER}};
 struct file f={FMODE_READ,true};
 struct xdev_ext_mech_stage st={.s=&s,.file=&f,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.arg0=4,.arg1=8};
 struct xdev_ext_mech_stage_uapi u={0};
 rawio=false; admin=false;
 assert(bind_case(&st,&u)==0 && resources==1);
 puts("ok - no RAWIO: READ authority comes from namespace fd and supported effects");
 f.f_mode=FMODE_WRITE; st.direction=XDEV_EXT_MECH_DIR_TO_DEVICE;
 assert(bind_case(&st,&u)==0 && resources==2);
 f.f_mode=FMODE_READ; assert(bind_case(&st,&u)==-EBADF && resources==2);
 st.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE; f.f_mode=FMODE_WRITE;
 assert(bind_case(&st,&u)==-EBADF && resources==2);
 f.f_mode=FMODE_READ; effects=0;
 assert(bind_case(&st,&u)==-EACCES && resources==2);
 effects=NVME_CMD_EFFECTS_CSUPP | 0x100;
 assert(bind_case(&st,&u)==-EACCES && resources==2);
 effects=NVME_CMD_EFFECTS_CSUPP | NVME_CMD_EFFECTS_LBCC;
 assert(bind_case(&st,&u)==-EACCES && resources==2);
 effects=NVME_CMD_EFFECTS_CSUPP;
 st.arg0=31; st.arg1=2;
 assert(bind_case(&st,&u)==-ERANGE && resources==2);
 st.arg0=4; st.arg1=8; ops.peer_rw=false;
 assert(bind_case(&st,&u)==-EOPNOTSUPP && resources==2);
 ops.peer_rw=true; ops.name="tcp";
 assert(bind_case(&st,&u)==-EOPNOTSUPP && resources==2);
 ops.name="pcie"; f.native_ns=false;
 assert(bind_case(&st,&u)==-EOPNOTSUPP && resources==2);
 puts("ok - access modes, native effects, namespace type, window and transport reject before resources");
 return 0;
}
