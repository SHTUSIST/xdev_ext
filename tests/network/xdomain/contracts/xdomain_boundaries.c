/* SPDX-License-Identifier: GPL-2.0 */
/* Only external link/device/lease and sealed-call bridge effects live here. */
#define HOST_GROUPS (4*XDEV_EXT_REL_MAX_WINDOW+32)
#define HOST_WIRE (16*XDEV_EXT_REL_MAX_WINDOW+64)
struct posted_group {
 struct xdev_ext_net_elem *elements;
 struct xdev_ext_mech_batch *batch;
 u64 ticket;
 unsigned count,order;
 u64 done,quiesced;
 bool accepted;
};
struct native_record {
 struct xdev_ext_mech_batch *batch;
 u64 session,ticket,cookie,lba;
 u32 bytes,opcode;
 unsigned submit_order,complete_order;
 int status;
};
struct wire_record { struct xdev_ext_xd_msg msg; unsigned order; bool delivered,dropped; };
struct side {
 struct xdev_ext_mech_session session;
 struct xdev_ext_xd_link link;
 struct xdev_ext_mech_batch batches[HOST_GROUPS];
 struct xdev_ext_xdomain_mech_cqe cqe[HOST_GROUPS];
 struct posted_group post[HOST_GROUPS];
 struct native_record native[HOST_GROUPS];
 unsigned native_submits,native_completes;
 struct wire_record wire[HOST_WIRE];
 unsigned posts,wires,wire_cursor,link_failures,live,released_q1,released_q0,endpoint_attaches,endpoint_detaches;
 unsigned admission_calls,admission_order,unbind_order,debug_order,stale_callbacks,policy_errors;
 unsigned drop_type,full_type,complete_inline,lease_blocked,lease_calls;
 int lease_error,post_error,admission_error,last_link_error;
 bool suppress_callbacks,down_queued,admitted_unbind_priv;
 char diagnostic[1024];
};
static struct side sides[2];
static void count_native_get(atomic_t *value) {
 for(unsigned i=0;i<2;i++)if(value==&sides[i].session.native_controls){
  assert(sides[i].session.ss.state==XDEV_EXT_MECH_SESSION_ACTIVE);sides[i].session.gets++;return;
 }
 assert(!"foreign native-control counter");
}
static void count_native_put(atomic_t *value) {
 for(unsigned i=0;i<2;i++)if(value==&sides[i].session.native_controls){sides[i].session.puts++;return;}
 assert(!"foreign native-control counter");
}
static struct side *side_of_stage(const struct xdev_ext_mech_stage *st) {
 for(unsigned i=0;i<2;i++)if(st->s==&sides[i].session)return &sides[i];
 assert(!"foreign real stage");return NULL;
}
static struct side *side_of_link(const struct xdev_ext_xd_link *link) {
 for(unsigned i=0;i<2;i++)if(link==&sides[i].link)return &sides[i];
 assert(!"foreign link");return NULL;
}
/* Existing native trace boundary only: the class supplies all observations.
 * Device acceptance and completion are independently recorded by the driver. */
static struct side *side_of_batch(struct xdev_ext_mech_batch *b) {
 for(unsigned i=0;i<2;i++)for(unsigned j=0;j<HOST_GROUPS;j++)if(b==&sides[i].batches[j])return &sides[i];
 assert(!"foreign trace batch");return NULL;
}
static struct posted_group *accepted_for_batch(struct side *side,struct xdev_ext_mech_batch *b) {
 for(unsigned i=0;i<side->posts;i++)if(side->post[i].accepted&&side->post[i].batch==b&&side->post[i].ticket==b->ticket)return &side->post[i];
 assert(!"native_submit before actual full-array post acceptance");return NULL;
}
static void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch *b,u64 cookie,u64 lba,u32 bytes,u32 opcode) {
 struct side *side=side_of_batch(b);struct posted_group *post=accepted_for_batch(side,b);
 assert(side->native_submits<HOST_GROUPS&&cookie&&!lba);
 for(unsigned i=0;i<side->native_submits;i++)assert(side->native[i].batch!=b||side->native[i].ticket!=b->ticket);
 unsigned planned=0;for(unsigned i=0;i<post->count;i++)planned+=post->elements[i].len;
 assert(bytes==planned&&opcode==side->session.st[side->session.nr_stages-1].direction);
 side->native[side->native_submits++]=(struct native_record){.batch=b,.session=side->session.id,.ticket=b->ticket,.cookie=cookie,.lba=lba,.bytes=bytes,.opcode=opcode,.submit_order=++observation_order};
}
static void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b,u64 ticket,int status) {
 struct side *side=side_of_batch(b);struct posted_group *post=accepted_for_batch(side,b);
 assert(ticket==b->ticket&&post->done==(post->count==64?UINT64_MAX:(1ULL<<post->count)-1));
 for(unsigned i=0;i<side->native_submits;i++)if(side->native[i].batch==b&&side->native[i].ticket==ticket){
  assert(!side->native[i].complete_order);side->native[i].complete_order=++observation_order;side->native[i].status=status;side->native_completes++;return;
 }
 assert(!"native_complete without matching accepted submit");
}
static struct side *other(struct side *side) { return side==&sides[0]?&sides[1]:&sides[0]; }
static struct xdev_ext_mech_stage *stage_of(struct side *side) { return &side->session.st[side->session.nr_stages-1]; }
static struct xdev_ext_netfam_stage *family_of(struct side *side) {
 /* ns embedding is explicitly specified by X5, not an invented public ABI. */
 return &((struct xdev_ext_xd_stage *)stage_of(side)->priv)->ns;
}
static unsigned total_posts(void) { return sides[0].posts+sides[1].posts; }
static unsigned total_wire(void) { return sides[0].wires+sides[1].wires; }
static unsigned total_published(void) {
 unsigned n=0;for(unsigned s=0;s<2;s++)for(unsigned b=0;b<HOST_GROUPS;b++)n+=sides[s].batches[b].publishes;return n;
}
static unsigned wire_count(struct side *side,unsigned type) {
 unsigned n=0;for(unsigned i=0;i<side->wires;i++)n+=side->wire[i].msg.type==type;return n;
}
static struct wire_record *last_wire(struct side *side,unsigned type) {
 for(unsigned i=side->wires;i;i--)if(side->wire[i-1].msg.type==type)return &side->wire[i-1];
 assert(!"required wire record absent");return NULL;
}
u32 xdev_ext_xd_crc(u32 crc,const void *data,size_t count) {
 const u8 *p=data;while(count--){crc^=*p++;for(unsigned b=0;b<8;b++)crc=(crc>>1)^(0x82f63b78U&-(crc&1));}return crc;
}
struct xdev_ext_xd_link *xdev_ext_xd_link_get(u64 token) {
 for(unsigned i=0;i<2;i++) { if(sides[i].link.token==token){sides[i].link.ref.refs++;return &sides[i].link;} }
 return NULL;
}
void xdev_ext_xd_link_put(struct xdev_ext_xd_link *link) { assert(link->ref.refs>0);link->ref.refs--; }
void xdev_ext_xd_link_fail(struct xdev_ext_xd_link *link,const struct xdev_ext_xd_ep *ep,int error) {
 struct side *side=side_of_link(link);assert(error<0);if(ep&&ep->detached)return;
 side->link_failures++;side->last_link_error=error;side->down_queued=true;
 /* Records a work item; does not stop rings recursively from callback. */
}
void xdev_ext_xd_link_down(struct xdev_ext_xd_link *link,int error) {
 struct side *side=side_of_link(link);link->up=false;
 for(unsigned d=0;d<2;d++)if(link->chan[0].ep[d]){
  struct xdev_ext_xd_ep *ep=link->chan[0].ep[d];ep->detached=true;link->chan[0].ep[d]=NULL;
  xdev_ext_mech_stage_dead(ep->st,error);
 }
 side->down_queued=false;
}
int xdev_ext_xd_seq_consume(struct xdev_ext_xd_link *link,u32 channel,u64 sequence,u32 count) {
 assert(channel==0);if(!link->up)return -ENOLINK;
 if(sequence!=link->chan[0].consumed||UINT64_MAX-sequence<count)return -EPROTO;
 link->chan[0].consumed+=count;return 0;
}
int xdev_ext_xd_msg_send(struct xdev_ext_xd_link *link,const struct xdev_ext_xd_ep *ep,u32 channel,struct xdev_ext_xd_msg *msg) {
 struct side *side=side_of_link(link);u8 encoded[128];struct xdev_ext_xd_msg decoded;
 assert(channel==0&&msg&&side->wires<HOST_WIRE);
 if(!link->up||(ep&&ep->detached))return -ENOLINK;
 if(side->full_type==msg->type)return -EAGAIN;
 msg->src_inc=link->local_inc;msg->dst_inc=link->remote_inc;
 if(msg->type==XDEV_EXT_XD_RTS){msg->data_seq=link->chan[0].announced;assert(UINT64_MAX-msg->data_seq>=msg->count);}
 assert(!xdev_ext_xd_msg_encode(encoded,msg,xdev_ext_xd_crc));
 assert(!xdev_ext_xd_msg_decode(encoded,sizeof(encoded),xdev_ext_xd_crc,&decoded));
 struct wire_record *record=&side->wire[side->wires++];
 *record=(struct wire_record){.msg=decoded,.order=++observation_order,.dropped=side->drop_type==msg->type};
 if(record->dropped)side->drop_type=0;
 if(msg->type==XDEV_EXT_XD_RTS)link->chan[0].announced+=msg->count;
 return 0;
}
/* This X5-only fixture never dispatches the X4 device-unbind hook. */
void xdev_ext_xd_refuse_rts(struct xdev_ext_xd_link *link,const struct xdev_ext_xd_msg *msg)
{ (void)link; (void)msg; assert(!"X4 teardown refusal requires the composed ring boundary"); abort(); }
static bool early_bind_progress;
static void *bind_progress_thread(void *arg) {
 struct xdev_ext_mech_stage *st=arg;
 xdev_ext_mech_progress_work(&st->s->progress_work.work);
 return NULL;
}
static void *device_bind(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_stage_uapi *u,void(*dead)(void *),void *arg) {
 struct side *side=side_of_stage(st);assert(dead&&arg==st&&st->priv);assert(u->arg0==side->link.token&&u->arg1==0);
 struct xdev_ext_xd_ep *ep=calloc(1,sizeof(*ep));assert(ep);
 ep->xl=&side->link;ep->st=st;ep->rx=st->direction==XDEV_EXT_MECH_DIR_FROM_DEVICE;
 ep->bound_local_inc=side->link.local_inc;ep->bound_remote_inc=side->link.remote_inc;
 assert(!side->link.chan[0].ep[ep->rx]);side->link.chan[0].ep[ep->rx]=ep;side->endpoint_attaches++;
 if(early_bind_progress) {
  pthread_t thread;
  xdev_ext_mech_session_stop(st->s,-ENOLINK);
  xdev_ext_mech_stage_dead(st,-ENOLINK);
  assert(!pthread_create(&thread,NULL,bind_progress_thread,st));
  assert(!pthread_join(thread,NULL));
 }
 return ep;
}
static void device_unbind(void *opaque) {
 struct xdev_ext_xd_ep *ep=opaque;struct side *side=side_of_link(ep->xl);
 side->admitted_unbind_priv=ep->st->priv!=NULL;side->unbind_order=++observation_order;
 if(side->link.chan[0].ep[ep->rx]==ep)side->link.chan[0].ep[ep->rx]=NULL;
 side->endpoint_detaches++;free(ep);
}
static struct pci_dev requester[2];
static struct pci_dev *device_requester(void *opaque) { return &requester[side_of_link(((struct xdev_ext_xd_ep *)opaque)->xl)-sides]; }
static u32 device_max_payload(void *opaque) { return ((struct xdev_ext_xd_ep *)opaque)->detached?0:4096; }
static void finish_element(struct side *side,unsigned group,unsigned k,int error,unsigned length,bool quiesced) {
 struct posted_group *p=&side->post[group];assert(p->accepted&&k<p->count&&!(p->done&(1ULL<<k)));
 /* X4 reports both the native CRC bit and -EBADMSG before family completion. */
 if(error==-EBADMSG&&stage_of(side)->direction==XDEV_EXT_MECH_DIR_FROM_DEVICE)
  p->elements[k].dev_flags|=XDEV_EXT_XD_DESC_CRC_ERROR;
 unsigned before=protocol_calls;p->done|=1ULL<<k;if(quiesced)p->quiesced|=1ULL<<k;callback_depth++;
 xdev_ext_net_elem_done(&p->elements[k],error,length,0,quiesced);
 callback_depth--;assert(protocol_calls==before);
}
static int device_post(void *opaque,struct xdev_ext_net_elem *elements,u32 count,bool rx) {
 struct xdev_ext_xd_ep *ep=opaque;struct side *side=side_of_link(ep->xl);
 assert(!held_spinlocks&&!held_mutexes&&ep->rx==rx&&count&&count<=64);
 if(ep->detached||!ep->xl->up)return -ENOLINK;
 if(side->post_error)return side->post_error;
 assert(side->posts<HOST_GROUPS);unsigned index=side->posts++;
 side->post[index]=(struct posted_group){.elements=elements,.batch=elements[0].slot->batch,.ticket=elements[0].slot->ticket,.count=count,.order=++observation_order,.accepted=true};
 for(unsigned i=0;i<count;i++)assert(elements[i].lease.file&&elements[i].buf_len==(rx?4096:elements[i].len));
 /* Acceptance precedes callbacks; epoch changes here MUST merge with reservation. */
 if(side->complete_inline){
  u64 ticket=elements[0].slot->ticket;
  for(unsigned i=0;i<count;i++)finish_element(side,index,i,0,elements[i].len,true);
  assert(elements[0].slot->busy&&elements[0].slot->ticket==ticket);
  for(unsigned i=0;i<count;i++)assert(elements[i].lease.file);
 }
 return 0;
}
static int device_tx(void *ep,struct xdev_ext_net_elem *e,u32 n) { return device_post(ep,e,n,false); }
static int device_rx(void *ep,struct xdev_ext_net_elem *e,u32 n) { return device_post(ep,e,n,true); }
const struct xdev_ext_net_dev_ops xdev_ext_xd_dev_ops={
 .hdr_policy=XDEV_EXT_NET_HDR_CHANNEL,.max_elems=64,.bind=device_bind,.unbind=device_unbind,
 .requester=device_requester,.max_payload=device_max_payload,.post_tx=device_tx,.post_rx=device_rx,
};
int xdev_ext_requester_bind(struct xdev_ext_requester *rq,struct xdev_ext_mech_stage *st,struct pci_dev *pdev,u32 flags) {
 struct side *side=side_of_stage(st);assert(st->priv&&pdev==&requester[side-sides]&&!flags);
 side->admission_calls++;side->admission_order=++observation_order;
 rq->pdev=pdev;rq->generation=st->s->pool.generation;rq->authority=&authority;
 rq->adm=(struct xdev_ext_admission){.reachability=side->admission_error?XDEV_EXT_CAP_TOPOLOGY_FAILED:XDEV_EXT_CAP_TOPOLOGY_PASSED,
  .refused=side->admission_error?XDEV_EXT_PEER_REFUSE_NO_P2P_PATH:0,.distance=side->admission_error?-1:2,.backing=XDEV_EXT_PEER_BACKING_MMIO_BAR};
 return side->admission_error;
}
void xdev_ext_requester_unbind(struct xdev_ext_requester *rq) { memset(rq,0,sizeof(*rq)); }
static void capture_debug(struct device *dev,const char *format,...) {
 struct side *side=NULL;for(unsigned i=0;i<2;i++)if(dev==&requester[i].dev)side=&sides[i];assert(side);
 va_list ap;va_start(ap,format);vsnprintf(side->diagnostic,sizeof(side->diagnostic),format,ap);va_end(ap);
 side->debug_order=++observation_order;
}
/* Lease boundary: only a callback carrying q=true proves native quiescence.
 * q=false RELEASE retains an opaque authority pin in our quarantine ledger. */
struct held_lease { struct xdev_ext_peer_fd_lease *lease;struct side *side;bool live,quarantined; };
static struct held_lease lease_ledger[HOST_GROUPS*128];
static void (*lease_schedule)(struct side *side);
int xdev_ext_peer_file_acquire(struct file *file,struct pci_dev *pdev,u64 generation,u64 offset,u32 length,enum dma_data_direction direction,struct xdev_ext_peer_fd_lease *lease) {
 struct side *side=NULL;for(unsigned i=0;i<2;i++)if(pdev==&requester[i])side=&sides[i];assert(side&&file==&authority);
 assert(generation==side->session.pool.generation&&!held_spinlocks&&length&&direction==(stage_of(side)->direction==XDEV_EXT_MECH_DIR_FROM_DEVICE?DMA_FROM_DEVICE:DMA_TO_DEVICE));
 side->lease_calls++;
 if(lease_schedule){void(*schedule)(struct side*)=lease_schedule;lease_schedule=NULL;schedule(side);}
 if(side->lease_error)return side->lease_error;
 for(unsigned i=0;i<ARRAY_SIZE(lease_ledger);i++)if(!lease_ledger[i].live&&!lease_ledger[i].quarantined){
  lease_ledger[i]=(struct held_lease){lease,side,true,false};side->live++;
  lease->file=file;lease->lease.mapping=(void *)(uintptr_t)(i+1);lease->lease.len=length;lease->lease.dma_address=0x100000+offset;return 0;
 }
 assert(!"bounded test lease ledger exhausted");return -ENOMEM;
}
void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *lease,bool quiesced) {
 if(!lease->file)return;
 for(unsigned i=0;i<ARRAY_SIZE(lease_ledger);i++)if(lease_ledger[i].live&&lease_ledger[i].lease==lease){
  struct held_lease *h=&lease_ledger[i];h->live=false;h->side->live--;h->quarantined=!quiesced;
  if(quiesced){h->side->released_q1++;memset(lease,0,sizeof(*lease));}else h->side->released_q0++;
  return;
 }
 assert(!"duplicate/foreign lease release");
}

/* BPF bridge is deliberately NOT a kernel identity implementation. X1 runs the
 * real invoke validator/kfuncs separately before this binary is compiled. */
enum injection {
 NORMAL,ABSENT_CALLBACK,NO_VERDICT,RAW_HOLD,RAW_RETRY,RAW_UNKNOWN,SWALLOWED_ERROR,
 ID_FOREIGN,EPOCH_FORGED,WAIT_FOREVER,WAIT_ZERO,WAIT_PAST,WAIT_LATE,WAIT_HARD,
 TX_POST_FORBIDDEN,RX_POST_FORBIDDEN,PUBLISH_SUCCESS,IGNORE_OBLIGATION,REJECT_POSTED,
 BAD_CREDIT_HIGH,BAD_CREDIT_LOW,BAD_CREDIT_OVERFLOW,BAD_CREDIT_FOREIGN,ALLOW_UNDERCREDIT,
 DUPLICATE_RECORD,INVALID_ACTION,BAD_VERSION,BAD_FLAGS,BAD_RESERVED,
 ALTERNATE_POLICY
};
static enum injection inject;
static unsigned inject_event,inject_limit,inject_seen;
static u64 early_withdraw_ns,delayed_ack_ns;
static void (*after_record)(struct xdev_ext_mech_stage *st);
static const struct xdev_ext_mech_call_args *active_args;
static struct xdev_ext_mech_stage *active_stage;
static struct xdev_ext_mech_ctx active_context;
static unsigned private_reads,private_writes;
static struct xdev_ext_xdomain_proto_info last_snapshot;
static struct xdev_ext_xdomain_proto_verdict last_recorded;
static int all_zero(const void *data,size_t count) { const u8*p=data;for(size_t i=0;i<count;i++)if(p[i])return 0;return 1; }
static bool chosen_injection(const struct xdev_ext_xdomain_proto_info *info) {
 if(inject==NORMAL|| (inject_event&&inject_event!=info->event))return false;
 if(inject_limit&&inject_seen>=inject_limit)return false;
 inject_seen++;return true;
}
static int bpf_xdev_ext_xdomain_info(const struct xdev_ext_mech_ctx *ctx,void *out,__u32 size) {
 assert(ctx==&active_context&&active_args&&size==256&&all_zero(out,size));private_reads++;
 memcpy(out,active_args->info,size);return 0;
}
static int bpf_xdev_ext_xdomain_verdict(const struct xdev_ext_mech_ctx *ctx,const void *in,__u32 size) {
 assert(ctx==&active_context&&active_args&&size==64);private_writes++;
 /* Record-only boundary. Duplicate/error validation belongs to actual dispatcher/X1. */
 active_args->xdomain->calls++;memcpy(&active_args->xdomain->verdict,in,64);return 0;
}

/* Ordinary v1 invocation storage exposed to the versioned reference policy.
 * Actual private kfunc identity/validation is tested independently. */
static int bpf_xdev_ext_xdomain_info_v2(const struct xdev_ext_mech_ctx *ctx,void *out,__u32 size)
{
 struct xdev_ext_xdomain_proto_info base={0};
 struct xdev_ext_xdomain_proto_info_v2 *info=out;
 int ret;
 if(!out||size!=sizeof(*info))return -EINVAL;
 ret=bpf_xdev_ext_xdomain_info(ctx,&base,sizeof(base));
 if(ret)return ret;
 if(base.size!=sizeof(base)||base.version!=XDEV_EXT_XDOMAIN_PROTO_VERSION)return -EINVAL;
 memset(out,0,size);info->base=base;
 info->base.size=sizeof(*info);info->base.version=XDEV_EXT_XDOMAIN_PROTO_V2_VERSION;
 return 0;
}
static int bpf_xdev_ext_xdomain_verdict_v2(const struct xdev_ext_mech_ctx *ctx,const void *in,__u32 size)
{
 struct xdev_ext_xdomain_proto_verdict verdict;
 if(!in||size!=sizeof(verdict))return -EINVAL;
 memcpy(&verdict,in,size);
 if(verdict.size!=size||verdict.version!=XDEV_EXT_XDOMAIN_PROTO_V2_VERSION||
    verdict.action>XDEV_EXT_XDP_ACT_CANCEL_ARMED)return -EINVAL;
 verdict.version=XDEV_EXT_XDOMAIN_PROTO_VERSION;
 return bpf_xdev_ext_xdomain_verdict(ctx,&verdict,size);
}

static void *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx,__u32 size) { (void)ctx;(void)size;assert(!"protocol generic info access");return NULL; }
static void *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx,__u32 slot,__u32 size) { (void)ctx;(void)slot;(void)size;assert(!"protocol descriptor access");return NULL; }
static void *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx,__u32 slot,__u32 size) { (void)ctx;(void)slot;(void)size;assert(!"protocol final CQE access");return NULL; }
static bool xdev_ext_mech_stage_has_member(const struct xdev_ext_mech_stage *st,u32 member) { (void)st;(void)member;return inject!=ABSENT_CALLBACK; }
static int alternate_complete(const struct xdev_ext_mech_ctx *ctx) {
 struct xdev_ext_xdomain_proto_info info={0};struct xdev_ext_xdomain_proto_verdict verdict={0};
 if(bpf_xdev_ext_xdomain_info(ctx,&info,sizeof(info))||xdomain_peer_choose(&info,&verdict))return XDEV_EXT_MP_ABORT;
 if(info.event==XDEV_EXT_XDP_EV_TIMER&&info.direction==XDEV_EXT_MECH_DIR_TO_DEVICE&&info.state==XDEV_EXT_RDV_ANNOUNCED&&!(info.facts&XDEV_EXT_XDP_F_WITHDRAWN)&&info.now_ns>=early_withdraw_ns){
  verdict.action=XDEV_EXT_XDP_ACT_WITHDRAW;verdict.wake_ns=verdict.credit=0;verdict.status=0;
 }
 if(verdict.action==XDEV_EXT_XDP_ACT_SEND_ACK&&info.now_ns<delayed_ack_ns){
  verdict.action=XDEV_EXT_XDP_ACT_WAIT;verdict.credit=0;verdict.status=0;
  verdict.wake_ns=min(info.now_ns+20000000ULL,delayed_ack_ns);
  if(info.hard_deadline_ns)verdict.wake_ns=min(verdict.wake_ns,info.hard_deadline_ns);
 }
 return bpf_xdev_ext_xdomain_verdict(ctx,&verdict,sizeof(verdict))?XDEV_EXT_MP_ABORT:0;
}
static void debug_stage_scalars(const char *label,struct side *side) {
 if(!getenv("X5_DEBUG"))return;
 fprintf(stderr,"XDDEBUG label=%s side=%td now=%llu posts=%u wires=%u fail=%u error=%d live=%u q0=%u q1=%u admissions=%d puts=%u\n",label,side-sides,(unsigned long long)host_ns,side->posts,side->wires,side->link_failures,side->last_link_error,side->live,side->released_q0,side->released_q1,side->session.native_controls,side->session.puts);
 for(unsigned n=0;n<side->session.nr_stages;n++) {
  struct xdev_ext_mech_stage *st=&side->session.st[n];if(st->cls!=registered||!st->priv)continue;
  struct xdev_ext_xd_stage *xs=st->priv;
  fprintf(stderr,"XDDEBUG stage=%u direction=%u dead=%u failed=%u epoch=%llu posted_groups=%u rts=%u ctl=%u base=%llu next=%llu credit=%llu\n",n,st->direction,xs->ns.dead,xs->failed,(unsigned long long)xs->epoch,xs->posted_groups,xs->rts_count,xs->ctl_count,(unsigned long long)xs->ns.tx.base_group,(unsigned long long)xs->ns.tx.next_group,(unsigned long long)xs->ns.tx.credit);
  for(unsigned k=0;k<xs->ns.depth;k++) {
   struct xdev_ext_net_slot *p=&xs->ns.slots[k];struct xdev_ext_xd_fact *f=&xs->facts[k];
   fprintf(stderr,"XDDEBUG stage=%u slot=%u busy=%u state=%u group=%llu ticket=%llu local_known=%u quiesced=%u sequester=%u accepted=%u reserved=%u event=%u epoch=%llu wake=%llu\n",n,k,p->busy,p->state,(unsigned long long)p->group,(unsigned long long)p->ticket,p->local_known,p->local_quiesced,p->sequestered,f->accepted,f->reserved,f->event,(unsigned long long)f->epoch,(unsigned long long)f->wake);
  }
 }
}
static int xdev_ext_mech_call(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_call_args *a,s32 *ret,struct xdev_ext_mech_hold_intent *hold) {
 (void)hold;assert(!held_spinlocks&&!held_mutexes&&!callback_depth&&worker_depth==1);
 assert(a->member==XDEV_EXT_MECH_MEMBER_COMPLETE&&a->callsite==XDEV_EXT_MECH_SITE_WORKER_PROTOCOL);
 assert(st->class_id==XDEV_EXT_MECH_CLASS_XDOMAIN&&a->xdomain&&a->info_size==256&&a->info);
 assert(!a->b&&!a->batch_id&&!a->frames&&!a->nr_frames&&!a->scratch&&!a->desc_size&&!a->desc_cap&&!a->cqe&&!a->cqe_size&&!a->cqe_cap&&!a->out_len&&!a->len_delta);
 assert(all_zero(a->xdomain,sizeof(*a->xdomain)));protocol_calls++;
 active_args=a;active_stage=st;private_reads=private_writes=0;
 active_context=(struct xdev_ext_mech_ctx){.base=*a->base,.callsite=a->callsite};
 last_snapshot=*(const struct xdev_ext_xdomain_proto_info *)a->info;
 assert(last_snapshot.size==256&&last_snapshot.version==1&&all_zero(last_snapshot.reserved,sizeof(last_snapshot.reserved)));
 bool malicious=chosen_injection(&last_snapshot);
 if(malicious&&inject==ABSENT_CALLBACK){active_args=NULL;return -ENOENT;}
 *ret=malicious&&inject==ALTERNATE_POLICY?alternate_complete(&active_context):xdomain_peer_complete(NULL,&active_context);
 if(malicious){
  struct xdev_ext_xdomain_proto_verdict *v=&a->xdomain->verdict;
  switch(inject){
  case NO_VERDICT:a->xdomain->calls=0;*ret=0;break;
  case RAW_HOLD:*ret=XDEV_EXT_MECH_HOLD;break;
  case RAW_RETRY:*ret=XDEV_EXT_MECH_RETRY;break;
  case RAW_UNKNOWN:*ret=1234567;break;
  case SWALLOWED_ERROR:active_args=NULL;return -EPROTO;
  case ID_FOREIGN:v->event_id+=10000;break;
  case EPOCH_FORGED:v->epoch++;break;
  case WAIT_FOREVER:v->action=XDEV_EXT_XDP_ACT_WAIT;v->wake_ns=host_ns+20000000;v->credit=0;v->status=0;break;
  case WAIT_ZERO:case WAIT_PAST:case WAIT_LATE:case WAIT_HARD:
   v->action=XDEV_EXT_XDP_ACT_WAIT;v->credit=0;v->status=0;
   v->wake_ns=inject==WAIT_ZERO?0:inject==WAIT_PAST?host_ns:inject==WAIT_LATE?host_ns+20000001:last_snapshot.hard_deadline_ns+1;break;
  case TX_POST_FORBIDDEN:v->action=XDEV_EXT_XDP_ACT_TX_POST;v->credit=v->wake_ns=0;v->status=0;break;
  case RX_POST_FORBIDDEN:v->action=XDEV_EXT_XDP_ACT_RX_POST;v->credit=v->wake_ns=0;v->status=0;break;
  case PUBLISH_SUCCESS:v->action=XDEV_EXT_XDP_ACT_PUBLISH;v->status=0;v->credit=v->wake_ns=0;break;
  case IGNORE_OBLIGATION:v->action=XDEV_EXT_XDP_ACT_IGNORE;v->status=0;v->credit=v->wake_ns=0;break;
  case REJECT_POSTED:v->action=XDEV_EXT_XDP_ACT_REJECT_RTS;v->status=-ECANCELED;v->credit=v->wake_ns=0;break;
  case BAD_CREDIT_HIGH:v->credit=last_snapshot.credit+1;break;
  case BAD_CREDIT_LOW:v->credit=1;break;
  case BAD_CREDIT_OVERFLOW:v->credit=UINT64_MAX;break;
  case BAD_CREDIT_FOREIGN:v->credit=last_snapshot.msg_credit+1;break;
  case ALLOW_UNDERCREDIT:v->credit=last_snapshot.credit-1;break;
  case DUPLICATE_RECORD:a->xdomain->calls=2;break;
  case INVALID_ACTION:v->action=UINT32_MAX;break;
  case BAD_VERSION:v->version=2;break;
  case BAD_FLAGS:v->flags=1;break;
  case BAD_RESERVED:v->reserved1=1;break;
  default:break;
  }
 }
 last_recorded=a->xdomain->verdict;
 if(getenv("X5_DEBUG")) {
  fprintf(stderr,"XDDEBUG candidate side=%td stage=%u direction=%u event=%u id=%llu epoch=%llu group=%llu state=%u facts=%u msg_type=%u now=%llu hard=%llu policy=%llu credit=%llu msg_credit=%llu action=%u out_id=%llu out_epoch=%llu out_credit=%llu status=%d wake=%llu injected=%u mode=%u\n",side_of_stage(st)-sides,st->index,st->direction,last_snapshot.event,(unsigned long long)last_snapshot.event_id,(unsigned long long)last_snapshot.epoch,(unsigned long long)last_snapshot.group,last_snapshot.state,last_snapshot.facts,last_snapshot.msg_type,(unsigned long long)last_snapshot.now_ns,(unsigned long long)last_snapshot.hard_deadline_ns,(unsigned long long)last_snapshot.policy_deadline_ns,(unsigned long long)last_snapshot.credit,(unsigned long long)last_snapshot.msg_credit,last_recorded.action,(unsigned long long)last_recorded.event_id,(unsigned long long)last_recorded.epoch,(unsigned long long)last_recorded.credit,last_recorded.status,(unsigned long long)last_recorded.wake_ns,malicious,inject);
 }
 if(after_record){void(*hook)(struct xdev_ext_mech_stage*)=after_record;after_record=NULL;hook(st);}
 active_args=NULL;active_stage=NULL;return 0;
}

/* Explicit driver/worker scheduling. A kick and all callbacks only record. */
static void run_worker_once(struct side *side) {
 assert(!held_spinlocks&&!held_mutexes&&!callback_depth&&!worker_depth);
 side->session.queued=0;worker_depth=1;unsigned before=protocol_calls;
 unsigned long delay=0;
 /* Actual core worker visits every bound stage; each class owns its policy. */
 for(unsigned i=0;i<side->session.nr_stages;i++) {
  struct xdev_ext_mech_stage *st=&side->session.st[i];
  if(st->priv&&st->cls&&st->cls->progress) {
   unsigned long next=st->cls->progress(st);if(next)delay=next;
  }
 }
 worker_depth=0;assert(protocol_calls-before<=4*XDEV_EXT_REL_MAX_WINDOW);
 if(delay)side->session.queued=1;
}
static void deliver_wire_once(struct side *sender) {
 if(sender->wire_cursor==sender->wires)return;
 struct wire_record *record=&sender->wire[sender->wire_cursor++];record->delivered=true;
 if(record->dropped)return;
 struct side *receiver=other(sender);struct xdev_ext_xd_msg msg=record->msg;
 if(xdev_ext_xd_msg_for_us(&msg,receiver->link.local_inc,receiver->link.remote_inc,1))return;
 struct xdev_ext_xd_ep *ep=receiver->link.chan[0].ep[msg.type==XDEV_EXT_XD_RTS||msg.type==XDEV_EXT_XD_CANCEL];
 unsigned before=protocol_calls;callback_depth++;
 if(ep)xdev_ext_xd_class_ctl(ep->st,&msg);
 else if(msg.type==XDEV_EXT_XD_RTS){
  int rc=xdev_ext_xd_seq_consume(&receiver->link,0,msg.data_seq,msg.count);assert(!rc);
  struct xdev_ext_xd_msg fail={.type=XDEV_EXT_XD_FAIL,.stream=msg.stream,.group=msg.group,.status=ENODEV};
  assert(!xdev_ext_xd_msg_send(&receiver->link,NULL,0,&fail));
 }
 callback_depth--;assert(protocol_calls==before);
}
static void drain_worker(unsigned budget) {
 for(unsigned pass=0;pass<budget;pass++){
  bool did=false;
  for(unsigned i=0;i<2;i++){
   struct side *side=&sides[i];
   if(side->wire_cursor<side->wires){deliver_wire_once(side);did=true;}
   if(side->session.queued&&stage_of(side)->priv){run_worker_once(side);did=true;}
  }
  if(!did)return;
 }
 /* A pending future timer or WAIT is allowed; no recursive/unbounded drain. */
}
static void advance_ms(u64 ms) { assert(UINT64_MAX-host_ns>=ms*1000000ULL);host_ns+=ms*1000000ULL;for(unsigned i=0;i<2;i++)sides[i].session.queued=1; }
static void request_stop(struct side *side) { xdev_ext_mech_session_stop(&side->session,0);side->session.queued=1; }
static void complete_group(struct side *side,unsigned group,int error,bool quiesced) {
 struct posted_group *p=&side->post[group];for(unsigned k=0;k<p->count;k++)if(!(p->done&(1ULL<<k)))finish_element(side,group,k,error,error?0:p->elements[k].len,quiesced);
}
static void complete_batch(struct side *side,unsigned batch,int error,bool quiesced) {
 struct posted_group *p=accepted_for_batch(side,&side->batches[batch]);
 complete_group(side,(unsigned)(p-side->post),error,quiesced);
}
static void down_run(bool callbacks) {
 assert(!callback_depth&&!held_spinlocks&&!held_mutexes);
 for(unsigned i=0;i<2;i++){
  struct side *side=&sides[i];xdev_ext_xd_link_down(&side->link,side->last_link_error?:-ENOLINK);
  if(callbacks)for(unsigned g=0;g<side->posts;g++)complete_group(side,g,-ECANCELED,false);
 }
 drain_worker(16);
}
static void source_end(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,int err) { (void)st;(void)b;(void)err; }
static const struct xdev_ext_mech_class_ops source_class={.batch_end=source_end};
static void fresh(unsigned tx_index,unsigned rx_index,unsigned depth,unsigned frame_size,unsigned bytes) {
 /* Each case uses a process-local fresh experiment; unknown allocations are
  * never unmapped or freed by production. Resetting ledger starts a NEW case. */
 memset(sides,0,sizeof(sides));memset(lease_ledger,0,sizeof(lease_ledger));
 host_ns=1000000;observation_order=frame_release_fail=0;inject=NORMAL;inject_event=inject_limit=inject_seen=0;after_record=NULL;lease_schedule=NULL;
 assert(!held_spinlocks&&!held_mutexes&&!callback_depth&&!worker_depth);protocol_calls=0;
 if(!registered)assert(!xdev_ext_xd_class_register());
 for(unsigned i=0;i<2;i++){
  struct side *side=&sides[i];unsigned index=i?rx_index:tx_index;
  side->session=(struct xdev_ext_mech_session){.pool={XDEV_EXT_MECH_POOL_PEER,frame_size,128,7},.l={frame_size,0,bytes,bytes},.depth=depth,.id=101+i,.nr_stages=index+1};
  side->session.ss.state=XDEV_EXT_MECH_SESSION_ACTIVE;
  for(unsigned j=0;j<index;j++)side->session.st[j]=(struct xdev_ext_mech_stage){.s=&side->session,.cls=&source_class,.index=j};
  side->session.st[index]=(struct xdev_ext_mech_stage){.s=&side->session,.cls=registered,.file=&authority,.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.index=index,.direction=i?XDEV_EXT_MECH_DIR_FROM_DEVICE:XDEV_EXT_MECH_DIR_TO_DEVICE};
  side->link.token=1001+i;side->link.local_inc=11+i;side->link.remote_inc=12-i;side->link.up=true;side->link.channels=1;
  /* Unit precondition: the external link/device boundary is preverified.
   * These family cases never claim actual startup challenge execution. */
  side->link.probe_phase=XD_PROBE_VERIFIED;side->link.data_verified_mask=1;
  memset(side->link.ctl_tx_free,0xff,sizeof(side->link.ctl_tx_free));
  side->link.nhi_pdev=&requester[i];
 }
}
static int bind_side(struct side *side) {
 struct xdev_ext_mech_stage_uapi u={.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN,.direction=stage_of(side)->direction,.arg0=side->link.token};
 int result=registered->bind(stage_of(side),&u);
 /* This unit stands in for completed CREATE publication only after its real
  * bind returns. A worker reentered during bind must still see false. */
 if(!result&&side->session.ss.state==XDEV_EXT_MECH_SESSION_ACTIVE)
  side->session.progress_ready=true;
 return result;
}
static void pair(unsigned tx_index,unsigned depth,unsigned bytes) { fresh(tx_index,0,depth,65536,bytes);assert(!bind_side(&sides[0])&&!bind_side(&sides[1])); }
static struct xdev_ext_mech_batch *prepare_raw(struct side *side,unsigned index) {
 assert(index<HOST_GROUPS);struct xdev_ext_mech_batch *b=&side->batches[index];
 *b=(struct xdev_ext_mech_batch){.priv=calloc(1,registered->batch_priv_size),.cookie=calloc(1,registered->batch_cookie_size),.nr=1,.ticket=index+100};
 assert(b->priv&&b->cookie);b->f[0]=(struct xdev_ext_mech_frame){.umem_addr=(u64)(index%128)*65536,.index=index%128,.data_len=side->session.l.seg_len};
 return b;
}
static const u8 test_tag[24]={0xa5,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,1,2,3,4,5,6,7,8};
static struct xdev_ext_mech_batch *prepare(struct side *side,unsigned index) {
 struct xdev_ext_mech_batch *b=prepare_raw(side,index);
 u8 scratch[32*64]={0};assert(!registered->default_build(stage_of(side),b,scratch));
 if(stage_of(side)->direction==XDEV_EXT_MECH_DIR_TO_DEVICE)memcpy(((struct xdev_ext_xdomain_desc*)scratch)[0].tag,test_tag,24);
 assert(!registered->validate(stage_of(side),b,scratch,1));return b;
}
static int submit(struct side *side,unsigned index) {
 struct xdev_ext_mech_batch *b=prepare(side,index);worker_depth=1;
 int result=registered->submit(stage_of(side),b);worker_depth=0;
 if(!result)side->session.ss.inflight++;
 return result;
}
static void consume(struct side *side,unsigned index) {
 struct xdev_ext_mech_batch *b=&side->batches[index];
 if(b->publishes!=1)fprintf(stderr,"X5 consume unmet: side=%td batch=%u publishes=%u status=%d posts=%u native_submit=%u native_complete=%u wires=%u link_fail=%u err=%d protocol_calls=%u\n",side-sides,index,b->publishes,b->status,side->posts,side->native_submits,side->native_completes,side->wires,side->link_failures,side->last_link_error,protocol_calls);
 assert(b->publishes==1);
 /* A complete CQE overwrites the caller buffer, including unused fields. */
 memset(&side->cqe[index],0xa5,sizeof(side->cqe[index]));
 registered->fill_cqe(stage_of(side),b,&side->cqe[index]);b->filled++;
 assert(side->cqe[index].rsvd==0);
 if(stage_of(side)->direction==XDEV_EXT_MECH_DIR_TO_DEVICE)
  assert(all_zero(side->cqe[index].tag,sizeof(side->cqe[index].tag)));
}
static void end_batch(struct side *side,unsigned index,int error,bool sequester) {
 struct xdev_ext_mech_batch *b=&side->batches[index];worker_depth=1;
 unsigned wire_before=total_wire(),calls_before=protocol_calls;
 xdev_ext_mech_end(&side->session,b,sequester?XDEV_EXT_MECH_END_SEQUESTER:error?XDEV_EXT_MECH_END_ABORT:XDEV_EXT_MECH_END_DONE,error);
 worker_depth=0;assert(total_wire()==wire_before&&protocol_calls==calls_before);
}
static void happy_group(unsigned index) {
 assert(!submit(&sides[1],index));assert(!submit(&sides[0],index));drain_worker(16);
 complete_batch(&sides[1],index,0,true);complete_batch(&sides[0],index,0,true);drain_worker(16);
 consume(&sides[1],index);end_batch(&sides[1],index,0,false);drain_worker(16);
 consume(&sides[0],index);end_batch(&sides[0],index,0,false);drain_worker(4);
}
struct failure_batch_fact { unsigned publishes;int status;bool prepared;u64 ticket;unsigned accepted,quiesced; };
static struct failure_batch_fact failure_before[2][HOST_GROUPS];
static unsigned failure_success_before, failure_q1_before[2];
static u64 failure_announced_before[2];
static void capture_failure_before(void) {
 failure_success_before=0;
 for(unsigned i=0;i<2;i++) {
  failure_q1_before[i]=sides[i].released_q1;failure_announced_before[i]=sides[i].link.chan[0].announced;
  for(unsigned k=0;k<HOST_GROUPS;k++) {
   struct xdev_ext_mech_batch *b=&sides[i].batches[k];
   failure_before[i][k]=(struct failure_batch_fact){.publishes=b->publishes,.status=b->status,.prepared=b->priv!=NULL,.ticket=b->ticket};
   for(unsigned n=0;n<sides[i].posts;n++) {
    struct posted_group *p=&sides[i].post[n];if(p->batch!=b||p->ticket!=b->ticket)continue;
    failure_before[i][k].accepted++;u64 mask=p->count==64?UINT64_MAX:(1ULL<<p->count)-1;
    failure_before[i][k].quiesced+=p->done==mask&&p->quiesced==mask;
   }
   failure_success_before+=b->publishes&&b->status==0;
  }
 }
}
static void malicious(enum injection mode,unsigned event,unsigned limit) {
 capture_failure_before();inject=mode;inject_event=event;inject_limit=limit;inject_seen=0;
}
/* Root SDD clarification: invalid intent has no selected effect; mandatory C
 * failure may later publish truthful negative custody, never success. */
static void assert_protocol_failure(unsigned posts_before,unsigned wire_before,unsigned publishes_before) {
 drain_worker(8);
 debug_stage_scalars("protocol-failure",&sides[0]);debug_stage_scalars("protocol-failure",&sides[1]);
 assert(sides[0].link_failures+sides[1].link_failures>0);
 assert((sides[0].last_link_error==-EPROTO)||(sides[1].last_link_error==-EPROTO));
 assert(total_posts()==posts_before&&total_wire()==wire_before);
 unsigned success_after=0,new_publications=0;
 for(unsigned i=0;i<2;i++) {
  assert(sides[i].link.chan[0].announced==failure_announced_before[i]);
  for(unsigned k=0;k<HOST_GROUPS;k++) {
   struct xdev_ext_mech_batch *b=&sides[i].batches[k];struct failure_batch_fact *old=&failure_before[i][k];
   success_after+=b->publishes&&b->status==0;
   if(b->publishes==old->publishes)continue;
   assert(b->publishes==old->publishes+1&&b->status<0);
   if(old->prepared)assert(b->ticket==old->ticket);
   struct xdev_ext_xd_batch *bp=b->priv;assert(bp&&bp->cqe.status==b->status);
   unsigned accepted=0;bool all_quiesced=true;
   for(unsigned n=0;n<sides[i].posts;n++) {
    struct posted_group *p=&sides[i].post[n];
    if(p->batch!=b||p->ticket!=b->ticket)continue;
    accepted++;u64 mask=p->count==64?UINT64_MAX:(1ULL<<p->count)-1;
    if(p->done!=mask||p->quiesced!=mask)all_quiesced=false;
   }
   fprintf(stderr,"Safety publication side=%u batch=%u before=%u/status%d after=%u/status%d ticket=%llu accepted_before=%u/quiesced_before=%u accepted_after=%u all_quiesced_after=%u sequester=%u remote=%u q1before=%u q1after=%u\n",i,k,old->publishes,old->status,b->publishes,b->status,(unsigned long long)b->ticket,old->accepted,old->quiesced,accepted,accepted&&all_quiesced,b->sequester,bp->cqe.remote,failure_q1_before[i],sides[i].released_q1);
   if(stage_of(&sides[i])->direction==XDEV_EXT_MECH_DIR_TO_DEVICE)assert(bp->cqe.remote==XDEV_EXT_NET_REMOTE_LOST);
   if(!accepted)assert(!b->sequester);
   else if(!all_quiesced)assert(b->sequester&&sides[i].released_q1==failure_q1_before[i]);
   new_publications++;
  }
 }
 assert(success_after==failure_success_before);
 assert(total_published()==publishes_before+new_publications);
}

/* Explicit activation dependency: the reviewable storage adapter is test-only.
 * It is written after actual X5 storage exists, and copies actual bounded queue
 * bytes/occupancy/latched bits. It never implements overflow or selects policy. */
struct pressure_observation {
 u8 queue[65536];
 size_t bytes;
 unsigned used;
 bool stop_pending,link_down_pending,stop_observed;
};
void pressure_seed_full(struct side *side,struct xdev_ext_xd_msg *one_more);
void pressure_capture(struct side *side,struct pressure_observation *out);
@PRESSURE@

/* These class/family unit cases never query diagnostics. The link is an
 * external recorder here; fail loudly if a new case attempts that query. */
#ifndef DIAG_CLASS_HAS_HOOK
int xdev_ext_xd_link_diag(struct xdev_ext_xd_ep *ep,struct xdev_ext_mech_stage_diag *out)
{(void)ep;(void)out;abort();}
#endif

/* The original class fixture opts into v1 only. Reject unexpected v2 wire I/O. */
int xdev_ext_xd_msg_send_v2(struct xdev_ext_xd_link *link,const struct xdev_ext_xd_ep *ep,struct xdev_ext_xd_msg_v2 *msg)
{ (void)link;(void)ep;(void)msg;assert(!"v2 wire outside original v1 class fixture");abort(); }
