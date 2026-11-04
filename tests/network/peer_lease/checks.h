#ifdef TEST_TYPED
#define HANDLE(e) (&(e)->lease.u.peer)
#else
#define HANDLE(e) (&(e)->lease)
#endif
static const struct xdev_ext_peer_provider_ops provider_ops={0};
struct world {struct xdev_ext_peer_region region;struct xdev_ext_peer_fd fd;struct xdev_ext_peer_authority authority;struct file file;struct xdev_ext_mech_session session;struct xdev_ext_mech_stage stage;struct xdev_ext_net_member member;struct xdev_ext_netfam_stage ns;struct xdev_ext_net_batch cb;struct xdev_ext_mech_batch batch;u64 addresses[4];};
static void prepare_world(struct world *w,bool rx) {
 memset(w,0,sizeof(*w));memset(&native_mapping,0,sizeof(native_mapping));acquire_calls=release_calls=requester_calls=0;map_calls=map_error=0;native_calls=native_returns=inline_publishes_seen=0;native_inline=native_post_error=native_status=0;native_quiesced=true;now_ms=100;alloc_fail=alloc_calls=0;expected_slotp=NULL;native_slot_visible=false;
 w->region.ops=&provider_ops;w->region.len=16384;w->region.generation=77;
 INIT_LIST_HEAD(&w->region.maps);INIT_LIST_HEAD(&w->fd.maps);w->fd.region=&w->region;w->fd.claimed=&w->authority;w->authority.parent=&w->fd;
 w->file=(struct file){.f_op=&xdev_ext_peer_authority_fops,.private_data=&w->authority,.refs=10};
 for(u32 i=0;i<4;i++)w->addresses[i]=0x123400000000ULL+(u64)i*0x10000;
 native_mapping.region=&w->region;native_mapping.peer=&requester_device;native_mapping.direction=DMA_BIDIRECTIONAL;native_mapping.users=1;native_mapping.dma=(struct xdev_ext_peer_dma){.addresses=w->addresses,.entries=4,.page_shift=12};
 w->session=(struct xdev_ext_mech_session){.depth=2,.admits=true,.pool={.authority=&w->file,.generation=77}};w->stage.priv=&w->ns;w->stage.s=&w->session;w->stage.direction=rx?2:1;
 w->member=xdev_ext_net_member;w->batch=(struct xdev_ext_mech_batch){.ticket=0x81923344,.priv=&w->cb};observed_batch=&w->batch;
 EQ(xdev_ext_netfam_init(&w->ns,&w->stage,&w->member,rx,14),0);EQ(xdev_ext_netfam_attach(&w->ns,&(struct xdev_ext_mech_stage_uapi){0},0),0);
}
static void discard_world(struct world *w) {
 assert(!native_mapping.active);EQ(w->file.refs,10);
 /* Fixture disposal after assertions, including deliberately non-reusable UNKNOWN
  * slots. This is not a production claim that a retained slot may be reclaimed. */
 free(w->ns.elems);free(w->ns.slots);
 while(w->fd.maps.next!=&w->fd.maps){struct list_head *p=w->fd.maps.next;w->fd.maps.next=p->next;free(container_of(p,struct xdev_ext_peer_fd_map,node));}
}
static struct xdev_ext_net_slot *slot(struct world *w){struct xdev_ext_net_slot *s=xdev_ext_netfam_slot_get(&w->ns,&w->batch);assert(s);return s;}
static void lease_ok(struct world *w,struct xdev_ext_net_slot *s,u32 i,u64 off,u32 len,u32 buf) {
 unsigned at=acquire_calls;EQ(xdev_ext_netfam_lease(&w->ns,s,i,off,len,buf),0);
 struct xdev_ext_net_elem *e=&s->elem[i];assert(acquire_log[at].handle==HANDLE(e));assert(acquire_log[at].file==&w->file);assert(acquire_log[at].peer==&requester_device);EQ(acquire_log[at].generation,77);EQ(acquire_log[at].off,off);EQ(acquire_log[at].len,buf);EQ(acquire_log[at].dir,w->ns.rx?DMA_FROM_DEVICE:DMA_TO_DEVICE);
 assert(native_mapping.leases==&HANDLE(e)->lease);assert(HANDLE(e)->lease.mapping==&native_mapping);EQ(HANDLE(e)->lease.dma_address,w->addresses[off/4096]+off%4096);EQ(HANDLE(e)->lease.len,buf);assert(HANDLE(e)->file==&w->file);assert(e->slot==s);EQ(e->len,len);EQ(e->buf_len,buf);EQ(s->nr,i+1);
#ifdef TEST_TYPED
 EQ(e->lease.kind,XDEV_EXT_NET_LEASE_PEER_DMA);
#endif
}
static void acquisition(void) {
 struct world w;prepare_world(&w,false);struct xdev_ext_net_slot *s=slot(&w);struct xdev_ext_net_elem *stable=s->elem;
 unsigned char untouched[sizeof(s->elem[1])];memcpy(untouched,&s->elem[1],sizeof(untouched));
 EQ(xdev_ext_netfam_lease(&w.ns,s,16,0,64,64),-EPROTO);EQ(xdev_ext_netfam_lease(&w.ns,s,0,0,0,64),-EPROTO);EQ(xdev_ext_netfam_lease(&w.ns,s,0,0,64,32),-EPROTO);EQ(acquire_calls,0);EQ(requester_calls,0);
 lease_ok(&w,s,0,128,64,128);EQ(w.file.refs,11);EQ(native_mapping.active,1);EQ(map_calls,1);assert(stable==s->elem);
 u64 ticket=HANDLE(&s->elem[0])->lease.ticket;unsigned char old[sizeof(s->elem[0])];memcpy(old,&s->elem[0],sizeof(old));
 EQ(xdev_ext_netfam_lease(&w.ns,s,0,128,64,128),-EINVAL);EQ(w.file.refs,11);EQ(native_mapping.active,1);EQ(HANDLE(&s->elem[0])->lease.ticket,ticket);assert(!memcmp(old,&s->elem[0],sizeof(old)));
 EQ(xdev_ext_netfam_lease(&w.ns,s,1,4080,64,64),-ERANGE);EQ(s->nr,1);EQ(w.file.refs,11);EQ(native_mapping.active,1);assert(!memcmp(untouched,&s->elem[1],sizeof(untouched)));assert(native_mapping.leases==&HANDLE(&s->elem[0])->lease);
 xdev_ext_netfam_release(s,true);EQ(release_calls,1);assert(release_handle[0]==HANDLE(&s->elem[0]));assert(release_quiesced[0]);EQ(native_mapping.active,0);assert(!native_mapping.leases);assert(!HANDLE(&s->elem[0])->file);assert(!s->busy);
#ifdef TEST_TYPED
 EQ(s->elem[0].lease.kind,XDEV_EXT_NET_LEASE_NONE);
#endif
 struct xdev_ext_net_slot *again=slot(&w);assert(again==s);assert(again->elem==stable);xdev_ext_netfam_release(again,true);discard_world(&w);
 prepare_world(&w,true);s=slot(&w);lease_ok(&w,s,0,4096,128,4096);xdev_ext_netfam_release(s,true);discard_world(&w);
 prepare_world(&w,false);s=slot(&w);map_error=-ENXIO;memcpy(old,&s->elem[0],sizeof(old));EQ(xdev_ext_netfam_lease(&w.ns,s,0,0,64,64),-ENXIO);assert(!memcmp(old,&s->elem[0],sizeof(old)));EQ(s->nr,0);EQ(w.file.refs,10);EQ(native_mapping.active,0);xdev_ext_netfam_release(s,true);discard_world(&w);
 puts("actual acquire:stable intrusive handle,exact args TX/RX,duplicate refs,prefix failure and release rollback");
}
static void quarantine(void) {
 struct world w;prepare_world(&w,false);struct xdev_ext_net_slot *s=slot(&w);lease_ok(&w,s,0,64,128,128);
 xdev_ext_netfam_release(s,false);EQ(release_calls,1);assert(!release_quiesced[0]);assert(w.region.invalid&&w.region.quarantined);EQ(native_mapping.active,0);assert(!native_mapping.leases);assert(!HANDLE(&s->elem[0])->lease.mapping);EQ(HANDLE(&s->elem[0])->lease.dma_address,0);EQ(HANDLE(&s->elem[0])->lease.len,0);assert(!HANDLE(&s->elem[0])->file);EQ(w.file.refs,10);assert(s->busy);
#ifdef TEST_TYPED
 EQ(s->elem[0].lease.kind,XDEV_EXT_NET_LEASE_NONE);
#endif
 struct xdev_ext_net_slot *other=slot(&w);assert(other!=s);assert(!xdev_ext_netfam_slot_get(&w.ns,&w.batch));xdev_ext_netfam_release(other,true);discard_world(&w);
 /* Exercise actual stale-release refusal, without asking a fake to retain. */
 prepare_world(&w,false);s=slot(&w);lease_ok(&w,s,0,64,128,128);struct xdev_ext_peer_fd_lease *h=HANDLE(&s->elem[0]);unsigned char before[sizeof(*h)];memcpy(before,h,sizeof(*h));
 EQ(xdev_ext_peer_release(&h->lease,h->lease.ticket+1,true),-ESTALE);assert(!memcmp(before,h,sizeof(*h)));EQ(w.file.refs,11);
 native_mapping.leases=NULL;xdev_ext_netfam_release(s,false);assert(!memcmp(before,h,sizeof(*h)));EQ(w.file.refs,11);EQ(native_mapping.active,1);assert(!w.region.quarantined);assert(s->busy);
#ifdef TEST_TYPED
 EQ(s->elem[0].lease.kind,XDEV_EXT_NET_LEASE_PEER_DMA);
#endif
 native_mapping.leases=&h->lease;xdev_ext_netfam_release(s,true);discard_world(&w);
 puts("actual release:false removes active lease+clears handle+quarantines backing while slot busy;stale refusal retains refs");
}
static void net_fields_and_callbacks(bool rx) {
 struct world w;prepare_world(&w,rx);struct xdev_ext_net_slot *s=slot(&w);lease_ok(&w,s,0,64,128,128);lease_ok(&w,s,1,4096,64,rx?4096:64);
 for(u32 i=0;i<2;i++){s->elem[i].hdr_len=14;memset(s->elem[i].hdr,0x80+i,128);}
 /* Native post's inline answers run actual adapter callbacks, tracker and NET CQE. */
 native_inline=1;EQ(xdev_ext_netfam_post(&w.ns,s),0);EQ(native_calls,1);EQ(native_returns,1);EQ(inline_publishes_seen,1);EQ(w.batch.claims,1);EQ(w.batch.publishes,1);EQ(w.batch.claimed_ticket,0x81923344);EQ(w.batch.published_ticket,0x81923344);EQ(w.batch.status,0);assert(!w.batch.sequester);EQ(w.cb.cqe.base.bytes_sent,192);EQ(w.cb.cqe.base.entries_done,2);
 if(rx){struct xdev_ext_peer_rx *x=rx_chain;for(u32 i=0;i<2;i++){assert(x);EQ(x->dma_address,w.addresses[i?1:0]+(i?0:64));EQ(x->len,i?64:128);EQ(x->header_room,14);assert(x->header==s->elem[i].hdr);assert(x->complete==xdev_ext_net_rx_done);for(u32 k=0;k<128;k++)EQ(x->header[k],0x80+i);x=x->next;}assert(!x);}
 else {struct xdev_ext_peer_tx *x=tx_chain;for(u32 i=0;i<2;i++){assert(x);EQ(x->dma_address,w.addresses[i?1:0]+(i?0:64));EQ(x->len,i?64:128);EQ(x->header_len,14);assert(x->header==s->elem[i].hdr);assert(x->complete==xdev_ext_net_tx_done);for(u32 k=0;k<128;k++)EQ(x->header[k],0x80+i);x=x->next;}assert(!x);}
 xdev_ext_netfam_fill_cqe(&w.ns,&s);assert(!s);discard_world(&w);
}
static void runtime_errors(void) {
 struct world w;prepare_world(&w,false);struct xdev_ext_net_slot *s=slot(&w);lease_ok(&w,s,0,64,128,128);native_post_error=-EAGAIN;EQ(xdev_ext_netfam_post(&w.ns,s),-EAGAIN);EQ(w.batch.claims,0);EQ(w.batch.publishes,0);assert(!s->busy);EQ(release_calls,1);assert(release_quiesced[0]);discard_world(&w);
 prepare_world(&w,false);s=slot(&w);lease_ok(&w,s,0,64,128,128);native_inline=1;native_quiesced=false;EQ(xdev_ext_netfam_post(&w.ns,s),0);EQ(w.batch.publishes,1);EQ(w.batch.status,-EIO);assert(w.batch.sequester);EQ(w.cb.cqe.base.bytes_sent,0);EQ(w.cb.cqe.base.entries_done,0);struct xdev_ext_net_slot *uncertain=s;xdev_ext_netfam_fill_cqe(&w.ns,&s);assert(!s&&uncertain->busy&&w.region.quarantined);discard_world(&w);
 prepare_world(&w,false);s=slot(&w);lease_ok(&w,s,0,64,128,128);EQ(xdev_ext_netfam_post(&w.ns,s),0);w.batch.ticket++;tx_chain->complete(tx_chain,0,true);EQ(w.batch.claims,1);EQ(w.batch.claimed_ticket,0x81923344);EQ(w.batch.publishes,0);xdev_ext_netfam_release(s,true);discard_world(&w);
 prepare_world(&w,false);s=slot(&w);lease_ok(&w,s,0,64,128,128);EQ(xdev_ext_netfam_post(&w.ns,s),0);now_ms=30100;EQ(xdev_ext_netfam_progress(&w.ns),20);EQ(w.batch.publishes,1);EQ(w.batch.status,-ETIMEDOUT);assert(w.batch.sequester);assert(s->busy);struct xdev_ext_net_slot *saved=s;xdev_ext_netfam_fill_cqe(&w.ns,&s);assert(!s);assert(saved->busy);assert(w.region.quarantined);w.batch.ticket++;tx_chain->complete(tx_chain,0,true);EQ(w.batch.claims,1);EQ(w.batch.publishes,1);discard_world(&w);
 puts("actual runtime:inline callbacks before post return,immutable ticket,preaccept refusal,timeout quarantine and late suppression");
}
static void actual_NET_submit(void) {
 struct world w;prepare_world(&w,false);w.cb.nr=2;
 w.cb.desc[0]=(struct xdev_ext_net_send_desc){.frame_pos=0,.frame_off=64,.len=128,.header_len=14};
 w.cb.desc[1]=(struct xdev_ext_net_send_desc){.frame_pos=1,.frame_off=4080,.len=64,.header_len=14};
 EQ(xdev_ext_net_submit(&w.stage,&w.batch),-ERANGE);EQ(acquire_calls,2);EQ(release_calls,1);EQ(native_mapping.active,0);EQ(w.file.refs,10);EQ(native_calls,0);assert(!w.ns.slots[0].busy&&!w.cb.slot);discard_world(&w);
 prepare_world(&w,false);w.cb.nr=1;w.cb.desc[0]=(struct xdev_ext_net_send_desc){.frame_pos=0,.frame_off=64,.len=128,.header_len=14};memset(w.cb.desc[0].header,0x6d,128);native_inline=1;expected_slotp=&w.cb.slot;
 EQ(xdev_ext_net_submit(&w.stage,&w.batch),0);assert(native_slot_visible);EQ(inline_publishes_seen,1);EQ(w.batch.publishes,1);assert(w.cb.slot);assert(tx_chain->header==w.cb.slot->elem[0].hdr);for(u32 k=0;k<14;k++)EQ(tx_chain->header[k],0x6d);
 struct xdev_ext_net_rx_mech_cqe out;xdev_ext_net_fill_cqe(&w.stage,&w.batch,&out);assert(!w.cb.slot);EQ(out.base.bytes_sent,128);EQ(out.base.entries_done,1);discard_world(&w);
 puts("actual NET class submit:prefix failure rollback and slot publication before inline native callback");
}
static unsigned local_calls;
static void local_observer(struct xdev_ext_netfam_stage *ns,struct xdev_ext_net_slot *s){local_calls++;assert(ns->lock.held);assert(s->local_known);}
static int withdraw_boundary(struct xdev_ext_netfam_stage *ns,struct xdev_ext_net_slot *s){return 0;}static void link_fail_boundary(struct xdev_ext_netfam_stage *ns,int err){}
static void xdomain_fields(bool rx) {
 struct world w;prepare_world(&w,rx);struct xdev_ext_net_dev_ops ops=*w.member.dev;ops.hdr_policy=XDEV_EXT_NET_HDR_CHANNEL;ops.post_tx=xdev_ext_xd_post_tx;ops.post_rx=xdev_ext_xd_post_rx;
 w.member.dev=&ops;w.member.local=local_observer;w.member.withdraw=withdraw_boundary;w.member.link_fail=link_fail_boundary;
 struct xdev_ext_xd_link link={.up=true,.data_verified_mask=1};struct tb_ring ring={1};link.chan[0].rx=link.chan[0].tx=&ring;struct xdev_ext_xd_ep ep={.xl=&link};w.ns.lk=&ep;struct xdev_ext_net_slot *s=slot(&w);
 lease_ok(&w,s,0,0,4096,4096);lease_ok(&w,s,1,4096,128,rx?4096:128);ring_calls=ring_notifies=local_calls=0;
 EQ(xdev_ext_netfam_post(&w.ns,s),0);EQ(ring_calls,2);EQ(ring_notifies,1);
 for(u32 i=0;i<2;i++){struct ring_frame *f=ring_log[i];assert(f==(void *)s->elem[i].dev.bytes);EQ(f->buffer_phy,w.addresses[i]);EQ(f->size,rx||!i?0:128);EQ(f->sof,1);EQ(f->eof,2);assert(f->callback==(rx?xdev_ext_xd_rx_cb:xdev_ext_xd_tx_cb));if(rx)f->size=s->elem[i].len==4096?0:s->elem[i].len;f->callback(&ring,f,false);}
 EQ(local_calls,1);EQ(w.batch.publishes,0);assert(s->local_known&&s->local_quiesced);EQ(s->local_status,0);xdev_ext_netfam_release(s,true);discard_world(&w);puts(rx?"actual XD RX ring fields and callback":"actual XD TX ring fields and callback");
}
#ifdef TEST_TYPED
static void typed_misuse(void) {
 EQ(XDEV_EXT_NET_LEASE_NONE,0);EQ(XDEV_EXT_NET_LEASE_PEER_DMA,1);EQ(xdev_ext_net_member.lease_kind,1);EQ(xd_member.lease_kind,1);assert(!xdev_ext_net_member.admit);assert(xd_member.admit);
 struct world w;prepare_world(&w,false);struct xdev_ext_net_slot *s=slot(&w);unsigned char old[sizeof(s->elem[0])];memcpy(old,&s->elem[0],sizeof(old));w.member.lease_kind=XDEV_EXT_NET_LEASE_NONE;unsigned a=acquire_calls,r=requester_calls;
 EQ(xdev_ext_netfam_lease(&w.ns,s,0,64,128,128),-EPROTO);EQ(acquire_calls,a);EQ(requester_calls,r);EQ(s->nr,0);assert(!memcmp(old,&s->elem[0],sizeof(old)));w.member.lease_kind=99;EQ(xdev_ext_netfam_lease(&w.ns,s,0,64,128,128),-EPROTO);EQ(acquire_calls,a);
 /* NONE release must not call the peer boundary. */
 s->nr=1;xdev_ext_netfam_release(s,true);EQ(release_calls,0);discard_world(&w);
 for(u32 kind=0;kind<3;kind+=2){struct xdev_ext_netfam_stage ns={0};struct xdev_ext_net_member m=xdev_ext_net_member;m.lease_kind=kind;alloc_calls=0;EQ(xdev_ext_netfam_init(&ns,&w.stage,&m,false,14),-EINVAL);EQ(alloc_calls,0);}
 puts("typed PEER:actual NET/XD declarations,new kind misuse,publication and release tag transitions");
}
#endif
static void init_failures(void) {
 struct xdev_ext_netfam_stage ns={0};struct xdev_ext_net_member m=xdev_ext_net_member;struct xdev_ext_mech_session session={.depth=2};struct xdev_ext_mech_stage stage={.s=&session};alloc_calls=0;
 EQ(xdev_ext_netfam_init(&ns,&stage,NULL,false,14),-EINVAL);m.result=NULL;EQ(xdev_ext_netfam_init(&ns,&stage,&m,false,14),-EINVAL);EQ(alloc_calls,0);m=xdev_ext_net_member;
 for(int fail=1;fail<=2;fail++){alloc_calls=0;alloc_fail=fail;memset(&ns,0,sizeof(ns));EQ(xdev_ext_netfam_init(&ns,&stage,&m,false,14),-ENOMEM);assert(!ns.slots&&!ns.elems);}alloc_fail=0;
}
static void checks(void){init_failures();acquisition();quarantine();net_fields_and_callbacks(false);net_fields_and_callbacks(true);runtime_errors();actual_NET_submit();xdomain_fields(false);xdomain_fields(true);
#ifdef TEST_TYPED
 typed_misuse();
#endif
 puts("PASS: actual PEER family/peer/fd/tracker/NET/XDomain adapter cohort");}
