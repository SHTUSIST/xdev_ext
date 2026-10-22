/* SPDX-License-Identifier: GPL-2.0 */
/* Included by the AF_XDP provider: the existing session worker owns progress.
 * RX and native callbacks only record bounded protocol/native events under
 * tx_lock, then kick that worker. Native DATA ownership ends before any retry.
 */
struct xsk_rel_data {
 struct xdev_ext_mech_batch *batch;
 u64 ticket;
 u32 count;
 struct xdp_desc desc[XDEV_EXT_REL_MAX_SEGMENTS];
};
struct xsk_rel_control {
 struct xsk_xdev_ext_mech_tx_batch tb;
 struct xdev_ext_mech_frame frame;
 bool busy, uncertain;
};
struct xsk_mech_reliable {
 struct xdev_ext_rel_tx tx;
 struct xdev_ext_rel_rx rx;
 struct xsk_rel_data data[XDEV_EXT_REL_MAX_WINDOW];
 struct xsk_rel_control control[XDEV_EXT_REL_MAX_WINDOW];
 u64 ack_pending[XDEV_EXT_REL_MAX_WINDOW];
 u64 nr_groups; /* zero: legacy unbounded stream; otherwise explicit range */
 /* Worker scratch is separate from the RX envelope. */
 struct xdev_ext_afxdp_reliable_info info;
 struct xdev_ext_mech_frame frames[XDEV_EXT_REL_MAX_SEGMENTS];
 struct xdp_desc scratch[XDEV_EXT_REL_MAX_SEGMENTS];
};

static int xsk_rel_config_load(const struct xdev_ext_mech_stage_uapi *u,
                              struct xdev_ext_afxdp_reliable_config *cfg,
                              u64 *nr_groups)
{
 *nr_groups=0;
 if (!(u->flags & XDEV_EXT_AFXDP_F_RELIABLE) ||
     (u->flags & ~(XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE))) return -EINVAL;
 if (u->flags & XDEV_EXT_AFXDP_F_FINITE) {
  struct xdev_ext_afxdp_reliable_finite_config finite;
  if (copy_from_user(&finite,u64_to_user_ptr(u->arg1),sizeof(finite))) return -EFAULT;
  *cfg=finite.base;
  if (!finite.nr_groups || !cfg->first_group || !cfg->window) return -EINVAL;
  if (cfg->first_group > ~0ULL-finite.nr_groups ||
      cfg->first_group+finite.nr_groups-1 > ~0ULL-cfg->window) return -EOVERFLOW;
  *nr_groups=finite.nr_groups;
 } else if (copy_from_user(cfg,u64_to_user_ptr(u->arg1),sizeof(*cfg))) return -EFAULT;
 return 0;
}

static int xsk_rel_bind(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_stage_uapi *u)
{
 struct xsk_xdev_ext_mech_stage *xst = st->priv;
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 struct xsk_xdev_ext_mech_provider *p = pool->priv;
 const struct xdev_ext_mech_layout *l = xdev_ext_mech_session_layout(st->s);
 struct xdev_ext_afxdp_reliable_config uc;
 struct xdev_ext_rel_cfg cfg;
 struct xsk_mech_reliable *r;
 u32 i;
 u64 nr_groups;
 int err;
 if (!p->zc || !xst->xs->rx || !xst->xs->tx ||
     l->hdr_room < 106 || xst->mtu < 100 ||
     l->seg_len != ((xst->mtu - 20 - 8 - 64) & ~7U)) return -EINVAL;
 if (st->direction==XDEV_EXT_MECH_DIR_FROM_DEVICE &&
     l->hdr_room != XDP_PACKET_HEADROOM+xst->xs->umem->headroom+106) return -EINVAL;
 err=xsk_rel_config_load(u,&uc,&nr_groups);
 if (err) return err;
 cfg = (struct xdev_ext_rel_cfg){.session=u->arg0,.first_group=uc.first_group,
      .timeout_ns=uc.timeout_ns,.window=uc.window,.max_attempts=uc.max_attempts,
      .group_bytes=l->group_bytes,.seg_len=l->seg_len};
 err=xdev_ext_rel_cfg_valid(&cfg);
 if (err) return err;
 if (cfg.window > xdev_ext_mech_session_depth(st->s) ||
     (u64)xdev_ext_mech_session_depth(st->s) * xdev_ext_mech_layout_frames(l) + cfg.window >
     pool->nr_frames - p->source_first) return -ENOSPC;
 r=kvzalloc(sizeof(*r),GFP_KERNEL);
 if (!r) return -ENOMEM;
 r->nr_groups=nr_groups;
 xdev_ext_rel_tx_init(&r->tx,&cfg); xdev_ext_rel_rx_init(&r->rx,&cfg);
 for (i=0;i<cfg.window;i++) {
  struct xsk_rel_control *c=&r->control[i];
  c->frame.index=pool->nr_frames-1-i;
  err=xdev_ext_mech_pool_frame_move(pool,c->frame.index,XDEV_EXT_MECH_F_K_FREE,XDEV_EXT_MECH_F_HELD);
  if (err) goto unwind;
  xsk_xdev_ext_mech_pool_resolve(pool,&c->frame);
  c->frame.data_off=l->hdr_room; c->frame.data_len=0;
  INIT_LIST_HEAD(&c->tb.done);
  c->tb.reliable_stage=st; c->tb.control=true;
 }
 xst->rel=r;
 return 0;
unwind:
 while (i--) xdev_ext_mech_pool_frame_move(pool,r->control[i].frame.index,
                                       XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_K_FREE);
 kvfree(r);
 return err;
}
static void xsk_rel_unbind(struct xdev_ext_mech_stage *st)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_mech_reliable *r=xst->rel;
 struct xdev_ext_mech_pool *pool=xdev_ext_mech_session_pool(st->s);
 u32 i;
 if (!r) return;
 for(i=0;i<r->tx.cfg.window;i++)
  WARN_ON_ONCE(xdev_ext_mech_pool_frame_move(pool,r->control[i].frame.index,
                                        XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_K_FREE));
 kvfree(r); xst->rel=NULL;
}
static void xsk_rel_info(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
                         struct xdev_ext_afxdp_reliable_info *in)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 struct xsk_mech_reliable *r=xst->rel;
 struct xdev_ext_rel_tx_entry *e;
 unsigned long flags;
 in->wire_session=r->tx.cfg.session;
 if (!b) return;
 in->wire_group=xdev_ext_mech_batch_key(b);
 in->wire_type=XDEV_EXT_REL_DATA;
 spin_lock_irqsave(&p->tx_lock,flags);
 e=xdev_ext_rel_tx_find(&r->tx,in->wire_group);
 in->wire_attempt=e ? e->attempt+1 : 1;
 spin_unlock_irqrestore(&p->tx_lock,flags);
}
/* Independently validate the complete Ethernet/IP/UDP envelope and v3 CRC.
 * BPF then supplies the HOLD intent, checked against this admitted message.
 */
static int xsk_rel_decode(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_frame *f,
                          struct xdev_ext_rel_msg *msg)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 struct xsk_xdev_ext_mech_tx_bounds bd={.hdr_room=f->data_off+106,.mtu=xst->mtu};
 struct xdev_ext_mech_frame_info fi={.umem_addr=f->umem_addr,
       .data_off=f->data_off+106,.data_len=f->data_len-106};
 struct xdp_desc d={.addr=f->umem_addr+f->data_off,.len=f->data_len};
 const struct xdev_ext_mech_peer *pe=xdev_ext_mech_session_peer(st->s);
 const u8 *pkt=(const u8 *)f->kaddr+f->data_off;
 u8 header[64];
 u32 crc;
 if (f->data_len<106 || f->data_off>xdev_ext_mech_session_layout(st->s)->frame_size ||
     f->data_len>xdev_ext_mech_session_layout(st->s)->frame_size-f->data_off)
  return XDEV_EXT_REL_BAD;
 if (!xdev_ext_mech_session_admits(st->s)) return XDEV_EXT_REL_BAD;
 memcpy(bd.peer.local_mac,pe->peer_mac,6); memcpy(bd.peer.peer_mac,pe->local_mac,6);
 bd.peer.local_ip=pe->peer_ip; bd.peer.peer_ip=pe->local_ip;
 bd.peer.local_port=pe->peer_port; bd.peer.peer_port=pe->local_port;
 if (p->zc) xp_dma_sync_for_cpu(f->pool_priv);
 if (xsk_xdev_ext_mech_tx_check(&d,&fi,f->kaddr,&bd) ||
     xsk_xdev_ext_mech_be16(pkt+24)!=xsk_xdev_ext_mech_ipv4_csum(pkt+14)) return XDEV_EXT_REL_BAD;
 /* A nonzero UDP checksum is not part of the explicitly configured layout. */
 if (pkt[40] || pkt[41]) return XDEV_EXT_REL_BAD;
 memcpy(header,pkt+42,64); memset(header+56,0,4);
 crc=crc32c(~0U,header,64); crc=crc32c(crc,pkt+106,f->data_len-106);
 return xdev_ext_rel_wire_decode(pkt+42,f->data_len-106,crc,&xst->rel->rx.cfg,msg);
}
static int xsk_rel_rx(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_frame *f,
                      struct xdev_ext_rel_msg *m)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_mech_reliable *r=xst->rel;
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 unsigned long flags;
 int action;
 if (xsk_rel_decode(st,f,m)) return XDEV_EXT_REL_BAD;
 spin_lock_irqsave(&p->tx_lock,flags);
 if (m->type==XDEV_EXT_REL_ACK) action=xdev_ext_rel_tx_ack(&r->tx,m);
 else if (st->direction!=XDEV_EXT_MECH_DIR_FROM_DEVICE) action=XDEV_EXT_REL_BAD;
 else if (r->nr_groups && (m->group<r->rx.cfg.first_group ||
          m->group-r->rx.cfg.first_group>=r->nr_groups)) action=XDEV_EXT_REL_BAD;
 else {
  struct xdev_ext_rel_rx_entry *e=&r->rx.entry[m->group % r->rx.cfg.window];
  action=xdev_ext_rel_rx_inspect(&r->rx,m);
  if (action!=XDEV_EXT_REL_BAD && e->group==m->group && m->attempt>e->latest_attempt)
   e->latest_attempt=m->attempt;
  if (action==XDEV_EXT_REL_REPLAY_ACK)
   r->ack_pending[m->group % r->rx.cfg.window]=m->group;
 }
 spin_unlock_irqrestore(&p->tx_lock,flags);
 if (m->type==XDEV_EXT_REL_ACK || action==XDEV_EXT_REL_REPLAY_ACK) xdev_ext_mech_stage_kick(st);
 return m->type==XDEV_EXT_REL_ACK ? XDEV_EXT_REL_RECYCLE : action;
}
static int xsk_rel_hold_commit(struct xdev_ext_mech_stage *st,const struct xdev_ext_rel_msg *m,
 const struct xdev_ext_mech_hold_intent *hold,const struct xdev_ext_mech_frame *f)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 unsigned long flags;
 int err;
 spin_lock_irqsave(&p->tx_lock,flags);
 err=xdev_ext_mech_hold_commit(st,hold,f);
 if (!err) WARN_ON_ONCE(xdev_ext_rel_rx_commit(&xst->rel->rx,m)==XDEV_EXT_REL_BAD);
 spin_unlock_irqrestore(&p->tx_lock,flags);
 return err;
}
/* C validates the requested protocol identity and CRC on every attempt.
 * Initial core validation and network-only rebuilds share the same boundary. */
static int xsk_rel_packet_check(struct xdev_ext_mech_stage *st,const struct xdp_desc *d,
 const struct xdev_ext_mech_frame_info *fi,const u8 *chunk,
 u64 group,u32 attempt,u64 credit,u8 type,u32 index)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_xdev_ext_mech_tx_bounds bd={
  .hdr_room=xdev_ext_mech_session_layout(st->s)->hdr_room,.mtu=xst->mtu,
  .peer=*xdev_ext_mech_session_peer(st->s),
 };
 struct xdev_ext_rel_msg m;
 const u8 *pkt;
 u8 hdr[64];
 u32 crc;
 int err=xsk_xdev_ext_mech_tx_check(d,fi,chunk,&bd);

 if (err) return err;
 if (d->len!=106+fi->data_len) return -EPROTO;
 pkt=chunk+(d->addr-fi->umem_addr);
 memcpy(hdr,pkt+42,64); memset(hdr+56,0,4);
 crc=crc32c(~0U,hdr,64); crc=crc32c(crc,pkt+106,fi->data_len);
 if (xdev_ext_rel_wire_decode(pkt+42,fi->data_len,crc,&xst->rel->tx.cfg,&m) ||
     m.group!=group || m.attempt!=attempt || m.credit!=credit ||
     m.type!=type || (type==XDEV_EXT_REL_DATA && m.index!=index)) return -EPROTO;
 return 0;
}

/* Initial DATA already has exactly one core BPF BUILD. Validate its v3
 * fields before staging; submit retains and enqueues these admitted bytes. */
static int xsk_rel_validate_initial(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 u32 i;
 int err;
 for (i=0;i<xst->tx_n;i++) {
  err=xsk_rel_packet_check(st,&xst->tx_desc[i],&xst->tx_fi[i],xst->tx_kaddr[i],
                           xdev_ext_mech_batch_key(b),1,0,XDEV_EXT_REL_DATA,i);
  if (err) return err;
  xsk_xdev_ext_mech_tx_finish(xst->tx_pkt[i]);
 }
 return 0;
}

/* Invoke the configured BPF builder directly for a network-only attempt or
 * an independent control frame. Never re-enter the core device chain. */
static int xsk_rel_build(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,
                         struct xsk_rel_control *control,u64 group,u32 attempt,u64 credit)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_mech_reliable *r=xst->rel;
 struct xdev_ext_mech_pool *pool=xdev_ext_mech_session_pool(st->s);
 struct xdev_ext_binding_ctx_v2 base=xdev_ext_binding_make_afxdp_native_tx_ctx(group,
                          control ? 0 : xdev_ext_mech_batch_bytes(b),pool->capabilities);
 struct xdev_ext_mech_call_args a={.member=XDEV_EXT_MECH_MEMBER_BUILD,
       .callsite=XDEV_EXT_MECH_SITE_WORKER,.base=&base,.b=b,
       .frames=r->frames,.nr_frames=control ? 1 : xdev_ext_mech_batch_nr_frames(b),
       .frame_size=pool->frame_size,.hdr_room=xdev_ext_mech_session_layout(st->s)->hdr_room,
       .info=&r->info,.info_size=sizeof(r->info),.scratch=(u8 *)r->scratch,
       .desc_size=sizeof(struct xdp_desc),.desc_cap=XDEV_EXT_REL_MAX_SEGMENTS};
 u32 i;
 s32 ret;
 int err;
 xsk_xdev_ext_mech_fill_info(st,b,&r->info);
 r->info.wire_group=group; r->info.wire_attempt=attempt;
 r->info.wire_credit=credit; r->info.wire_type=control ? XDEV_EXT_REL_ACK : XDEV_EXT_REL_DATA;
 if (control) {
  r->frames[0]=control->frame;
  r->info.base.nr_frames=1;
  r->info.base.f[0]=(struct xdev_ext_mech_frame_info){.umem_addr=control->frame.umem_addr,
                                     .data_off=control->frame.data_off};
 } else for(i=0;i<a.nr_frames;i++) xdev_ext_mech_batch_frame(b,i,&r->frames[i]);
 memset(r->scratch,0,sizeof(r->scratch));
 err=xdev_ext_mech_call(st,&a,&ret,NULL);
 if (err || ret!=XDEV_EXT_MECH_BUILD_SUBMIT) return err ?: -EPROTO;
 for(i=0;i<a.nr_frames;i++) {
  struct xdev_ext_mech_frame_info *fi=&r->info.base.f[i];
  u8 *pkt;
  err=xsk_rel_packet_check(st,&r->scratch[i],fi,r->frames[i].kaddr,
                           group,attempt,credit,control ? XDEV_EXT_REL_ACK : XDEV_EXT_REL_DATA,i);
  if (err) return err;
  pkt=r->frames[i].kaddr+(r->scratch[i].addr-fi->umem_addr);
  xsk_xdev_ext_mech_tx_finish(pkt);
 }
 return 0;
}
/* tx_lock held; reserve all descriptors before the native attempt exists. */
static int xsk_rel_enqueue(struct xdev_ext_mech_stage *st,struct xsk_xdev_ext_mech_tx_batch *tb,
                           const struct xdp_desc *desc,u32 count)
{
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 u32 start,i;
 int err;
 if (p->stopped || ((struct xsk_xdev_ext_mech_stage *)st->priv)->dead) return -ENXIO;
 err=xsk_mech_zc_reserve(&p->ring,count,&start);
 if (err) return err;
 INIT_LIST_HEAD(&tb->done); tb->completion=(struct xsk_mech_zc_batch){.pending=count};
 tb->cancelled_before_native=false;
 tb->native_error=0;
 tb->reliable_stage=st; tb->n=count;
 for(i=0;i<count;i++) {
  struct xsk_mech_zc_slot *slot=&p->slots[(start+i)&(p->ring.capacity-1)];
  xp_dma_sync_for_device(p->xp,xp_raw_get_dma(p->xp,desc[i].addr),desc[i].len);
  *slot=(struct xsk_mech_zc_slot){.desc=desc[i],.batch=tb,.slot=i,
                                .state=XSK_MECH_ZC_PENDING,
                                .owner=tb->control ? XSK_MECH_ZC_CONTROL : XSK_MECH_ZC_DATA};
 }
 return 0;
}
static void xsk_rel_wakeup(struct xdev_ext_mech_stage *st)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 int err;
 mutex_lock(&xst->xs->mutex);
 err=xst->xs->state==XSK_BOUND && !READ_ONCE(xst->dead) ?
     xst->xs->dev->netdev_ops->ndo_xsk_wakeup(xst->xs->dev,xst->xs->queue_id,XDP_WAKEUP_TX) : -ENXIO;
 mutex_unlock(&xst->xs->mutex);
 if (err) { xsk_mech_zc_cancel_pending(p,err); xdev_ext_mech_stage_dead(st,err); }
}
static int xsk_rel_submit(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_mech_reliable *r=xst->rel;
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 struct xsk_xdev_ext_mech_tx_batch *tb=xdev_ext_mech_batch_priv(b);
 u64 group=xdev_ext_mech_batch_key(b);
 struct xsk_rel_data *d=&r->data[group % r->tx.cfg.window];
 struct xdev_ext_rel_tx_entry *e;
 unsigned long flags;
 int action,err;
 spin_lock_irqsave(&p->tx_lock,flags);
 e=xdev_ext_rel_tx_find(&r->tx,group);
 action=e ? XDEV_EXT_REL_SEND : xdev_ext_rel_tx_open(&r->tx,group,
                  xdev_ext_mech_batch_bytes(b),xdev_ext_mech_batch_nr_frames(b));
 if (action!=XDEV_EXT_REL_SEND) { err=action==XDEV_EXT_REL_BACKPRESSURE ? -EAGAIN : -EPROTO; goto out; }
 e=xdev_ext_rel_tx_find(&r->tx,group);
 if (e->attempt || e->native_pending) { err=-EPROTO; goto out; }
 d->ticket=xdev_ext_mech_batch_ticket(b); d->count=xst->tx_n;
 memcpy(d->desc,xst->tx_desc,sizeof(*d->desc)*d->count);
 tb->batch=b; tb->ticket=d->ticket; tb->control=false;
 err=xsk_rel_enqueue(st,tb,d->desc,d->count);
 if (!err) {
  d->batch=b;
  action=xdev_ext_rel_tx_native_begin(&r->tx,group,ktime_get_ns());
  WARN_ON_ONCE(action!=XDEV_EXT_REL_SEND); tb->attempt=e->attempt;
 }
out:
 spin_unlock_irqrestore(&p->tx_lock,flags);
 if (!err) { xsk_rel_wakeup(st); xdev_ext_mech_stage_kick(st); }
 return err;
}
static void xsk_rel_native_done(struct xsk_xdev_ext_mech_tx_batch *tb)
{
 struct xdev_ext_mech_stage *st=tb->reliable_stage;
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 struct xsk_mech_reliable *r=xst->rel;
 unsigned long flags;
 u32 i;
 bool control=tb->control,uncertain=tb->completion.uncertain;
 int status=tb->native_error ?: tb->completion.status;
 bool cancelled=tb->cancelled_before_native && !tb->native_error;
 bool mapped;
 spin_lock_irqsave(&p->tx_lock,flags);
 /* Completion may have left the journal before pool_dead latched stopped
  * and unmapped the NIC. That definite completion still ends native
  * ownership, but no longer grants access to the old DMA mapping. */
 mapped=!p->stopped && p->xp->dev && p->xp->dma_pages;
 if (tb->control) {
  struct xsk_rel_control *c=container_of(tb,struct xsk_rel_control,tb);
  c->uncertain=tb->completion.uncertain;
  if (!c->uncertain) {
   if (mapped)
    dma_sync_single_for_cpu(p->xp->dev,xp_raw_get_dma(p->xp,
                c->frame.umem_addr+c->frame.data_off-106),106,DMA_BIDIRECTIONAL);
   xdev_ext_mech_pool_frame_move(xdev_ext_mech_session_pool(st->s),c->frame.index,
                            XDEV_EXT_MECH_F_INFLIGHT,XDEV_EXT_MECH_F_HELD);
   c->busy=false;
  }
 } else {
  u64 group=xdev_ext_mech_batch_key(tb->batch);
  struct xsk_rel_data *d=&r->data[group % r->tx.cfg.window];
  if (!tb->completion.uncertain && mapped)
   for(i=0;i<d->count;i++)
    dma_sync_single_for_cpu(p->xp->dev,xp_raw_get_dma(p->xp,d->desc[i].addr),
                            d->desc[i].len,DMA_BIDIRECTIONAL);
  xdev_ext_rel_tx_native_done(&r->tx,group,tb->attempt,tb->completion.status,
                         tb->completion.uncertain,ktime_get_ns());
 }
 spin_unlock_irqrestore(&p->tx_lock,flags);
 /* Error publication must precede the last native reference: STOP may
  * otherwise finish and free the session before seeing this failure. */
 if (status && !cancelled)
  xdev_ext_mech_stage_dead(st,status);
 if (control && !uncertain) xdev_ext_mech_stage_native_put(st);
 xdev_ext_mech_stage_kick(st);
}
static void xsk_rel_transport_stats(struct xdev_ext_mech_stage *st,
                                   u32 *pending_acks,u32 *uncertain_controls)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 struct xsk_mech_reliable *r=xst->rel;
 unsigned long flags;
 u32 i;
 if (!r) return;
 spin_lock_irqsave(&p->tx_lock,flags);
 for(i=0;i<r->rx.cfg.window;i++) {
  *pending_acks += !!r->ack_pending[i];
  *uncertain_controls += !!r->control[i].uncertain;
 }
 spin_unlock_irqrestore(&p->tx_lock,flags);
}
static void xsk_rel_batch_end(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,int err)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 u64 group=xdev_ext_mech_batch_key(b);
 unsigned long flags;
 int action;
 if (!xst->rel || st->direction!=XDEV_EXT_MECH_DIR_FROM_DEVICE) return;
 spin_lock_irqsave(&p->tx_lock,flags);
 action=xdev_ext_rel_rx_finish(&xst->rel->rx,group,err);
 if (action==XDEV_EXT_REL_REPLAY_ACK)
  xst->rel->ack_pending[group % xst->rel->rx.cfg.window]=group;
 spin_unlock_irqrestore(&p->tx_lock,flags);
 if (action==XDEV_EXT_REL_REPLAY_ACK) xdev_ext_mech_stage_kick(st);
}
static void xsk_rel_dead(struct xdev_ext_mech_stage *st)
{
 if (((struct xsk_xdev_ext_mech_stage *)st->priv)->rel) xdev_ext_mech_stage_kick(st);
}
static unsigned long xsk_rel_progress(struct xdev_ext_mech_stage *st)
{
 struct xsk_xdev_ext_mech_stage *xst=st->priv;
 struct xsk_xdev_ext_mech_provider *p=xdev_ext_mech_session_pool(st->s)->priv;
 struct xsk_mech_reliable *r=xst->rel;
 unsigned long flags;
 u32 i;
 bool again=false,wake=false;
 if (!r) return 0;
 if (!xdev_ext_mech_session_admits(st->s)) {
  bool pending=false;
  /* Cancel only the journal suffix that hardware never accepted. */
  xsk_mech_zc_cancel_pending(p,-ECANCELED);
  for(i=0;i<r->tx.cfg.window;i++) {
   struct xdev_ext_mech_batch *b=NULL;
   u64 ticket=0;
   bool uncertain=false;
   spin_lock_irqsave(&p->tx_lock,flags);
   if (r->data[i].batch) {
    uncertain=r->tx.entry[i].native_pending;
    if (!uncertain || xst->dead) {
     b=r->data[i].batch; ticket=r->data[i].ticket;
     r->data[i].batch=NULL; r->tx.entry[i].terminal=XDEV_EXT_REL_UNKNOWN;
    } else pending=true;
   }
   spin_unlock_irqrestore(&p->tx_lock,flags);
   if (b) {
    if (uncertain) xdev_ext_mech_batch_sequester(b,ticket,-ENXIO);
    else xdev_ext_mech_batch_complete_cancelled(b,ticket,-ECANCELED);
   }
  }
  return pending ? 1 : 0;
 }
 for(i=0;i<r->tx.cfg.window;i++) {
  struct xdev_ext_mech_batch *b=NULL;
  u64 ticket=0,group;
  int action,err;
  spin_lock_irqsave(&p->tx_lock,flags);
  group=r->tx.entry[i].group;
  action=r->data[i].batch ? xdev_ext_rel_tx_poll(&r->tx,group,ktime_get_ns()) : XDEV_EXT_REL_NONE;
  if (r->data[i].batch) again=true;
  if ((action==XDEV_EXT_REL_COMPLETE || action==XDEV_EXT_REL_UNKNOWN) &&
      !r->tx.entry[i].native_pending) {
   b=r->data[i].batch; ticket=r->data[i].ticket; r->data[i].batch=NULL;
   xdev_ext_rel_tx_retire(&r->tx,group);
  }
  spin_unlock_irqrestore(&p->tx_lock,flags);
  if (b) {
   xdev_ext_mech_batch_complete(b,ticket,action==XDEV_EXT_REL_COMPLETE ? 0 : -EREMOTEIO);
   continue;
  }
  if (action==XDEV_EXT_REL_SEND) {
   struct xsk_rel_data *d=&r->data[i];
   struct xsk_xdev_ext_mech_tx_batch *tb=xdev_ext_mech_batch_priv(d->batch);
   u32 attempt=r->tx.entry[i].attempt+1;
   err=xsk_rel_build(st,d->batch,NULL,group,attempt,0);
   if (err) { xdev_ext_mech_stage_dead(st,err); return 0; }
   memcpy(d->desc,r->scratch,sizeof(*d->desc)*d->count);
   spin_lock_irqsave(&p->tx_lock,flags);
   /* ACK may have arrived while the worker built headers. It still cannot
    * release frames until this same worker publishes the terminal event. */
   if (!r->tx.entry[i].acked && !r->tx.entry[i].terminal) {
    err=xsk_rel_enqueue(st,tb,d->desc,d->count);
    if (!err) { xdev_ext_rel_tx_native_begin(&r->tx,group,ktime_get_ns()); tb->attempt=attempt; wake=true; }
   } else err=0;
   spin_unlock_irqrestore(&p->tx_lock,flags);
   if (err && err!=-EAGAIN) { xdev_ext_mech_stage_dead(st,err); return 0; }
  }
 }
 for(i=0;i<r->rx.cfg.window;i++) {
  struct xsk_rel_control *c=NULL;
  u64 group,credit;
  u32 j,attempt;
  int err;
  spin_lock_irqsave(&p->tx_lock,flags);
  group=r->ack_pending[i]; credit=r->rx.credit;
  attempt=r->rx.entry[i].latest_attempt;
  if (group) {
   again=true;
   for(j=0;j<r->rx.cfg.window;j++)
    if (!r->control[j].busy) { c=&r->control[j]; break; }
  }
  spin_unlock_irqrestore(&p->tx_lock,flags);
  if (!c) continue;
  err=xsk_rel_build(st,NULL,c,group,attempt,credit);
  if (err) { xdev_ext_mech_stage_dead(st,err); return 0; }
  spin_lock_irqsave(&p->tx_lock,flags);
  /* Lock order matches RX HOLD: provider -> session. STOP must either
   * observe this lease before deciding release, or deny the admission. */
  err=xdev_ext_mech_stage_native_get(st);
  if (!err) {
   err=xsk_rel_enqueue(st,&c->tb,r->scratch,1);
   if (err) xdev_ext_mech_stage_native_put(st);
   else {
    c->busy=true;
    xdev_ext_mech_pool_frame_move(xdev_ext_mech_session_pool(st->s),c->frame.index,
                             XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_INFLIGHT);
    if (r->ack_pending[i]==group) r->ack_pending[i]=0;
    wake=true;
   }
  }
  spin_unlock_irqrestore(&p->tx_lock,flags);
  if (err==-ESHUTDOWN) return 0;
  if (err && err!=-EAGAIN) { xdev_ext_mech_stage_dead(st,err); return 0; }
 }
 if (wake) xsk_rel_wakeup(st);
 return again ? max_t(unsigned long,1,nsecs_to_jiffies(r->tx.cfg.timeout_ns/4)) : 0;
}
