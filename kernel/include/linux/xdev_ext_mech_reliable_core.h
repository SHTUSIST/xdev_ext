/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XDEV_EXT_MECH_RELIABLE_CORE_H
#define _XDEV_EXT_MECH_RELIABLE_CORE_H

/* Allocation-free protocol rules. Callers serialize each TX/RX instance. */
#define XDEV_EXT_REL_VERSION 3
#define XDEV_EXT_REL_HEADER_LEN 64
#define XDEV_EXT_REL_MAX_WINDOW 32
#define XDEV_EXT_REL_MAX_SEGMENTS 32
#define XDEV_EXT_REL_DATA 1
#define XDEV_EXT_REL_ACK 2
/* Receiver holds every segment and its device chain is still running. Sent
 * only in reply to a retransmission; it never carries completion or credit. */
#define XDEV_EXT_REL_HELD 3
#define XDEV_EXT_REL_ACK_CUM 4
#define XDEV_EXT_REL_MAGIC 0x4e585033U
#define XDEV_EXT_REL_RX_EMPTY 0
#define XDEV_EXT_REL_RX_COLLECT 1
#define XDEV_EXT_REL_RX_SUBMITTED 2
#define XDEV_EXT_REL_RX_DONE 3
#define XDEV_EXT_REL_RX_FAILED 4

/* A BPF translation unit already obtains these exact kernel-owned types
 * from its target's generated vmlinux.h. Portable/host users define them here. */
#ifndef __VMLINUX_H__
enum xdev_ext_rel_action {
 XDEV_EXT_REL_NONE, XDEV_EXT_REL_SEND, XDEV_EXT_REL_COMPLETE, XDEV_EXT_REL_UNKNOWN,
 XDEV_EXT_REL_BACKPRESSURE, XDEV_EXT_REL_HOLD, XDEV_EXT_REL_RECYCLE, XDEV_EXT_REL_REPLAY_ACK,
 XDEV_EXT_REL_SUBMIT, XDEV_EXT_REL_BAD, XDEV_EXT_REL_STALE, XDEV_EXT_REL_REPLAY_HELD,
};
struct xdev_ext_rel_cfg {
 __u64 session, first_group, timeout_ns;
 __u32 window, max_attempts, group_bytes, seg_len;
 __u64 rto_max_ns, ack_delay_ns;
 __u32 initial_credit;
 __u8 resend_order, rsvd[3];
};
struct xdev_ext_rel_msg {
 __u64 session, group, credit;
 __u32 attempt, total_len, relative_offset, payload_len;
 __u16 index, count;
 __u8 type;
};
struct xdev_ext_rel_tx_entry {
 __u64 group, deadline_ns;
 __u32 attempt, total_len;
 __u32 declined;
 __u32 held_attempt; /* newest attempt the receiver reported HELD */
 __u16 count;
 __u8 live, native_pending, acked, terminal;
};
struct xdev_ext_rel_tx {
 struct xdev_ext_rel_cfg cfg;
 __u64 next_group, base_group, credit;
 __u64 retransmits, held_acks; /* observational: attempts > 1, accepted HELD */
 __u32 rr_next;
 struct xdev_ext_rel_tx_entry entry[XDEV_EXT_REL_MAX_WINDOW];
};
struct xdev_ext_rel_rx_entry {
 __u64 group;
 __u32 total_len, present, latest_attempt;
 __u16 count;
 __u8 state;
 __u8 reply; /* pending reply type for this slot: HELD, otherwise ACK */
};
struct xdev_ext_rel_rx {
 struct xdev_ext_rel_cfg cfg;
 __u64 base_group, credit;
 __u64 dup_suppressed; /* observational: DATA never passed downstream again */
 struct xdev_ext_rel_rx_entry entry[XDEV_EXT_REL_MAX_WINDOW];
};
struct xdev_ext_rel_rx_view {
 __u64 group, slot_group, base_group, credit;
 __u32 present, latest_attempt, total_len;
 __u16 count;
 __u8 state, reply;
 __u64 owed;
 __u32 owed_count;
 __u8 must_emit, rsvd[3];
};
struct xdev_ext_rel_tx_candidate {
 __u64 group;
 __u32 slot, attempt;
};
struct xdev_ext_rel_tx_view {
 __u32 count, window, rr_next, rsvd;
 struct xdev_ext_rel_tx_candidate candidate[XDEV_EXT_REL_MAX_WINDOW];
};

#endif
static inline __u64 xdev_ext_rel_be(const __u8 *p, unsigned int n)
{
 __u64 v = 0;
 unsigned int i;
 for (i = 0; i < n; i++) v = (v << 8) | p[i];
 return v;
}
static inline void xdev_ext_rel_put(__u8 *p, __u64 v, unsigned int n)
{
 unsigned int i;
 for (i = 0; i < n; i++) p[n - i - 1] = v >> (8 * i);
}
static inline int xdev_ext_rel_cfg_valid(const struct xdev_ext_rel_cfg *c)
{
 if (!c || !c->session || !c->first_group || !c->timeout_ns ||
     !c->window || c->window > XDEV_EXT_REL_MAX_WINDOW || !c->max_attempts ||
     c->initial_credit > c->window ||
     (c->rto_max_ns && c->rto_max_ns <= c->timeout_ns) || c->resend_order > 2 ||
     (c->ack_delay_ns && c->ack_delay_ns >= c->timeout_ns) ||
     !c->group_bytes || !c->seg_len ||
     (c->group_bytes - 1) / c->seg_len >= XDEV_EXT_REL_MAX_SEGMENTS)
  return -EINVAL;
 if (c->first_group > ~(__u64)0 - c->window) return -EOVERFLOW;
 return 0;
}
static inline int xdev_ext_rel_layout(const struct xdev_ext_rel_cfg *c,
                                 const struct xdev_ext_rel_msg *m)
{
 __u32 off, len, count;
 if (!m->session || !m->group || !m->attempt) return XDEV_EXT_REL_BAD;
 if (m->type == XDEV_EXT_REL_ACK || m->type == XDEV_EXT_REL_HELD ||
     m->type == XDEV_EXT_REL_ACK_CUM)
  return (!m->credit || m->total_len || m->relative_offset ||
          m->payload_len || m->index || m->count) ? XDEV_EXT_REL_BAD : 0;
 if (m->type != XDEV_EXT_REL_DATA || m->credit || !m->total_len || !m->count ||
     m->count > XDEV_EXT_REL_MAX_SEGMENTS || m->index >= m->count ||
     !m->payload_len || m->relative_offset > m->total_len ||
     m->payload_len > m->total_len - m->relative_offset)
  return XDEV_EXT_REL_BAD;
 if ((!m->index && m->relative_offset) ||
     (m->index+1 == m->count ? m->relative_offset+m->payload_len != m->total_len :
                             m->relative_offset+m->payload_len >= m->total_len))
  return XDEV_EXT_REL_BAD;
 if (!c) return 0;
 count = (c->group_bytes - 1) / c->seg_len + 1;
 off = (__u32)m->index * c->seg_len;
 len = c->group_bytes - off;
 if (len > c->seg_len) len = c->seg_len;
 return m->total_len != c->group_bytes || m->count != count ||
        m->relative_offset != off || m->payload_len != len ? XDEV_EXT_REL_BAD : 0;
}
static inline int xdev_ext_rel_tx_init(struct xdev_ext_rel_tx *t, const struct xdev_ext_rel_cfg *c)
{
 unsigned int i;
 int err = xdev_ext_rel_cfg_valid(c);
 if (err) return err;
 t->cfg = *c; t->next_group = t->base_group = c->first_group;
 t->credit = c->first_group + (c->initial_credit ?: c->window);
 t->retransmits = t->held_acks = 0; t->rr_next=0;
 for (i = 0; i < XDEV_EXT_REL_MAX_WINDOW; i++)
  t->entry[i] = (struct xdev_ext_rel_tx_entry){};
 return 0;
}
static inline int xdev_ext_rel_rx_init(struct xdev_ext_rel_rx *r, const struct xdev_ext_rel_cfg *c)
{
 unsigned int i;
 int err = xdev_ext_rel_cfg_valid(c);
 if (err) return err;
 r->cfg = *c; r->base_group = c->first_group;
 r->credit = c->first_group + (c->initial_credit ?: c->window);
 r->dup_suppressed = 0;
 for (i = 0; i < XDEV_EXT_REL_MAX_WINDOW; i++)
  r->entry[i] = (struct xdev_ext_rel_rx_entry){};
 return 0;
}
static inline int xdev_ext_rel_wire_encode(__u8 hdr[64], const struct xdev_ext_rel_msg *m)
{
 unsigned int i;
 if (xdev_ext_rel_layout(0, m)) return -EINVAL;
 for (i = 0; i < 64; i++) hdr[i] = 0;
 xdev_ext_rel_put(hdr, XDEV_EXT_REL_MAGIC, 4);
 hdr[4] = XDEV_EXT_REL_VERSION; hdr[5] = 64; hdr[6] = m->type;
 xdev_ext_rel_put(hdr + 8, m->session, 8); xdev_ext_rel_put(hdr + 16, m->group, 8);
 xdev_ext_rel_put(hdr + 24, m->attempt, 4); xdev_ext_rel_put(hdr + 28, m->total_len, 4);
 xdev_ext_rel_put(hdr + 32, m->index, 2); xdev_ext_rel_put(hdr + 34, m->count, 2);
 xdev_ext_rel_put(hdr + 36, m->relative_offset, 4);
 xdev_ext_rel_put(hdr + 40, m->payload_len, 4); xdev_ext_rel_put(hdr + 48, m->credit, 8);
 return 0;
}
static inline int xdev_ext_rel_wire_decode(const __u8 hdr[64], __u32 payload_bytes,
                                     __u32 crc, const struct xdev_ext_rel_cfg *c,
                                     struct xdev_ext_rel_msg *out)
{
 struct xdev_ext_rel_msg m;
 if (xdev_ext_rel_cfg_valid(c) || xdev_ext_rel_be(hdr, 4) != XDEV_EXT_REL_MAGIC ||
     hdr[4] != 3 || hdr[5] != 64 || hdr[7] ||
     xdev_ext_rel_be(hdr + 44, 4) || xdev_ext_rel_be(hdr + 60, 4) ||
     xdev_ext_rel_be(hdr + 56, 4) != (crc ^ 0xffffffffU)) return XDEV_EXT_REL_BAD;
 m = (struct xdev_ext_rel_msg){
  .session = xdev_ext_rel_be(hdr + 8, 8), .group = xdev_ext_rel_be(hdr + 16, 8),
  .attempt = xdev_ext_rel_be(hdr + 24, 4), .total_len = xdev_ext_rel_be(hdr + 28, 4),
  .index = xdev_ext_rel_be(hdr + 32, 2), .count = xdev_ext_rel_be(hdr + 34, 2),
  .relative_offset = xdev_ext_rel_be(hdr + 36, 4),
  .payload_len = xdev_ext_rel_be(hdr + 40, 4), .credit = xdev_ext_rel_be(hdr + 48, 8),
  .type = hdr[6],
 };
 if (m.session != c->session || m.group < c->first_group ||
     m.group > ~(__u64)0 - c->window || payload_bytes != m.payload_len ||
     xdev_ext_rel_layout(c, &m)) return XDEV_EXT_REL_BAD;
 *out = m;
 return 0;
}
static inline struct xdev_ext_rel_tx_entry *xdev_ext_rel_tx_find(struct xdev_ext_rel_tx *t, __u64 g)
{
 struct xdev_ext_rel_tx_entry *e = &t->entry[g % t->cfg.window];
 return e->live && e->group == g ? e : 0;
}
/* Retry budget: max_attempts consecutive attempts that the receiver never
 * reported HELD. A HELD group is slow downstream, not lost on the wire. */
static inline bool xdev_ext_rel_tx_budget_spent(const struct xdev_ext_rel_tx *t,
                                         const struct xdev_ext_rel_tx_entry *e)
{
 return e->attempt == ~(__u32)0 || (__u64)e->attempt + e->declined - e->held_attempt >= t->cfg.max_attempts;
}
/* Pure admission check of the next group; tx_open applies it. */
static inline int xdev_ext_rel_tx_can_open(const struct xdev_ext_rel_tx *t, __u64 g,
                                    __u32 total, __u16 count)
{
 if (!g || g != t->next_group || total != t->cfg.group_bytes ||
     count != (total - 1) / t->cfg.seg_len + 1 ||
     g > ~(__u64)0 - t->cfg.window) return XDEV_EXT_REL_BAD;
 if (g >= t->credit || g - t->base_group >= t->cfg.window ||
     t->entry[g % t->cfg.window].live)
  return XDEV_EXT_REL_BACKPRESSURE;
 return XDEV_EXT_REL_SEND;
}
static inline int xdev_ext_rel_tx_open(struct xdev_ext_rel_tx *t, __u64 g,
                                 __u32 total, __u16 count)
{
 struct xdev_ext_rel_tx_entry *e;
 int action = xdev_ext_rel_tx_can_open(t, g, total, count);
 if (action != XDEV_EXT_REL_SEND) return action;
 e = &t->entry[g % t->cfg.window];
 *e = (struct xdev_ext_rel_tx_entry){.group=g, .total_len=total, .count=count, .live=1};
 t->next_group++;
 return XDEV_EXT_REL_SEND;
}
static inline int xdev_ext_rel_tx_native_begin(struct xdev_ext_rel_tx *t, __u64 g, __u64 now)
{
 struct xdev_ext_rel_tx_entry *e = xdev_ext_rel_tx_find(t, g);
 (void)now;
 if (e && e->terminal) return XDEV_EXT_REL_BAD;
 if (e && e->native_pending) return XDEV_EXT_REL_BACKPRESSURE;
 if (!e || e->terminal || e->acked || xdev_ext_rel_tx_budget_spent(t, e))
  return XDEV_EXT_REL_BAD;
 e->attempt++; e->native_pending=1;
 if (e->attempt > 1) { t->retransmits++; t->rr_next=(g % t->cfg.window+1) % t->cfg.window; }
 return XDEV_EXT_REL_SEND;
}
static inline __u64 xdev_ext_rel_rto(const struct xdev_ext_rel_cfg *c, __u32 attempt)
{
 __u32 shift=attempt ? attempt-1 : 0;
 if (!c->rto_max_ns) return c->timeout_ns;
 if (shift>=64 || c->timeout_ns>(c->rto_max_ns >> shift)) return c->rto_max_ns;
 return c->timeout_ns << shift;
}
static inline __u64 xdev_ext_rel_deadline(__u64 now, __u64 delay)
{
 return now>~(__u64)0-delay ? ~(__u64)0 : now+delay;
}
static inline int xdev_ext_rel_tx_native_done(struct xdev_ext_rel_tx *t, __u64 g,
                                        __u32 attempt, int status, bool uncertain,
                                        __u64 now)
{
 struct xdev_ext_rel_tx_entry *e = xdev_ext_rel_tx_find(t, g);
 if (!e || e->attempt != attempt || !e->native_pending) return XDEV_EXT_REL_STALE;
 if (uncertain || status) e->terminal = XDEV_EXT_REL_UNKNOWN;
 if (!uncertain) e->native_pending = 0;
 if (e->terminal == XDEV_EXT_REL_UNKNOWN) return XDEV_EXT_REL_UNKNOWN;
 if (e->acked) return e->terminal = XDEV_EXT_REL_COMPLETE;
 e->deadline_ns=xdev_ext_rel_deadline(now,xdev_ext_rel_rto(&t->cfg,e->attempt));
 return XDEV_EXT_REL_NONE;
}
/* ACK completes a group and may raise credit. HELD only restores the retry
 * budget of an attempt the receiver has seen; it never completes or credits. */
static inline int xdev_ext_rel_tx_ack(struct xdev_ext_rel_tx *t, const struct xdev_ext_rel_msg *m)
{
 struct xdev_ext_rel_tx_entry *e;
 if (m->session != t->cfg.session ||
     (m->type != XDEV_EXT_REL_ACK && m->type != XDEV_EXT_REL_HELD) ||
     xdev_ext_rel_layout(&t->cfg, m) ||
     m->credit < t->cfg.first_group + (t->cfg.initial_credit ?: t->cfg.window) ||
     t->next_group > ~(__u64)0 - t->cfg.window ||
     m->credit > t->next_group + t->cfg.window) return XDEV_EXT_REL_BAD;
 e = xdev_ext_rel_tx_find(t, m->group);
 if (!e || e->terminal || e->acked) return XDEV_EXT_REL_STALE;
 if (!e->attempt) return XDEV_EXT_REL_BAD;
 if (m->type == XDEV_EXT_REL_HELD) {
  if (m->attempt > e->attempt) return XDEV_EXT_REL_BAD;
  if (m->attempt <= e->held_attempt) return XDEV_EXT_REL_STALE;
  e->held_attempt = m->attempt; t->held_acks++;
  return XDEV_EXT_REL_NONE;
 }
 if (m->credit > t->credit) t->credit = m->credit;
 e->acked = 1;
 if (!e->native_pending) return e->terminal = XDEV_EXT_REL_COMPLETE;
 return XDEV_EXT_REL_NONE;
}
static inline int xdev_ext_rel_tx_poll(struct xdev_ext_rel_tx *t, __u64 g, __u64 now)
{
 struct xdev_ext_rel_tx_entry *e = xdev_ext_rel_tx_find(t, g);
 if (!e) return XDEV_EXT_REL_STALE;
 if (e->terminal) return e->terminal;
 if (e->native_pending || !e->attempt || now < e->deadline_ns) return XDEV_EXT_REL_NONE;
 if (xdev_ext_rel_tx_budget_spent(t, e)) return e->terminal = XDEV_EXT_REL_UNKNOWN;
 return XDEV_EXT_REL_SEND;
}
static inline int xdev_ext_rel_tx_retire(struct xdev_ext_rel_tx *t, __u64 g)
{
 struct xdev_ext_rel_tx_entry *e = xdev_ext_rel_tx_find(t, g);
 unsigned int i;
 if (!e || !e->terminal || e->native_pending) return -EBUSY;
 e->live=0;
 for (i=0; i<XDEV_EXT_REL_MAX_WINDOW && t->base_group<t->next_group; i++) {
  e=&t->entry[t->base_group % t->cfg.window];
  if (e->group != t->base_group || e->live) break;
  t->base_group++;
 }
 return 0;
}
#ifdef XDEV_EXT_REL_C_GLUE
static inline int xdev_ext_rel_rx_inspect(const struct xdev_ext_rel_rx *r,
                                    const struct xdev_ext_rel_msg *m)
{
 const struct xdev_ext_rel_rx_entry *e;
 if (m->session != r->cfg.session || m->type != XDEV_EXT_REL_DATA ||
     m->group < r->cfg.first_group || m->group > ~(__u64)0 - r->cfg.window ||
     xdev_ext_rel_layout(&r->cfg,m)) return XDEV_EXT_REL_BAD;
 e=&r->entry[m->group % r->cfg.window];
 if (e->group == m->group && e->state) {
  if (e->total_len!=m->total_len || e->count!=m->count) return XDEV_EXT_REL_BAD;
  if (e->state==XDEV_EXT_REL_RX_DONE) return XDEV_EXT_REL_REPLAY_ACK;
  if (e->state==XDEV_EXT_REL_RX_SUBMITTED) return XDEV_EXT_REL_REPLAY_HELD;
  if (e->state==XDEV_EXT_REL_RX_FAILED || (e->present & (1U << m->index)))
   return XDEV_EXT_REL_RECYCLE;
  return XDEV_EXT_REL_HOLD;
 }
 if (m->group < r->base_group) return XDEV_EXT_REL_STALE;
 if (m->group >= r->credit) return XDEV_EXT_REL_BACKPRESSURE;
 return XDEV_EXT_REL_HOLD;
}
/* Record which reply a pending slot owes: HELD only while the chain runs. */
static inline void xdev_ext_rel_rx_reply(struct xdev_ext_rel_rx *r, __u64 g, int action)
{
 struct xdev_ext_rel_rx_entry *e=&r->entry[g % r->cfg.window];
 if (e->group==g)
  e->reply = action==XDEV_EXT_REL_REPLAY_HELD ? XDEV_EXT_REL_HELD : XDEV_EXT_REL_ACK;
}
static inline __u8 xdev_ext_rel_rx_reply_type(const struct xdev_ext_rel_rx *r, __u64 g)
{
 const struct xdev_ext_rel_rx_entry *e=&r->entry[g % r->cfg.window];
 return e->group==g && e->state==XDEV_EXT_REL_RX_SUBMITTED && e->reply==XDEV_EXT_REL_HELD ?
        XDEV_EXT_REL_HELD : XDEV_EXT_REL_ACK;
}
static inline int xdev_ext_rel_rx_commit(struct xdev_ext_rel_rx *r, const struct xdev_ext_rel_msg *m)
{
 struct xdev_ext_rel_rx_entry *e;
 int action=xdev_ext_rel_rx_inspect(r,m);
 if (action!=XDEV_EXT_REL_HOLD) return action;
 e=&r->entry[m->group % r->cfg.window];
 if (e->group!=m->group || !e->state)
  *e=(struct xdev_ext_rel_rx_entry){.group=m->group,.total_len=m->total_len,
                              .count=m->count,.state=XDEV_EXT_REL_RX_COLLECT};
 if (m->attempt>e->latest_attempt) e->latest_attempt=m->attempt;
 e->present |= 1U << m->index;
 if (e->present == (~0U >> (32-e->count))) {
  e->state=XDEV_EXT_REL_RX_SUBMITTED; return XDEV_EXT_REL_SUBMIT;
 }
 return XDEV_EXT_REL_HOLD;
}
#endif
static inline int xdev_ext_rel_rx_finish(struct xdev_ext_rel_rx *r, __u64 g, int status)
{
 struct xdev_ext_rel_rx_entry *e=&r->entry[g % r->cfg.window];
 unsigned int i;
 if (e->group!=g || !e->state || e->state>=XDEV_EXT_REL_RX_DONE) return XDEV_EXT_REL_STALE;
 if (e->state!=XDEV_EXT_REL_RX_SUBMITTED) return XDEV_EXT_REL_BAD;
 if (status) { e->state=XDEV_EXT_REL_RX_FAILED; return XDEV_EXT_REL_NONE; }
 e->state=XDEV_EXT_REL_RX_DONE;
 for (i=0;i<XDEV_EXT_REL_MAX_WINDOW;i++) {
  e=&r->entry[r->base_group % r->cfg.window];
  if (e->group!=r->base_group || e->state!=XDEV_EXT_REL_RX_DONE) break;
  /* Refuse credit wrap; the final admitted identity remains replayable. */
  if (r->base_group >= ~(__u64)0-r->cfg.window) break;
  r->base_group++;
 }
 r->credit=r->base_group+r->cfg.window;
 return XDEV_EXT_REL_REPLAY_ACK;
}
/* Fixed enforcement. Protocol programs cannot override these guards. */
static inline int xdev_ext_rel_wire_verify(const __u8 hdr[64], __u32 crc)
{
 return xdev_ext_rel_be(hdr,4)!=XDEV_EXT_REL_MAGIC || hdr[4]!=3 || hdr[5]!=64 ||
        xdev_ext_rel_be(hdr+56,4)!=(crc^~0U) ? -EBADMSG : 0;
}
static inline void xdev_ext_rel_rx_view_fill(const struct xdev_ext_rel_rx *r, __u64 owed,
                                             __u64 group, struct xdev_ext_rel_rx_view *v)
{
 const struct xdev_ext_rel_rx_entry *e=&r->entry[group % r->cfg.window];
 *v=(struct xdev_ext_rel_rx_view){.group=group,.slot_group=e->group,.base_group=r->base_group,
  .credit=r->credit,.present=e->present,.latest_attempt=e->latest_attempt,.total_len=e->total_len,
  .count=e->count,.state=e->state,.reply=e->reply,.owed=owed};
}
static inline int xdev_ext_rel_rx_claim_check(const struct xdev_ext_rel_rx *r,
                                              __u64 group, __u16 index, __u32 attempt)
{
 const struct xdev_ext_rel_rx_entry *e;
 __u32 count=(r->cfg.group_bytes-1)/r->cfg.seg_len+1;
 if (!group || !attempt) return -EINVAL;
 if (group<r->cfg.first_group || group>~(__u64)0-r->cfg.window) return -ERANGE;
 if (index>=count) return -EINVAL;
 e=&r->entry[group % r->cfg.window];
 if (e->group==group && e->state &&
     (e->state!=XDEV_EXT_REL_RX_COLLECT || (e->present & (1U<<index)))) return -EEXIST;
 if (group<r->base_group || group>=r->credit) return -ERANGE;
 return 0;
}
static inline int xdev_ext_rel_rx_claim(struct xdev_ext_rel_rx *r, __u64 group,
                                        __u16 index, __u32 attempt)
{
 struct xdev_ext_rel_rx_entry *e;
 int err=xdev_ext_rel_rx_claim_check(r,group,index,attempt);
 if (err) return err;
 e=&r->entry[group % r->cfg.window];
 if (e->group!=group || !e->state)
  *e=(struct xdev_ext_rel_rx_entry){.group=group,.total_len=r->cfg.group_bytes,
   .count=(r->cfg.group_bytes-1)/r->cfg.seg_len+1,.state=XDEV_EXT_REL_RX_COLLECT};
 if (attempt>e->latest_attempt) e->latest_attempt=attempt;
 e->present |= 1U<<index;
 if (e->present==(~0U>>(32-e->count))) { e->state=XDEV_EXT_REL_RX_SUBMITTED; return XDEV_EXT_REL_SUBMIT; }
 return XDEV_EXT_REL_HOLD;
}
static inline int xdev_ext_rel_rx_verdict(struct xdev_ext_rel_rx *r, __u64 *owed,
                                          __u64 group, __u16 index, __u32 attempt, int verdict)
{
 struct xdev_ext_rel_rx_entry *e;
 int ret=0;
 if (!group || !attempt) return -EINVAL;
 if (group<r->cfg.first_group || group>~(__u64)0-r->cfg.window) return -ERANGE;
 e=&r->entry[group % r->cfg.window];
 switch (verdict) {
 case XDEV_EXT_REL_HOLD:
  ret=xdev_ext_rel_rx_claim_check(r,group,index,attempt);
  if (ret) return ret;
  break;
 case XDEV_EXT_REL_REPLAY_ACK:
  if (!(e->group==group && e->state==XDEV_EXT_REL_RX_DONE) && group>=r->base_group) return -EINVAL;
  *owed=group; if (e->group==group) e->reply=XDEV_EXT_REL_ACK; ret=1; break;
 case XDEV_EXT_REL_REPLAY_HELD:
  if (e->group!=group || e->state!=XDEV_EXT_REL_RX_SUBMITTED) return -EINVAL;
  if (*owed) return -EBUSY;
  *owed=group; e->reply=XDEV_EXT_REL_HELD; ret=1; break;
 case XDEV_EXT_REL_RECYCLE:
 case XDEV_EXT_REL_STALE:
 case XDEV_EXT_REL_BACKPRESSURE: break;
 case XDEV_EXT_REL_BAD: return 0;
 default: return -EINVAL;
 }
 if (e->group==group && attempt>e->latest_attempt) e->latest_attempt=attempt;
 if (verdict==XDEV_EXT_REL_RECYCLE || verdict==XDEV_EXT_REL_STALE ||
     verdict==XDEV_EXT_REL_REPLAY_ACK || verdict==XDEV_EXT_REL_REPLAY_HELD) r->dup_suppressed++;
 return ret;
}
static inline int xdev_ext_rel_rx_control_check(const struct xdev_ext_rel_rx *r,
                                                __u64 owed, const struct xdev_ext_rel_msg *m)
{
 const struct xdev_ext_rel_rx_entry *e;
 if (m->session!=r->cfg.session ||
     (m->type!=XDEV_EXT_REL_ACK && m->type!=XDEV_EXT_REL_HELD && m->type!=XDEV_EXT_REL_ACK_CUM) ||
     xdev_ext_rel_layout(&r->cfg,m)) return -EINVAL;
 if (m->credit<r->cfg.first_group+(r->cfg.initial_credit ?: r->cfg.window) ||
     m->credit>r->credit) return -ERANGE;
 e=&r->entry[m->group % r->cfg.window];
 if (m->type==XDEV_EXT_REL_ACK_CUM)
  return owed && owed<r->base_group && m->group>=owed && m->group<r->base_group ? 0 : -EINVAL;
 if (m->group!=owed) return -EINVAL;
 if (m->type==XDEV_EXT_REL_ACK)
  return (e->group==m->group && e->state==XDEV_EXT_REL_RX_DONE) || m->group<r->base_group ? 0 : -EINVAL;
 return e->group==m->group && e->state==XDEV_EXT_REL_RX_SUBMITTED &&
        m->attempt<=e->latest_attempt ? 0 : -EINVAL;
}
static inline int xdev_ext_rel_tx_control(struct xdev_ext_rel_tx *t, __u64 group,
                                          __u32 attempt, __u64 credit, __u8 type)
{
 struct xdev_ext_rel_tx_entry *e;
 unsigned int i;
 int ret=-ESTALE;
 if (!group || !attempt || !credit ||
     (type!=XDEV_EXT_REL_ACK && type!=XDEV_EXT_REL_HELD && type!=XDEV_EXT_REL_ACK_CUM)) return -EINVAL;
 if (credit<t->cfg.first_group+(t->cfg.initial_credit ?: t->cfg.window) ||
     t->next_group>~(__u64)0-t->cfg.window || credit>t->next_group+t->cfg.window) return -ERANGE;
 if (type==XDEV_EXT_REL_ACK_CUM) {
  /* A cumulative identity must have been admitted and transmitted. */
  if (group<t->cfg.first_group || group>=t->next_group) return -ESTALE;
  for(i=0;i<t->cfg.window;i++) {
   e=&t->entry[i];
   if (!e->live || e->terminal || e->acked || e->group>group || !e->attempt) continue;
   e->acked=1;
   if (!e->native_pending) { e->terminal=XDEV_EXT_REL_COMPLETE; ret=XDEV_EXT_REL_COMPLETE; }
   else if (ret<0) ret=XDEV_EXT_REL_NONE;
  }
  if (ret>=0 && credit>t->credit) t->credit=credit;
  return ret;
 }
 e=xdev_ext_rel_tx_find(t,group);
 if (!e || e->terminal || e->acked) return -ESTALE;
 if (!e->attempt) return -EINVAL;
 if (type==XDEV_EXT_REL_HELD) {
  if (attempt>e->attempt) return -EINVAL;
  if (attempt<=e->held_attempt) return -ESTALE;
  e->held_attempt=attempt; t->held_acks++; return XDEV_EXT_REL_NONE;
 }
 if (credit>t->credit) t->credit=credit;
 e->acked=1;
 if (!e->native_pending) return e->terminal=XDEV_EXT_REL_COMPLETE;
 return XDEV_EXT_REL_NONE;
}
static inline __u32 xdev_ext_rel_tx_scan_start(const struct xdev_ext_rel_tx *t)
{
 return t->cfg.resend_order==1 ? t->base_group % t->cfg.window :
        t->cfg.resend_order==2 ? t->rr_next % t->cfg.window : 0;
}
static inline int xdev_ext_rel_tx_select_check(const struct xdev_ext_rel_tx *t,
                                              __u64 group, __u64 now)
{
 const struct xdev_ext_rel_tx_entry *e;
 if (!group || group<t->base_group || group-t->base_group>=t->cfg.window ||
     group>~(__u64)0-t->cfg.window) return -ERANGE;
 e=&t->entry[group % t->cfg.window];
 if (!e->live || e->group!=group || e->terminal || e->acked) return -ESTALE;
 if (group<t->base_group || group>=t->next_group || group-t->base_group>=t->cfg.window) return -ERANGE;
 if (e->native_pending || !e->attempt || now<e->deadline_ns) return -EAGAIN;
 return xdev_ext_rel_tx_budget_spent(t,e) ? -EREMOTEIO : 0;
}
static inline int xdev_ext_rel_tx_decline(struct xdev_ext_rel_tx *t, __u64 group, __u64 now)
{
 struct xdev_ext_rel_tx_entry *e=xdev_ext_rel_tx_find(t,group);
 if (!e || e->terminal || e->acked || e->native_pending || !e->attempt || now<e->deadline_ns)
  return XDEV_EXT_REL_STALE;
 e->declined++;
 if (xdev_ext_rel_tx_budget_spent(t,e)) return e->terminal=XDEV_EXT_REL_UNKNOWN;
 e->deadline_ns=xdev_ext_rel_deadline(now,xdev_ext_rel_rto(&t->cfg,e->attempt));
 return XDEV_EXT_REL_NONE;
}
#endif
