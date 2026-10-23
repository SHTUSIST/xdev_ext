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
 __u32 held_attempt; /* newest attempt the receiver reported HELD */
 __u16 count;
 __u8 live, native_pending, acked, terminal;
};
struct xdev_ext_rel_tx {
 struct xdev_ext_rel_cfg cfg;
 __u64 next_group, base_group, credit;
 __u64 retransmits, held_acks; /* observational: attempts > 1, accepted HELD */
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
 if (m->type == XDEV_EXT_REL_ACK || m->type == XDEV_EXT_REL_HELD)
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
 t->credit = c->first_group + c->window;
 t->retransmits = t->held_acks = 0;
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
 r->credit = c->first_group + c->window;
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
 return e->attempt == ~(__u32)0 || e->attempt - e->held_attempt >= t->cfg.max_attempts;
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
 if (e->attempt > 1) t->retransmits++;
 return XDEV_EXT_REL_SEND;
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
 e->deadline_ns = now > ~(__u64)0 - t->cfg.timeout_ns ?
                  ~(__u64)0 : now + t->cfg.timeout_ns;
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
     m->credit < t->cfg.first_group + t->cfg.window ||
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
#endif
