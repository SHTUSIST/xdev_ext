/* SPDX-License-Identifier: GPL-2.0 */
#ifndef HFT_CORE_H
#define HFT_CORE_H
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
enum hft_phase {HFT_FREE,HFT_READ_PENDING,HFT_READY,HFT_TX_PENDING,HFT_WAIT_RELEASE,HFT_UNKNOWN};
enum { HFT_CQE_MORE=1, HFT_CQE_NOTIF=2, HFT_CQE_COPIED=4 };
struct hft_slot { enum hft_phase phase; unsigned index, bytes; uint64_t token, read_token; };
static inline void hft_slot_init(struct hft_slot *s, unsigned i)
{ *s=(struct hft_slot){.phase=HFT_FREE,.index=i}; }
static inline void hft_slot_unknown(struct hft_slot *s) { s->phase=HFT_UNKNOWN; }
static inline int hft_slot_reusable(const struct hft_slot *s) { return s->phase==HFT_FREE; }
static inline int hft_slot_read_begin(struct hft_slot *s, uint64_t t)
{ if(s->phase!=HFT_FREE) return -EBUSY; s->token=t; s->read_token=t; s->phase=HFT_READ_PENDING; return 0; }
static inline int hft_slot_read_complete(struct hft_slot *s,uint64_t t,int r,unsigned n)
{ if(s->phase!=HFT_READ_PENDING || t!=s->token) {hft_slot_unknown(s);return -EPROTO;}
  s->phase=r>=0 && (unsigned)r==n?HFT_READY:HFT_FREE; return s->phase==HFT_READY?0:-EIO; }
static inline int hft_slot_send_begin(struct hft_slot *s,uint64_t t,unsigned n)
{ if(s->phase!=HFT_READY || t==s->read_token) return -EBUSY; s->token=t;s->bytes=n;s->phase=HFT_TX_PENDING;return 0; }
static inline int hft_slot_cqe(struct hft_slot *s,uint64_t t,int r,unsigned f)
{ if(t!=s->token || (f&~7U) || (f&HFT_CQE_COPIED && !(f&HFT_CQE_NOTIF))) goto bad;
  if(s->phase==HFT_WAIT_RELEASE && (f==HFT_CQE_NOTIF || f==(HFT_CQE_NOTIF|HFT_CQE_COPIED)) && r==0) {s->phase=HFT_FREE;return 0;}
  if(s->phase!=HFT_TX_PENDING || (f&HFT_CQE_NOTIF)) goto bad;
  s->phase=f&HFT_CQE_MORE?HFT_WAIT_RELEASE:HFT_FREE;
  return r>=0 && (unsigned)r==s->bytes?0:-EIO;
 bad: hft_slot_unknown(s); return -EPROTO; }
static inline int hft_guards_ok(const unsigned char *p,size_t n,size_t prefix,size_t payload)
{ size_t i; if(prefix>n || payload>n-prefix) return 0;
  for(i=0;i<prefix;i++) if(p[i]!=0xa5) return 0;
  for(i=prefix+payload;i<n;i++) if(p[i]!=0x5a) return 0;
  return 1; }
#endif
