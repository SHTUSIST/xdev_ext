// SPDX-License-Identifier: GPL-2.0
#ifndef MV_UMEM_GUARD_H
#define MV_UMEM_GUARD_H
#include "mv_create_capture.h"
#define MV_GUARD_MAX (32U*1024U*1024U)
struct mv_umem_guard {
    struct xdp_umem_reg registration;
    const char *prefix;
    int registration_return,registration_errno;
};
static unsigned char mv_guard_byte(uint64_t offset,uint32_t chunk)
{
    return (unsigned char)(0xa7U+offset*131U+(offset/chunk)*17U);
}
static int mv_guard_begin(struct mv_umem_guard *g,const struct xdp_umem_reg *reg,const char *prefix)
{
    uint64_t offset;
    unsigned char *memory=(void *)(uintptr_t)reg->addr;
    if (g->prefix || !memory || !reg->len || reg->len>MV_GUARD_MAX ||
        !reg->chunk_size || reg->len%reg->chunk_size) { errno=EINVAL; return -1; }
    g->registration=*reg; g->prefix=prefix; g->registration_return=-1;
    for (offset=0;offset<reg->len;offset++) memory[offset]=mv_guard_byte(offset,reg->chunk_size);
    return mv_blob(prefix,"umem.before",memory,(size_t)reg->len);
}
static int mv_guard_finish(const struct mv_umem_guard *g,const struct xdev_ext_mech_layout *l,
                          uint64_t session,long stop_return,int stop_errno)
{
    const struct xdp_umem_reg *reg=&g->registration;
    const unsigned char *memory=(void *)(uintptr_t)reg->addr;
    uint64_t offset,checked=0,bad=0;
    long long first=-1;
    char metadata[2048];
    int size;
    if (!g->prefix || g->registration_return || stop_return || !session ||
        l->frame_size!=reg->chunk_size || l->hdr_room<82 ||
        l->hdr_room>l->frame_size || l->seg_len>l->frame_size-l->hdr_room) { errno=EINVAL; return -1; }
    for (offset=0;offset<reg->len;offset++) {
        uint32_t within=(uint32_t)(offset%reg->chunk_size);
        if (within>=l->hdr_room-82 && within<l->hdr_room+l->seg_len) continue;
        checked++;
        if (memory[offset]!=mv_guard_byte(offset,reg->chunk_size)) {
            if (!bad) first=(long long)offset;
            bad++;
        }
    }
    /* Snapshot all actual registered memory after synchronous successful STOP,
     * while its mapping remains live. Host checks tighter per-frame spans. */
    if (mv_blob(g->prefix,"umem.after",memory,(size_t)reg->len)) return -1;
    size=snprintf(metadata,sizeof(metadata),
      "{\"registered_addr\":%llu,\"registered_bytes\":%llu,\"chunk_size\":%u,\"headroom\":%u,\"registration_return\":%d,\"registration_errno\":%d,\"session_id\":%llu,\"stop_syscall_return\":%ld,\"stop_errno\":%d,\"layout\":{\"frame_size\":%u,\"hdr_room\":%u,\"seg_len\":%u,\"group_bytes\":%u},\"checked_bytes\":%llu,\"mismatches\":%llu,\"first_mismatch\":%lld}\n",
      (unsigned long long)reg->addr,(unsigned long long)reg->len,reg->chunk_size,reg->headroom,
      g->registration_return,g->registration_errno,(unsigned long long)session,stop_return,stop_errno,
      l->frame_size,l->hdr_room,l->seg_len,l->group_bytes,(unsigned long long)checked,
      (unsigned long long)bad,first);
    if (size<0 || size>=(int)sizeof(metadata) || mv_blob(g->prefix,"umem.json",metadata,(size_t)size)) return -1;
    if (bad) { errno=EIO; return -1; }
    return 0;
}
#endif
