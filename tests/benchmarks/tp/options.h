// SPDX-License-Identifier: GPL-2.0
#ifndef TP_EVAL_OPTIONS_H
#define TP_EVAL_OPTIONS_H
#include <cerrno>
#include <cstdint>
#include <climits>
struct tp_eval_options {
 unsigned rank=0, mode=1, depth=1, dtype=3, operation=1, device=0;
 uint64_t elements=1024, rows=1, iterations=10, first_sequence=1;
 uint64_t communicator=1, epoch=1, link=0, timeout_ns=600000000000ULL;
 unsigned group_bytes=0, frame_count=0, trace_capacity=0;
 uint64_t payload_bytes=0, allocation_bytes=0;
};
static inline int tp_eval_geometry(tp_eval_options &o) {
 if (o.rank>1 || (o.mode!=1 && o.mode!=2) || !o.depth || o.depth>256 ||
     (o.mode==1 && o.depth!=1) || !o.iterations || !o.first_sequence ||
     !o.communicator || !o.epoch || o.dtype<1 || o.dtype>3 ||
     o.operation<1 || o.operation>4 || (o.operation==4 && o.mode!=1) || !o.timeout_ns || o.device>INT_MAX)
  return -EINVAL;
 if (o.operation==1 && o.rows!=1) return -EINVAL;
 uint64_t item=o.dtype==3 ? 4:2;
 if (o.rows && o.elements>UINT64_MAX/o.rows) return -EOVERFLOW;
 uint64_t n=o.rows*o.elements;
 if (n>(131072-64)/item) return -E2BIG; // Native max32 frame spans.
 o.payload_bytes=n*item;
 o.group_bytes=unsigned((o.payload_bytes+64+63)&~uint64_t(63));
 unsigned per=(o.group_bytes+4095)/4096;
 o.frame_count=per*o.depth;
 o.allocation_bytes=(uint64_t(o.frame_count)*4096+65535)&~uint64_t(65535);
 if (o.iterations>(UINT64_MAX-o.first_sequence)/o.depth ||
     o.iterations>uint64_t(UINT_MAX)/(o.depth*6ULL)) return -EOVERFLOW;
 o.trace_capacity=unsigned(o.iterations*o.depth*6ULL);
 return 0;
}
#endif
